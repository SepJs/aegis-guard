use std::time::Duration;
use std::collections::VecDeque;

use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tracing::{debug, info, warn};

use crate::{IpcError, RING_CAP};

const BACKOFF_MS: &[u64] = &[100, 200, 400, 800, 1600, 3200];

pub struct IpcWriter {
    socket_path: String,
    stream:      Option<UnixStream>,
    ring:        VecDeque<Vec<u8>>,
}

impl IpcWriter {
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self { socket_path: socket_path.into(), stream: None, ring: VecDeque::with_capacity(RING_CAP) }
    }

    pub async fn send<T: Serialize>(&mut self, value: &T) -> Result<(), IpcError> {
        let payload = serde_json::to_vec(value)?;
        if payload.len() > u32::MAX as usize { return Err(IpcError::PayloadTooLarge(payload.len())); }
        if self.ring.len() >= RING_CAP {
            self.ring.pop_front();
            warn!("IPC ring buffer full — oldest event dropped");
        }
        self.ring.push_back(payload);
        self.flush_ring().await;
        Ok(())
    }

    async fn flush_ring(&mut self) {
        if self.stream.is_none() {
            if let Err(e) = self.try_connect().await {
                debug!("flush skipped — not connected: {e}");
                return;
            }
        }
        let stream = match self.stream.as_mut() { Some(s) => s, None => return };
        while let Some(payload) = self.ring.front() {
            let len_bytes = (payload.len() as u32).to_be_bytes();
            let result = async {
                stream.write_all(&len_bytes).await?;
                stream.write_all(payload).await?;
                stream.flush().await
            }.await;
            match result {
                Ok(_) => { self.ring.pop_front(); }
                Err(e) => { warn!("IPC write failed: {e} — will retry on next event"); self.stream = None; break; }
            }
        }
    }

    async fn try_connect(&mut self) -> Result<(), IpcError> {
        for (attempt, &delay_ms) in BACKOFF_MS.iter().enumerate() {
            match UnixStream::connect(&self.socket_path).await {
                Ok(s) => { info!(attempt = attempt + 1, socket = %self.socket_path, "IPC connected"); self.stream = Some(s); return Ok(()); }
                Err(e) => { debug!(attempt = attempt + 1, delay_ms, error = %e, "IPC connect failed — retrying"); tokio::time::sleep(Duration::from_millis(delay_ms)).await; }
            }
        }
        Err(IpcError::ReconnectExhausted(BACKOFF_MS.len() as u32))
    }
}
