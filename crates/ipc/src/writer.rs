// ipc/src/writer.rs — process-engine side
//
// Usage (in process-engine main.rs Week 2 replacement):
//
//   let mut writer = IpcWriter::connect("/run/aegis/proc.sock").await?;
//   writer.send(&proc_event).await?;

use std::time::Duration;
use std::collections::VecDeque;

use anyhow::Result;
use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tracing::{debug, info, warn};

use crate::{IpcError, RING_CAP};

/// Back-off schedule: 100 ms → 200 → 400 → 800 → 1600 → 3200 ms
const BACKOFF_MS: &[u64] = &[100, 200, 400, 800, 1600, 3200];

pub struct IpcWriter {
    socket_path: String,
    stream:      Option<UnixStream>,
    /// Ring buffer — holds serialised payloads not yet flushed
    ring:        VecDeque<Vec<u8>>,
}

impl IpcWriter {
    /// Create a writer. Does NOT connect immediately — connection is lazy
    /// so the engine can start before the Tauri backend is ready.
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
            stream:      None,
            ring:        VecDeque::with_capacity(RING_CAP),
        }
    }

    /// Serialise `value` and send it over the socket.
    /// If the socket is not connected, buffers the event and retries connection.
    pub async fn send<T: Serialize>(&mut self, value: &T) -> Result<(), IpcError> {
        let payload = serde_json::to_vec(value)?;

        if payload.len() > u32::MAX as usize {
            return Err(IpcError::PayloadTooLarge(payload.len()));
        }

        // Buffer the payload
        if self.ring.len() >= RING_CAP {
            // Drop oldest — ring buffer policy
            self.ring.pop_front();
            warn!("IPC ring buffer full — oldest event dropped");
        }
        self.ring.push_back(payload);

        // Try to flush buffered events
        self.flush_ring().await;
        Ok(())
    }

    /// Flush all buffered payloads. Silently stops if write fails —
    /// next call to send() will attempt reconnect.
    async fn flush_ring(&mut self) {
        // Ensure we have a live connection
        if self.stream.is_none() {
            if let Err(e) = self.try_connect().await {
                debug!("flush skipped — not connected: {e}");
                return;
            }
        }

        let stream = match self.stream.as_mut() {
            Some(s) => s,
            None    => return,
        };

        while let Some(payload) = self.ring.front() {
            let len_bytes = (payload.len() as u32).to_be_bytes();

            let result = async {
                stream.write_all(&len_bytes).await?;
                stream.write_all(payload).await?;
                stream.flush().await
            }.await;

            match result {
                Ok(_) => { self.ring.pop_front(); }
                Err(e) => {
                    warn!("IPC write failed: {e} — will retry on next event");
                    self.stream = None; // force reconnect next time
                    break;
                }
            }
        }
    }

    /// Attempt connection with exponential back-off.
    async fn try_connect(&mut self) -> Result<(), IpcError> {
        for (attempt, &delay_ms) in BACKOFF_MS.iter().enumerate() {
            match UnixStream::connect(&self.socket_path).await {
                Ok(s) => {
                    info!(
                        attempt = attempt + 1,
                        socket  = %self.socket_path,
                        "IPC connected"
                    );
                    self.stream = Some(s);
                    return Ok(());
                }
                Err(e) => {
                    debug!(
                        attempt = attempt + 1,
                        delay_ms,
                        error = %e,
                        "IPC connect failed — retrying"
                    );
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
            }
        }

        Err(IpcError::ReconnectExhausted(BACKOFF_MS.len() as u32))
    }
}
