// ipc/src/reader.rs — Tauri backend side
//
// Usage (in tauri-app/src-tauri/main.rs):
//
//   let mut reader = IpcReader::listen("/run/aegis/proc.sock").await?;
//   while let Some(event) = reader.next_event::<ProcEvent>().await {
//       journal.insert(&event)?;
//       app_handle.emit("proc-event", &event)?;
//   }

use std::path::Path;

use anyhow::Result;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncReadExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{info, warn, debug};

use crate::IpcError;

/// Listens on a Unix socket and deserialises incoming events.
/// The process-engine is the writer; the Tauri backend is the single reader.
pub struct IpcReader {
    listener: UnixListener,
}

impl IpcReader {
    /// Bind the socket and start listening.
    /// Creates /run/aegis/ directory if it does not exist.
    /// Removes a stale socket file if present.
    pub async fn listen(socket_path: impl AsRef<Path>) -> Result<Self> {
        let path = socket_path.as_ref();

        // Ensure the directory exists
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // Remove stale socket from a previous run
        if path.exists() {
            tokio::fs::remove_file(path).await?;
            debug!("removed stale socket at {}", path.display());
        }

        let listener = UnixListener::bind(path)?;
        info!(socket = %path.display(), "IPC listener bound");

        Ok(Self { listener })
    }

    /// Accept one writer connection and return a stream reader.
    /// Call this in a loop to handle reconnects when process-engine restarts.
    pub async fn accept(&self) -> Result<IpcStreamReader> {
        let (stream, _addr) = self.listener.accept().await?;
        info!("IPC writer connected");
        Ok(IpcStreamReader {
            reader: BufReader::new(stream),
        })
    }
}

/// Reads framed JSON messages from a single connected writer.
pub struct IpcStreamReader {
    reader: BufReader<UnixStream>,
}

impl IpcStreamReader {
    /// Read one length-prefixed JSON message and deserialise it.
    /// Returns None when the writer closes the connection.
    pub async fn next_event<T: DeserializeOwned>(&mut self) -> Option<Result<T, IpcError>> {
        // Read 4-byte length prefix
        let mut len_buf = [0u8; 4];
        match self.reader.read_exact(&mut len_buf).await {
            Ok(_)  => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                debug!("IPC writer disconnected");
                return None;
            }
            Err(e) => return Some(Err(IpcError::Io(e))),
        }

        let payload_len = u32::from_be_bytes(len_buf) as usize;

        // Read payload
        let mut payload = vec![0u8; payload_len];
        if let Err(e) = self.reader.read_exact(&mut payload).await {
            return Some(Err(IpcError::Io(e)));
        }

        // Deserialise
        match serde_json::from_slice::<T>(&payload) {
            Ok(v)  => Some(Ok(v)),
            Err(e) => {
                warn!("IPC deserialise error: {e}");
                Some(Err(IpcError::Json(e)))
            }
        }
    }
}
