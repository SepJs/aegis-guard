use std::path::Path;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncReadExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, info, warn};

use crate::IpcError;

pub struct IpcReader { listener: UnixListener }

impl IpcReader {
    pub async fn listen(socket_path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = socket_path.as_ref();
        if let Some(parent) = path.parent() { tokio::fs::create_dir_all(parent).await?; }
        if path.exists() { tokio::fs::remove_file(path).await?; debug!("removed stale socket at {}", path.display()); }
        let listener = UnixListener::bind(path)?;
        info!(socket = %path.display(), "IPC listener bound");
        Ok(Self { listener })
    }

    pub async fn accept(&self) -> anyhow::Result<IpcStreamReader> {
        let (stream, _addr) = self.listener.accept().await?;
        info!("IPC writer connected");
        Ok(IpcStreamReader { reader: BufReader::new(stream) })
    }
}

pub struct IpcStreamReader { reader: BufReader<UnixStream> }

impl IpcStreamReader {
    pub async fn next_event<T: DeserializeOwned>(&mut self) -> Option<Result<T, IpcError>> {
        let mut len_buf = [0u8; 4];
        match self.reader.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => { debug!("IPC writer disconnected"); return None; }
            Err(e) => return Some(Err(IpcError::Io(e))),
        }
        let payload_len = u32::from_be_bytes(len_buf) as usize;
        let mut payload = vec![0u8; payload_len];
        if let Err(e) = self.reader.read_exact(&mut payload).await { return Some(Err(IpcError::Io(e))); }
        match serde_json::from_slice::<T>(&payload) {
            Ok(v) => Some(Ok(v)),
            Err(e) => { warn!("IPC deserialise error: {e}"); Some(Err(IpcError::Json(e))) }
        }
    }
}
