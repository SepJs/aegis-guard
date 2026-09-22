use std::path::Path;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncReadExt, BufReader};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use crate::IpcError;

pub enum IpcListenerInner {
    #[cfg(unix)]
    Unix(UnixListener),
    Tcp(TcpListener),
}

pub struct IpcReader {
    inner: IpcListenerInner,
}

impl IpcReader {
    pub async fn listen(socket_path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = socket_path.as_ref();
        let path_str = path.to_string_lossy();

        if path_str.contains(':') || cfg!(windows) {
            let addr = if path_str.contains(':') {
                path_str.to_string()
            } else {
                "127.0.0.1:50054".to_string()
            };
            let listener = TcpListener::bind(&addr).await?;
            info!(addr = %addr, "IPC TCP listener bound");
            return Ok(Self { inner: IpcListenerInner::Tcp(listener) });
        }

        #[cfg(unix)]
        {
            if let Some(parent) = path.parent() { tokio::fs::create_dir_all(parent).await?; }
            if path.exists() { tokio::fs::remove_file(path).await?; debug!("removed stale socket at {}", path.display()); }
            let listener = UnixListener::bind(path)?;
            info!(socket = %path.display(), "IPC Unix listener bound");
            Ok(Self { inner: IpcListenerInner::Unix(listener) })
        }

        #[cfg(not(unix))]
        {
            let listener = TcpListener::bind("127.0.0.1:50054").await?;
            info!("IPC TCP fallback listener bound on 127.0.0.1:50054");
            Ok(Self { inner: IpcListenerInner::Tcp(listener) })
        }
    }

    pub async fn accept(&self) -> anyhow::Result<IpcStreamReader> {
        match &self.inner {
            #[cfg(unix)]
            IpcListenerInner::Unix(listener) => {
                let (stream, _addr) = listener.accept().await?;
                info!("IPC Unix writer connected");
                Ok(IpcStreamReader::Unix(BufReader::new(stream)))
            }
            IpcListenerInner::Tcp(listener) => {
                let (stream, addr) = listener.accept().await?;
                info!(remote = %addr, "IPC TCP writer connected");
                Ok(IpcStreamReader::Tcp(BufReader::new(stream)))
            }
        }
    }
}

pub enum IpcStreamReader {
    #[cfg(unix)]
    Unix(BufReader<UnixStream>),
    Tcp(BufReader<TcpStream>),
}

impl IpcStreamReader {
    pub async fn next_event<T: DeserializeOwned>(&mut self) -> Option<Result<T, IpcError>> {
        let mut len_buf = [0u8; 4];
        let read_res = match self {
            #[cfg(unix)]
            IpcStreamReader::Unix(r) => r.read_exact(&mut len_buf).await,
            IpcStreamReader::Tcp(r) => r.read_exact(&mut len_buf).await,
        };

        match read_res {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => { debug!("IPC writer disconnected"); return None; }
            Err(e) => return Some(Err(IpcError::Io(e))),
        }
        let payload_len = u32::from_be_bytes(len_buf) as usize;
        let mut payload = vec![0u8; payload_len];

        let payload_res = match self {
            #[cfg(unix)]
            IpcStreamReader::Unix(r) => r.read_exact(&mut payload).await,
            IpcStreamReader::Tcp(r) => r.read_exact(&mut payload).await,
        };

        if let Err(e) = payload_res { return Some(Err(IpcError::Io(e))); }
        match serde_json::from_slice::<T>(&payload) {
            Ok(v) => Some(Ok(v)),
            Err(e) => { warn!("IPC deserialise error: {e}"); Some(Err(IpcError::Json(e))) }
        }
    }
}
