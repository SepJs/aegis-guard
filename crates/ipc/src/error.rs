// ipc/src/error.rs

use thiserror::Error;

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("socket I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialisation error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("payload too large: {0} bytes (max 4 GiB)")]
    PayloadTooLarge(usize),

    #[error("connection closed by peer")]
    ConnectionClosed,

    #[error("all reconnect attempts exhausted after {0} tries")]
    ReconnectExhausted(u32),
}
