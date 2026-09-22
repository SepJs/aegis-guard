pub mod writer;
pub mod reader;
pub mod error;

#[cfg(unix)]
pub const DEFAULT_SOCKET_PATH: &str = "/run/aegis/proc.sock";
#[cfg(windows)]
pub const DEFAULT_SOCKET_PATH: &str = "127.0.0.1:50054";

pub const RING_CAP: usize = 512;

pub use error::IpcError;
