pub mod writer;
pub mod reader;
pub mod error;

pub const DEFAULT_SOCKET_PATH: &str = "/run/aegis/proc.sock";
pub const RING_CAP: usize = 512;

pub use error::IpcError;
