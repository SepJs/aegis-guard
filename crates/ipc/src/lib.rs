// ipc/src/lib.rs — Unix Domain Socket bridge
//
// Wire format (same on both ends):
//   [ 4 bytes: payload length as u32 big-endian ][ N bytes: UTF-8 JSON ]
//
// Two halves:
//   writer::IpcWriter  — used by process-engine to send ProcEvents
//   reader::IpcReader  — used by tauri backend to receive ProcEvents
//
// Reconnect strategy:
//   Writer retries with exponential back-off (100ms → 3.2s, max 6 attempts).
//   Reader exposes an async stream; caller loops and reconnects on error.
//   Ring buffer: writer drops oldest event when buffer > RING_CAP.

pub mod writer;
pub mod reader;
pub mod error;

/// Default socket path — can be overridden via AEGIS_SOCKET env var.
pub const DEFAULT_SOCKET_PATH: &str = "/run/aegis/proc.sock";

/// Maximum events buffered in the writer before oldest are dropped.
pub const RING_CAP: usize = 512;

pub use error::IpcError;
