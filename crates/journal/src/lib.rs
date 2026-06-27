// journal/src/lib.rs — Aegis-Guard SQLite threat journal
//
// Two tables:
//   threat_incidents — genuine detections, BLAKE3 tamper-evident
//   debug_log        — false positives / benign activity for investigation
//
// All writes are synchronous (rusqlite); called from Tauri async command
// via spawn_blocking. This keeps the DB logic simple and testable.

pub mod db;
pub mod models;
pub mod digest;
pub mod export;

pub use db::Journal;
pub use models::{DebugEntry, Severity, ThreatIncident};
