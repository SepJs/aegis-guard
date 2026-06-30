// models.rs — self-protection event types

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfProtectKind {
    /// Own binary was modified on disk while running
    BinaryTampered,
    /// Process is being traced via ptrace (e.g. gdb, strace)
    PtraceDetected,
    /// Audit log BLAKE3 chain is broken
    AuditChainBroken,
    /// IPC socket replaced or permissions changed
    SocketTampered,
    /// Journal database file modified externally
    JournalTampered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfProtectEvent {
    pub id:         String,
    pub kind:       SelfProtectKind,
    pub confidence: String,
    pub reason:     String,
    pub detail:     String,
    pub ts:         i64,
}
