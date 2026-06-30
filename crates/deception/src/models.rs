// models.rs — deception layer data types

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrapKind {
    TrapFileAccessed,
    TrapFileModified,
    TrapFileExecuted,
    HoneypotConnected,
    HoneypotKillAttempt,
    CanaryTokenExfiltrated,
}

/// Emitted when any deception element is triggered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeceptionEvent {
    pub id:          String,
    pub kind:        TrapKind,
    /// Path of the trap file, or addr of honeypot connection
    pub target:      String,
    /// PID of the process that triggered the trap (if known)
    pub trigger_pid: Option<u32>,
    pub trigger_proc: Option<String>,
    /// Confidence is always HIGH for deception — legitimate processes
    /// never access files or services that don't exist for them
    pub confidence:  String,
    pub reason:      String,
    pub ts:          i64,
}
