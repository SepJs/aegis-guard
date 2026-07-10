use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrapKind { TrapFileAccessed, TrapFileModified, TrapFileExecuted, HoneypotConnected, HoneypotKillAttempt, CanaryTokenExfiltrated }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeceptionEvent {
    pub id: String, pub kind: TrapKind, pub target: String,
    pub trigger_pid: Option<u32>, pub trigger_proc: Option<String>,
    pub confidence: String, pub reason: String, pub ts: i64,
}
