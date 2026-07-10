use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind { Kill, Quarantine, LiftQuarantine, Whitelist }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRequest {
    pub pid: u32, pub process_name: String, pub exe_path: Option<String>,
    pub kind: ActionKind, pub incident_id: Option<String>, pub challenge: String, pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult { pub success: bool, pub pid: u32, pub action: ActionKind, pub message: String, pub ts: i64 }

impl ActionResult {
    pub fn success(pid: u32, action: ActionKind, message: String) -> Result<Self, super::ResponseError> {
        Ok(Self { success: true, pid, action, message, ts: chrono::Utc::now().timestamp_millis() })
    }
}

#[derive(Debug, Error, Serialize)]
pub enum ResponseError {
    #[error("safety boundary violation: {reason}")]
    SafetyViolation { reason: String },
    #[error("process pid={pid} name='{name}' is whitelisted and cannot be acted upon")]
    Whitelisted { pid: u32, name: String },
    #[error("invalid challenge token — action rejected")]
    InvalidChallenge,
    #[error("audit write failed: {0}")]
    AuditFailed(String),
    #[error("action execution failed: {0}")]
    ExecutionFailed(String),
    #[error("process pid={0} does not exist or already exited")]
    ProcessNotFound(u32),
}
