use crate::models::{ActionKind, ActionRequest, ResponseError};

const FORBIDDEN_PIDS: &[u32] = &[0, 1, 2];
const MIN_SAFE_PID: u32 = 100;
const PROTECTED_NAMES: &[&str] = &["systemd","init","kthreadd","kworker","ksoftirqd","migration","watchdog","kdevtmpfs","kauditd","khungtaskd","aegis-process-engine","aegis-network-observer","aegis-tauri"];

#[derive(Debug, Default)]
pub struct SafetyBoundary;

impl SafetyBoundary {
    pub fn check(&self, req: &ActionRequest) -> Result<(), ResponseError> {
        if req.pid < MIN_SAFE_PID || FORBIDDEN_PIDS.contains(&req.pid) {
            return Err(ResponseError::SafetyViolation { reason: format!("PID {} is below the minimum safe threshold ({}). Kernel threads and init cannot be targeted.", req.pid, MIN_SAFE_PID) });
        }
        let name_lower = req.process_name.to_lowercase();
        for &protected in PROTECTED_NAMES {
            if name_lower == protected || name_lower.starts_with(protected) {
                return Err(ResponseError::SafetyViolation { reason: format!("Process '{}' (pid {}) is a protected system process and cannot be targeted by active defense actions.", req.process_name, req.pid) });
            }
        }
        if req.kind == ActionKind::LiftQuarantine || req.kind == ActionKind::Whitelist { return Ok(()); }
        if !proc_exists(req.pid) { return Err(ResponseError::ProcessNotFound(req.pid)); }
        if req.kind == ActionKind::Kill && req.challenge.trim().is_empty() { return Err(ResponseError::InvalidChallenge); }
        Ok(())
    }
}

fn proc_exists(pid: u32) -> bool { std::path::Path::new(&format!("/proc/{}", pid)).exists() }
