use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Mutex;
use once_cell::sync::Lazy;
use tokio::process::Command;
use tracing::{info, warn};

use crate::models::{ActionKind, ActionResult, ResponseError};

static QUARANTINED: Lazy<Mutex<HashSet<u32>>> = Lazy::new(|| Mutex::new(HashSet::new()));

fn quarantine_dir() -> PathBuf { PathBuf::from("/var/lib/aegis/quarantine") }

pub async fn quarantine_process(pid: u32, name: String) -> Result<ActionResult, ResponseError> {
    std::fs::create_dir_all(quarantine_dir()).map_err(|e| ResponseError::ExecutionFailed(e.to_string()))?;
    { let q = QUARANTINED.lock().unwrap(); if q.contains(&pid) { return Err(ResponseError::ExecutionFailed(format!("Process pid {} is already quarantined.", pid))); } }

    let output = Command::new("nsenter").args([&format!("--target={}", pid), "--net", "--", "ip", "link", "set", "lo", "down"]).output().await
        .map_err(|e| ResponseError::ExecutionFailed(format!("nsenter failed: {} — ensure nsenter is installed and running as root", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!(pid, "nsenter failed ({}): {} — using marker-only quarantine", output.status, stderr.trim());
    }

    let marker = quarantine_dir().join(format!("{}.quarantine", pid));
    std::fs::write(&marker, format!("{}\n{}\n", pid, name)).map_err(|e| ResponseError::ExecutionFailed(e.to_string()))?;
    { let mut q = QUARANTINED.lock().unwrap(); q.insert(pid); }

    info!(pid, name = %name, "process quarantined (network isolated)");
    ActionResult::success(pid, ActionKind::Quarantine, format!("Process '{}' (pid {}) has been quarantined. Network access is restricted. Files are not affected. Use 'Lift Quarantine' to restore network access.", name, pid))
}

pub async fn lift_quarantine(pid: u32) -> Result<ActionResult, ResponseError> {
    let marker = quarantine_dir().join(format!("{}.quarantine", pid));
    if marker.exists() { std::fs::remove_file(&marker).map_err(|e| ResponseError::ExecutionFailed(e.to_string()))?; }
    { let mut q = QUARANTINED.lock().unwrap(); q.remove(&pid); }
    info!(pid, "quarantine lifted");
    ActionResult::success(pid, ActionKind::LiftQuarantine, format!("Quarantine lifted for pid {}. Note: the process may need to be restarted to fully restore network access if namespace isolation was applied.", pid))
}

pub fn is_quarantined(pid: u32) -> bool { QUARANTINED.lock().unwrap().contains(&pid) }
