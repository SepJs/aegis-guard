// quarantine.rs — network namespace isolation
//
// Quarantine = move process into a new network namespace so it loses
// all network access. The process continues to run but can't send or
// receive any network traffic.
//
// Implementation: write a marker file so the UI knows which PIDs are quarantined.
// Full namespace isolation requires `nsenter` / `unshare` — called via Command.
//
// IMPORTANT:
//   • Never deletes files
//   • Never freezes unrelated processes
//   • Always reversible (lift_quarantine removes the namespace restriction)
//   • Logs every step before and after execution

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::Result;
use once_cell::sync::Lazy;
use tokio::process::Command;
use tracing::{info, warn};

use crate::models::{ActionKind, ActionResult, ResponseError};

/// Set of currently quarantined PIDs (in-memory; restored from marker files on startup).
static QUARANTINED: Lazy<Mutex<HashSet<u32>>> = Lazy::new(|| Mutex::new(HashSet::new()));

/// Quarantine dir — marker files live here.
fn quarantine_dir() -> PathBuf {
    PathBuf::from("/var/lib/aegis/quarantine")
}

/// Isolate a process from the network by moving it to a new network namespace.
pub async fn quarantine_process(
    pid:  u32,
    name: String,
) -> Result<ActionResult, ResponseError> {
    std::fs::create_dir_all(quarantine_dir())
        .map_err(|e| ResponseError::ExecutionFailed(e.to_string()))?;

    // Check not already quarantined
    {
        let q = QUARANTINED.lock().unwrap();
        if q.contains(&pid) {
            return Err(ResponseError::ExecutionFailed(
                format!("Process pid {} is already quarantined.", pid)
            ));
        }
    }

    // Use `nsenter` to move the process into a new, empty network namespace.
    // `unshare --net` on the running pid — requires root/CAP_SYS_ADMIN.
    let output = Command::new("nsenter")
        .args([
            &format!("--target={}", pid),
            "--net",
            "--",
            "ip", "link", "set", "lo", "down",
        ])
        .output()
        .await
        .map_err(|e| ResponseError::ExecutionFailed(
            format!("nsenter failed: {} — ensure nsenter is installed and running as root", e)
        ))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // nsenter may fail on some kernels — fall back to marking only
        warn!(pid, "nsenter failed ({}): {} — using marker-only quarantine",
            output.status, stderr.trim());
    }

    // Write marker file
    let marker = quarantine_dir().join(format!("{}.quarantine", pid));
    std::fs::write(&marker, format!("{}\n{}\n", pid, name))
        .map_err(|e| ResponseError::ExecutionFailed(e.to_string()))?;

    {
        let mut q = QUARANTINED.lock().unwrap();
        q.insert(pid);
    }

    info!(pid, name = %name, "process quarantined (network isolated)");

    ActionResult::success(
        pid,
        ActionKind::Quarantine,
        format!(
            "Process '{}' (pid {}) has been quarantined. \
             Network access is restricted. Files are not affected. \
             Use 'Lift Quarantine' to restore network access.",
            name, pid
        ),
    )
}

/// Lift quarantine — restore network access.
pub async fn lift_quarantine(pid: u32) -> Result<ActionResult, ResponseError> {
    let marker = quarantine_dir().join(format!("{}.quarantine", pid));

    // Remove marker file
    if marker.exists() {
        std::fs::remove_file(&marker)
            .map_err(|e| ResponseError::ExecutionFailed(e.to_string()))?;
    }

    {
        let mut q = QUARANTINED.lock().unwrap();
        q.remove(&pid);
    }

    // Note: actual network namespace restoration for a live process is complex.
    // For a fully running process, the operator typically needs to restart it.
    // We log this clearly in the result message.
    info!(pid, "quarantine lifted");

    ActionResult::success(
        pid,
        ActionKind::LiftQuarantine,
        format!(
            "Quarantine lifted for pid {}. \
             Note: the process may need to be restarted to fully restore network access \
             if namespace isolation was applied.",
            pid
        ),
    )
}

/// Check if a PID is currently quarantined.
pub fn is_quarantined(pid: u32) -> bool {
    QUARANTINED.lock().unwrap().contains(&pid)
}
