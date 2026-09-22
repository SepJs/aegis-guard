use std::time::Duration;
use tracing::{info, warn};

#[cfg(target_os = "linux")]
use nix::sys::signal::{self, Signal};
#[cfg(target_os = "linux")]
use nix::unistd::Pid;

use crate::models::{ActionKind, ActionResult, ResponseError};

const GRACE_PERIOD_SECS: u64 = 5;
const POLL_INTERVAL_MS: u64 = 100;

pub async fn kill_process(pid: u32, name: String) -> Result<ActionResult, ResponseError> {
    #[cfg(target_os = "linux")]
    {
        let nix_pid = Pid::from_raw(pid as i32);
        info!(pid, name = %name, "sending SIGTERM");
        signal::kill(nix_pid, Signal::SIGTERM).map_err(|e| ResponseError::ExecutionFailed(format!("SIGTERM failed for pid {}: {}", pid, e)))?;

        let deadline = tokio::time::Instant::now() + Duration::from_secs(GRACE_PERIOD_SECS);
        loop {
            tokio::time::sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
            if !proc_exists(pid) {
                info!(pid, name = %name, "process exited after SIGTERM");
                return ActionResult::success(pid, ActionKind::Kill, format!("Process '{}' (pid {}) terminated cleanly after SIGTERM.", name, pid));
            }
            if tokio::time::Instant::now() >= deadline { break; }
        }

        warn!(pid, name = %name, "process did not exit after {}s — sending SIGKILL", GRACE_PERIOD_SECS);
        signal::kill(nix_pid, Signal::SIGKILL).map_err(|e| ResponseError::ExecutionFailed(format!("SIGKILL failed for pid {}: {}", pid, e)))?;
        tokio::time::sleep(Duration::from_millis(200)).await;

        if proc_exists(pid) {
            return Err(ResponseError::ExecutionFailed(format!("Process pid {} still alive after SIGKILL — may be in uninterruptible sleep (D state).", pid)));
        }
        ActionResult::success(pid, ActionKind::Kill, format!("Process '{}' (pid {}) did not respond to SIGTERM. Forcefully terminated with SIGKILL after {}s grace period.", name, pid, GRACE_PERIOD_SECS))
    }

    #[cfg(windows)]
    {
        info!(pid, name = %name, "terminating Windows process via taskkill");
        let status = tokio::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F", "/T"])
            .output().await
            .map_err(|e| ResponseError::ExecutionFailed(format!("taskkill execution failed: {}", e)))?;
        if !status.status.success() {
            let stderr = String::from_utf8_lossy(&status.stderr);
            return Err(ResponseError::ExecutionFailed(format!("taskkill failed for pid {}: {}", pid, stderr.trim())));
        }
        ActionResult::success(pid, ActionKind::Kill, format!("Process '{}' (pid {}) terminated forcefully on Windows.", name, pid))
    }

    #[cfg(all(not(target_os = "linux"), not(windows)))]
    {
        Err(ResponseError::ExecutionFailed("Unsupported OS for process termination".into()))
    }
}

fn proc_exists(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        std::path::Path::new(&format!("/proc/{}", pid)).exists()
    }
    #[cfg(windows)]
    {
        std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {}", pid)])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()))
            .unwrap_or(false)
    }
    #[cfg(all(not(target_os = "linux"), not(windows)))]
    {
        let _ = pid;
        false
    }
}
