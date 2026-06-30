// kill.rs — two-phase process termination
//
// Phase 1: SIGTERM — gives process a chance to clean up (5 second grace)
// Phase 2: SIGKILL — only if still running after grace period
//
// Kill is IRREVERSIBLE. Every kill is logged before execution.
// The caller must have already verified safety and written the audit entry.

use std::time::Duration;

use anyhow::Result;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use tracing::{info, warn};

use crate::models::{ActionKind, ActionResult, ResponseError};

const GRACE_PERIOD_SECS: u64 = 5;
const POLL_INTERVAL_MS:  u64 = 100;

/// Terminate a process: SIGTERM → 5s grace → SIGKILL if still alive.
pub async fn kill_process(
    pid:  u32,
    name: String,
) -> Result<ActionResult, ResponseError> {
    let nix_pid = Pid::from_raw(pid as i32);

    // ── Step 1: SIGTERM ───────────────────────────────────────────────────────
    info!(pid, name = %name, "sending SIGTERM");

    signal::kill(nix_pid, Signal::SIGTERM)
        .map_err(|e| ResponseError::ExecutionFailed(
            format!("SIGTERM failed for pid {}: {}", pid, e)
        ))?;

    // ── Step 2: Wait for voluntary exit ──────────────────────────────────────
    let deadline = tokio::time::Instant::now()
        + Duration::from_secs(GRACE_PERIOD_SECS);

    loop {
        tokio::time::sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;

        // Process exited voluntarily
        if !proc_exists(pid) {
            info!(pid, name = %name, "process exited after SIGTERM");
            return ActionResult::success(
                pid,
                ActionKind::Kill,
                format!("Process '{}' (pid {}) terminated cleanly after SIGTERM.", name, pid),
            );
        }

        if tokio::time::Instant::now() >= deadline {
            break;
        }
    }

    // ── Step 3: SIGKILL — process ignored SIGTERM ─────────────────────────────
    warn!(pid, name = %name, "process did not exit after {}s — sending SIGKILL", GRACE_PERIOD_SECS);

    signal::kill(nix_pid, Signal::SIGKILL)
        .map_err(|e| ResponseError::ExecutionFailed(
            format!("SIGKILL failed for pid {}: {}", pid, e)
        ))?;

    // Brief wait to confirm
    tokio::time::sleep(Duration::from_millis(200)).await;

    if proc_exists(pid) {
        // Extremely unusual — likely a zombie or kernel bug
        return Err(ResponseError::ExecutionFailed(format!(
            "Process pid {} still alive after SIGKILL — may be in uninterruptible sleep (D state).",
            pid
        )));
    }

    ActionResult::success(
        pid,
        ActionKind::Kill,
        format!(
            "Process '{}' (pid {}) did not respond to SIGTERM. \
             Forcefully terminated with SIGKILL after {}s grace period.",
            name, pid, GRACE_PERIOD_SECS
        ),
    )
}

fn proc_exists(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{}", pid)).exists()
}
