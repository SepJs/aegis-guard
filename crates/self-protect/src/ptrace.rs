// ptrace.rs — detect if this process is being traced/debugged
//
// Reads TracerPid from /proc/self/status.
// If non-zero, a debugger (gdb, strace, ltrace) is attached.
// This is a legitimate defensive check — security tools need to know
// if they are being observed by an attacker trying to reverse them.

use std::time::Duration;
use anyhow::Result;
use chrono::Utc;
use tokio::sync::mpsc;
use tracing::{info, warn};
use uuid::Uuid;

use crate::models::{SelfProtectEvent, SelfProtectKind};

const CHECK_INTERVAL_SECS: u64 = 10;

/// Read TracerPid from /proc/self/status.
/// Returns 0 if not traced, >0 if a tracer is attached.
pub fn read_tracer_pid() -> Result<u32> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("TracerPid:\t") {
            return Ok(rest.trim().parse().unwrap_or(0));
        }
    }
    Ok(0)
}

/// Spawn background ptrace detection loop.
pub async fn start_ptrace_monitor(tx: mpsc::Sender<SelfProtectEvent>) {
    info!("ptrace monitor started — checking every {}s", CHECK_INTERVAL_SECS);

    let mut interval = tokio::time::interval(Duration::from_secs(CHECK_INTERVAL_SECS));
    let mut was_traced = false;

    loop {
        interval.tick().await;

        let tracer_pid = match read_tracer_pid() {
            Ok(pid) => pid,
            Err(e)  => { warn!("ptrace check failed: {}", e); continue; }
        };

        let is_traced = tracer_pid != 0;

        // Only emit on state change (don't spam if tracer stays attached)
        if is_traced && !was_traced {
            warn!(tracer_pid, "PTRACE DETECTED — debugger attached to process-engine");

            let ev = SelfProtectEvent {
                id:         Uuid::new_v4().to_string(),
                kind:       SelfProtectKind::PtraceDetected,
                confidence: "high".into(),
                reason:     format!(
                    "Aegis-Guard process-engine is being traced by pid {}. \
                     A debugger or monitoring tool (gdb, strace, ltrace) is attached. \
                     An attacker may be attempting to reverse-engineer or disable the security engine.",
                    tracer_pid
                ),
                detail: format!("tracer_pid={}", tracer_pid),
                ts: Utc::now().timestamp_millis(),
            };
            let _ = tx.send(ev).await;
        }

        was_traced = is_traced;
    }
}
