// safety.rs — hard safety boundaries that can NEVER be overridden
//
// These checks run before any action is executed.
// If ANY check fails, the action is rejected immediately — no exceptions.

use crate::models::{ActionKind, ActionRequest, ResponseError};

/// PIDs that are absolutely forbidden to act upon.
const FORBIDDEN_PIDS: &[u32] = &[0, 1, 2];

/// Minimum PID that can be targeted — never act on kernel threads.
const MIN_SAFE_PID: u32 = 100;

/// Process names that can never be killed or quarantined.
const PROTECTED_NAMES: &[&str] = &[
    "systemd", "init", "kthreadd", "kworker",
    "ksoftirqd", "migration", "watchdog",
    "kdevtmpfs", "kauditd", "khungtaskd",
    // Aegis-Guard itself must never self-destruct
    "aegis-process-engine",
    "aegis-network-observer",
    "aegis-tauri",
];

#[derive(Debug, Default)]
pub struct SafetyBoundary;

impl SafetyBoundary {
    /// Check all safety constraints for a given action request.
    /// Returns Ok(()) if safe to proceed, Err(SafetyViolation) otherwise.
    pub fn check(&self, req: &ActionRequest) -> Result<(), ResponseError> {
        // ── Rule 1: PID floor ─────────────────────────────────────────────────
        if req.pid < MIN_SAFE_PID || FORBIDDEN_PIDS.contains(&req.pid) {
            return Err(ResponseError::SafetyViolation {
                reason: format!(
                    "PID {} is below the minimum safe threshold ({}). \
                     Kernel threads and init cannot be targeted.",
                    req.pid, MIN_SAFE_PID
                ),
            });
        }

        // ── Rule 2: Protected process names ───────────────────────────────────
        let name_lower = req.process_name.to_lowercase();
        for &protected in PROTECTED_NAMES {
            if name_lower == protected || name_lower.starts_with(protected) {
                return Err(ResponseError::SafetyViolation {
                    reason: format!(
                        "Process '{}' (pid {}) is a protected system process \
                         and cannot be targeted by active defense actions.",
                        req.process_name, req.pid
                    ),
                });
            }
        }

        // ── Rule 3: LiftQuarantine doesn't need kill-specific checks ──────────
        if req.kind == ActionKind::LiftQuarantine || req.kind == ActionKind::Whitelist {
            return Ok(());
        }

        // ── Rule 4: Verify the process still exists before acting ─────────────
        if !proc_exists(req.pid) {
            return Err(ResponseError::ProcessNotFound(req.pid));
        }

        // ── Rule 5: Kill challenge must be non-empty ──────────────────────────
        if req.kind == ActionKind::Kill && req.challenge.trim().is_empty() {
            return Err(ResponseError::InvalidChallenge);
        }

        Ok(())
    }
}

fn proc_exists(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{}", pid)).exists()
}
