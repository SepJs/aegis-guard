// active-defense/src/lib.rs — Phase 4: Active Response Engine
//
// SAFETY CONTRACT (hard limits — never cross these):
//
//   1. NEVER kill PID ≤ 100 or any kernel thread
//   2. NEVER kill without SIGTERM first + grace period
//   3. NEVER quarantine PID 1 (init) or systemd
//   4. NEVER delete files — quarantine = network isolation only
//   5. EVERY action writes an immutable BLAKE3-chained audit entry BEFORE execution
//   6. Whitelisted processes are NEVER acted upon, even if re-flagged
//   7. Every destructive action requires a cryptographic challenge token confirmed by caller
//
// Actions are irreversible (kill) or reversible (quarantine — can be lifted).
// The UI must present these limits clearly.

pub mod audit;
pub mod kill;
pub mod quarantine;
pub mod whitelist;
pub mod safety;
pub mod models;

pub use models::{ActionRequest, ActionResult, ActionKind, ResponseError};
pub use safety::SafetyBoundary;

use std::sync::Arc;
use anyhow::Result;
use tracing::{info, warn, error};

use audit::AuditLog;
use whitelist::WhitelistStore;

/// Central dispatcher — every active response goes through here.
/// Checks safety, validates challenge token, writes audit, then executes.
pub struct ResponseEngine {
    audit:     Arc<AuditLog>,
    whitelist: Arc<WhitelistStore>,
    boundary:  SafetyBoundary,
}

impl ResponseEngine {
    pub fn new(data_dir: &std::path::Path) -> Result<Self> {
        Ok(Self {
            audit:     Arc::new(AuditLog::open(data_dir.join("audit.db"))?),
            whitelist: Arc::new(WhitelistStore::load(data_dir.join("whitelist.json"))?),
            boundary:  SafetyBoundary::default(),
        })
    }

    /// Execute an active response action.
    /// Returns Ok(ActionResult) on success, Err on safety violation or OS error.
    pub async fn execute(&self, req: ActionRequest) -> Result<ActionResult, ResponseError> {
        // ── Step 1: Safety boundary check ────────────────────────────────────
        self.boundary.check(&req)?;

        // ── Step 2: Whitelist check ───────────────────────────────────────────
        if self.whitelist.is_whitelisted(req.pid, &req.process_name) {
            warn!(
                pid  = req.pid,
                name = %req.process_name,
                "action blocked — process is whitelisted"
            );
            return Err(ResponseError::Whitelisted {
                pid:  req.pid,
                name: req.process_name.clone(),
            });
        }

        // ── Step 3: Write audit entry BEFORE execution ────────────────────────
        let audit_id = self.audit.record_before(&req)
            .map_err(|e| ResponseError::AuditFailed(e.to_string()))?;

        // ── Step 4: Execute the action ────────────────────────────────────────
        let result = match req.kind {
            ActionKind::Kill => {
                kill::kill_process(req.pid, req.process_name.clone()).await
            }
            ActionKind::Quarantine => {
                quarantine::quarantine_process(req.pid, req.process_name.clone()).await
            }
            ActionKind::LiftQuarantine => {
                quarantine::lift_quarantine(req.pid).await
            }
            ActionKind::Whitelist => {
                self.whitelist.add(req.pid, req.process_name.clone(), req.exe_path.clone())
                    .map_err(|e| ResponseError::ExecutionFailed(e.to_string()))?;
                ActionResult::success(
                    req.pid,
                    ActionKind::Whitelist,
                    format!("Process '{}' (pid {}) added to whitelist",
                        req.process_name, req.pid),
                )
            }
        };

        // ── Step 5: Update audit with outcome ─────────────────────────────────
        match &result {
            Ok(res) => {
                info!(
                    audit_id = %audit_id,
                    action   = ?req.kind,
                    pid      = req.pid,
                    "action completed successfully"
                );
                self.audit.record_after(&audit_id, true, &res.message).ok();
            }
            Err(e) => {
                error!(
                    audit_id = %audit_id,
                    action   = ?req.kind,
                    pid      = req.pid,
                    error    = %e,
                    "action failed"
                );
                self.audit.record_after(&audit_id, false, &e.to_string()).ok();
            }
        }

        result
    }

    pub fn audit_log(&self)     -> Arc<AuditLog>      { self.audit.clone() }
    pub fn whitelist(&self)     -> Arc<WhitelistStore> { self.whitelist.clone() }
}
