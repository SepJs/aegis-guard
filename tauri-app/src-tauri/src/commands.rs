use std::sync::Arc;
use tauri::State;

use active_defense::{
    audit::AuditEntry,
    models::{ActionKind, ActionRequest, ActionResult},
    whitelist::WhitelistEntry,
};
use deception::canary::CanaryToken;
use entropy::models::{ScanRequest, ScanSummary};
use journal::export;
use threat_intel::ioc::IocStats;
use threat_intel::models::IocMatch;
use updater::UpdateInfo;

use crate::state::AppState;

type Res<T> = Result<T, String>;
fn je(e: impl std::fmt::Display) -> String { e.to_string() }

// ── Journal commands ──────────────────────────────────────────────────────────

#[tauri::command]
pub fn list_incidents(limit: u32, offset: u32, state: State<'_, Arc<AppState>>) -> Res<Vec<journal::models::ThreatIncident>> {
    state.journal.lock().map_err(je)?.list_incidents(limit, offset).map_err(je)
}

#[tauri::command]
pub fn list_debug_log(limit: u32, offset: u32, state: State<'_, Arc<AppState>>) -> Res<Vec<journal::models::DebugEntry>> {
    state.journal.lock().map_err(je)?.list_debug(limit, offset).map_err(je)
}

#[tauri::command]
pub fn resolve_incident(id: String, state: State<'_, Arc<AppState>>) -> Res<()> {
    state.journal.lock().map_err(je)?.resolve_incident(&id).map_err(je)
}

#[tauri::command]
pub fn count_open(state: State<'_, Arc<AppState>>) -> Res<u32> {
    state.journal.lock().map_err(je)?.count_open().map_err(je)
}

#[tauri::command]
pub fn export_markdown(state: State<'_, Arc<AppState>>) -> Res<String> {
    let inc = state.journal.lock().map_err(je)?.list_incidents(1000, 0).map_err(je)?;
    Ok(export::to_markdown(&inc, "Aegis-Guard Threat Report — Vladimir Unknown"))
}

#[tauri::command]
pub fn export_json(state: State<'_, Arc<AppState>>) -> Res<String> {
    let inc = state.journal.lock().map_err(je)?.list_incidents(1000, 0).map_err(je)?;
    export::to_json(&inc).map_err(je)
}

// ── Entropy commands ──────────────────────────────────────────────────────────

#[tauri::command]
pub async fn scan_entropy(request: ScanRequest) -> Res<ScanSummary> {
    tokio::task::spawn_blocking(move || entropy::scan_path(request).map_err(je)).await.map_err(je)?
}

// ── Updater commands ──────────────────────────────────────────────────────────

#[tauri::command]
pub async fn check_update() -> Res<UpdateInfo> { updater::check_update().await.map_err(je) }

// ── Phase 4: Active Defense commands ─────────────────────────────────────────

#[tauri::command]
pub fn generate_challenge(pid: u32, action: String) -> Res<String> {
    Ok(format!("CONFIRM-{}-{}", action.to_uppercase(), pid))
}

#[tauri::command]
pub async fn execute_action(
    pid: u32, process_name: String, exe_path: Option<String>, action: String,
    incident_id: Option<String>, challenge: String, note: String,
    state: State<'_, Arc<AppState>>,
) -> Res<ActionResult> {
    let expected = format!("CONFIRM-{}-{}", action.to_uppercase(), pid);
    if challenge.trim() != expected {
        return Err(format!("Invalid challenge token. Expected '{}', got '{}'.", expected, challenge.trim()));
    }
    let kind = match action.as_str() {
        "kill" => ActionKind::Kill, "quarantine" => ActionKind::Quarantine,
        "lift_quarantine" => ActionKind::LiftQuarantine, "whitelist" => ActionKind::Whitelist,
        other => return Err(format!("Unknown action: {}", other)),
    };
    let req = ActionRequest { pid, process_name, exe_path, kind, incident_id, challenge: challenge.clone(), note };
    // No .lock() — response_engine is Send + Sync on its own.
    state.response_engine.execute(req).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub fn list_audit_log(limit: u32, offset: u32, state: State<'_, Arc<AppState>>) -> Res<Vec<AuditEntry>> {
    state.response_engine.audit_log().list(limit, offset).map_err(je)
}

#[tauri::command]
pub fn verify_audit_chain(state: State<'_, Arc<AppState>>) -> Res<Vec<String>> {
    state.response_engine.audit_log().verify_chain().map_err(je)
}

#[tauri::command]
pub fn list_whitelist(state: State<'_, Arc<AppState>>) -> Res<Vec<WhitelistEntry>> {
    Ok(state.response_engine.whitelist().list())
}

#[tauri::command]
pub fn remove_from_whitelist(pid: u32, state: State<'_, Arc<AppState>>) -> Res<bool> {
    state.response_engine.whitelist().remove(pid).map_err(je)
}

// ── Phase 5: Threat Intel + Canary + Behavioral commands ─────────────────────

#[tauri::command]
pub fn get_ioc_stats() -> Res<IocStats> {
    threat_intel::ThreatMatcher::new().map(|m| m.stats()).map_err(je)
}

#[tauri::command]
pub fn check_ioc_manual(value: String, context: String) -> Res<Option<IocMatch>> {
    let matcher = threat_intel::ThreatMatcher::new().map_err(je)?;
    if let Some(m) = matcher.check_ip(&value, &context) { return Ok(Some(m)); }
    if let Some(m) = matcher.check_domain(&value, &context) { return Ok(Some(m)); }
    if let Some(m) = matcher.check_hash(&value, &context) { return Ok(Some(m)); }
    Ok(None)
}

#[tauri::command]
pub fn list_canaries() -> Res<Vec<CanaryToken>> {
    deception::canary::CanaryManager::new().map(|m| m.list()).map_err(je)
}

#[tauri::command]
pub fn create_canary(file_path: String, description: String) -> Res<CanaryToken> {
    let mgr = deception::canary::CanaryManager::new().map_err(je)?;
    mgr.create_canary(&file_path, &description).map_err(je)
}

#[tauri::command]
pub fn delete_canary(id: String) -> Res<bool> {
    let mgr = deception::canary::CanaryManager::new().map_err(je)?;
    mgr.delete(&id).map_err(je)
}

#[tauri::command]
pub fn get_behavioral_stats(_state: State<'_, Arc<AppState>>) -> Res<serde_json::Value> {
    Ok(serde_json::json!({
        "status": "active",
        "description": "Behavioral baseline engine running — collecting /proc observations every 5s",
        "min_samples_for_detection": 30,
        "anomaly_threshold_z": 3.5
    }))
}
