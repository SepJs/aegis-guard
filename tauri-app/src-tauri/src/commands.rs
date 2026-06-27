// commands.rs — all Tauri commands (journal + entropy + updater + debug log)

use std::sync::Arc;
use tauri::State;

use entropy::models::{ScanRequest, ScanSummary};
use journal::export;
use updater::UpdateInfo;

use crate::state::AppState;

type Res<T> = Result<T, String>;
fn je(e: impl std::fmt::Display) -> String { e.to_string() }

// ── Journal commands ──────────────────────────────────────────────────────────

#[tauri::command]
pub fn list_incidents(
    limit:  u32,
    offset: u32,
    state:  State<'_, Arc<AppState>>,
) -> Res<Vec<journal::models::ThreatIncident>> {
    state.journal.lock().map_err(je)?
        .list_incidents(limit, offset).map_err(je)
}

#[tauri::command]
pub fn list_debug_log(
    limit:  u32,
    offset: u32,
    state:  State<'_, Arc<AppState>>,
) -> Res<Vec<journal::models::DebugEntry>> {
    state.journal.lock().map_err(je)?
        .list_debug(limit, offset).map_err(je)
}

#[tauri::command]
pub fn resolve_incident(
    id:    String,
    state: State<'_, Arc<AppState>>,
) -> Res<()> {
    state.journal.lock().map_err(je)?
        .resolve_incident(&id).map_err(je)
}

#[tauri::command]
pub fn count_open(state: State<'_, Arc<AppState>>) -> Res<u32> {
    state.journal.lock().map_err(je)?
        .count_open().map_err(je)
}

#[tauri::command]
pub fn export_markdown(state: State<'_, Arc<AppState>>) -> Res<String> {
    let incidents = state.journal.lock().map_err(je)?
        .list_incidents(1000, 0).map_err(je)?;
    Ok(export::to_markdown(&incidents, "Aegis-Guard Threat Report"))
}

#[tauri::command]
pub fn export_json(state: State<'_, Arc<AppState>>) -> Res<String> {
    let incidents = state.journal.lock().map_err(je)?
        .list_incidents(1000, 0).map_err(je)?;
    export::to_json(&incidents).map_err(je)
}

// ── Entropy commands ──────────────────────────────────────────────────────────

/// Scan a single file or directory tree for entropy anomalies.
/// Runs in a blocking thread pool — never blocks the async runtime.
#[tauri::command]
pub async fn scan_entropy(request: ScanRequest) -> Res<ScanSummary> {
    tokio::task::spawn_blocking(move || {
        entropy::scan_path(request).map_err(je)
    })
    .await
    .map_err(je)?
}

// ── Updater commands ──────────────────────────────────────────────────────────

/// Check GitHub for a newer release (async, non-blocking).
#[tauri::command]
pub async fn check_update() -> Res<UpdateInfo> {
    updater::check_update().await.map_err(je)
}
