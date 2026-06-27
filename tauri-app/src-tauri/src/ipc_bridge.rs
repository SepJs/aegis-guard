// ipc_bridge.rs — reads ProcEvents from Unix socket, persists + emits to UI
// Phase 2: handles PATH/ARG/ENV rule kinds in addition to PAR rules

use std::sync::Arc;
use chrono::{TimeZone, Utc};
use tauri::{AppHandle, Emitter};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use ipc::{reader::IpcReader, DEFAULT_SOCKET_PATH};
use journal::models::{Severity, ThreatIncident};
use crate::state::AppState;

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
pub struct ProcEvent {
    pub id:         String,
    pub kind:       String,
    pub pid:        u32,
    pub ppid:       u32,
    pub name:       String,
    pub cmdline:    Vec<String>,
    pub exe:        Option<String>,
    pub cwd:        Option<String>,
    pub uid:        u32,
    pub gid:        u32,
    pub start_time: u64,
    pub anomaly:    Option<AnomalyDetail>,
    pub ts:         i64,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
pub struct AnomalyDetail {
    pub rule:       String,
    pub confidence: String,
    pub reason:     String,
    pub parent_exe: Option<String>,
    pub ancestors:  Vec<u32>,
}

pub async fn run(socket_path: String, state: Arc<AppState>, app: AppHandle) {
    loop {
        info!(socket = %socket_path, "IPC bridge: binding socket…");

        let reader = match IpcReader::listen(&socket_path).await {
            Ok(r)  => r,
            Err(e) => {
                error!("IPC listen error: {e} — retry in 2s");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                continue;
            }
        };

        match reader.accept().await {
            Ok(mut stream) => {
                info!("IPC bridge: process-engine connected");
                loop {
                    match stream.next_event::<ProcEvent>().await {
                        Some(Ok(event)) => handle_event(event, &state, &app),
                        Some(Err(e))    => warn!("IPC decode error: {e}"),
                        None            => { info!("IPC bridge: process-engine disconnected"); break; }
                    }
                }
            }
            Err(e) => error!("IPC accept error: {e}"),
        }

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

fn handle_event(event: ProcEvent, state: &Arc<AppState>, app: &AppHandle) {
    debug!(pid = event.pid, kind = %event.kind, name = %event.name, "IPC event");

    // Emit every event to React (live process list)
    let _ = app.emit("proc-event", &event);

    if let Some(ref anomaly) = event.anomaly {
        // Derive kind string for the journal from rule prefix
        let kind = if anomaly.rule.starts_with("PAR") {
            "suspicious_parentage"
        } else if anomaly.rule.starts_with("PATH") {
            "anomalous_exec_path"
        } else if anomaly.rule.starts_with("ARG") {
            "cmdline_obfuscation"
        } else if anomaly.rule.starts_with("ENV") {
            "env_manipulation"
        } else {
            "unknown"
        };

        let severity = match anomaly.confidence.as_str() {
            "high"   => Severity::High,
            "medium" => Severity::Medium,
            _        => Severity::Low,
        };

        let incident = ThreatIncident {
            id:         Uuid::new_v4().to_string(),
            kind:       kind.into(),
            severity,
            pid:        event.pid,
            ppid:       event.ppid,
            process:    event.name.clone(),
            cmdline:    event.cmdline.clone(),
            exe_path:   event.exe.clone(),
            rule:       anomaly.rule.clone(),
            confidence: anomaly.confidence.clone(),
            reason:     anomaly.reason.clone(),
            ancestors:  anomaly.ancestors.clone(),
            ts:         Utc.timestamp_millis_opt(event.ts).unwrap(),
            resolved:   false,
            digest:     String::new(),
        };

        match state.journal.lock() {
            Ok(j) => match j.insert_incident(incident) {
                Ok(saved) => {
                    info!(id = %saved.id, rule = %saved.rule, kind = %saved.kind, "incident persisted");
                    let _ = app.emit("anomaly", &saved);
                }
                Err(e) => error!("journal insert: {e}"),
            },
            Err(e) => error!("journal lock poisoned: {e}"),
        }
    }
}
