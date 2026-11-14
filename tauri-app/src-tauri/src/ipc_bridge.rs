use std::sync::Arc;
use chrono::{TimeZone, Utc};
use tauri::{AppHandle, Emitter};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use ipc::reader::IpcReader;
use journal::models::{Severity, ThreatIncident};
use crate::state::AppState;

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
pub struct ProcEvent {
    pub id: String,
    pub kind: String,
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    #[serde(default)] pub state: char,
    #[serde(default)] pub state_label: String,
    #[serde(default)] pub cpu_pct: f32,
    #[serde(default)] pub mem_rss_kb: u64,
    #[serde(default)] pub threads: u32,
    #[serde(default)] pub cmdline: Vec<String>,
    pub exe: Option<String>,
    pub cwd: Option<String>,
    #[serde(default)] pub uid: u32,
    #[serde(default)] pub gid: u32,
    #[serde(default)] pub start_time: u64,
    pub anomaly: Option<AnomalyDetail>,
    pub ts: i64,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
pub struct AnomalyDetail {
    pub rule: String,
    pub confidence: String,
    #[serde(default)] pub priority_tier: String,
    #[serde(default)] pub risk_score: u8,
    pub reason: String,
    pub parent_exe: Option<String>,
    #[serde(default)] pub ancestors: Vec<u32>,
}

pub async fn run(socket_path: String, state: Arc<AppState>, app: AppHandle) {
    loop {
        info!(socket = %socket_path, "IPC bridge: binding socket…");
        let reader = match IpcReader::listen(&socket_path).await {
            Ok(r) => r,
            Err(e) => { error!("IPC listen error: {e} — retry in 2s"); tokio::time::sleep(std::time::Duration::from_secs(2)).await; continue; }
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
    let _ = app.emit("proc-event", &event);

    if let Some(ref anomaly) = event.anomaly {
        let kind = if anomaly.rule.starts_with("PAR") { "suspicious_parentage" }
            else if anomaly.rule.starts_with("PATH") { "anomalous_exec_path" }
            else if anomaly.rule.starts_with("ARG") { "cmdline_obfuscation" }
            else if anomaly.rule.starts_with("ENV") { "env_manipulation" }
            else { "unknown" };
        let severity = match anomaly.confidence.as_str() { "high" => Severity::High, "medium" => Severity::Medium, _ => Severity::Low };

        let incident = ThreatIncident {
            id: Uuid::new_v4().to_string(), kind: kind.into(), severity,
            risk_score: match anomaly.confidence.as_str() { "high" => 85.0, "medium" => 55.0, _ => 25.0 },
            pid: event.pid, ppid: event.ppid, process: event.name.clone(),
            cmdline: event.cmdline.clone(), exe_path: event.exe.clone(),
            rule: anomaly.rule.clone(), confidence: anomaly.confidence.clone(), reason: anomaly.reason.clone(),
            ancestors: anomaly.ancestors.clone(), ts: Utc.timestamp_millis_opt(event.ts).single().unwrap_or_else(Utc::now),
            resolved: false, digest: String::new(),
        };

        match state.journal.lock() {
            Ok(j) => match j.insert_incident(incident) {
                Ok(saved) => { info!(id = %saved.id, rule = %saved.rule, kind = %saved.kind, "incident persisted"); let _ = app.emit("anomaly", &saved); }
                Err(e) => error!("journal insert: {e}"),
            },
            Err(e) => error!("journal lock poisoned: {e}"),
        }
    }
}
