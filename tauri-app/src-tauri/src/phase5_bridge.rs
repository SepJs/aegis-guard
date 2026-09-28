use std::sync::Arc;
use std::time::Duration;

use chrono::{TimeZone, Utc};
use tauri::{AppHandle, Emitter};
use tokio::sync::mpsc;
use tracing::{info, warn};
use uuid::Uuid;

use behavioral::BehaviorEngine;
use deception::canary::CanaryManager;
use deception::{HoneypotManager, TrapManager};
use journal::models::{Severity, ThreatIncident};
use self_protect::{IntegrityMonitor, SelfProtectEvent};
use threat_intel::ThreatMatcher;

use crate::state::AppState;

pub async fn start(state: Arc<AppState>, app: AppHandle, data_dir: std::path::PathBuf) {
    match ThreatMatcher::new() {
        Ok(matcher) => { info!("threat intel loaded: {:?}", matcher.stats()); matcher.start_auto_update(); }
        Err(e) => warn!("threat intel init failed: {}", e),
    }

    let data_str = data_dir.to_string_lossy().to_string();
    match BehaviorEngine::new(&data_str) {
        Ok(engine) => {
            info!("behavioral engine ready ({} baselines)", engine.baseline_count());
            let engine = Arc::new(engine);
            let app2 = app.clone();
            let st2 = state.clone();
            tokio::spawn(async move { behavioral_scan_loop(engine, st2, app2).await; });
        }
        Err(e) => warn!("behavioral engine init failed: {}", e),
    }

    let (sp_tx, mut sp_rx) = mpsc::channel::<SelfProtectEvent>(64);
    IntegrityMonitor::start(sp_tx).await;

    let app3 = app.clone();
    let st3 = state.clone();
    tokio::spawn(async move {
        while let Some(ev) = sp_rx.recv().await {
            let _ = app3.emit("self-protect-event", &ev);
            let incident = ThreatIncident {
                id: Uuid::new_v4().to_string(), kind: "self_protection".into(), severity: Severity::High,
                risk_score: 72.0,
                pid: std::process::id(), ppid: 0, process: "aegis-process-engine".into(),
                cmdline: vec![], exe_path: None, rule: format!("{:?}", ev.kind),
                confidence: ev.confidence.clone(), reason: ev.reason.clone(), ancestors: vec![],
                ts: Utc.timestamp_millis_opt(ev.ts).unwrap(), resolved: false, digest: String::new(),
            };
            if let Ok(j) = st3.journal.lock() {
                if let Ok(saved) = j.insert_incident(incident) { let _ = app3.emit("anomaly", &saved); }
            }
        }
    });

    match CanaryManager::new() {
        Ok(canary) => info!("canary manager ready ({} tokens)", canary.list().len()),
        Err(e) => warn!("canary manager init failed: {}", e),
    }

    // Deploy filesystem traps + start honeypot listeners (loopback only)
    {
        let app_t = app.clone();
        let st_t = state.clone();
        tokio::task::spawn_blocking(move || {
            let traps = TrapManager::new();
            match traps.deploy_defaults() {
                Ok(n) => info!("deception traps deployed ({n} new decoys)"),
                Err(e) => warn!("trap deploy failed: {e}"),
            }
            traps.start_watcher();
            loop {
                std::thread::sleep(Duration::from_secs(5));
                for ev in traps.drain_events() {
                    let _ = app_t.emit("deception-event", &ev);
                    let incident = ThreatIncident {
                        id: Uuid::new_v4().to_string(),
                        kind: "deception_trap".into(),
                        severity: Severity::High,
                        risk_score: 80.0,
                        pid: ev.trigger_pid.unwrap_or(0),
                        ppid: 0,
                        process: ev.trigger_proc.clone().unwrap_or_else(|| "unknown".into()),
                        cmdline: vec![],
                        exe_path: None,
                        rule: format!("{:?}", ev.kind),
                        confidence: ev.confidence.clone(),
                        reason: ev.reason.clone(),
                        ancestors: vec![],
                        ts: Utc.timestamp_millis_opt(ev.ts).unwrap(),
                        resolved: false,
                        digest: String::new(),
                    };
                    if let Ok(j) = st_t.journal.lock() {
                        if let Ok(saved) = j.insert_incident(incident) {
                            let _ = app_t.emit("anomaly", &saved);
                        }
                    }
                }
            }
        });
    }

    {
        let app_h = app.clone();
        let st_h = state.clone();
        tokio::task::spawn_blocking(move || {
            let hp = HoneypotManager::new();
            hp.start();
            info!("honeypot listeners armed (loopback decoy ports)");
            loop {
                std::thread::sleep(Duration::from_secs(5));
                for ev in hp.drain_events() {
                    let _ = app_h.emit("deception-event", &ev);
                    let incident = ThreatIncident {
                        id: Uuid::new_v4().to_string(),
                        kind: "honeypot".into(),
                        severity: Severity::High,
                        risk_score: 85.0,
                        pid: 0,
                        ppid: 0,
                        process: "honeypot".into(),
                        cmdline: vec![],
                        exe_path: None,
                        rule: format!("{:?}", ev.kind),
                        confidence: ev.confidence.clone(),
                        reason: ev.reason.clone(),
                        ancestors: vec![],
                        ts: Utc.timestamp_millis_opt(ev.ts).unwrap(),
                        resolved: false,
                        digest: String::new(),
                    };
                    if let Ok(j) = st_h.journal.lock() {
                        if let Ok(saved) = j.insert_incident(incident) {
                            let _ = app_h.emit("anomaly", &saved);
                        }
                    }
                }
            }
        });
    }

    info!("Phase 5 modules started");
}

async fn behavioral_scan_loop(engine: Arc<BehaviorEngine>, state: Arc<AppState>, app: AppHandle) {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    loop {
        interval.tick().await;
        let pids = match collect_all_pids() { Ok(p) => p, Err(_) => continue };
        for pid in pids {
            let obs = match BehaviorEngine::collect_observation(pid) { Some(o) => o, None => continue };
            if let Some(anomaly) = engine.observe(obs) {
                let _ = app.emit("behavioral-anomaly", &anomaly);
                let incident = ThreatIncident {
                    id: Uuid::new_v4().to_string(), kind: "behavioral_deviation".into(),
                    severity: if anomaly.anomaly_score > 70.0 { Severity::High } else { Severity::Medium },
                    risk_score: anomaly.anomaly_score,
                    pid: anomaly.pid, ppid: 0, process: anomaly.name.clone(), cmdline: vec![], exe_path: None,
                    rule: "BEH-001".into(), confidence: anomaly.confidence.clone(), reason: anomaly.reason.clone(),
                    ancestors: vec![], ts: Utc.timestamp_millis_opt(anomaly.ts).unwrap(), resolved: false, digest: String::new(),
                };
                if let Ok(j) = state.journal.lock() {
                    if let Ok(saved) = j.insert_incident(incident) { let _ = app.emit("anomaly", &saved); }
                }
            }
        }
        static CYCLE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = CYCLE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if n % 60 == 0 { engine.persist().ok(); }
    }
}

fn collect_all_pids() -> anyhow::Result<Vec<u32>> {
    let map = process_engine::snapshot_all().unwrap_or_default();
    Ok(map.keys().copied().collect())
}
