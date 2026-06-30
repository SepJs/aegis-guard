// phase5_bridge.rs — Phase 5: wires behavioral, threat-intel, self-protect,
// and canary modules into the Tauri backend.
//
// Spawned as background tasks from lib.rs setup().

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tauri::{AppHandle, Emitter};
use tokio::sync::mpsc;
use tracing::{info, warn};
use uuid::Uuid;

use behavioral::BehaviorEngine;
use deception::canary::CanaryManager;
use journal::models::{Severity, ThreatIncident};
use self_protect::{IntegrityMonitor, SelfProtectEvent};
use threat_intel::ThreatMatcher;

use crate::state::AppState;

/// Start all Phase 5 background tasks.
pub async fn start(
    state:    Arc<AppState>,
    app:      AppHandle,
    data_dir: std::path::PathBuf,
) {
    // ── Threat Intelligence ───────────────────────────────────────────────────
    let matcher = match ThreatMatcher::new() {
        Ok(m)  => {
            info!("threat intel loaded: {:?}", m.stats());
            m.start_auto_update();
            Arc::new(m)
        }
        Err(e) => {
            warn!("threat intel init failed: {}", e);
            return;
        }
    };

    let m1  = matcher.clone();
    let app1 = app.clone();
    let st1  = state.clone();
    tokio::spawn(async move {
        ioc_net_check_loop(m1, st1, app1).await;
    });

    // ── Behavioral Baseline ───────────────────────────────────────────────────
    let data_str = data_dir.to_string_lossy().to_string();
    match BehaviorEngine::new(&data_str) {
        Ok(engine) => {
            info!("behavioral engine ready ({} baselines)", engine.baseline_count());
            let engine = Arc::new(engine);
            let app2   = app.clone();
            let st2    = state.clone();
            tokio::spawn(async move {
                behavioral_scan_loop(engine, st2, app2).await;
            });
        }
        Err(e) => warn!("behavioral engine init failed: {}", e),
    }

    // ── Self-Protection ───────────────────────────────────────────────────────
    let (sp_tx, mut sp_rx) = mpsc::channel::<SelfProtectEvent>(64);
    IntegrityMonitor::start(sp_tx).await;

    let app3 = app.clone();
    let st3  = state.clone();
    tokio::spawn(async move {
        while let Some(ev) = sp_rx.recv().await {
            // Emit to React immediately
            let _ = app3.emit("self-protect-event", &ev);

            // Persist as a high-severity incident
            let incident = ThreatIncident {
                id:         Uuid::new_v4().to_string(),
                kind:       "self_protection".into(),
                severity:   Severity::High,
                pid:        std::process::id(),
                ppid:       0,
                process:    "aegis-process-engine".into(),
                cmdline:    vec![],
                exe_path:   None,
                rule:       format!("{:?}", ev.kind),
                confidence: ev.confidence.clone(),
                reason:     ev.reason.clone(),
                ancestors:  vec![],
                ts:         chrono::Utc.timestamp_millis_opt(ev.ts).unwrap(),
                resolved:   false,
                digest:     String::new(),
            };

            if let Ok(j) = st3.journal.lock() {
                if let Ok(saved) = j.insert_incident(incident) {
                    let _ = app3.emit("anomaly", &saved);
                }
            }
        }
    });

    // ── Canary Manager ────────────────────────────────────────────────────────
    match CanaryManager::new() {
        Ok(canary) => {
            info!("canary manager ready ({} tokens)", canary.list().len());
            let canary = Arc::new(canary);
            // Subscribe to net-event stream from net_bridge to check payloads
            // (In Phase 5 we listen via Tauri event from net_bridge)
            // Canary checking in net_bridge is wired separately (see net_bridge.rs)
            let _ = canary; // kept alive
        }
        Err(e) => warn!("canary manager init failed: {}", e),
    }

    info!("Phase 5 modules started");
}

// ── IOC net check loop ────────────────────────────────────────────────────────
// Receives net-event Tauri events and cross-references remote IPs/domains
// against the threat intelligence feed.
// NOTE: In the full build this subscribes directly to the net_bridge channel.
// For Phase 5 bootstrap, it polls the journal for recent net incidents.

async fn ioc_net_check_loop(
    matcher: Arc<ThreatMatcher>,
    state:   Arc<AppState>,
    app:     AppHandle,
) {
    // This is a stub entry point; in the complete integration the net_bridge
    // calls matcher.check_ip() inline on every NetEvent.
    // Left as an explicit task to make the architecture visible.
    info!("IOC net-check loop ready (integrated in net_bridge)");

    // Keep alive — actual calls happen in net_bridge::handle_net_event()
    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
        info!("threat intel stats: {:?}", matcher.stats());
    }
}

// ── Behavioral scan loop ──────────────────────────────────────────────────────

async fn behavioral_scan_loop(
    engine: Arc<BehaviorEngine>,
    state:  Arc<AppState>,
    app:    AppHandle,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(5));

    loop {
        interval.tick().await;

        // Collect observations for all running processes
        let pids = match collect_all_pids() {
            Ok(p)  => p,
            Err(_) => continue,
        };

        for pid in pids {
            let obs = match BehaviorEngine::collect_observation(pid) {
                Some(o) => o,
                None    => continue,
            };

            if let Some(anomaly) = engine.observe(obs) {
                // Emit to React
                let _ = app.emit("behavioral-anomaly", &anomaly);

                // Persist to journal
                let incident = ThreatIncident {
                    id:         Uuid::new_v4().to_string(),
                    kind:       "behavioral_deviation".into(),
                    severity:   if anomaly.anomaly_score > 70.0 {
                        Severity::High
                    } else {
                        Severity::Medium
                    },
                    pid:        anomaly.pid,
                    ppid:       0,
                    process:    anomaly.name.clone(),
                    cmdline:    vec![],
                    exe_path:   None,
                    rule:       "BEH-001".into(),
                    confidence: anomaly.confidence.clone(),
                    reason:     anomaly.reason.clone(),
                    ancestors:  vec![],
                    ts:         chrono::Utc.timestamp_millis_opt(anomaly.ts).unwrap(),
                    resolved:   false,
                    digest:     String::new(),
                };

                if let Ok(j) = state.journal.lock() {
                    if let Ok(saved) = j.insert_incident(incident) {
                        let _ = app.emit("anomaly", &saved);
                    }
                }
            }
        }

        // Persist baselines every 60 cycles (~5 min)
        static CYCLE: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(0);
        let n = CYCLE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if n % 60 == 0 {
            engine.persist().ok();
        }
    }
}

fn collect_all_pids() -> anyhow::Result<Vec<u32>> {
    let mut pids = Vec::new();
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
            pids.push(pid);
        }
    }
    Ok(pids)
}
