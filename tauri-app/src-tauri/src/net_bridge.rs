// net_bridge.rs — Phase 3: reads NetEvents from network-observer JSON bridge
//
// The Go network-observer listens on 127.0.0.1:50053 and sends
// length-prefixed JSON NetEvents. This module connects as a client,
// reads events, persists anomalies to the journal, and emits
// "net-event" / "net-anomaly" Tauri events to React.

use std::sync::Arc;

use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncReadExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use journal::models::{Severity, ThreatIncident};
use crate::state::AppState;

const NET_BRIDGE_ADDR: &str = "127.0.0.1:50053";
const RECONNECT_DELAY_MS: u64 = 2000;

// ── Wire types (must match Go netmon.NetEvent JSON) ───────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetAlert {
    #[serde(rename = "Rule")]
    pub rule:       String,
    #[serde(rename = "Confidence")]
    pub confidence: String,
    #[serde(rename = "Reason")]
    pub reason:     String,
    #[serde(rename = "Category")]
    pub category:   String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetEvent {
    #[serde(rename = "ID")]
    pub id:          String,
    #[serde(rename = "Kind")]
    pub kind:        String,
    #[serde(rename = "PID")]
    pub pid:         u32,
    #[serde(rename = "Process")]
    pub process:     String,
    #[serde(rename = "Protocol")]
    pub protocol:    String,
    #[serde(rename = "Direction")]
    pub direction:   String,
    #[serde(rename = "LocalIP")]
    pub local_ip:    String,
    #[serde(rename = "LocalPort")]
    pub local_port:  u16,
    #[serde(rename = "RemoteIP")]
    pub remote_ip:   String,
    #[serde(rename = "RemotePort")]
    pub remote_port: u16,
    #[serde(rename = "BytesTX")]
    pub bytes_tx:    u64,
    #[serde(rename = "BytesRX")]
    pub bytes_rx:    u64,
    #[serde(rename = "Alert")]
    pub alert:       Option<NetAlert>,
    #[serde(rename = "TsMs")]
    pub ts_ms:       i64,
}

// ── Bridge loop ───────────────────────────────────────────────────────────────

/// Runs forever — connects to network-observer, reads events, reconnects on error.
pub async fn run(state: Arc<AppState>, app: AppHandle) {
    loop {
        info!("net bridge: connecting to {}", NET_BRIDGE_ADDR);

        match TcpStream::connect(NET_BRIDGE_ADDR).await {
            Ok(stream) => {
                info!("net bridge: connected to network-observer");
                let mut reader = BufReader::new(stream);

                loop {
                    // Read 4-byte length prefix
                    let mut len_buf = [0u8; 4];
                    match reader.read_exact(&mut len_buf).await {
                        Ok(_) => {}
                        Err(_) => {
                            warn!("net bridge: connection closed by observer");
                            break;
                        }
                    }

                    let len = u32::from_be_bytes(len_buf) as usize;
                    if len > 1_000_000 {
                        warn!("net bridge: oversized payload {} — dropping", len);
                        break;
                    }

                    let mut payload = vec![0u8; len];
                    if reader.read_exact(&mut payload).await.is_err() {
                        break;
                    }

                    match serde_json::from_slice::<NetEvent>(&payload) {
                        Ok(ev)  => handle_net_event(ev, &state, &app),
                        Err(e)  => warn!("net bridge: decode error: {}", e),
                    }
                }
            }
            Err(e) => {
                debug!("net bridge: connection failed: {} — retry in {}ms",
                    e, RECONNECT_DELAY_MS);
            }
        }

        tokio::time::sleep(
            std::time::Duration::from_millis(RECONNECT_DELAY_MS)
        ).await;
    }
}

fn handle_net_event(ev: NetEvent, state: &Arc<AppState>, app: &AppHandle) {
    debug!(
        pid     = ev.pid,
        process = %ev.process,
        kind    = %ev.kind,
        remote  = format!("{}:{}", ev.remote_ip, ev.remote_port),
        "net event"
    );

    // Emit every event to React (network activity view — Phase 3 UI)
    let _ = app.emit("net-event", &ev);

    // Persist anomalies
    if let Some(ref alert) = ev.alert {
        let severity = match alert.confidence.as_str() {
            "high"   => Severity::High,
            "medium" => Severity::Medium,
            _        => Severity::Low,
        };

        let incident = ThreatIncident {
            id:         Uuid::new_v4().to_string(),
            kind:       format!("network_{}", alert.category.to_lowercase()),
            severity,
            pid:        ev.pid,
            ppid:       0,
            process:    ev.process.clone(),
            cmdline:    vec![],
            exe_path:   None,
            rule:       alert.rule.clone(),
            confidence: alert.confidence.clone(),
            reason:     alert.reason.clone(),
            ancestors:  vec![],
            ts:         Utc.timestamp_millis_opt(ev.ts_ms).unwrap(),
            resolved:   false,
            digest:     String::new(),
        };

        match state.journal.lock() {
            Ok(j) => match j.insert_incident(incident) {
                Ok(saved) => {
                    info!(
                        id   = %saved.id,
                        rule = %saved.rule,
                        "net incident persisted"
                    );
                    let _ = app.emit("net-anomaly", &saved);
                }
                Err(e) => error!("journal insert: {}", e),
            },
            Err(e) => error!("journal lock poisoned: {}", e),
        }
    }
}
