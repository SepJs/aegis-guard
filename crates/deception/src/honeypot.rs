//! Lightweight TCP honeypot listeners that flag unexpected connections.
//! Binds only to localhost by default for safety; optional bind address via env.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{info, warn};

use crate::models::{DeceptionEvent, TrapKind};

/// Default decoy ports often probed by malware / scanners (loopback only).
const DEFAULT_PORTS: &[u16] = &[4444, 31337, 6666, 1234, 5555];

pub struct HoneypotManager {
    events: Arc<Mutex<Vec<DeceptionEvent>>>,
    running: Arc<Mutex<bool>>,
}

impl HoneypotManager {
    pub fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(Vec::new())),
            running: Arc::new(Mutex::new(false)),
        }
    }

    /// Start background listeners on decoy ports (loopback). Safe for desktop use.
    pub fn start(&self) {
        let mut flag = self.running.lock().unwrap();
        if *flag {
            return;
        }
        *flag = true;
        drop(flag);

        let events = self.events.clone();
        let running = self.running.clone();

        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(r) => r,
                Err(e) => {
                    warn!("honeypot runtime failed: {e}");
                    return;
                }
            };
            rt.block_on(async move {
                let mut handles = Vec::new();
                for &port in DEFAULT_PORTS {
                    let ev = events.clone();
                    let run = running.clone();
                    handles.push(tokio::spawn(async move {
                        listen_port(port, ev, run).await;
                    }));
                }
                for h in handles {
                    let _ = h.await;
                }
            });
        });
        info!(ports = ?DEFAULT_PORTS, "honeypot listeners started (loopback)");
    }

    pub fn stop(&self) {
        *self.running.lock().unwrap() = false;
    }

    pub fn drain_events(&self) -> Vec<DeceptionEvent> {
        let mut g = self.events.lock().unwrap();
        std::mem::take(&mut *g)
    }

    pub fn recent_events(&self) -> Vec<DeceptionEvent> {
        self.events.lock().unwrap().clone()
    }
}

impl Default for HoneypotManager {
    fn default() -> Self {
        Self::new()
    }
}

async fn listen_port(
    port: u16,
    events: Arc<Mutex<Vec<DeceptionEvent>>>,
    running: Arc<Mutex<bool>>,
) {
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            // Port in use is fine — skip quietly
            tracing::debug!(port, "honeypot bind skipped: {e}");
            return;
        }
    };
    info!(port, "honeypot listening");

    loop {
        if !*running.lock().unwrap() {
            break;
        }
        // Accept with short timeout so we can observe stop flag
        let accept = tokio::time::timeout(Duration::from_secs(2), listener.accept()).await;
        match accept {
            Ok(Ok((socket, peer))) => {
                let peer_s = peer.to_string();
                warn!(port, peer = %peer_s, "HONEYPOT CONNECTION — unexpected client");
                let ev = DeceptionEvent {
                    id: uuid::Uuid::new_v4().to_string(),
                    kind: TrapKind::HoneypotConnected,
                    target: format!("tcp/{}", port),
                    trigger_pid: None,
                    trigger_proc: None,
                    confidence: "high".into(),
                    reason: format!(
                        "Unexpected connection to decoy port {} from {}. Legitimate software rarely connects here.",
                        port, peer_s
                    ),
                    ts: chrono::Utc::now().timestamp_millis(),
                };
                if let Ok(mut g) = events.lock() {
                    g.push(ev);
                    if g.len() > 200 {
                        let drain = g.len() - 200;
                        g.drain(0..drain);
                    }
                }
                drop(socket);
            }
            Ok(Err(_)) | Err(_) => continue,
        }
    }
}
