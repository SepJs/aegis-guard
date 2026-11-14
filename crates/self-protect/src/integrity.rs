use std::time::Duration;
use chrono::Utc;
use tokio::sync::mpsc;
use tracing::info;
use uuid::Uuid;

use crate::models::{SelfProtectEvent, SelfProtectKind};

const SOCKET_PATH: &str = "/run/aegis/proc.sock";
const JOURNAL_PATH: &str = "/var/lib/aegis/journal.db";
const CHECK_INTERVAL: u64 = 30;

pub struct IntegrityMonitor;

impl IntegrityMonitor {
    pub async fn start(tx: mpsc::Sender<SelfProtectEvent>) {
        info!("self-protection integrity monitor starting");
        let tx1 = tx.clone();
        tokio::spawn(async move { crate::binary::start_binary_monitor(tx1).await; });
        let tx2 = tx.clone();
        tokio::spawn(async move { crate::ptrace::start_ptrace_monitor(tx2).await; });
        tokio::spawn(async move { socket_journal_monitor(tx).await; });
    }
}

async fn socket_journal_monitor(tx: mpsc::Sender<SelfProtectEvent>) {
    let socket_path = std::env::var("AEGIS_SOCKET").unwrap_or_else(|_| SOCKET_PATH.to_string());
    let _socket_meta = std::fs::metadata(&socket_path).ok();
    let _journal_hash = hash_file_if_exists(JOURNAL_PATH);

    let mut interval = tokio::time::interval(Duration::from_secs(CHECK_INTERVAL));
    interval.tick().await;

    loop {
        interval.tick().await;
        #[cfg(unix)]
        if !socket_path.contains(':') {
            if let Ok(meta) = std::fs::metadata(&socket_path) {
                use std::os::unix::fs::FileTypeExt;
                if !meta.file_type().is_socket() {
                    let ev = make_event(SelfProtectKind::SocketTampered,
                        format!("IPC socket at '{}' has been replaced with a non-socket file. An attacker may have replaced the socket to intercept security engine communications.", socket_path),
                        format!("path={}", socket_path));
                    let _ = tx.send(ev).await;
                }
            }
        }
    }
}

fn hash_file_if_exists(path: &str) -> Option<String> {
    let data = std::fs::read(path).ok()?;
    Some(blake3::hash(&data).to_hex().to_string())
}

fn make_event(kind: SelfProtectKind, reason: String, detail: String) -> SelfProtectEvent {
    SelfProtectEvent { id: Uuid::new_v4().to_string(), kind, confidence: "high".into(), reason, detail, ts: Utc::now().timestamp_millis() }
}
