// binary.rs — own binary integrity checker
//
// Hashes the running binary on startup, then re-checks every 60s.
// If the file on disk changes → BinaryTampered event.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use chrono::Utc;
use tokio::sync::mpsc;
use tracing::{info, warn};
use uuid::Uuid;

use crate::models::{SelfProtectEvent, SelfProtectKind};

const CHECK_INTERVAL_SECS: u64 = 60;

/// Compute BLAKE3 hash of the given file path.
pub fn hash_file(path: &std::path::Path) -> Result<String> {
    let data = std::fs::read(path)?;
    Ok(blake3::hash(&data).to_hex().to_string())
}

/// Resolve path of the currently running binary.
pub fn own_binary_path() -> Result<PathBuf> {
    Ok(std::fs::read_link("/proc/self/exe")?)
}

/// Spawn a background task that monitors own binary integrity.
/// Sends SelfProtectEvents on the provided channel if tampering is detected.
pub async fn start_binary_monitor(tx: mpsc::Sender<SelfProtectEvent>) {
    let path = match own_binary_path() {
        Ok(p)  => p,
        Err(e) => {
            warn!("binary integrity: cannot resolve own path: {}", e);
            return;
        }
    };

    let baseline = match hash_file(&path) {
        Ok(h)  => h,
        Err(e) => {
            warn!("binary integrity: cannot hash own binary: {}", e);
            return;
        }
    };

    info!(
        path   = %path.display(),
        digest = &baseline[..16],
        "binary integrity baseline established"
    );

    let mut interval = tokio::time::interval(Duration::from_secs(CHECK_INTERVAL_SECS));
    interval.tick().await; // skip immediate first tick

    loop {
        interval.tick().await;

        let current = match hash_file(&path) {
            Ok(h)  => h,
            Err(e) => {
                warn!("binary integrity: re-hash failed: {}", e);
                continue;
            }
        };

        if current != baseline {
            warn!(
                path     = %path.display(),
                baseline = &baseline[..16],
                current  = &current[..16],
                "BINARY TAMPERED — hash mismatch"
            );

            let ev = SelfProtectEvent {
                id:         Uuid::new_v4().to_string(),
                kind:       SelfProtectKind::BinaryTampered,
                confidence: "high".into(),
                reason:     format!(
                    "Aegis-Guard binary at '{}' has been modified on disk while running. \
                     Baseline digest: {}… Current digest: {}… \
                     The security tool may have been backdoored.",
                    path.display(),
                    &baseline[..16],
                    &current[..16],
                ),
                detail: format!("path={} baseline={} current={}",
                    path.display(), baseline, current),
                ts: Utc::now().timestamp_millis(),
            };

            let _ = tx.send(ev).await;
        }
    }
}
