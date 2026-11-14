//! File-system tripwires: decoy files watched for access / modification.
//! Uses periodic mtime/size checks (cross-platform, no inotify required).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{info, warn};

use crate::models::{DeceptionEvent, TrapKind};

const DEFAULT_DECOYS: &[(&str, &str)] = &[
    (".aws/credentials", "[default]\naws_access_key_id=AKIA_AEGIS_CANARY_FAKE\naws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYAEGISCANARY\n"),
    (".ssh/id_rsa_aegis_decoy", "-----BEGIN RSA PRIVATE KEY-----\nAegisGuard-Decoy-Key-Do-Not-Use\n-----END RSA PRIVATE KEY-----\n"),
    ("wallet.dat.aegis", "AEGIS_DECOY_WALLET_NOT_REAL\n"),
    (".env.production.aegis", "DB_PASSWORD=aegis_decoy_secret\nAPI_KEY=sk_aegis_fake_key\n"),
];

#[derive(Clone)]
struct TrapState {
    path: PathBuf,
    mtime: u64,
    size: u64,
    label: String,
}

pub struct TrapManager {
    traps: Arc<Mutex<HashMap<String, TrapState>>>,
    events: Arc<Mutex<Vec<DeceptionEvent>>>,
    running: Arc<Mutex<bool>>,
    base_dir: PathBuf,
}

impl TrapManager {
    pub fn new() -> Self {
        let base = trap_base_dir();
        let _ = std::fs::create_dir_all(&base);
        Self {
            traps: Arc::new(Mutex::new(HashMap::new())),
            events: Arc::new(Mutex::new(Vec::new())),
            running: Arc::new(Mutex::new(false)),
            base_dir: base,
        }
    }

    /// Deploy default decoy files and start watching them.
    pub fn deploy_defaults(&self) -> anyhow::Result<usize> {
        let mut count = 0;
        for (rel, content) in DEFAULT_DECOYS {
            let path = self.base_dir.join(rel);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            if !path.exists() {
                std::fs::write(&path, content)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
                }
                count += 1;
            }
            self.watch_file(path.to_string_lossy().as_ref(), rel)?;
        }
        info!(count, base = %self.base_dir.display(), "decoy trap files deployed");
        Ok(count)
    }

    pub fn watch_file(&self, path: &str, label: &str) -> anyhow::Result<()> {
        let p = PathBuf::from(path);
        let (mtime, size) = file_meta(&p);
        self.traps.lock().unwrap().insert(
            path.to_string(),
            TrapState {
                path: p,
                mtime,
                size,
                label: label.to_string(),
            },
        );
        Ok(())
    }

    pub fn start_watcher(&self) {
        let mut flag = self.running.lock().unwrap();
        if *flag {
            return;
        }
        *flag = true;
        drop(flag);

        let traps = self.traps.clone();
        let events = self.events.clone();
        let running = self.running.clone();

        std::thread::spawn(move || {
            while *running.lock().unwrap() {
                std::thread::sleep(Duration::from_secs(3));
                let snapshot: Vec<(String, TrapState)> = traps
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();

                for (key, prev) in snapshot {
                    if !prev.path.exists() {
                        // File deleted — strong signal
                        push_event(
                            &events,
                            TrapKind::TrapFileModified,
                            &key,
                            &format!(
                                "Trap file '{}' was deleted or moved — possible ransomware/indexing activity.",
                                prev.label
                            ),
                        );
                        traps.lock().unwrap().remove(&key);
                        continue;
                    }
                    let (mtime, size) = file_meta(&prev.path);
                    if mtime != prev.mtime || size != prev.size {
                        warn!(path = %key, "TRAP FILE MODIFIED");
                        push_event(
                            &events,
                            TrapKind::TrapFileModified,
                            &key,
                            &format!(
                                "Trap/decoy file '{}' was modified (size {}→{}, mtime changed). Unauthorized access likely.",
                                prev.label, prev.size, size
                            ),
                        );
                        if let Some(t) = traps.lock().unwrap().get_mut(&key) {
                            t.mtime = mtime;
                            t.size = size;
                        }
                    }
                }
            }
        });
        info!("trap file watcher started");
    }

    pub fn stop(&self) {
        *self.running.lock().unwrap() = false;
    }

    pub fn drain_events(&self) -> Vec<DeceptionEvent> {
        let mut g = self.events.lock().unwrap();
        std::mem::take(&mut *g)
    }

    pub fn list_traps(&self) -> Vec<String> {
        self.traps.lock().unwrap().keys().cloned().collect()
    }
}

impl Default for TrapManager {
    fn default() -> Self {
        Self::new()
    }
}

fn trap_base_dir() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var("LOCALAPPDATA")
            .map(|p| PathBuf::from(p).join("Aegis-Guard").join("traps"))
            .unwrap_or_else(|_| PathBuf::from("C:\\ProgramData\\Aegis-Guard\\traps"))
    }
    #[cfg(not(windows))]
    {
        if let Ok(home) = std::env::var("HOME") {
            let p = PathBuf::from(home).join(".local/share/aegis/traps");
            if std::fs::create_dir_all(&p).is_ok() {
                return p;
            }
        }
        let sys = PathBuf::from("/var/lib/aegis/traps");
        if std::fs::create_dir_all(&sys).is_ok() {
            return sys;
        }
        std::env::temp_dir().join("aegis-guard-traps")
    }
}

fn file_meta(path: &Path) -> (u64, u64) {
    match path.metadata() {
        Ok(m) => {
            let mtime = m
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            (mtime, m.len())
        }
        Err(_) => (0, 0),
    }
}

fn push_event(events: &Arc<Mutex<Vec<DeceptionEvent>>>, kind: TrapKind, target: &str, reason: &str) {
    let ev = DeceptionEvent {
        id: uuid::Uuid::new_v4().to_string(),
        kind,
        target: target.to_string(),
        trigger_pid: None,
        trigger_proc: None,
        confidence: "high".into(),
        reason: reason.to_string(),
        ts: chrono::Utc::now().timestamp_millis(),
    };
    if let Ok(mut g) = events.lock() {
        g.push(ev);
        if g.len() > 200 {
            let drain = g.len() - 200;
            g.drain(0..drain);
        }
    }
}
