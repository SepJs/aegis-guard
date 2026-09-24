use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use crate::models::{DeceptionEvent, TrapKind};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoyTrap {
    pub id: String,
    pub path: String,
    pub trap_type: String,
    pub original_hash: String,
    pub created_ts: i64,
    pub last_checked_ts: i64,
    pub triggered: bool,
    pub trigger_count: u32,
}

pub struct TrapManager {
    traps: RwLock<HashMap<String, DecoyTrap>>,
    store: PathBuf,
}

fn get_deception_dir() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var("LOCALAPPDATA")
            .map(|p| PathBuf::from(p).join("Aegis-Guard").join("traps"))
            .unwrap_or_else(|_| PathBuf::from("C:\\ProgramData\\Aegis-Guard\\traps"))
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/var/lib/aegis/traps")
    }
}

impl TrapManager {
    pub fn new() -> Result<Self> {
        let dir = get_deception_dir();
        std::fs::create_dir_all(&dir)?;
        let store = dir.join("traps.json");

        let traps = if store.exists() {
            let raw: Vec<DecoyTrap> = serde_json::from_str(&std::fs::read_to_string(&store)?).unwrap_or_default();
            raw.into_iter().map(|t| (t.id.clone(), t)).collect()
        } else {
            HashMap::new()
        };

        Ok(Self {
            traps: RwLock::new(traps),
            store,
        })
    }

    pub fn deploy_decoy_credential(&self, target_path: &str, trap_type: &str) -> Result<DecoyTrap> {
        let id = Uuid::new_v4().to_string();
        let path = Path::new(target_path);

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let decoy_content = match trap_type {
            "aws_credentials" => {
                format!(
                    "[default]\naws_access_key_id = AKIA{:016X}\naws_secret_access_key = aegis_trap_{:032x}\n# Protected by Aegis Decoy System\n",
                    blake3::hash(id.as_bytes()).as_bytes().iter().take(8).fold(0u64, |acc, &b| (acc << 8) | b as u64),
                    id
                )
            }
            "ssh_private_key" => {
                format!(
                    "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\nAEGIS_DECOY_TRAP_{}==\n-----END OPENSSH PRIVATE KEY-----\n",
                    id
                )
            }
            "env_secret" => {
                format!(
                    "DATABASE_URL=postgres://db_admin:aegis_trap_{}@127.0.0.1:5432/prod_db\nJWT_SECRET=aegis_decoy_sec_{}\nSTRIPE_API_KEY=sk_live_aegis_trap_{}\n",
                    id, id, id
                )
            }
            _ => format!("# Aegis Honeytoken Decoy File\nTOKEN_ID={}\nCREATED_AT={}\n", id, Utc::now().to_rfc3339()),
        };

        std::fs::write(target_path, &decoy_content).context("write decoy trap file")?;
        let hash = blake3::hash(decoy_content.as_bytes()).to_hex().to_string();

        let trap = DecoyTrap {
            id: id.clone(),
            path: target_path.to_string(),
            trap_type: trap_type.to_string(),
            original_hash: hash,
            created_ts: Utc::now().timestamp_millis(),
            last_checked_ts: Utc::now().timestamp_millis(),
            triggered: false,
            trigger_count: 0,
        };

        self.traps.write().unwrap().insert(id, trap.clone());
        self.persist()?;

        info!(path = %target_path, trap_type = %trap_type, "Decoy trap deployed");
        Ok(trap)
    }

    pub fn inspect_all_traps(&self) -> Vec<DeceptionEvent> {
        let mut alerts = Vec::new();
        let mut traps = self.traps.write().unwrap();
        let now = Utc::now().timestamp_millis();

        for trap in traps.values_mut() {
            trap.last_checked_ts = now;
            let path = Path::new(&trap.path);

            if !path.exists() {
                // Trap file deleted!
                if !trap.triggered {
                    trap.triggered = true;
                    trap.trigger_count += 1;
                    warn!(path = %trap.path, "🚨 DECOY TRAP DELETED: Potential ransomware or wiper activity!");
                    alerts.push(DeceptionEvent {
                        id: Uuid::new_v4().to_string(),
                        kind: TrapKind::TrapFileModified,
                        target: trap.path.clone(),
                        trigger_pid: None,
                        trigger_proc: None,
                        confidence: "high".to_string(),
                        reason: format!("Decoy trap file '{}' was deleted by an unauthorized process", trap.path),
                        ts: now,
                    });
                }
            } else if let Ok(content) = std::fs::read(path) {
                let current_hash = blake3::hash(&content).to_hex().to_string();
                if current_hash != trap.original_hash {
                    // Trap file tampered with or overwritten!
                    trap.triggered = true;
                    trap.trigger_count += 1;
                    warn!(path = %trap.path, "🚨 DECOY TRAP MODIFIED: Tampering or encryption detected!");
                    alerts.push(DeceptionEvent {
                        id: Uuid::new_v4().to_string(),
                        kind: TrapKind::TrapFileModified,
                        target: trap.path.clone(),
                        trigger_pid: None,
                        trigger_proc: None,
                        confidence: "high".to_string(),
                        reason: format!("Decoy trap file '{}' was modified/encrypted (hash mismatch)", trap.path),
                        ts: now,
                    });
                }
            }
        }

        let _ = self.persist_locked(&traps);
        alerts
    }

    pub fn list_traps(&self) -> Vec<DecoyTrap> {
        self.traps.read().unwrap().values().cloned().collect()
    }

    fn persist(&self) -> Result<()> {
        let traps = self.traps.read().unwrap();
        self.persist_locked(&traps)
    }

    fn persist_locked(&self, traps: &HashMap<String, DecoyTrap>) -> Result<()> {
        let list: Vec<&DecoyTrap> = traps.values().collect();
        let json = serde_json::to_string_pretty(&list)?;
        std::fs::write(&self.store, json)?;
        Ok(())
    }
}

impl Default for TrapManager {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            traps: RwLock::new(HashMap::new()),
            store: PathBuf::from("traps.json"),
        })
    }
}
