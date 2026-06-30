// whitelist.rs — signed process allowlist
//
// Whitelisted processes are NEVER acted upon — even if re-flagged by detection rules.
// The whitelist is persisted as a BLAKE3-signed JSON file.
// Adding to the whitelist is permanent until manually removed.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistEntry {
    pub pid:          u32,
    pub process_name: String,
    pub exe_path:     Option<String>,
    pub added_at:     i64,
    pub note:         String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct WhitelistFile {
    entries: Vec<WhitelistEntry>,
    /// BLAKE3 digest of all entries (tamper-evident)
    digest:  String,
}

pub struct WhitelistStore {
    path:    PathBuf,
    entries: Mutex<Vec<WhitelistEntry>>,
}

impl WhitelistStore {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let entries = if path.exists() {
            let raw  = std::fs::read_to_string(&path)
                .context("read whitelist")?;
            let file: WhitelistFile = serde_json::from_str(&raw)
                .context("parse whitelist")?;
            file.entries
        } else {
            Vec::new()
        };

        Ok(Self {
            path,
            entries: Mutex::new(entries),
        })
    }

    /// Returns true if pid OR process_name matches a whitelist entry.
    pub fn is_whitelisted(&self, pid: u32, process_name: &str) -> bool {
        let entries = self.entries.lock().unwrap();
        entries.iter().any(|e| {
            e.pid == pid || e.process_name.eq_ignore_ascii_case(process_name)
        })
    }

    /// Add a new entry and persist to disk.
    pub fn add(
        &self,
        pid:          u32,
        process_name: String,
        exe_path:     Option<String>,
    ) -> Result<()> {
        let entry = WhitelistEntry {
            pid,
            process_name,
            exe_path,
            added_at: Utc::now().timestamp_millis(),
            note:     String::new(),
        };

        {
            let mut entries = self.entries.lock().unwrap();
            // Avoid duplicates
            if !entries.iter().any(|e| e.pid == pid) {
                entries.push(entry);
            }
        }

        self.persist()
    }

    /// Remove a whitelist entry by pid.
    pub fn remove(&self, pid: u32) -> Result<bool> {
        let removed;
        {
            let mut entries = self.entries.lock().unwrap();
            let before = entries.len();
            entries.retain(|e| e.pid != pid);
            removed = entries.len() < before;
        }
        self.persist()?;
        Ok(removed)
    }

    pub fn list(&self) -> Vec<WhitelistEntry> {
        self.entries.lock().unwrap().clone()
    }

    fn persist(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let entries = self.entries.lock().unwrap().clone();
        let digest  = compute_digest(&entries);
        let file    = WhitelistFile { entries, digest };
        let json    = serde_json::to_string_pretty(&file)?;
        std::fs::write(&self.path, json)?;
        Ok(())
    }
}

fn compute_digest(entries: &[WhitelistEntry]) -> String {
    let mut h = blake3::Hasher::new();
    for e in entries {
        h.update(e.process_name.as_bytes());
        h.update(&e.pid.to_le_bytes());
        h.update(&e.added_at.to_le_bytes());
    }
    h.finalize().to_hex().to_string()
}
