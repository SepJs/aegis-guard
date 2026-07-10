use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

const CANARY_DIR: &str = "/var/lib/aegis/canaries";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryToken { pub id: String, pub token: String, pub file_path: String, pub description: String, pub created_ts: i64, pub triggered: bool }

pub struct CanaryManager { tokens: RwLock<HashMap<String, CanaryToken>>, store: PathBuf }

impl CanaryManager {
    pub fn new() -> Result<Self> {
        let store = PathBuf::from(CANARY_DIR).join("tokens.json");
        std::fs::create_dir_all(CANARY_DIR)?;
        let tokens = if store.exists() {
            let raw: Vec<CanaryToken> = serde_json::from_str(&std::fs::read_to_string(&store)?).unwrap_or_default();
            raw.into_iter().map(|t| (t.token.clone(), t)).collect()
        } else { HashMap::new() };
        Ok(Self { tokens: RwLock::new(tokens), store })
    }

    pub fn create_canary(&self, file_path: &str, description: &str) -> Result<CanaryToken> {
        let id = Uuid::new_v4().to_string();
        let seed = format!("{}:{}", file_path, id);
        let token = format!("aegis-{:016x}", blake3::hash(seed.as_bytes()).as_bytes().iter().take(8).fold(0u64, |acc, &b| (acc << 8) | b as u64));
        let canary = CanaryToken { id: id.clone(), token: token.clone(), file_path: file_path.to_string(), description: description.to_string(), created_ts: Utc::now().timestamp_millis(), triggered: false };
        if Path::new(file_path).exists() { self.embed_in_file(file_path, &token)?; }
        self.tokens.write().unwrap().insert(token, canary.clone());
        self.persist()?;
        info!(id = %id, file = %file_path, "canary token created");
        Ok(canary)
    }

    fn embed_in_file(&self, path: &str, token: &str) -> Result<()> {
        let existing = std::fs::read_to_string(path).context("read target file for canary embedding")?;
        if existing.contains(token) { return Ok(()); }
        let comment = if path.ends_with(".py") || path.ends_with(".sh") || path.ends_with(".yaml") || path.ends_with(".yml") { format!("\n# {}\n", token) }
        else if path.ends_with(".json") { return self.write_sidecar(path, token); }
        else { format!("\n# aegis-canary: {}\n", token) };
        let mut content = existing;
        content.push_str(&comment);
        std::fs::write(path, content)?;
        info!(path, "canary embedded in file");
        Ok(())
    }

    fn write_sidecar(&self, original_path: &str, token: &str) -> Result<()> {
        let sidecar = format!("{}.aegis-canary", original_path);
        std::fs::write(&sidecar, format!("aegis-canary: {}\n", token))?;
        info!(sidecar, "canary written to sidecar file");
        Ok(())
    }

    pub fn check_payload(&self, payload: &str) -> Option<CanaryToken> {
        let tokens = self.tokens.read().unwrap();
        for (token, canary) in tokens.iter() {
            if payload.contains(token.as_str()) {
                warn!(token = &token[..12], file = %canary.file_path, "CANARY TOKEN DETECTED IN NETWORK PAYLOAD");
                return Some(canary.clone());
            }
        }
        None
    }

    pub fn mark_triggered(&self, token: &str) -> Result<()> {
        let mut tokens = self.tokens.write().unwrap();
        if let Some(c) = tokens.get_mut(token) { c.triggered = true; }
        drop(tokens);
        self.persist()
    }

    pub fn list(&self) -> Vec<CanaryToken> { self.tokens.read().unwrap().values().cloned().collect() }

    pub fn delete(&self, id: &str) -> Result<bool> {
        let mut tokens = self.tokens.write().unwrap();
        let before = tokens.len();
        tokens.retain(|_, c| c.id != id);
        let removed = tokens.len() < before;
        drop(tokens);
        self.persist()?;
        Ok(removed)
    }

    fn persist(&self) -> Result<()> {
        let list: Vec<CanaryToken> = self.tokens.read().unwrap().values().cloned().collect();
        std::fs::write(&self.store, serde_json::to_string_pretty(&list)?)?;
        Ok(())
    }
}

impl Default for CanaryManager { fn default() -> Self { Self::new().expect("canary manager init") } }
