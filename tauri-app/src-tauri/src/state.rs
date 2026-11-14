use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Mutex;

use active_defense::ResponseEngine;
use journal::Journal;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemSettings {
    pub process_inspection_enabled: bool,
    pub active_kill_enabled: bool,
    pub net_admin_enabled: bool,
    pub tamper_proof_audit: bool,
    pub auto_update_enabled: bool,
    pub realtime_av_enabled: bool,
}

impl Default for SystemSettings {
    fn default() -> Self {
        Self {
            process_inspection_enabled: true,
            active_kill_enabled: true,
            net_admin_enabled: true,
            tamper_proof_audit: true,
            auto_update_enabled: true,
            realtime_av_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketInspectorConfig {
    pub deep_inspection: bool,
    pub syn_flood_guard: bool,
    pub port_scan_guard: bool,
    pub dns_tunnel_guard: bool,
    pub arp_spoof_guard: bool,
    pub syn_flood_threshold: u32,
    pub port_scan_threshold: u32,
}

impl Default for PacketInspectorConfig {
    fn default() -> Self {
        Self {
            deep_inspection: true,
            syn_flood_guard: true,
            port_scan_guard: true,
            dns_tunnel_guard: true,
            arp_spoof_guard: true,
            syn_flood_threshold: 60,
            port_scan_threshold: 20,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoPruneConfig {
    pub enabled: bool,
    pub retention_days: u32,
    pub max_debug_entries: u32,
    pub clean_temp_files: bool,
    pub clean_sandbox_artifacts: bool,
    pub clean_pcap_buffers: bool,
    pub interval_hours: u32,
}

impl Default for AutoPruneConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            retention_days: 14,
            max_debug_entries: 100,
            clean_temp_files: true,
            clean_sandbox_artifacts: true,
            clean_pcap_buffers: true,
            interval_hours: 6,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetDefenseConfig {
    pub ids_enabled: bool,
    pub auto_drop_attackers: bool,
    pub auto_block_c2: bool,
    pub sniffing_detection_active: bool,
    pub anti_port_scan_filter: bool,
    pub port_scan_threshold: u32,
    pub syn_flood_protection: bool,
    pub dns_tunneling_guard: bool,
    pub capture_interface: String,
    pub blocked_ip_list: Vec<String>,
}

impl Default for NetDefenseConfig {
    fn default() -> Self {
        Self {
            ids_enabled: true,
            auto_drop_attackers: true,
            auto_block_c2: true,
            sniffing_detection_active: true,
            anti_port_scan_filter: true,
            port_scan_threshold: 20,
            syn_flood_protection: true,
            dns_tunneling_guard: true,
            capture_interface: "auto".into(),
            blocked_ip_list: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareScanResult {
    pub id: String,
    pub target_path: String,
    pub file_path: String,
    pub is_infected: bool,
    pub threat_name: Option<String>,
    pub malware_name: Option<String>,
    pub rule_matched: String,
    pub detection_method: String,
    pub user_verdict: Option<String>,
    pub sandbox_jail_id: Option<String>,
    pub family: Option<String>,
    pub category: Option<String>,
    pub confidence: String,
    pub entropy: f64,
    pub file_size: u64,
    pub is_quarantined: bool,
    pub quarantined: bool,
    pub hash_sha256: String,
    pub sha256: String,
    pub indicators: Vec<String>,
    pub remediation_status: String,
    pub scanned_at: i64,
    pub status: String,
}

pub struct AppState {
    pub journal: Mutex<Journal>,
    pub response_engine: ResponseEngine,
    pub data_dir: PathBuf,
    pub settings: Mutex<SystemSettings>,
    pub packet_config: Mutex<PacketInspectorConfig>,
    pub prune_config: Mutex<AutoPruneConfig>,
    pub net_config: Mutex<NetDefenseConfig>,
    pub blocked_ips: Mutex<HashSet<String>>,
    pub malware_results: Mutex<Vec<MalwareScanResult>>,
    pub auto_remediation: Mutex<bool>,
    pub files_scanned: Mutex<u64>,
    pub threats_blocked: Mutex<u64>,
    pub last_pruned_ts: Mutex<Option<i64>>,
    pub packets_inspected: Mutex<u64>,
}

impl AppState {
    pub fn load_persisted<T: serde::de::DeserializeOwned + Default>(data_dir: &std::path::Path, filename: &str) -> T {
        let p = data_dir.join(filename);
        if let Ok(raw) = std::fs::read_to_string(p) {
            serde_json::from_str(&raw).unwrap_or_default()
        } else {
            T::default()
        }
    }

    pub fn save_persisted<T: serde::Serialize>(&self, filename: &str, value: &T) {
        let p = self.data_dir.join(filename);
        if let Ok(json) = serde_json::to_string_pretty(value) {
            let _ = std::fs::write(p, json);
        }
    }
}
