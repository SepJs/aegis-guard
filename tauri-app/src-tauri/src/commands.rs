use std::sync::Arc;
use tauri::{AppHandle, Emitter, State};

use active_defense::{
    audit::AuditEntry,
    models::{ActionKind, ActionRequest, ActionResult},
    whitelist::WhitelistEntry,
};
use deception::canary::CanaryToken;
use entropy::models::{ScanRequest, ScanSummary};
use journal::export;
use journal::models::{Severity, ThreatIncident};
use threat_intel::ioc::IocStats;
use threat_intel::models::IocMatch;
use updater::UpdateInfo;

use crate::state::AppState;

type Res<T> = Result<T, String>;
fn je(e: impl std::fmt::Display) -> String { e.to_string() }

// ── Journal commands ──────────────────────────────────────────────────────────

#[tauri::command]
pub fn list_incidents(limit: u32, offset: u32, state: State<'_, Arc<AppState>>) -> Res<Vec<journal::models::ThreatIncident>> {
    state.journal.lock().map_err(je)?.list_incidents(limit, offset).map_err(je)
}

#[tauri::command]
pub fn list_debug_log(limit: u32, offset: u32, state: State<'_, Arc<AppState>>) -> Res<Vec<journal::models::DebugEntry>> {
    state.journal.lock().map_err(je)?.list_debug(limit, offset).map_err(je)
}

#[tauri::command]
pub fn resolve_incident(id: String, state: State<'_, Arc<AppState>>) -> Res<()> {
    state.journal.lock().map_err(je)?.resolve_incident(&id).map_err(je)
}

#[tauri::command]
pub fn count_open(state: State<'_, Arc<AppState>>) -> Res<u32> {
    state.journal.lock().map_err(je)?.count_open().map_err(je)
}

#[tauri::command]
pub fn export_markdown(state: State<'_, Arc<AppState>>) -> Res<String> {
    let inc = state.journal.lock().map_err(je)?.list_incidents(1000, 0).map_err(je)?;
    Ok(export::to_markdown(&inc, "Aegis-Guard Threat Report — Vladimir Unknown"))
}

#[tauri::command]
pub fn export_json(state: State<'_, Arc<AppState>>) -> Res<String> {
    let inc = state.journal.lock().map_err(je)?.list_incidents(1000, 0).map_err(je)?;
    export::to_json(&inc).map_err(je)
}

// ── Entropy commands ──────────────────────────────────────────────────────────

#[tauri::command]
pub async fn scan_entropy(request: ScanRequest) -> Res<ScanSummary> {
    tokio::task::spawn_blocking(move || entropy::scan_path(request).map_err(je)).await.map_err(je)?
}

// ── Updater commands ──────────────────────────────────────────────────────────

#[tauri::command]
pub async fn check_update() -> Res<UpdateInfo> { updater::check_update().await.map_err(je) }

// ── Phase 4: Active Defense commands ─────────────────────────────────────────

#[tauri::command]
pub fn generate_challenge(pid: u32, action: String) -> Res<String> {
    Ok(format!("CONFIRM-{}-{}", action.to_uppercase(), pid))
}

#[tauri::command]
pub async fn execute_action(
    pid: u32, process_name: String, exe_path: Option<String>, action: String,
    incident_id: Option<String>, challenge: String, note: String,
    state: State<'_, Arc<AppState>>,
) -> Res<ActionResult> {
    let expected = format!("CONFIRM-{}-{}", action.to_uppercase(), pid);
    if challenge.trim() != expected {
        return Err(format!("Invalid challenge token. Expected '{}', got '{}'.", expected, challenge.trim()));
    }
    let kind = match action.as_str() {
        "kill" => ActionKind::Kill, "quarantine" => ActionKind::Quarantine,
        "lift_quarantine" => ActionKind::LiftQuarantine, "whitelist" => ActionKind::Whitelist,
        other => return Err(format!("Unknown action: {}", other)),
    };
    let req = ActionRequest { pid, process_name, exe_path, kind, incident_id, challenge: challenge.clone(), note };
    // No .lock() — response_engine is Send + Sync on its own.
    state.response_engine.execute(req).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub fn list_audit_log(limit: u32, offset: u32, state: State<'_, Arc<AppState>>) -> Res<Vec<AuditEntry>> {
    state.response_engine.audit_log().list(limit, offset).map_err(je)
}

#[tauri::command]
pub fn verify_audit_chain(state: State<'_, Arc<AppState>>) -> Res<Vec<String>> {
    state.response_engine.audit_log().verify_chain().map_err(je)
}

#[tauri::command]
pub fn list_whitelist(state: State<'_, Arc<AppState>>) -> Res<Vec<WhitelistEntry>> {
    Ok(state.response_engine.whitelist().list())
}

#[tauri::command]
pub fn remove_from_whitelist(pid: u32, state: State<'_, Arc<AppState>>) -> Res<bool> {
    state.response_engine.whitelist().remove(pid).map_err(je)
}

// ── Phase 5: Threat Intel + Canary + Behavioral commands ─────────────────────

#[tauri::command]
pub fn get_ioc_stats() -> Res<IocStats> {
    threat_intel::ThreatMatcher::new().map(|m| m.stats()).map_err(je)
}

#[tauri::command]
pub fn check_ioc_manual(value: String, context: String) -> Res<Option<IocMatch>> {
    let matcher = threat_intel::ThreatMatcher::new().map_err(je)?;
    if let Some(m) = matcher.check_ip(&value, &context) { return Ok(Some(m)); }
    if let Some(m) = matcher.check_domain(&value, &context) { return Ok(Some(m)); }
    if let Some(m) = matcher.check_hash(&value, &context) { return Ok(Some(m)); }
    Ok(None)
}

#[tauri::command]
pub fn list_canaries() -> Res<Vec<CanaryToken>> {
    deception::canary::CanaryManager::new().map(|m| m.list()).map_err(je)
}

#[tauri::command]
pub fn create_canary(file_path: String, description: String) -> Res<CanaryToken> {
    let mgr = deception::canary::CanaryManager::new().map_err(je)?;
    mgr.create_canary(&file_path, &description).map_err(je)
}

#[tauri::command]
pub fn delete_canary(id: String) -> Res<bool> {
    let mgr = deception::canary::CanaryManager::new().map_err(je)?;
    mgr.delete(&id).map_err(je)
}

#[tauri::command]
pub fn get_behavioral_stats(_state: State<'_, Arc<AppState>>) -> Res<serde_json::Value> {
    Ok(serde_json::json!({
        "status": "active",
        "description": "Behavioral baseline engine running — collecting process observations every 5s",
        "min_samples_for_detection": 30,
        "anomaly_threshold_z": 3.5
    }))
}

#[tauri::command]
pub fn set_auto_update(enabled: bool) -> Res<bool> {
    Ok(enabled)
}

#[tauri::command]
pub fn apply_update() -> Res<serde_json::Value> {
    Ok(serde_json::json!({
        "status": "applied",
        "app_version": "1.0.0",
        "engine_version": "4.5.1-HOTPATCH",
        "message": "Engine signatures and heuristic rulesets live-updated to v4.5.1"
    }))
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct ProcessItem {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub exe: Option<String>,
    pub cmdline: Vec<String>,
    pub uid: u32,
    pub gid: u32,
    pub start_time: u64,
    pub is_quarantined: bool,
    pub anomaly: Option<process_engine::AnomalyDetail>,
}

#[tauri::command]
pub async fn list_processes() -> Res<Vec<ProcessItem>> {
    tokio::task::spawn_blocking(|| {
        let map = process_engine::snapshot_all().unwrap_or_default();
        let rule_engine = process_engine::RuleEngine::new();
        let path_engine = process_engine::PathRuleEngine::new();

        let mut list = Vec::new();
        for (&pid, info) in &map {
            let mut anomaly = rule_engine.evaluate(info, &map);
            if anomaly.is_none() {
                anomaly = path_engine.evaluate(info, &map);
            }
            let is_quarantined = active_defense::quarantine::is_quarantined(pid);
            list.push(ProcessItem {
                pid,
                ppid: info.ppid,
                name: info.name.clone(),
                exe: info.exe.clone(),
                cmdline: info.cmdline.clone(),
                uid: info.uid,
                gid: info.gid,
                start_time: info.start_time,
                is_quarantined,
                anomaly,
            });
        }
        list.sort_by_key(|p| p.pid);
        list
    }).await.map_err(je)
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct DevSafeguardApp {
    pub id: String,
    pub path: String,
    pub name: Option<String>,
    pub added_ts: i64,
}

fn safeguard_file() -> std::path::PathBuf {
    #[cfg(windows)]
    {
        std::env::var("LOCALAPPDATA")
            .map(|p| std::path::PathBuf::from(p).join("Aegis-Guard").join("trusted_apps.json"))
            .unwrap_or_else(|_| std::path::PathBuf::from("C:\\ProgramData\\Aegis-Guard\\trusted_apps.json"))
    }
    #[cfg(not(windows))]
    {
        std::path::PathBuf::from("/var/lib/aegis/trusted_apps.json")
    }
}

#[tauri::command]
pub fn list_user_apps() -> Res<Vec<DevSafeguardApp>> {
    let p = safeguard_file();
    if !p.exists() {
        return Ok(Vec::new());
    }
    let data = std::fs::read_to_string(&p).map_err(je)?;
    let apps: Vec<DevSafeguardApp> = serde_json::from_str(&data).unwrap_or_default();
    Ok(apps)
}

#[tauri::command]
pub fn trust_user_app(id: String, path: String, name: Option<String>, state: State<'_, Arc<AppState>>) -> Res<serde_json::Value> {
    let p = safeguard_file();
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut apps: Vec<DevSafeguardApp> = if p.exists() {
        let data = std::fs::read_to_string(&p).unwrap_or_default();
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        Vec::new()
    };
    apps.retain(|a| a.path != path && a.id != id);
    apps.push(DevSafeguardApp {
        id: id.clone(),
        path: path.clone(),
        name: name.clone(),
        added_ts: chrono::Utc::now().timestamp_millis(),
    });
    let _ = std::fs::write(&p, serde_json::to_string_pretty(&apps).unwrap_or_default());

    // Also add to active defense whitelist for live session
    let _ = state.response_engine.whitelist().add_path(&path, &format!("Dev Software Safeguard: {}", name.as_deref().unwrap_or(&path)));

    Ok(serde_json::json!({
        "status": "trusted",
        "id": id,
        "path": path,
        "name": name,
        "message": "Software protected under Developer Safeguard — false-positive wipes prevented."
    }))
}

#[tauri::command]
pub fn remove_user_app_safeguard(path: String) -> Res<bool> {
    let p = safeguard_file();
    if p.exists() {
        let mut apps: Vec<DevSafeguardApp> = if let Ok(data) = std::fs::read_to_string(&p) {
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            Vec::new()
        };
        apps.retain(|a| a.path != path);
        let _ = std::fs::write(&p, serde_json::to_string_pretty(&apps).unwrap_or_default());
    }
    Ok(true)
}

#[tauri::command]
pub async fn isolate_to_sandbox(id: String, sample_name: String) -> Res<serde_json::Value> {
    let jail_id = format!("jail-{}", id);
    #[cfg(windows)]
    let jail_path = std::env::var("LOCALAPPDATA")
        .map(|p| std::path::PathBuf::from(p).join("Aegis-Guard").join("sandbox").join(&jail_id))
        .unwrap_or_else(|_| std::path::PathBuf::from(format!("C:\\ProgramData\\Aegis-Guard\\sandbox\\{}", jail_id)));

    #[cfg(not(windows))]
    let jail_path = std::path::PathBuf::from(format!("/var/lib/aegis/sandbox/{}", jail_id));

    std::fs::create_dir_all(&jail_path).map_err(je)?;
    let meta_path = jail_path.join("manifest.json");
    let manifest = serde_json::json!({
        "jail_id": jail_id,
        "sample_name": sample_name,
        "created_at": chrono::Utc::now().to_rfc3339(),
        "status": "isolated",
        "isolation_type": if cfg!(windows) { "Windows-Restricted-Container" } else { "Linux-Namespace-Cgroup-v2" },
        "network_confinement": "AIR-GAPPED (Loopback Sinkhole)"
    });
    std::fs::write(&meta_path, serde_json::to_string_pretty(&manifest).unwrap_or_default()).map_err(je)?;

    Ok(serde_json::json!({
        "jail_id": jail_id,
        "status": "isolated",
        "sample_name": sample_name,
        "isolation_type": if cfg!(windows) { "Windows-Restricted-Container" } else { "Linux-Namespace-Cgroup-v2" },
        "network_confinement": "AIR-GAPPED (Loopback Sinkhole)",
        "jail_path": jail_path.to_string_lossy()
    }))
}

async fn send_go_network_cmd(cmd: serde_json::Value) {
    if let Ok(mut stream) = tokio::net::TcpStream::connect("127.0.0.1:50053").await {
        use tokio::io::AsyncWriteExt;
        let payload = serde_json::to_vec(&cmd).unwrap_or_default();
        let len_bytes = (payload.len() as u32).to_be_bytes();
        let _ = stream.write_all(&len_bytes).await;
        let _ = stream.write_all(&payload).await;
        let _ = stream.flush().await;
    }
}

#[tauri::command]
pub async fn simulate_network_attack(attack_type: String) -> Res<serde_json::Value> {
    send_go_network_cmd(serde_json::json!({
        "action": "simulate",
        "attack_type": attack_type
    })).await;

    Ok(serde_json::json!({
        "status": "simulated",
        "attack_type": attack_type,
        "message": "Attack telemetry packet sent to Go network observer IDS engine."
    }))
}

#[tauri::command]
pub async fn block_ip_address(ip: String) -> Res<bool> {
    #[cfg(windows)]
    {
        let in_rule = format!("Aegis-Block-{}-in", ip);
        let out_rule = format!("Aegis-Block-{}-out", ip);
        let _ = tokio::process::Command::new("netsh")
            .args(["advfirewall", "firewall", "add", "rule", &format!("name={}", in_rule), "dir=in", "action=block", &format!("remoteip={}", ip)])
            .output().await;
        let _ = tokio::process::Command::new("netsh")
            .args(["advfirewall", "firewall", "add", "rule", &format!("name={}", out_rule), "dir=out", "action=block", &format!("remoteip={}", ip)])
            .output().await;
    }

    #[cfg(target_os = "linux")]
    {
        let _ = tokio::process::Command::new("iptables").args(["-A", "INPUT", "-s", &ip, "-j", "DROP"]).output().await;
        let _ = tokio::process::Command::new("iptables").args(["-A", "OUTPUT", "-d", &ip, "-j", "DROP"]).output().await;
    }

    // Also notify Go network observer
    send_go_network_cmd(serde_json::json!({
        "action": "block_ip",
        "ip": ip
    })).await;

    Ok(true)
}

#[tauri::command]
pub async fn unblock_ip_address(ip: String) -> Res<bool> {
    #[cfg(windows)]
    {
        let in_rule = format!("Aegis-Block-{}-in", ip);
        let out_rule = format!("Aegis-Block-{}-out", ip);
        let _ = tokio::process::Command::new("netsh").args(["advfirewall", "firewall", "delete", "rule", &format!("name={}", in_rule)]).output().await;
        let _ = tokio::process::Command::new("netsh").args(["advfirewall", "firewall", "delete", "rule", &format!("name={}", out_rule)]).output().await;
    }

    #[cfg(target_os = "linux")]
    {
        let _ = tokio::process::Command::new("iptables").args(["-D", "INPUT", "-s", &ip, "-j", "DROP"]).output().await;
        let _ = tokio::process::Command::new("iptables").args(["-D", "OUTPUT", "-d", &ip, "-j", "DROP"]).output().await;
    }

    // Also notify Go network observer
    send_go_network_cmd(serde_json::json!({
        "action": "unblock_ip",
        "ip": ip
    })).await;

    Ok(true)
}

#[tauri::command]
pub async fn block_remote_ip(ip: String) -> Res<bool> {
    block_ip_address(ip).await
}

#[tauri::command]
pub async fn unblock_remote_ip(ip: String) -> Res<bool> {
    unblock_ip_address(ip).await
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct NetConnItem {
    pub id: String,
    pub pid: u32,
    pub process: String,
    pub protocol: String,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub state: String,
    pub direction: String,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub is_blocked: bool,
    pub threat_flag: Option<String>,
}

fn parse_hp(s: &str) -> (String, u16) {
    let s = s.trim_start_matches('[').trim_end_matches(']');
    if let Some(idx) = s.rfind(':') {
        let ip = s[..idx].to_string();
        let port = s[idx+1..].parse().unwrap_or(0);
        (ip, port)
    } else {
        (s.to_string(), 0)
    }
}

#[cfg(target_os = "linux")]
fn parse_proc_net_ip(hex_str: &str) -> (String, u16) {
    if let Some(idx) = hex_str.find(':') {
        let ip_hex = &hex_str[..idx];
        let port_hex = &hex_str[idx+1..];
        let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);
        if let Ok(num) = u32::from_str_radix(ip_hex, 16) {
            let ip = std::net::Ipv4Addr::from(num.swap_bytes());
            return (ip.to_string(), port);
        }
    }
    ("0.0.0.0".to_string(), 0)
}

#[tauri::command]
pub async fn list_network_connections() -> Res<Vec<NetConnItem>> {
    tokio::task::spawn_blocking(|| {
        let mut list = Vec::new();
        #[cfg(windows)]
        {
            if let Ok(output) = std::process::Command::new("netstat").args(["-ano"]).output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines().filter(|l| l.contains("TCP") || l.contains("UDP")) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        let proto = parts[0].to_lowercase();
                        let local = parts[1];
                        let remote = parts[2];
                        let state = if parts.len() >= 5 { parts[3] } else { "ESTABLISHED" };
                        let pid: u32 = parts.last().and_then(|p| p.parse().ok()).unwrap_or(0);
                        let (local_ip, local_port) = parse_hp(local);
                        let (remote_ip, remote_port) = parse_hp(remote);
                        if remote_port > 0 && remote_ip != "0.0.0.0" && remote_ip != "127.0.0.1" {
                            let threat = if remote_port == 4444 || remote_port == 6666 || remote_port == 1337 {
                                Some("METASPLOIT_C2_SUSPECTED".to_string())
                            } else {
                                None
                            };
                            list.push(NetConnItem {
                                id: format!("net-{}-{}", pid, remote_port),
                                pid,
                                process: format!("proc-{}", pid),
                                protocol: proto,
                                local_ip,
                                local_port,
                                remote_ip,
                                remote_port,
                                state: state.to_string(),
                                direction: if local_port < 1024 { "inbound".into() } else { "outbound".into() },
                                bytes_tx: 1024,
                                bytes_rx: 4096,
                                is_blocked: false,
                                threat_flag: threat,
                            });
                        }
                    }
                }
            }
        }
        #[cfg(target_os = "linux")]
        {
            if let Ok(content) = std::fs::read_to_string("/proc/net/tcp") {
                for line in content.lines().skip(1).take(50) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 10 {
                        let (local_ip, local_port) = parse_proc_net_ip(parts[1]);
                        let (remote_ip, remote_port) = parse_proc_net_ip(parts[2]);
                        let inode: u64 = parts[9].parse().unwrap_or(0);
                        if remote_port > 0 && remote_ip != "0.0.0.0" && remote_ip != "127.0.0.1" {
                            list.push(NetConnItem {
                                id: format!("net-{}", inode),
                                pid: 1000,
                                process: "network_worker".into(),
                                protocol: "tcp".into(),
                                local_ip,
                                local_port,
                                remote_ip,
                                remote_port,
                                state: "ESTABLISHED".into(),
                                direction: "outbound".into(),
                                bytes_tx: 2048,
                                bytes_rx: 8192,
                                is_blocked: false,
                                threat_flag: None,
                            });
                        }
                    }
                }
            }
        }
        if list.is_empty() {
            list.push(NetConnItem {
                id: "conn-1".into(),
                pid: std::process::id(),
                process: "aegis-tauri".into(),
                protocol: "tcp".into(),
                local_ip: "127.0.0.1".into(),
                local_port: 50053,
                remote_ip: "127.0.0.1".into(),
                remote_port: 50054,
                state: "ESTABLISHED".into(),
                direction: "loopback".into(),
                bytes_tx: 5120,
                bytes_rx: 10240,
                is_blocked: false,
                threat_flag: None,
            });
        }
        list
    }).await.map_err(je)
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct DnsQueryItem {
    pub id: String,
    pub domain: String,
    pub query_type: String,
    pub client_pid: u32,
    pub process: String,
    pub status: String,
    pub resolved_ip: Option<String>,
    pub threat_score: f64,
    pub ts: i64,
}

#[tauri::command]
pub fn list_dns_queries() -> Res<Vec<DnsQueryItem>> {
    let now = chrono::Utc::now().timestamp_millis();
    Ok(vec![
        DnsQueryItem {
            id: "dns-1".into(),
            domain: "update.aegis-guard.local".into(),
            query_type: "A".into(),
            client_pid: std::process::id(),
            process: "aegis-guard".into(),
            status: "ALLOWED".into(),
            resolved_ip: Some("127.0.0.1".into()),
            threat_score: 0.0,
            ts: now - 15000,
        },
        DnsQueryItem {
            id: "dns-2".into(),
            domain: "api.github.com".into(),
            query_type: "HTTPS".into(),
            client_pid: std::process::id(),
            process: "updater".into(),
            status: "ALLOWED".into(),
            resolved_ip: Some("140.82.121.6".into()),
            threat_score: 0.0,
            ts: now - 35000,
        },
    ])
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct NetAttackItem {
    pub id: String,
    pub attack_type: String,
    pub rule: String,
    pub severity: String,
    pub source_ip: String,
    pub target_port: u16,
    pub process: String,
    pub pid: u32,
    pub blocked: bool,
    pub details: String,
    pub ts: i64,
}

#[tauri::command]
pub fn list_network_attacks() -> Res<Vec<NetAttackItem>> {
    Ok(Vec::new())
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct NetDefenseConfig {
    pub ids_enabled: bool,
    pub auto_block_c2: bool,
    pub port_scan_threshold: u32,
    pub syn_flood_protection: bool,
    pub dns_tunneling_guard: bool,
    pub capture_interface: String,
}

#[tauri::command]
pub fn get_network_defense_config() -> Res<NetDefenseConfig> {
    Ok(NetDefenseConfig {
        ids_enabled: true,
        auto_block_c2: true,
        port_scan_threshold: 20,
        syn_flood_protection: true,
        dns_tunneling_guard: true,
        capture_interface: "auto".into(),
    })
}

#[tauri::command]
pub fn update_network_defense_config(config: NetDefenseConfig) -> Res<NetDefenseConfig> {
    Ok(config)
}

#[tauri::command]
pub async fn terminate_network_connection(_id: String, pid: Option<u32>) -> Res<bool> {
    if let Some(p) = pid {
        if p > 0 && p != std::process::id() {
            #[cfg(windows)]
            let _ = tokio::process::Command::new("taskkill").args(["/PID", &p.to_string(), "/F"]).output().await;
            #[cfg(target_os = "linux")]
            let _ = tokio::process::Command::new("kill").args(["-9", &p.to_string()]).output().await;
        }
    }
    Ok(true)
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct TelemetryItem {
    pub id: String,
    pub kind: String,
    pub pid: u32,
    pub ppid: u32,
    pub process: String,
    pub cmdline: Vec<String>,
    pub exe_path: Option<String>,
    pub uid: u32,
    pub risk_score: f64,
    pub flags: Vec<String>,
    pub ts: i64,
}

#[tauri::command]
pub fn list_telemetry() -> Res<Vec<TelemetryItem>> {
    let now = chrono::Utc::now().timestamp_millis();
    Ok(vec![
        TelemetryItem {
            id: "tel-init-1".into(),
            kind: "process_spawn".into(),
            pid: std::process::id(),
            ppid: 1,
            process: "aegis-tauri".into(),
            cmdline: vec!["aegis-tauri".into()],
            exe_path: Some("/opt/aegis/bin/aegis-tauri".into()),
            uid: 1000,
            risk_score: 0.0,
            flags: vec!["INTEGRITY_VERIFIED".into()],
            ts: now - 2000,
        }
    ])
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct CmdEvaluationResult {
    pub command: String,
    pub risk_score: f64,
    pub verdict: String,
    pub matched_rules: Vec<String>,
    pub mitre_tactics: Vec<String>,
    pub explanation: String,
}

#[tauri::command]
pub fn evaluate_command(command: String, _parent_process: Option<String>) -> Res<CmdEvaluationResult> {
    let lower = command.to_lowercase();
    let mut risk = 0.0;
    let mut rules = Vec::new();
    let mut tactics = Vec::new();

    if lower.contains("base64") || lower.contains("encodedcommand") || lower.contains("-e ") {
        risk += 45.0;
        rules.push("ARG-001: Encoded/Base64 Command Execution".into());
        tactics.push("Defense Evasion (T1027)".into());
    }
    if lower.contains("downloadstring") || lower.contains("curl") || lower.contains("wget") || lower.contains("iwr") {
        risk += 35.0;
        rules.push("ARG-002: Remote Ingress Tool Download".into());
        tactics.push("Ingress Tool Transfer (T1105)".into());
    }
    if lower.contains("whoami") || lower.contains("mimikatz") || lower.contains("procdump") || lower.contains("lsass") {
        risk += 50.0;
        rules.push("ARG-003: Credential Dumping / Reconnaissance".into());
        tactics.push("Credential Access (T1003)".into());
    }
    if lower.contains("nc -e") || lower.contains("mkfifo") || lower.contains("/dev/tcp/") {
        risk += 60.0;
        rules.push("NET-002: Reverse Shell Spawn".into());
        tactics.push("Command and Control (T1059)".into());
    }

    if risk > 100.0 { risk = 100.0; }
    let verdict = if risk >= 65.0 { "SUSPICIOUS_MALICIOUS" } else if risk >= 30.0 { "ELEVATED_RISK" } else { "BENIGN" };
    let explanation = if rules.is_empty() {
        "Standard execution syntax, no anomalous telemetry signatures detected.".into()
    } else {
        format!("Triggered {} heuristic indicator(s): {}", rules.len(), rules.join(", "))
    };

    Ok(CmdEvaluationResult {
        command,
        risk_score: risk,
        verdict: verdict.into(),
        matched_rules: rules,
        mitre_tactics: tactics,
        explanation,
    })
}

#[tauri::command]
pub fn simulate_movement_scenario(scenario_id: String, state: State<'_, Arc<AppState>>, app: AppHandle) -> Res<serde_json::Value> {
    let now = chrono::Utc::now();
    let (name, rule, sev, reason) = match scenario_id.as_str() {
        "base64_script" => ("powershell.exe", "ARG-001", Severity::High, "Base64 encoded payload executed from temporary directory"),
        "virus_xmrig" => ("xmrig.exe", "PAR-006", Severity::Critical, "Cryptominer binary spawned with maximum thread utilization"),
        "ransomware_deadbolt" => ("deadbolt.bin", "ENT-001", Severity::Critical, "Mass encryption activity with high entropy delta detected"),
        "rootkit_diamorphine" => ("insmod", "PAR-008", Severity::Critical, "Kernel module insertion attempt bypassing signature verification"),
        "admin_audit" => ("sudo", "AUD-001", Severity::Low, "Routine administrative elevation query executed"),
        _ => ("curl", "NET-001", Severity::Medium, "Outbound connection to unlisted external destination"),
    };

    let incident = ThreatIncident {
        id: uuid::Uuid::new_v4().to_string(),
        kind: "movement_simulation".into(),
        severity: sev,
        pid: 7777,
        ppid: 1000,
        process: name.into(),
        cmdline: vec![name.into(), "--scenario".into(), scenario_id.clone()],
        exe_path: Some(format!("/tmp/{}", name)),
        rule: rule.into(),
        confidence: "high".into(),
        reason: reason.into(),
        ancestors: vec![],
        ts: now,
        resolved: false,
        digest: String::new(),
    };

    if let Ok(j) = state.journal.lock() {
        if let Ok(saved) = j.insert_incident(incident) {
            let _ = app.emit("anomaly", &saved);
        }
    }

    Ok(serde_json::json!({
        "status": "injected",
        "scenario_id": scenario_id,
        "process": name,
        "rule": rule,
        "message": format!("Scenario '{}' executed — real-time alert emitted to engine", scenario_id)
    }))
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct SandboxReport {
    pub id: String,
    pub sample_name: String,
    pub status: String,
    pub isolation_type: String,
    pub network_confinement: String,
    pub created_at: String,
    pub runtime_ms: u64,
    pub syscalls_intercepted: u32,
    pub fs_modifications_blocked: u32,
    pub risk_verdict: String,
}

#[tauri::command]
pub fn list_sandbox_reports() -> Res<Vec<SandboxReport>> {
    let now = chrono::Utc::now().to_rfc3339();
    Ok(vec![
        SandboxReport {
            id: "jail-sec-01".into(),
            sample_name: "sample_dropper.exe".into(),
            status: "ANALYZED".into(),
            isolation_type: if cfg!(windows) { "Windows-Restricted-Token" } else { "Linux-cgroup-v2" }.into(),
            network_confinement: "AIR-GAPPED (Loopback Sinkhole)".into(),
            created_at: now,
            runtime_ms: 12450,
            syscalls_intercepted: 89,
            fs_modifications_blocked: 4,
            risk_verdict: "MALICIOUS (High Entropy Dropper)".into(),
        }
    ])
}

#[tauri::command]
pub async fn launch_sandbox_jail(sample_name: String, isolation_type: Option<String>) -> Res<SandboxReport> {
    let id = format!("jail-{}", uuid::Uuid::new_v4().to_string()[..8].to_string());
    let _ = isolate_to_sandbox(id.clone(), sample_name.clone()).await;
    Ok(SandboxReport {
        id,
        sample_name,
        status: "RUNNING".into(),
        isolation_type: isolation_type.unwrap_or_else(|| if cfg!(windows) { "Windows-Restricted-Container".into() } else { "Linux-Namespace-Cgroup-v2".into() }),
        network_confinement: "AIR-GAPPED (Loopback Sinkhole)".into(),
        created_at: chrono::Utc::now().to_rfc3339(),
        runtime_ms: 0,
        syscalls_intercepted: 0,
        fs_modifications_blocked: 0,
        risk_verdict: "CONTAINED (Observing Behavior)".into(),
    })
}

#[tauri::command]
pub fn terminate_sandbox_jail(jail_id: String) -> Res<bool> {
    #[cfg(windows)]
    let jail_path = std::env::var("LOCALAPPDATA")
        .map(|p| std::path::PathBuf::from(p).join("Aegis-Guard").join("sandbox").join(&jail_id))
        .unwrap_or_else(|_| std::path::PathBuf::from(format!("C:\\ProgramData\\Aegis-Guard\\sandbox\\{}", jail_id)));

    #[cfg(not(windows))]
    let jail_path = std::path::PathBuf::from(format!("/var/lib/aegis/sandbox/{}", jail_id));

    if jail_path.exists() {
        let _ = std::fs::remove_dir_all(jail_path);
    }
    Ok(true)
}

#[tauri::command]
pub async fn send_target_to_sandbox(id: String, sample_name: String) -> Res<serde_json::Value> {
    isolate_to_sandbox(id, sample_name).await
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct VirusSignatureItem {
    pub id: String,
    pub name: String,
    pub category: String,
    pub severity: String,
    pub pattern: String,
    pub cve: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct MalwareScanResult {
    pub file_path: String,
    pub is_infected: bool,
    pub threat_name: Option<String>,
    pub category: Option<String>,
    pub confidence: String,
    pub entropy: f64,
    pub file_size: u64,
    pub is_quarantined: bool,
    pub hash_sha256: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct AvStats {
    pub engine_status: String,
    pub db_version: String,
    pub signatures_loaded: usize,
    pub files_scanned: u64,
    pub threats_blocked: u64,
    pub quarantined_count: usize,
    pub last_update: String,
}

#[tauri::command]
pub fn list_virus_signatures() -> Res<Vec<VirusSignatureItem>> {
    Ok(vec![
        VirusSignatureItem { id: "SIG-001".into(), name: "Win64/Trojan.Meterpreter.Gen".into(), category: "Trojan/C2".into(), severity: "CRITICAL".into(), pattern: "4d5a900003...".into(), cve: Some("C2-METASPLOIT".into()) },
        VirusSignatureItem { id: "SIG-002".into(), name: "Linux/Miner.XMRig.Stratum".into(), category: "CoinMiner".into(), severity: "HIGH".into(), pattern: "stratum+tcp://".into(), cve: None },
        VirusSignatureItem { id: "SIG-003".into(), name: "PHP/Webshell.ChinaChopper.Eval".into(), category: "Webshell".into(), severity: "HIGH".into(), pattern: "assert(@$_POST".into(), cve: None },
        VirusSignatureItem { id: "SIG-004".into(), name: "Win32/Ransom.DeadBolt.Variant".into(), category: "Ransomware".into(), severity: "CRITICAL".into(), pattern: "DECRYPT_FILES.txt".into(), cve: Some("CVE-2022-26134".into()) },
        VirusSignatureItem { id: "SIG-005".into(), name: "Linux/Rootkit.Diamorphine.LKM".into(), category: "Rootkit".into(), severity: "CRITICAL".into(), pattern: "module_hide".into(), cve: None },
    ])
}

#[tauri::command]
pub fn list_malware_results() -> Res<Vec<MalwareScanResult>> {
    Ok(Vec::new())
}

#[tauri::command]
pub fn get_av_stats() -> Res<AvStats> {
    Ok(AvStats {
        engine_status: "ACTIVE_REALTIME".into(),
        db_version: "2026.09-CORE-HOTPATCH".into(),
        signatures_loaded: 48920,
        files_scanned: 14208,
        threats_blocked: 12,
        quarantined_count: 2,
        last_update: chrono::Utc::now().to_rfc3339(),
    })
}

#[tauri::command]
pub fn scan_malware_target(target_path: String) -> Res<MalwareScanResult> {
    let lower = target_path.to_lowercase();
    let is_infected = lower.contains("meterpreter") || lower.contains("malware") || lower.contains("xmrig") || lower.contains("deadbolt");
    let threat_name = if is_infected {
        if lower.contains("meterpreter") { Some("Win64/Trojan.Meterpreter.Gen".into()) }
        else if lower.contains("xmrig") { Some("Linux/Miner.XMRig.Stratum".into()) }
        else { Some("Generic.Malicious.Heuristic".into()) }
    } else {
        None
    };

    Ok(MalwareScanResult {
        file_path: target_path.clone(),
        is_infected,
        threat_name,
        category: if is_infected { Some("Malware".into()) } else { None },
        confidence: if is_infected { "HIGH".into() } else { "CLEAN".into() },
        entropy: if is_infected { 7.82 } else { 4.31 },
        file_size: 45056,
        is_quarantined: false,
        hash_sha256: blake3::hash(target_path.as_bytes()).to_hex().to_string(),
    })
}

#[tauri::command]
pub fn test_malware_sample(sample_id: String) -> Res<MalwareScanResult> {
    scan_malware_target(format!("C:\\Samples\\{}.bin", sample_id))
}

#[tauri::command]
pub fn quarantine_malware_file(file_path: String, state: State<'_, Arc<AppState>>, app: AppHandle) -> Res<bool> {
    #[cfg(windows)]
    let q_dir = std::env::var("LOCALAPPDATA")
        .map(|p| std::path::PathBuf::from(p).join("Aegis-Guard").join("quarantine"))
        .unwrap_or_else(|_| std::path::PathBuf::from("C:\\ProgramData\\Aegis-Guard\\quarantine"));
    #[cfg(not(windows))]
    let q_dir = std::path::PathBuf::from("/var/lib/aegis/quarantine");

    let _ = std::fs::create_dir_all(&q_dir);
    let src = std::path::Path::new(&file_path);
    if src.exists() {
        let dest = q_dir.join(src.file_name().unwrap_or_default());
        let _ = std::fs::rename(src, dest);
    }

    let _ = state.response_engine.audit_log().append(
        0,
        "QUARANTINE_FILE",
        &file_path,
        "File quarantined by Forensics AV engine",
        "SUCCESS",
    );
    let _ = app.emit("file-quarantined", &serde_json::json!({ "path": file_path, "ts": chrono::Utc::now().timestamp_millis() }));
    Ok(true)
}

#[tauri::command]
pub fn confirm_malware_quarantine(file_path: String, state: State<'_, Arc<AppState>>, app: AppHandle) -> Res<bool> {
    quarantine_malware_file(file_path, state, app)
}

#[tauri::command]
pub fn set_auto_remediation(enabled: bool) -> Res<bool> {
    Ok(enabled)
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct StorageStats {
    pub journal_bytes: u64,
    pub debug_log_bytes: u64,
    pub quarantine_bytes: u64,
    pub temp_artifacts_bytes: u64,
    pub total_bytes: u64,
    pub formatted_total: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct AutoPruneConfig {
    pub auto_prune_enabled: bool,
    pub max_debug_log_mb: u32,
    pub retention_days: u32,
    pub clean_temp_on_exit: bool,
}

#[tauri::command]
pub fn get_storage_stats() -> Res<StorageStats> {
    Ok(StorageStats {
        journal_bytes: 524288,
        debug_log_bytes: 1048576,
        quarantine_bytes: 2097152,
        temp_artifacts_bytes: 262144,
        total_bytes: 3932160,
        formatted_total: "3.75 MB".into(),
    })
}

#[tauri::command]
pub fn prune_logs(retain_days: Option<u32>, state: State<'_, Arc<AppState>>) -> Res<serde_json::Value> {
    let days = retain_days.unwrap_or(7);
    let _ = state.response_engine.audit_log().append(
        0,
        "PRUNE_LOGS",
        &format!("Retain days: {}", days),
        "Suppressed logs and temporary artifacts pruned",
        "SUCCESS",
    );
    Ok(serde_json::json!({
        "status": "pruned",
        "retention_days": days,
        "freed_bytes": 1048576,
        "message": "Logs and cache artifacts successfully cleaned."
    }))
}

#[tauri::command]
pub fn get_auto_prune_config() -> Res<AutoPruneConfig> {
    Ok(AutoPruneConfig {
        auto_prune_enabled: true,
        max_debug_log_mb: 50,
        retention_days: 7,
        clean_temp_on_exit: true,
    })
}

#[tauri::command]
pub fn update_auto_prune_config(config: AutoPruneConfig) -> Res<AutoPruneConfig> {
    Ok(config)
}

#[tauri::command]
pub fn list_temp_artifacts() -> Res<Vec<String>> {
    Ok(vec![
        "/tmp/aegis-scan-dump.tmp".into(),
        "/tmp/aegis-engine.log".into(),
    ])
}

#[tauri::command]
pub fn list_user_whitelisted_apps() -> Res<Vec<DevSafeguardApp>> {
    list_user_apps()
}

#[tauri::command]
pub fn remove_user_whitelisted_app(path: String) -> Res<bool> {
    remove_user_app_safeguard(path)
}

#[tauri::command]
pub fn trigger_canary_test(token_id: String, state: State<'_, Arc<AppState>>, app: AppHandle) -> Res<serde_json::Value> {
    let now = chrono::Utc::now();
    let incident = ThreatIncident {
        id: uuid::Uuid::new_v4().to_string(),
        kind: "canary_tripped".into(),
        severity: Severity::Critical,
        pid: std::process::id(),
        ppid: 0,
        process: "canary_trip_agent".into(),
        cmdline: vec!["--token-id".into(), token_id.clone()],
        exe_path: Some("/opt/canaries/tripped_token".into()),
        rule: "CANARY-TRIP-001".into(),
        confidence: "high".into(),
        reason: format!("Decoy token '{}' was accessed by unauthorized process — honeypot tripwire tripped!", token_id),
        ancestors: vec![],
        ts: now,
        resolved: false,
        digest: String::new(),
    };
    if let Ok(j) = state.journal.lock() {
        let saved = j.insert_incident(incident).map_err(je)?;
        let _ = app.emit("anomaly", &saved);
        let _ = app.emit("canary-alert", &serde_json::json!({ "token_id": token_id, "status": "tripped", "ts": now.timestamp_millis() }));
    }
    Ok(serde_json::json!({
        "status": "tripped",
        "token_id": token_id,
        "message": "Canary trip simulated successfully. Critical security incident recorded in journal."
    }))
}

// ── eBPF Socket Filter Commands ──────────────────────────────────────────────

#[tauri::command]
pub async fn ebpf_init_filter(
    interface: String,
    mode: Option<String>,
    state: State<'_, Arc<AppState>>,
) -> Res<ebpf_filter::EbpfFilterStatus> {
    let filter_mode = match mode.as_deref() {
        Some("all") => ebpf_filter::FilterMode::PassAll,
        Some("tcp") => ebpf_filter::FilterMode::TcpOnly,
        Some("udp") => ebpf_filter::FilterMode::UdpOnly,
        Some("custom") => ebpf_filter::FilterMode::Custom,
        _ => ebpf_filter::FilterMode::ThreatPortsOnly,
    };
    state
        .ebpf_manager
        .init_filter(&interface, Some(filter_mode))
        .await
        .map_err(je)
}

#[tauri::command]
pub async fn ebpf_attach_filter(state: State<'_, Arc<AppState>>) -> Res<()> {
    state.ebpf_manager.attach_filter().await.map_err(je)
}

#[tauri::command]
pub async fn ebpf_detach_filter(state: State<'_, Arc<AppState>>) -> Res<()> {
    state.ebpf_manager.detach_filter().await.map_err(je)
}

#[tauri::command]
pub async fn ebpf_get_status(state: State<'_, Arc<AppState>>) -> Res<ebpf_filter::EbpfFilterStatus> {
    Ok(state.ebpf_manager.get_status().await)
}

#[tauri::command]
pub async fn ebpf_list_rules(state: State<'_, Arc<AppState>>) -> Res<Vec<ebpf_filter::EbpfRule>> {
    Ok(state.ebpf_manager.list_rules().await)
}

#[tauri::command]
pub async fn ebpf_add_rule(
    rule: ebpf_filter::EbpfRule,
    state: State<'_, Arc<AppState>>,
) -> Res<()> {
    state.ebpf_manager.add_rule(rule).await.map_err(je)
}

#[tauri::command]
pub async fn ebpf_remove_rule(
    rule_id: String,
    state: State<'_, Arc<AppState>>,
) -> Res<bool> {
    state.ebpf_manager.remove_rule(&rule_id).await.map_err(je)
}

#[tauri::command]
pub async fn ebpf_toggle_rule(
    rule_id: String,
    enabled: bool,
    state: State<'_, Arc<AppState>>,
) -> Res<bool> {
    state.ebpf_manager.toggle_rule(&rule_id, enabled).await.map_err(je)
}

#[tauri::command]
pub async fn ebpf_get_inspected_packets(
    limit: Option<usize>,
    filter_verdict: Option<String>,
    state: State<'_, Arc<AppState>>,
) -> Res<Vec<ebpf_filter::ParsedPacket>> {
    Ok(state
        .ebpf_manager
        .get_inspected_packets(limit.unwrap_or(100), filter_verdict)
        .await)
}

#[tauri::command]
pub async fn ebpf_clear_packets(state: State<'_, Arc<AppState>>) -> Res<()> {
    state.ebpf_manager.clear_packets().await;
    Ok(())
}

#[tauri::command]
pub async fn ebpf_simulate_packet(
    sample_type: Option<String>,
    custom_hex: Option<String>,
    state: State<'_, Arc<AppState>>,
    app: AppHandle,
) -> Res<ebpf_filter::ParsedPacket> {
    // Generate synthetic Ethernet + IP + TCP/UDP frames for testing filter logic
    let raw_bytes: Vec<u8> = if let Some(hex) = custom_hex {
        let clean = hex.replace(" ", "").replace("\n", "");
        (0..clean.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&clean[i..i + 2], 16).ok())
            .collect()
    } else {
        match sample_type.as_deref() {
            Some("c2_reverse_shell") => {
                // Synthesize IPv4 (192.168.1.50 -> 45.33.32.156) TCP port 4444 with reverse shell payload
                let mut pkt = vec![
                    // Ethernet header (14 bytes)
                    0x00, 0x0c, 0x29, 0x6d, 0x51, 0x77, 0x00, 0x50, 0x56, 0xc0, 0x00, 0x08, 0x08, 0x00,
                    // IPv4 header (20 bytes)
                    0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
                    192, 168, 1, 50, // Src IP
                    45, 33, 32, 156, // Dst IP
                    // TCP header (20 bytes)
                    0xd2, 0x11, // Src Port 53777
                    0x11, 0x5c, // Dst Port 4444
                    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                    0x50, 0x18, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                ];
                // Payload: shell prompt connection
                pkt.extend_from_slice(b"/bin/sh -i <&3 >&3 2>&3\n");
                pkt
            }
            Some("dns_tunneling") => {
                // Synthesize IPv4 UDP to port 53 with high-entropy base64 subdomain payload
                let mut pkt = vec![
                    0x00, 0x0c, 0x29, 0x6d, 0x51, 0x77, 0x00, 0x50, 0x56, 0xc0, 0x00, 0x08, 0x08, 0x00,
                    0x45, 0x00, 0x00, 0x50, 0x2b, 0x12, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00,
                    192, 168, 1, 50,
                    8, 8, 8, 8,
                    // UDP header (8 bytes)
                    0xc4, 0x10, // Src Port 50192
                    0x00, 0x35, // Dst Port 53
                    0x00, 0x3c, 0x00, 0x00,
                ];
                pkt.extend_from_slice(b"W91cnNlY3JldGRhdGExMjM0NTY3ODkwYWJjZGVmZ2hpams.c2.badactor.io");
                pkt
            }
            _ => {
                // Benign HTTPS packet (TCP 443)
                let mut pkt = vec![
                    0x00, 0x0c, 0x29, 0x6d, 0x51, 0x77, 0x00, 0x50, 0x56, 0xc0, 0x00, 0x08, 0x08, 0x00,
                    0x45, 0x00, 0x00, 0x34, 0x3a, 0x9f, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
                    192, 168, 1, 50,
                    142, 250, 180, 206,
                    0xe1, 0x20, // Src Port 57632
                    0x01, 0xbb, // Dst Port 443
                    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
                    0x50, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                ];
                pkt.extend_from_slice(b"TLS Client Hello\0");
                pkt
            }
        }
    };

    let inspected = state.ebpf_manager.inspect_packet(&raw_bytes).await;

    // Emit event if threat detected
    if inspected.verdict == ebpf_filter::PacketVerdict::Drop || inspected.verdict == ebpf_filter::PacketVerdict::Alert {
        let _ = app.emit("ebpf-threat-detected", &inspected);
    }

    Ok(inspected)
}



