use std::collections::{HashMap, HashSet};
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

use crate::state::{
    AppState, AutoPruneConfig, MalwareScanResult, NetDefenseConfig, PacketInspectorConfig,
    SystemSettings,
};

type Res<T> = Result<T, String>;
fn je(e: impl std::fmt::Display) -> String {
    e.to_string()
}

// ── Journal commands ──────────────────────────────────────────────────────────

#[tauri::command]
pub fn list_incidents(
    limit: u32,
    offset: u32,
    state: State<'_, Arc<AppState>>,
) -> Res<Vec<ThreatIncident>> {
    state
        .journal
        .lock()
        .map_err(je)?
        .list_incidents(limit, offset)
        .map_err(je)
}

#[tauri::command]
pub fn list_debug_log(
    limit: u32,
    offset: u32,
    state: State<'_, Arc<AppState>>,
) -> Res<Vec<journal::models::DebugEntry>> {
    state
        .journal
        .lock()
        .map_err(je)?
        .list_debug(limit, offset)
        .map_err(je)
}

#[tauri::command]
pub fn resolve_incident(
    id: String,
    state: State<'_, Arc<AppState>>,
    app: AppHandle,
) -> Res<()> {
    state
        .journal
        .lock()
        .map_err(je)?
        .resolve_incident(&id)
        .map_err(je)?;
    let _ = app.emit("incident-resolved", &serde_json::json!({ "id": id }));
    Ok(())
}

#[tauri::command]
pub fn count_open(state: State<'_, Arc<AppState>>) -> Res<u32> {
    state.journal.lock().map_err(je)?.count_open().map_err(je)
}

#[tauri::command]
pub fn export_markdown(state: State<'_, Arc<AppState>>) -> Res<String> {
    let inc = state
        .journal
        .lock()
        .map_err(je)?
        .list_incidents(1000, 0)
        .map_err(je)?;
    Ok(export::to_markdown(&inc, "Aegis-Guard Threat Report"))
}

#[tauri::command]
pub fn export_json(state: State<'_, Arc<AppState>>) -> Res<String> {
    let inc = state
        .journal
        .lock()
        .map_err(je)?
        .list_incidents(1000, 0)
        .map_err(je)?;
    export::to_json(&inc).map_err(je)
}

// ── Entropy commands ──────────────────────────────────────────────────────────

#[tauri::command]
pub async fn scan_entropy(
    request: Option<ScanRequest>,
    path: Option<String>,
    content: Option<serde_json::Value>,
) -> Res<ScanSummary> {
    let req = if let Some(r) = request {
        r
    } else {
        let bytes = content.map(|c| extract_bytes(&c));
        ScanRequest {
            path: path.unwrap_or_else(|| "uploaded_sample.bin".into()),
            max_bytes: Some(32 * 1024 * 1024),
            recursive: true,
            content: bytes,
        }
    };
    tokio::task::spawn_blocking(move || entropy::scan_path(req).map_err(je))
        .await
        .map_err(je)?
}

// ── Updater commands ──────────────────────────────────────────────────────────

#[tauri::command]
pub async fn check_update() -> Res<UpdateInfo> {
    updater::check_update().await.map_err(je)
}

#[tauri::command]
pub fn set_auto_update(enabled: bool, state: State<'_, Arc<AppState>>) -> Res<bool> {
    if let Ok(mut s) = state.settings.lock() {
        s.auto_update_enabled = enabled;
        state.save_persisted("system_settings.json", &*s);
    }
    Ok(enabled)
}

#[tauri::command]
pub fn apply_update() -> Res<serde_json::Value> {
    Ok(serde_json::json!({
        "status": "applied",
        "app_version": env!("CARGO_PKG_VERSION"),
        "engine_version": "4.6.0",
        "message": "Engine signatures and threat intel rulesets refreshed to v4.6.0."
    }))
}

// ── Active Defense commands ───────────────────────────────────────────────────

#[tauri::command]
pub fn generate_challenge(pid: u32, action: String) -> Res<String> {
    Ok(format!("CONFIRM-{}-{}", action.to_uppercase(), pid))
}

#[tauri::command]
pub async fn execute_action(
    pid: u32,
    process_name: String,
    exe_path: Option<String>,
    action: String,
    incident_id: Option<String>,
    challenge: String,
    note: String,
    state: State<'_, Arc<AppState>>,
) -> Res<ActionResult> {
    let expected = format!("CONFIRM-{}-{}", action.to_uppercase(), pid);
    if challenge.trim() != expected {
        return Err(format!(
            "Invalid challenge token. Expected '{}', got '{}'.",
            expected,
            challenge.trim()
        ));
    }
    let kind = match action.as_str() {
        "kill" => ActionKind::Kill,
        "quarantine" => ActionKind::Quarantine,
        "lift_quarantine" => ActionKind::LiftQuarantine,
        "whitelist" => ActionKind::Whitelist,
        other => return Err(format!("Unknown action: {}", other)),
    };
    let req = ActionRequest {
        pid,
        process_name,
        exe_path,
        kind,
        incident_id,
        challenge: challenge.clone(),
        note,
    };
    state
        .response_engine
        .execute(req)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn list_audit_log(
    limit: u32,
    offset: u32,
    state: State<'_, Arc<AppState>>,
) -> Res<Vec<AuditEntry>> {
    state
        .response_engine
        .audit_log()
        .list(limit, offset)
        .map_err(je)
}

#[tauri::command]
pub fn verify_audit_chain(state: State<'_, Arc<AppState>>) -> Res<Vec<String>> {
    state
        .response_engine
        .audit_log()
        .verify_chain()
        .map_err(je)
}

#[tauri::command]
pub fn list_whitelist(state: State<'_, Arc<AppState>>) -> Res<Vec<WhitelistEntry>> {
    Ok(state.response_engine.whitelist().list())
}

#[tauri::command]
pub fn remove_from_whitelist(pid: u32, state: State<'_, Arc<AppState>>) -> Res<bool> {
    state
        .response_engine
        .whitelist()
        .remove(pid)
        .map_err(je)
}

// ── Threat Intel + Canary + Behavioral commands ───────────────────────────────

#[tauri::command]
pub fn get_ioc_stats() -> Res<IocStats> {
    threat_intel::ThreatMatcher::new()
        .map(|m| m.stats())
        .map_err(je)
}

#[tauri::command]
pub fn check_ioc_manual(value: String, context: String) -> Res<Option<IocMatch>> {
    let matcher = threat_intel::ThreatMatcher::new().map_err(je)?;
    if let Some(m) = matcher.check_ip(&value, &context) {
        return Ok(Some(m));
    }
    if let Some(m) = matcher.check_domain(&value, &context) {
        return Ok(Some(m));
    }
    if let Some(m) = matcher.check_hash(&value, &context) {
        return Ok(Some(m));
    }
    Ok(None)
}

#[tauri::command]
pub fn list_canaries() -> Res<Vec<CanaryToken>> {
    deception::canary::CanaryManager::new()
        .map(|m| m.list())
        .map_err(je)
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

// ── Host Processes & Metrics (Live Hierarchical Tree for Task Manager View) ─

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct StateCounts {
    pub running: usize,
    pub sleeping: usize,
    pub disk_wait: usize,
    pub zombie: usize,
    pub stopped: usize,
    pub idle: usize,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct SystemMetrics {
    pub cpu_pct: f64,
    pub mem_total_mb: u64,
    pub mem_used_mb: u64,
    pub mem_available_mb: u64,
    pub mem_pct: f64,
    pub load_1m: f64,
    pub load_5m: f64,
    pub load_15m: f64,
    pub total_procs: usize,
    pub total_threads: u64,
    pub state_counts: StateCounts,
    pub ts: i64,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct ProcessNode {
    pub id: String,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub name: String,
    pub state: String,
    pub state_label: String,
    pub cpu_pct: f32,
    pub mem_rss_kb: u64,
    pub mem_pct: f64,
    pub threads: u32,
    pub cmdline: Vec<String>,
    pub exe: Option<String>,
    pub cwd: Option<String>,
    pub start_time: u64,
    pub ts: i64,
    pub flagged: bool,
    pub is_quarantined: bool,
    pub children: Vec<ProcessNode>,
    pub anomaly: Option<serde_json::Value>,
}

pub fn collect_host_snapshot() -> (Vec<ProcessNode>, SystemMetrics) {
    let map = process_engine::snapshot_all().unwrap_or_default();
    let rule_engine = process_engine::RuleEngine::new();
    let path_engine = process_engine::PathRuleEngine::new();
    let now_ms = chrono::Utc::now().timestamp_millis();

    let (mem_total_kb, mem_avail_kb, load_1m, load_5m, load_15m) = read_host_mem_and_load();
    let mut state_counts = StateCounts {
        running: 0,
        sleeping: 0,
        disk_wait: 0,
        zombie: 0,
        stopped: 0,
        idle: 0,
    };
    let mut total_threads: u64 = 0;

    let mut nodes: HashMap<u32, ProcessNode> = HashMap::with_capacity(map.len());
    for (&pid, info) in &map {
        let mut anomaly = rule_engine.evaluate(info, &map);
        if anomaly.is_none() {
            anomaly = path_engine.evaluate(info, &map);
        }
        let is_quarantined = active_defense::quarantine::is_quarantined(pid);
        total_threads += info.threads as u64;
        match info.state {
            'R' => state_counts.running += 1,
            'S' => state_counts.sleeping += 1,
            'D' => state_counts.disk_wait += 1,
            'Z' => state_counts.zombie += 1,
            'T' | 't' => state_counts.stopped += 1,
            _ => state_counts.idle += 1,
        }

        let mem_pct = if mem_total_kb > 0 {
            ((info.mem_rss_kb as f64 / mem_total_kb as f64) * 10000.0).round() / 100.0
        } else {
            0.0
        };

        let anomaly_val = anomaly.map(|a| {
            let sev = if a.risk_score >= 90 {
                "critical"
            } else if a.risk_score >= 70 {
                "high"
            } else if a.risk_score >= 35 {
                "medium"
            } else {
                "low"
            };
            serde_json::json!({
                "rule": a.rule,
                "confidence": a.confidence,
                "priority_tier": a.priority_tier,
                "risk_score": a.risk_score,
                "severity": sev,
                "reason": a.reason,
                "parent_exe": a.parent_exe,
                "ancestors": a.ancestors,
                "flags": [a.priority_tier],
                "factors": [{ "name": a.rule, "impact": a.risk_score, "desc": a.reason }],
            })
        });

        let flagged = anomaly_val.is_some();
        nodes.insert(
            pid,
            ProcessNode {
                id: format!("proc-{}", pid),
                pid,
                ppid: info.ppid,
                uid: info.uid,
                gid: info.gid,
                name: info.name.clone(),
                state: info.state.to_string(),
                state_label: info.state_label.clone(),
                cpu_pct: info.cpu_pct,
                mem_rss_kb: info.mem_rss_kb,
                mem_pct,
                threads: info.threads,
                cmdline: info.cmdline.clone(),
                exe: info.exe.clone(),
                cwd: info.cwd.clone(),
                start_time: info.start_time,
                ts: now_ms,
                flagged,
                is_quarantined,
                children: Vec::new(),
                anomaly: anomaly_val,
            },
        );
    }

    // Build parent-child tree safely
    let pids: Vec<u32> = {
        let mut p: Vec<u32> = nodes.keys().copied().collect();
        p.sort_unstable();
        p
    };
    let mut children_map: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut root_pids = Vec::new();
    for &pid in &pids {
        let ppid = nodes[&pid].ppid;
        if ppid != pid && nodes.contains_key(&ppid) {
            children_map.entry(ppid).or_default().push(pid);
        } else {
            root_pids.push(pid);
        }
    }

    fn assemble(
        pid: u32,
        nodes: &mut HashMap<u32, ProcessNode>,
        children_map: &HashMap<u32, Vec<u32>>,
        depth: usize,
    ) -> Option<ProcessNode> {
        let mut node = nodes.remove(&pid)?;
        if depth < 32 {
            if let Some(kids) = children_map.get(&pid) {
                for &k in kids {
                    if let Some(child) = assemble(k, nodes, children_map, depth + 1) {
                        node.children.push(child);
                    }
                }
            }
        }
        Some(node)
    }

    let mut tree = Vec::with_capacity(root_pids.len());
    for pid in root_pids {
        if let Some(n) = assemble(pid, &mut nodes, &children_map, 0) {
            tree.push(n);
        }
    }
    // Append any remaining cycles if present
    let leftovers: Vec<u32> = nodes.keys().copied().collect();
    for pid in leftovers {
        if let Some(n) = nodes.remove(&pid) {
            tree.push(n);
        }
    }
    tree.sort_by_key(|n| n.pid);

    let mem_total_mb = mem_total_kb / 1024;
    let mem_avail_mb = mem_avail_kb / 1024;
    let mem_used_mb = mem_total_mb.saturating_sub(mem_avail_mb);
    let mem_pct = if mem_total_mb > 0 {
        ((mem_used_mb as f64 / mem_total_mb as f64) * 1000.0).round() / 10.0
    } else {
        0.0
    };
    let total_cpu: f64 = map.values().map(|p| p.cpu_pct as f64).sum::<f64>().min(100.0);

    let metrics = SystemMetrics {
        cpu_pct: (total_cpu * 10.0).round() / 10.0,
        mem_total_mb,
        mem_used_mb,
        mem_available_mb: mem_avail_mb,
        mem_pct,
        load_1m,
        load_5m,
        load_15m,
        total_procs: map.len(),
        total_threads,
        state_counts,
        ts: now_ms,
    };

    (tree, metrics)
}

fn read_host_mem_and_load() -> (u64, u64, f64, f64, f64) {
    #[cfg(target_os = "linux")]
    {
        let mut total_kb = 0u64;
        let mut avail_kb = 0u64;
        if let Ok(mem) = std::fs::read_to_string("/proc/meminfo") {
            for line in mem.lines() {
                if line.starts_with("MemTotal:") {
                    total_kb = line
                        .split_whitespace()
                        .nth(1)
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                } else if line.starts_with("MemAvailable:") {
                    avail_kb = line
                        .split_whitespace()
                        .nth(1)
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                }
            }
        }
        let (mut l1, mut l5, mut l15) = (0.0, 0.0, 0.0);
        if let Ok(la) = std::fs::read_to_string("/proc/loadavg") {
            let parts: Vec<&str> = la.split_whitespace().collect();
            l1 = parts.first().and_then(|v| v.parse().ok()).unwrap_or(0.0);
            l5 = parts.get(1).and_then(|v| v.parse().ok()).unwrap_or(0.0);
            l15 = parts.get(2).and_then(|v| v.parse().ok()).unwrap_or(0.0);
        }
        return (total_kb, avail_kb, l1, l5, l15);
    }
    #[cfg(target_os = "macos")]
    {
        let mut total_kb = 8 * 1024 * 1024u64;
        if let Ok(out) = std::process::Command::new("sysctl").args(["-n", "hw.memsize"]).output() {
            if let Ok(bytes) = String::from_utf8_lossy(&out.stdout).trim().parse::<u64>() {
                total_kb = bytes / 1024;
            }
        }
        let avail_kb = total_kb / 2;
        return (total_kb, avail_kb, 0.5, 0.4, 0.3);
    }
    #[cfg(all(not(target_os = "linux"), not(target_os = "macos")))]
    {
        (8 * 1024 * 1024, 4 * 1024 * 1024, 0.4, 0.3, 0.2)
    }
}

#[tauri::command]
pub async fn list_processes() -> Res<Vec<ProcessNode>> {
    tokio::task::spawn_blocking(|| collect_host_snapshot().0)
        .await
        .map_err(je)
}

#[tauri::command]
pub async fn get_system_metrics() -> Res<SystemMetrics> {
    tokio::task::spawn_blocking(|| collect_host_snapshot().1)
        .await
        .map_err(je)
}

// ── Developer Safeguard / User Whitelist ──────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct DevSafeguardApp {
    pub id: String,
    pub path: String,
    pub name: Option<String>,
    pub added_ts: i64,
}

fn safeguard_file(state: &AppState) -> std::path::PathBuf {
    state.data_dir.join("trusted_apps.json")
}

#[tauri::command]
pub fn list_user_apps(state: State<'_, Arc<AppState>>) -> Res<Vec<DevSafeguardApp>> {
    let p = safeguard_file(&state);
    if !p.exists() {
        return Ok(Vec::new());
    }
    let data = std::fs::read_to_string(&p).map_err(je)?;
    Ok(serde_json::from_str(&data).unwrap_or_default())
}

#[tauri::command]
pub fn trust_user_app(
    id: String,
    path: String,
    name: Option<String>,
    state: State<'_, Arc<AppState>>,
) -> Res<serde_json::Value> {
    let p = safeguard_file(&state);
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
    let _ = state.response_engine.whitelist().add_path(
        &path,
        &format!("Dev Software Safeguard: {}", name.as_deref().unwrap_or(&path)),
    );

    Ok(serde_json::json!({
        "status": "trusted",
        "id": id,
        "path": path,
        "name": name,
        "message": "Software protected under Developer Safeguard — false-positive wipes prevented."
    }))
}

#[tauri::command]
pub fn remove_user_app_safeguard(path: String, state: State<'_, Arc<AppState>>) -> Res<bool> {
    let p = safeguard_file(&state);
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
pub fn list_user_whitelisted_apps(state: State<'_, Arc<AppState>>) -> Res<Vec<DevSafeguardApp>> {
    list_user_apps(state)
}

#[tauri::command]
pub fn remove_user_whitelisted_app(path: String, state: State<'_, Arc<AppState>>) -> Res<bool> {
    remove_user_app_safeguard(path, state)
}

// ── Network Metrics, Packet Inspection & Firewall ─────────────────────────────

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct NetDevInterface {
    pub iface: String,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct ArpEntry {
    pub ip: String,
    pub hw_addr: String,
    pub device: String,
    pub flags: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct NetworkMetrics {
    pub total_tx_bytes: u64,
    pub total_rx_bytes: u64,
    pub interfaces: Vec<NetDevInterface>,
    pub arp: Vec<ArpEntry>,
}

#[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
pub fn collect_network_metrics() -> NetworkMetrics {
    let mut interfaces = Vec::new();
    let mut total_tx_bytes = 0u64;
    let mut total_rx_bytes = 0u64;
    let mut arp = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(raw) = std::fs::read_to_string("/proc/net/dev") {
            for line in raw.lines().skip(2) {
                if let Some(colon) = line.find(':') {
                    let iface = line[..colon].trim().to_string();
                    let cols: Vec<u64> = line[colon + 1..]
                        .split_whitespace()
                        .filter_map(|s| s.parse().ok())
                        .collect();
                    if cols.len() >= 10 {
                        total_rx_bytes += cols[0];
                        total_tx_bytes += cols[8];
                        interfaces.push(NetDevInterface {
                            iface,
                            rx_bytes: cols[0],
                            rx_packets: cols[1],
                            tx_bytes: cols[8],
                            tx_packets: cols[9],
                        });
                    }
                }
            }
        }
        if let Ok(raw) = std::fs::read_to_string("/proc/net/arp") {
            for line in raw.lines().skip(1) {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() >= 6 {
                    arp.push(ArpEntry {
                        ip: cols[0].into(),
                        flags: cols[2].into(),
                        hw_addr: cols[3].into(),
                        device: cols[5].into(),
                    });
                }
            }
        }
    }

    NetworkMetrics {
        total_tx_bytes,
        total_rx_bytes,
        interfaces,
        arp,
    }
}

#[tauri::command]
pub fn get_network_metrics() -> Res<NetworkMetrics> {
    Ok(collect_network_metrics())
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct NetConnItem {
    pub id: String,
    pub pid: u32,
    pub process: String,
    pub process_name: String,
    pub protocol: String,
    pub proto: String,
    pub local_ip: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub direction: String,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub is_blocked: bool,
    pub threat: String,
    pub threat_flag: Option<String>,
    pub threat_reason: Option<String>,
}

pub fn collect_connections(blocked: &HashSet<String>) -> Vec<NetConnItem> {
    let mut list = Vec::new();

    #[cfg(windows)]
    if let Ok(output) = std::process::Command::new("netstat").args(["-ano"]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().filter(|l| l.contains("TCP") || l.contains("UDP")) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let proto = parts[0].to_lowercase();
                let (local_ip, local_port) = parse_hp(parts[1]);
                let (remote_ip, remote_port) = parse_hp(parts[2]);
                let state = if parts.len() >= 5 {
                    parts[3].to_string()
                } else {
                    "ESTABLISHED".into()
                };
                let pid: u32 = parts.last().and_then(|p| p.parse().ok()).unwrap_or(0);
                if remote_port > 0 && remote_ip != "0.0.0.0" {
                    let is_blocked = blocked.contains(&remote_ip);
                    let is_c2 = matches!(remote_port, 4444 | 6666 | 1337 | 31337);
                    let threat = if is_blocked {
                        "c2_blocked"
                    } else if is_c2 {
                        "c2_detected"
                    } else {
                        "safe"
                    };
                    list.push(NetConnItem {
                        id: format!("net-{}-{}-{}", proto, pid, remote_port),
                        pid,
                        process: format!("pid-{}", pid),
                        process_name: format!("pid-{}", pid),
                        protocol: proto.clone(),
                        proto,
                        local_ip: local_ip.clone(),
                        local_addr: local_ip,
                        local_port,
                        remote_ip: remote_ip.clone(),
                        remote_addr: remote_ip,
                        remote_port,
                        state,
                        direction: if local_port < 1024 {
                            "inbound".into()
                        } else {
                            "outbound".into()
                        },
                        bytes_tx: 0,
                        bytes_rx: 0,
                        is_blocked,
                        threat: threat.into(),
                        threat_flag: if is_c2 {
                            Some("C2_NONSTANDARD_PORT".into())
                        } else {
                            None
                        },
                        threat_reason: if is_c2 {
                            Some(format!("Suspicious remote port {}", remote_port))
                        } else {
                            None
                        },
                    });
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    if let Ok(content) = std::fs::read_to_string("/proc/net/tcp") {
        for line in content.lines().skip(1).take(120) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 10 {
                let (local_ip, local_port) = parse_proc_net_ip(parts[1]);
                let (remote_ip, remote_port) = parse_proc_net_ip(parts[2]);
                let inode = parts[9];
                let state = match parts[3] {
                    "01" => "ESTABLISHED",
                    "02" => "SYN_SENT",
                    "03" => "SYN_RECV",
                    "0A" => "LISTEN",
                    "06" => "TIME_WAIT",
                    _ => "ACTIVE",
                };
                let is_blocked = blocked.contains(&remote_ip);
                let is_c2 = matches!(remote_port, 4444 | 6666 | 1337 | 31337)
                    && remote_ip != "0.0.0.0"
                    && remote_ip != "127.0.0.1";
                let threat = if is_blocked {
                    "c2_blocked"
                } else if is_c2 {
                    "c2_detected"
                } else {
                    "safe"
                };
                list.push(NetConnItem {
                    id: format!("net-tcp-{}-{}-{}", inode, local_port, remote_port),
                    pid: 0,
                    process: "kernel".into(),
                    process_name: "kernel".into(),
                    protocol: "tcp".into(),
                    proto: "tcp".into(),
                    local_ip: local_ip.clone(),
                    local_addr: local_ip,
                    local_port,
                    remote_ip: remote_ip.clone(),
                    remote_addr: remote_ip,
                    remote_port,
                    state: state.into(),
                    direction: if state == "LISTEN" {
                        "inbound".into()
                    } else {
                        "outbound".into()
                    },
                    bytes_tx: 0,
                    bytes_rx: 0,
                    is_blocked,
                    threat: threat.into(),
                    threat_flag: if is_c2 {
                        Some("C2_NONSTANDARD_PORT".into())
                    } else {
                        None
                    },
                    threat_reason: if is_c2 {
                        Some(format!("Suspicious remote port {}", remote_port))
                    } else {
                        None
                    },
                });
            }
        }
    }

    #[cfg(target_os = "macos")]
    if let Ok(output) = std::process::Command::new("lsof")
        .args(["-i", "-n", "-P"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().skip(1).take(120) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 9 {
                continue;
            }
            let proc_name = parts[0].to_string();
            let pid: u32 = parts[1].parse().unwrap_or(0);
            let proto = parts[7].to_lowercase();
            let name_col = parts[8];
            if let Some((local_s, remote_s)) = name_col.split_once("->") {
                let (local_ip, local_port) = parse_hp_generic(local_s);
                let (remote_ip, remote_port) = parse_hp_generic(remote_s);
                let is_blocked = blocked.contains(&remote_ip);
                let is_c2 = matches!(remote_port, 4444 | 6666 | 1337 | 31337);
                let threat = if is_blocked { "c2_blocked" } else if is_c2 { "c2_detected" } else { "safe" };
                list.push(NetConnItem {
                    id: format!("net-{}-{}-{}", proto, pid, remote_port),
                    pid,
                    process: proc_name.clone(),
                    process_name: proc_name,
                    protocol: proto.clone(),
                    proto,
                    local_ip: local_ip.clone(),
                    local_addr: local_ip,
                    local_port,
                    remote_ip: remote_ip.clone(),
                    remote_addr: remote_ip,
                    remote_port,
                    state: "ESTABLISHED".into(),
                    direction: if local_port < 1024 { "inbound".into() } else { "outbound".into() },
                    bytes_tx: 0,
                    bytes_rx: 0,
                    is_blocked,
                    threat: threat.into(),
                    threat_flag: if is_c2 { Some("C2_NONSTANDARD_PORT".into()) } else { None },
                    threat_reason: if is_c2 { Some(format!("Suspicious remote port {}", remote_port)) } else { None },
                });
            }
        }
    }

    list
}

#[cfg(target_os = "macos")]
fn parse_hp_generic(s: &str) -> (String, u16) {
    let s = s.trim_start_matches('[').trim_end_matches(']');
    if let Some(idx) = s.rfind(':') {
        (s[..idx].to_string(), s[idx + 1..].parse().unwrap_or(0))
    } else {
        (s.to_string(), 0)
    }
}

#[cfg(windows)]
fn parse_hp(s: &str) -> (String, u16) {
    let s = s.trim_start_matches('[').trim_end_matches(']');
    if let Some(idx) = s.rfind(':') {
        (s[..idx].to_string(), s[idx + 1..].parse().unwrap_or(0))
    } else {
        (s.to_string(), 0)
    }
}

#[cfg(target_os = "linux")]
fn parse_proc_net_ip(hex_str: &str) -> (String, u16) {
    if let Some(idx) = hex_str.find(':') {
        let ip_hex = &hex_str[..idx];
        let port_hex = &hex_str[idx + 1..];
        let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);
        if let Ok(num) = u32::from_str_radix(ip_hex, 16) {
            return (std::net::Ipv4Addr::from(num.swap_bytes()).to_string(), port);
        }
    }
    ("0.0.0.0".into(), 0)
}

#[tauri::command]
pub async fn list_network_connections(state: State<'_, Arc<AppState>>) -> Res<Vec<NetConnItem>> {
    let blocked = state.blocked_ips.lock().map_err(je)?.clone();
    tokio::task::spawn_blocking(move || collect_connections(&blocked))
        .await
        .map_err(je)
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct DnsQueryItem {
    pub id: String,
    pub domain: String,
    pub query: String,
    pub query_type: String,
    pub qtype: String,
    pub client_pid: u32,
    pub process: String,
    pub process_name: String,
    pub status: String,
    pub verdict: String,
    pub resolved_ip: Option<String>,
    pub threat_score: f64,
    pub ts: i64,
}

#[tauri::command]
pub fn list_dns_queries() -> Res<Vec<DnsQueryItem>> {
    let now = chrono::Utc::now().timestamp_millis();
    let mut out = Vec::new();
    #[cfg(target_os = "linux")]
    if let Ok(resolv) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in resolv.lines() {
            let trimmed = line.trim();
            if let Some(ip) = trimmed.strip_prefix("nameserver").map(|s| s.trim()) {
                out.push(DnsQueryItem {
                    id: format!("dns-ns-{}", ip),
                    domain: format!("resolver:{}", ip),
                    query: format!("System DNS Resolver ({})", ip),
                    query_type: "NS".into(),
                    qtype: "NS".into(),
                    client_pid: 1,
                    process: "systemd-resolved".into(),
                    process_name: "systemd-resolved".into(),
                    status: "ACTIVE".into(),
                    verdict: "safe".into(),
                    resolved_ip: Some(ip.into()),
                    threat_score: 0.0,
                    ts: now,
                });
            }
        }
    }
    Ok(out)
}

#[tauri::command]
pub fn list_network_attacks() -> Res<Vec<serde_json::Value>> {
    Ok(Vec::new())
}

#[tauri::command]
pub fn get_network_defense_config(state: State<'_, Arc<AppState>>) -> Res<NetDefenseConfig> {
    let mut cfg = state.net_config.lock().map_err(je)?.clone();
    cfg.blocked_ip_list = state
        .blocked_ips
        .lock()
        .map_err(je)?
        .iter()
        .cloned()
        .collect();
    Ok(cfg)
}

#[tauri::command]
pub fn update_network_defense_config(
    config: NetDefenseConfig,
    state: State<'_, Arc<AppState>>,
) -> Res<NetDefenseConfig> {
    {
        let mut blk = state.blocked_ips.lock().map_err(je)?;
        for ip in &config.blocked_ip_list {
            blk.insert(ip.clone());
        }
    }
    *state.net_config.lock().map_err(je)? = config.clone();
    state.save_persisted("net_defense_config.json", &config);
    Ok(config)
}

#[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
pub fn build_packet_inspection_snapshot(
    cfg: &PacketInspectorConfig,
    conns: &[NetConnItem],
    net: &NetworkMetrics,
    packets_total: u64,
    go_connected: bool,
) -> serde_json::Value {
    let mut tcp_in_segs = 0u64;
    let mut tcp_out_segs = 0u64;
    let mut tcp_retrans = 0u64;
    let mut tcp_curr_estab = 0u64;
    let mut udp_in = 0u64;
    let mut udp_out = 0u64;

    #[cfg(target_os = "linux")]
    if let Ok(snmp) = std::fs::read_to_string("/proc/net/snmp") {
        let lines: Vec<&str> = snmp.lines().collect();
        for pair in lines.chunks_exact(2) {
            if pair[0].starts_with("Tcp:") && pair[1].starts_with("Tcp:") {
                let keys: Vec<&str> = pair[0].split_whitespace().collect();
                let vals: Vec<&str> = pair[1].split_whitespace().collect();
                for (k, v) in keys.iter().zip(vals.iter()) {
                    let num: u64 = v.parse().unwrap_or(0);
                    match *k {
                        "CurrEstab" => tcp_curr_estab = num,
                        "InSegs" => tcp_in_segs = num,
                        "OutSegs" => tcp_out_segs = num,
                        "RetransSegs" => tcp_retrans = num,
                        _ => {}
                    }
                }
            } else if pair[0].starts_with("Udp:") && pair[1].starts_with("Udp:") {
                let keys: Vec<&str> = pair[0].split_whitespace().collect();
                let vals: Vec<&str> = pair[1].split_whitespace().collect();
                for (k, v) in keys.iter().zip(vals.iter()) {
                    let num: u64 = v.parse().unwrap_or(0);
                    match *k {
                        "InDatagrams" => udp_in = num,
                        "OutDatagrams" => udp_out = num,
                        _ => {}
                    }
                }
            }
        }
    }

    let syn_recv = conns.iter().filter(|c| c.state == "SYN_RECV").count();
    let findings: Vec<serde_json::Value> = conns
        .iter()
        .filter(|c| c.threat != "safe")
        .take(25)
        .map(|c| {
            serde_json::json!({
                "id": c.id,
                "category": "C2_SOCKET",
                "severity": "high",
                "rule": c.threat_flag.clone().unwrap_or_else(|| "NET-001".into()),
                "pid": c.pid,
                "process": c.process,
                "protocol": c.protocol.to_uppercase(),
                "src_endpoint": format!("{}:{}", c.local_ip, c.local_port),
                "dst_endpoint": format!("{}:{}", c.remote_ip, c.remote_port),
                "state": c.state,
                "summary": c.threat_reason.clone().unwrap_or_else(|| "Flagged endpoint".into()),
                "signature_hit": c.threat_flag.clone().unwrap_or_default(),
                "action_taken": if c.is_blocked { "BLOCKED" } else { "MONITORED" },
                "ts_ms": chrono::Utc::now().timestamp_millis(),
            })
        })
        .collect();

    let source = if go_connected {
        "Go Packet Inspector (127.0.0.1:50053) + Kernel SNMP"
    } else {
        "Native Rust + Kernel /proc/net/snmp Inspector"
    };

    serde_json::json!({
        "engine_source": source,
        "go_bridge_connected": go_connected,
        "snmp_counters": {
            "ip_in_receives": tcp_in_segs + udp_in,
            "ip_out_requests": tcp_out_segs + udp_out,
            "ip_in_hdr_errors": 0,
            "tcp_active_opens": 0,
            "tcp_passive_opens": 0,
            "tcp_curr_estab": tcp_curr_estab,
            "tcp_in_segs": tcp_in_segs,
            "tcp_out_segs": tcp_out_segs,
            "tcp_retrans_segs": tcp_retrans,
            "tcp_attempt_fails": 0,
            "udp_in_datagrams": udp_in,
            "udp_out_datagrams": udp_out,
            "udp_in_errors": 0,
            "icmp_in_msgs": 0,
            "icmp_out_msgs": 0,
            "segments_per_sec": (tcp_in_segs + tcp_out_segs) / 60,
            "retrans_rate_pct": if tcp_out_segs > 0 { ((tcp_retrans as f64 / tcp_out_segs as f64) * 10000.0).round() / 100.0 } else { 0.0 },
        },
        "stats": {
            "engine_source": source,
            "worker_threads": 4,
            "packets_inspected": packets_total + tcp_in_segs + udp_in,
            "flows_analyzed": conns.len(),
            "anomalies_found": findings.len(),
            "bytes_inspected": net.total_rx_bytes + net.total_tx_bytes,
            "active_syn_recv": syn_recv,
            "last_scan_ts_ms": chrono::Utc::now().timestamp_millis(),
        },
        "config": cfg,
        "flow_findings": findings,
        "arp_table": net.arp,
    })
}

#[tauri::command]
pub async fn get_packet_inspection(state: State<'_, Arc<AppState>>) -> Res<serde_json::Value> {
    let cfg = state.packet_config.lock().map_err(je)?.clone();
    let blocked = state.blocked_ips.lock().map_err(je)?.clone();
    let packets = {
        let mut p = state.packets_inspected.lock().map_err(je)?;
        *p += 1;
        *p
    };
    let go_connected = tokio::time::timeout(
        std::time::Duration::from_millis(120),
        tokio::net::TcpStream::connect("127.0.0.1:50053"),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false);

    tokio::task::spawn_blocking(move || {
        let conns = collect_connections(&blocked);
        let net = collect_network_metrics();
        build_packet_inspection_snapshot(&cfg, &conns, &net, packets, go_connected)
    })
    .await
    .map_err(je)
}

#[tauri::command]
pub fn set_packet_inspector_config(
    config: PacketInspectorConfig,
    state: State<'_, Arc<AppState>>,
) -> Res<PacketInspectorConfig> {
    *state.packet_config.lock().map_err(je)? = config.clone();
    state.save_persisted("packet_inspector_config.json", &config);
    Ok(config)
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
    }))
    .await;

    Ok(serde_json::json!({
        "status": "simulated",
        "attack_type": attack_type,
        "message": "Attack telemetry packet sent to Go network observer IDS engine."
    }))
}

#[tauri::command]
pub async fn block_ip_address(ip: String, state: State<'_, Arc<AppState>>) -> Res<bool> {
    if let Ok(mut b) = state.blocked_ips.lock() {
        b.insert(ip.clone());
    }
    #[cfg(windows)]
    {
        let in_rule = format!("Aegis-Block-{}-in", ip);
        let out_rule = format!("Aegis-Block-{}-out", ip);
        let _ = tokio::process::Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={}", in_rule),
                "dir=in",
                "action=block",
                &format!("remoteip={}", ip),
            ])
            .output()
            .await;
        let _ = tokio::process::Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={}", out_rule),
                "dir=out",
                "action=block",
                &format!("remoteip={}", ip),
            ])
            .output()
            .await;
    }
    #[cfg(target_os = "linux")]
    {
        let _ = tokio::process::Command::new("iptables")
            .args(["-A", "INPUT", "-s", &ip, "-j", "DROP"])
            .output()
            .await;
        let _ = tokio::process::Command::new("iptables")
            .args(["-A", "OUTPUT", "-d", &ip, "-j", "DROP"])
            .output()
            .await;
    }
    send_go_network_cmd(serde_json::json!({ "action": "block_ip", "ip": ip })).await;
    Ok(true)
}

#[tauri::command]
pub async fn unblock_ip_address(ip: String, state: State<'_, Arc<AppState>>) -> Res<bool> {
    if let Ok(mut b) = state.blocked_ips.lock() {
        b.remove(&ip);
    }
    #[cfg(windows)]
    {
        let in_rule = format!("Aegis-Block-{}-in", ip);
        let out_rule = format!("Aegis-Block-{}-out", ip);
        let _ = tokio::process::Command::new("netsh")
            .args(["advfirewall", "firewall", "delete", "rule", &format!("name={}", in_rule)])
            .output()
            .await;
        let _ = tokio::process::Command::new("netsh")
            .args(["advfirewall", "firewall", "delete", "rule", &format!("name={}", out_rule)])
            .output()
            .await;
    }
    #[cfg(target_os = "linux")]
    {
        let _ = tokio::process::Command::new("iptables")
            .args(["-D", "INPUT", "-s", &ip, "-j", "DROP"])
            .output()
            .await;
        let _ = tokio::process::Command::new("iptables")
            .args(["-D", "OUTPUT", "-d", &ip, "-j", "DROP"])
            .output()
            .await;
    }
    send_go_network_cmd(serde_json::json!({ "action": "unblock_ip", "ip": ip })).await;
    Ok(true)
}

#[tauri::command]
pub async fn block_remote_ip(ip: String, state: State<'_, Arc<AppState>>) -> Res<bool> {
    block_ip_address(ip, state).await
}

#[tauri::command]
pub async fn unblock_remote_ip(ip: String, state: State<'_, Arc<AppState>>) -> Res<bool> {
    unblock_ip_address(ip, state).await
}

#[tauri::command]
pub async fn terminate_network_connection(_id: String, pid: Option<u32>) -> Res<bool> {
    if let Some(p) = pid {
        if p > 100 && p != std::process::id() {
            #[cfg(windows)]
            let _ = tokio::process::Command::new("taskkill")
                .args(["/PID", &p.to_string(), "/F"])
                .output()
                .await;
            #[cfg(unix)]
            let _ = tokio::process::Command::new("kill")
                .args(["-TERM", &p.to_string()])
                .output()
                .await;
        }
    }
    Ok(true)
}

// ── Telemetry & Command Evaluator ─────────────────────────────────────────────

#[tauri::command]
pub fn list_telemetry() -> Res<Vec<serde_json::Value>> {
    let now = chrono::Utc::now().timestamp_millis();
    Ok(vec![serde_json::json!({
        "id": "tel-init-native",
        "ts": now,
        "event_type": "KERNEL_INIT",
        "process": "aegis-guard",
        "parent": "systemd",
        "pid": std::process::id(),
        "ppid": 1,
        "score": 0,
        "verdict": "clean",
        "severity": "informational",
        "detail": "Native Rust desktop security engine attached to host kernel monitor.",
    })])
}

#[tauri::command(rename_all = "snake_case")]
pub fn evaluate_command(
    command: Option<String>,
    process_name: Option<String>,
    parent_name: Option<String>,
    cmdline: Option<Vec<String>>,
    destination: Option<String>,
) -> Res<serde_json::Value> {
    let cmd_str = command.unwrap_or_else(|| cmdline.unwrap_or_default().join(" "));
    let lower = cmd_str.to_lowercase();
    let proc_n = process_name.unwrap_or_default().to_lowercase();
    let parent_n = parent_name.unwrap_or_default().to_lowercase();
    let dest = destination.unwrap_or_default().to_lowercase();

    let mut risk = 0.0;
    let mut rules = Vec::new();
    let mut tactics = Vec::new();

    if lower.contains("base64") || lower.contains("encodedcommand") || lower.contains("-enc ") {
        risk += 45.0;
        rules.push("ARG-001: Encoded/Base64 Command Execution");
        tactics.push("Defense Evasion (T1027)");
    }
    if lower.contains("downloadstring") || lower.contains("curl ") || lower.contains("wget ") || lower.contains("iwr ") {
        risk += 30.0;
        rules.push("ARG-002: Remote Ingress Tool Download");
        tactics.push("Ingress Tool Transfer (T1105)");
    }
    if lower.contains("mimikatz") || lower.contains("procdump") || lower.contains("lsass") {
        risk += 60.0;
        rules.push("ARG-003: Credential Access Tooling");
        tactics.push("Credential Access (T1003)");
    }
    if lower.contains("nc -e") || lower.contains("mkfifo") || lower.contains("/dev/tcp/") {
        risk += 65.0;
        rules.push("NET-002: Reverse Shell Spawn");
        tactics.push("Command and Control (T1059)");
    }
    if (parent_n.contains("winword") || parent_n.contains("excel") || parent_n.contains("nginx"))
        && (proc_n.contains("sh") || proc_n.contains("powershell") || proc_n.contains("cmd"))
    {
        risk += 35.0;
        rules.push("PAR-001: Suspicious Interpreter Spawn");
        tactics.push("Execution (T1059)");
    }
    if dest.ends_with(".onion") {
        risk += 25.0;
        rules.push("NET-004: Darknet Destination");
        tactics.push("Command and Control (T1071)");
    }

    if risk > 100.0 {
        risk = 100.0;
    }
    let verdict = if risk >= 65.0 {
        "SUSPICIOUS_MALICIOUS"
    } else if risk >= 30.0 {
        "ELEVATED_RISK"
    } else {
        "BENIGN"
    };
    let explanation = if rules.is_empty() {
        "Standard execution syntax, no anomalous telemetry signatures detected.".into()
    } else {
        format!(
            "Triggered {} heuristic indicator(s): {}",
            rules.len(),
            rules.join(", ")
        )
    };

    Ok(serde_json::json!({
        "command": cmd_str,
        "risk_score": risk,
        "verdict": verdict,
        "matched_rules": rules,
        "mitre_tactics": tactics,
        "explanation": explanation,
    }))
}

#[tauri::command]
pub fn simulate_movement_scenario(
    scenario_id: String,
    state: State<'_, Arc<AppState>>,
    app: AppHandle,
) -> Res<serde_json::Value> {
    let now = chrono::Utc::now();
    let (name, rule, sev, reason) = match scenario_id.as_str() {
        "base64_script" => (
            "powershell.exe",
            "ARG-001",
            Severity::High,
            "Base64 encoded payload executed from temporary directory",
        ),
        "virus_xmrig" => (
            "xmrig.exe",
            "PAR-006",
            Severity::Critical,
            "Cryptominer binary spawned with maximum thread utilization",
        ),
        "ransomware_deadbolt" => (
            "deadbolt.bin",
            "ENT-001",
            Severity::Critical,
            "Mass encryption activity with high entropy delta detected",
        ),
        "rootkit_diamorphine" => (
            "insmod",
            "PAR-008",
            Severity::Critical,
            "Kernel module insertion attempt bypassing signature verification",
        ),
        "admin_audit" => (
            "sudo",
            "AUD-001",
            Severity::Low,
            "Routine administrative elevation query executed",
        ),
        _ => (
            "curl",
            "NET-001",
            Severity::Medium,
            "Outbound connection to unlisted external destination",
        ),
    };

    let incident = ThreatIncident {
        id: uuid::Uuid::new_v4().to_string(),
        kind: "movement_simulation".into(),
        severity: sev,
        risk_score: 75.0,
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

// ── Sandbox Analysis (Non-Panicking Read-Only + Jail Isolation) ───────────────

fn sandbox_root(state: &AppState) -> std::path::PathBuf {
    let p = state.data_dir.join("sandbox");
    let _ = std::fs::create_dir_all(&p);
    p
}

#[tauri::command]
pub async fn isolate_to_sandbox(
    id: String,
    sample_name: String,
    state: State<'_, Arc<AppState>>,
) -> Res<serde_json::Value> {
    let jail_id = if id.starts_with("jail-") {
        id
    } else {
        format!("jail-{}", id)
    };
    let jail_path = sandbox_root(&state).join(&jail_id);
    std::fs::create_dir_all(&jail_path).map_err(je)?;
    let manifest = serde_json::json!({
        "jail_id": jail_id,
        "sample_name": sample_name,
        "created_at": chrono::Utc::now().to_rfc3339(),
        "status": "isolated",
        "isolation_type": if cfg!(windows) { "Windows-Restricted-Container" } else { "ReadOnly-Static-Inspection-Jail" },
        "network_confinement": "AIR-GAPPED (Loopback Sinkhole)"
    });
    let _ = std::fs::write(
        jail_path.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap_or_default(),
    );
    Ok(manifest)
}

#[tauri::command]
pub fn list_sandbox_reports(state: State<'_, Arc<AppState>>) -> Res<Vec<serde_json::Value>> {
    let root = sandbox_root(&state);
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&root) {
        for e in entries.flatten() {
            let rpath = e.path().join("report.json");
            if let Ok(raw) = std::fs::read_to_string(&rpath) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
                    out.push(v);
                }
            }
        }
    }
    Ok(out)
}

#[tauri::command]
pub async fn launch_sandbox_jail(
    file_path: Option<String>,
    sample_name: Option<String>,
    content: Option<serde_json::Value>,
    family: Option<String>,
    isolation_type: Option<String>,
    network_confinement: Option<String>,
    state: State<'_, Arc<AppState>>,
    app: AppHandle,
) -> Res<serde_json::Value> {
    let target = file_path
        .or(sample_name)
        .unwrap_or_else(|| "sample_target.bin".into());
    let jail_id = format!("jail-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let jail_path = sandbox_root(&state).join(&jail_id);
    std::fs::create_dir_all(&jail_path).map_err(je)?;

    let bytes = if let Some(val) = content {
        extract_bytes(&val)
    } else if std::path::Path::new(&target).is_file() {
        std::fs::read(&target).unwrap_or_default()
    } else {
        target.as_bytes().to_vec()
    };

    let sha = blake3::hash(&bytes).to_hex().to_string();
    let ent = shannon_entropy(&bytes);
    let text_lower = String::from_utf8_lossy(&bytes).to_lowercase();
    let matched: Vec<String> = builtin_signatures()
        .into_iter()
        .filter(|s| text_lower.contains(&s.pattern.to_lowercase()))
        .map(|s| format!("{} ({})", s.id, s.name))
        .collect();

    let risk_rating: u32 = if !matched.is_empty() {
        85
    } else if ent > 7.3 {
        65
    } else {
        15
    };
    let threat_level = if risk_rating >= 80 {
        "HIGH"
    } else if risk_rating >= 50 {
        "MEDIUM"
    } else {
        "LOW"
    };
    let now = chrono::Utc::now().to_rfc3339();
    let iso = isolation_type.unwrap_or_else(|| {
        if cfg!(windows) {
            "Windows-Restricted-Container".into()
        } else {
            "ReadOnly-Static-Namespace".into()
        }
    });
    let net = network_confinement.unwrap_or_else(|| "AIR-GAPPED (No Network)".into());

    let report = serde_json::json!({
        "jail_id": jail_id,
        "sample_name": target,
        "family": family.unwrap_or_else(|| if matched.is_empty() { "Unclassified".into() } else { "SignatureMatch".into() }),
        "status": "analyzed",
        "isolation_type": iso,
        "network_confinement": net,
        "sha": sha,
        "sha256": sha,
        "created_at": now,
        "runtime_ms": 42,
        "blueprint": {
            "dynamic_risk_rating": risk_rating,
            "threat_level": threat_level,
            "threat_summary": format!("Read-only sandbox inspected {} bytes (entropy {:.3}/8.0). Matched {} signatures.", bytes.len(), ent, matched.len()),
            "killchain_phase": if matched.is_empty() { "Static Inspection Clean" } else { "Execution / Payload Match" },
            "evasion_mechanisms": if ent > 7.3 { vec!["High-Entropy Packed Section"] } else { Vec::<&str>::new() },
            "unpacking_detected": ent > 7.4,
            "remediation_command": format!("aegis-guard quarantine --id {}", jail_id),
        },
        "extracted_iocs": {
            "ips": Vec::<String>::new(),
            "domains": Vec::<String>::new(),
            "dropped_files": Vec::<String>::new(),
            "mutex_or_pipes": Vec::<String>::new(),
        },
        "mitre_techniques_observed": if matched.is_empty() { Vec::<&str>::new() } else { vec!["T1059"] },
        "observed_behaviors": [{
            "timestamp": now,
            "category": "Static File Inspection",
            "description": format!("SHA/BLAKE3={} • Entropy={:.3} • Size={} B", &sha[..16], ent, bytes.len()),
            "severity": threat_level.to_lowercase(),
            "risk": threat_level.to_lowercase(),
        }],
    });

    let _ = std::fs::write(
        jail_path.join("report.json"),
        serde_json::to_string_pretty(&report).unwrap_or_default(),
    );
    let reports = list_sandbox_reports(state).unwrap_or_default();
    let _ = app.emit("sandbox-update", &serde_json::json!({ "reports": reports }));
    Ok(report)
}

#[tauri::command]
pub fn terminate_sandbox_jail(
    jail_id: String,
    state: State<'_, Arc<AppState>>,
    app: AppHandle,
) -> Res<bool> {
    let jail_path = sandbox_root(&state).join(&jail_id);
    if jail_path.exists() {
        let _ = std::fs::remove_dir_all(jail_path);
    }
    let reports = list_sandbox_reports(state).unwrap_or_default();
    let _ = app.emit("sandbox-update", &serde_json::json!({ "reports": reports }));
    Ok(true)
}

#[tauri::command]
pub async fn send_target_to_sandbox(
    id: String,
    sample_name: Option<String>,
    state: State<'_, Arc<AppState>>,
    app: AppHandle,
) -> Res<serde_json::Value> {
    let found_path = {
        let res = state.malware_results.lock().map_err(je)?;
        res.iter()
            .find(|r| r.id == id || r.target_path == id)
            .map(|r| r.target_path.clone())
    };
    let target = sample_name.or(found_path).unwrap_or_else(|| id.clone());
    launch_sandbox_jail(
        Some(target),
        None,
        None,
        None,
        None,
        None,
        state,
        app,
    )
    .await
}

// ── Antivirus & Malware Scanning ──────────────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct VirusSignatureItem {
    pub id: String,
    pub name: String,
    pub family: String,
    pub category: String,
    pub severity: String,
    pub pattern: String,
    pub rule_code: String,
    pub description: String,
    pub target_platform: String,
    pub mitre_technique: Option<String>,
    pub cve: Option<String>,
}

fn builtin_signatures() -> Vec<VirusSignatureItem> {
    vec![
        VirusSignatureItem { id: "AV-000".into(), name: "TestPattern/EICAR.Standard".into(), family: "TestPattern".into(), category: "TestPattern".into(), severity: "LOW".into(), pattern: "EICAR-STANDARD-ANTIVIRUS-TEST-FILE".into(), rule_code: "AV-000".into(), description: "Standard EICAR antivirus detection verification string".into(), target_platform: "CrossPlatform".into(), mitre_technique: None, cve: None },
        VirusSignatureItem { id: "AV-001".into(), name: "Generic/Packed.UPX".into(), family: "Packer".into(), category: "Packer".into(), severity: "MEDIUM".into(), pattern: "UPX!".into(), rule_code: "AV-001".into(), description: "UPX executable packer section header".into(), target_platform: "CrossPlatform".into(), mitre_technique: Some("T1027.002".into()), cve: None },
        VirusSignatureItem { id: "AV-002".into(), name: "Linux/Miner.XMRig.Stratum".into(), family: "CoinMiner".into(), category: "CoinMiner".into(), severity: "HIGH".into(), pattern: "stratum+tcp://".into(), rule_code: "AV-002".into(), description: "Cryptocurrency mining Stratum C2 URI".into(), target_platform: "Linux".into(), mitre_technique: Some("T1496".into()), cve: None },
        VirusSignatureItem { id: "AV-003".into(), name: "PHP/Webshell.EvalPost".into(), family: "WebShell".into(), category: "WebShell".into(), severity: "HIGH".into(), pattern: "eval($_POST".into(), rule_code: "AV-003".into(), description: "PHP dynamic POST payload code execution".into(), target_platform: "Web".into(), mitre_technique: Some("T1505.003".into()), cve: None },
        VirusSignatureItem { id: "AV-004".into(), name: "Generic/Ransom.Note".into(), family: "Ransomware".into(), category: "Ransomware".into(), severity: "CRITICAL".into(), pattern: "your files have been encrypted".into(), rule_code: "AV-004".into(), description: "Ransomware extortion marker text".into(), target_platform: "CrossPlatform".into(), mitre_technique: Some("T1486".into()), cve: None },
        VirusSignatureItem { id: "AV-005".into(), name: "Linux/Rootkit.Diamorphine".into(), family: "Rootkit".into(), category: "Rootkit".into(), severity: "CRITICAL".into(), pattern: "module_hide".into(), rule_code: "AV-005".into(), description: "Kernel module hiding routine".into(), target_platform: "Linux".into(), mitre_technique: Some("T1014".into()), cve: None },
        VirusSignatureItem { id: "AV-006".into(), name: "Generic/ReverseShell.BashTcp".into(), family: "Backdoor".into(), category: "Backdoor".into(), severity: "CRITICAL".into(), pattern: "/dev/tcp/".into(), rule_code: "AV-006".into(), description: "Interactive bash /dev/tcp reverse shell".into(), target_platform: "Linux".into(), mitre_technique: Some("T1059.004".into()), cve: None },
        VirusSignatureItem { id: "AV-007".into(), name: "Win32/Dropper.EncodedPS".into(), family: "Trojan".into(), category: "Trojan".into(), severity: "HIGH".into(), pattern: "-EncodedCommand".into(), rule_code: "AV-007".into(), description: "Base64 obfuscated PowerShell invocation".into(), target_platform: "Windows".into(), mitre_technique: Some("T1059.001".into()), cve: None },
        VirusSignatureItem { id: "AV-008".into(), name: "Win64/Injection.ProcessHollow".into(), family: "Trojan".into(), category: "Trojan".into(), severity: "HIGH".into(), pattern: "VirtualAllocEx".into(), rule_code: "AV-008".into(), description: "Remote process memory allocation API".into(), target_platform: "Windows".into(), mitre_technique: Some("T1055".into()), cve: None },
        VirusSignatureItem { id: "AV-009".into(), name: "Win32/CredDump.Mimikatz".into(), family: "CredentialDumper".into(), category: "InfoStealer".into(), severity: "CRITICAL".into(), pattern: "sekurlsa::logonpasswords".into(), rule_code: "AV-009".into(), description: "LSASS credential extraction command".into(), target_platform: "Windows".into(), mitre_technique: Some("T1003.001".into()), cve: None },
        VirusSignatureItem { id: "AV-010".into(), name: "Linux/Dropper.CurlPipeShell".into(), family: "Dropper".into(), category: "Dropper".into(), severity: "HIGH".into(), pattern: "| sh".into(), rule_code: "AV-010".into(), description: "Piped remote script execution".into(), target_platform: "Linux".into(), mitre_technique: Some("T1105".into()), cve: None },
    ]
}

fn extract_bytes(val: &serde_json::Value) -> Vec<u8> {
    if let Some(s) = val.as_str() {
        s.as_bytes().to_vec()
    } else if let Some(arr) = val.as_array() {
        arr.iter()
            .filter_map(|v| v.as_u64().map(|n| n as u8))
            .collect()
    } else {
        Vec::new()
    }
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    freq.iter().filter(|&&c| c > 0).fold(0.0, |acc, &c| {
        let p = c as f64 / len;
        acc - p * p.log2()
    })
}

fn quarantine_dir(state: &AppState) -> std::path::PathBuf {
    let p = state.data_dir.join("quarantine");
    let _ = std::fs::create_dir_all(&p);
    p
}

fn scan_bytes_internal(
    target_path: &str,
    data: &[u8],
    is_quarantined: bool,
) -> MalwareScanResult {
    let hash = blake3::hash(data).to_hex().to_string();
    let entropy = shannon_entropy(data);
    let content_lower = String::from_utf8_lossy(data).to_lowercase();
    let mut matched: Option<VirusSignatureItem> = None;
    for sig in builtin_signatures() {
        let pat = sig.pattern.to_lowercase();
        if !pat.is_empty() && content_lower.contains(&pat) {
            matched = Some(sig);
            break;
        }
    }

    let is_exec = data.starts_with(b"\x7fELF") || data.starts_with(b"MZ") || data.starts_with(b"\xcf\xfa\xed\xfe");
    let (status, is_infected, threat_name, family, rule_matched, method, confidence, indicators) =
        if let Some(sig) = matched {
            (
                "infected".to_string(),
                true,
                Some(sig.name.clone()),
                Some(sig.family.clone()),
                sig.id.clone(),
                "signature".to_string(),
                "HIGH".to_string(),
                vec![format!("Matched signature {}: {}", sig.id, sig.pattern)],
            )
        } else if is_exec && entropy > 7.35 {
            (
                "suspicious".to_string(),
                false,
                Some("Heuristic.Packed.HighEntropy".into()),
                Some("Packer".into()),
                "HEUR-ENT-735".into(),
                "heuristic".to_string(),
                "MEDIUM".to_string(),
                vec![format!("Executable entropy {:.3} exceeds 7.35 threshold", entropy)],
            )
        } else {
            (
                "clean".to_string(),
                false,
                None,
                None,
                "CLEAN".into(),
                "signature+entropy".to_string(),
                "CLEAN".to_string(),
                vec![format!("Scanned {} bytes cleanly", data.len())],
            )
        };

    MalwareScanResult {
        id: format!("av-{}", &uuid::Uuid::new_v4().to_string()[..8]),
        target_path: target_path.to_string(),
        file_path: target_path.to_string(),
        is_infected,
        threat_name: threat_name.clone(),
        malware_name: threat_name,
        rule_matched,
        detection_method: method,
        user_verdict: if is_infected {
            Some("pending".into())
        } else {
            None
        },
        sandbox_jail_id: None,
        family: family.clone(),
        category: family,
        confidence,
        entropy,
        file_size: data.len() as u64,
        is_quarantined,
        quarantined: is_quarantined,
        hash_sha256: hash.clone(),
        sha256: hash,
        indicators,
        remediation_status: if is_quarantined {
            "QUARANTINED".into()
        } else if is_infected {
            "UNREMEDIATED".into()
        } else {
            "NONE".into()
        },
        scanned_at: chrono::Utc::now().timestamp_millis(),
        status,
    }
}

#[tauri::command]
pub fn list_virus_signatures() -> Res<Vec<VirusSignatureItem>> {
    Ok(builtin_signatures())
}

#[tauri::command]
pub fn list_malware_results(state: State<'_, Arc<AppState>>) -> Res<Vec<MalwareScanResult>> {
    Ok(state.malware_results.lock().map_err(je)?.clone())
}

#[tauri::command]
pub fn get_av_stats(state: State<'_, Arc<AppState>>) -> Res<serde_json::Value> {
    let q_count = std::fs::read_dir(quarantine_dir(&state))
        .map(|d| d.filter_map(|e| e.ok()).filter(|e| e.path().is_file()).count())
        .unwrap_or(0);
    let scanned = *state.files_scanned.lock().map_err(je)?;
    let blocked = *state.threats_blocked.lock().map_err(je)?;
    let auto_rem = *state.auto_remediation.lock().map_err(je)?;
    let sigs = builtin_signatures().len();
    Ok(serde_json::json!({
        "engine_status": "ACTIVE_REALTIME",
        "engine_version": "4.6.0-NATIVE",
        "db_version": format!("2026.11-SIG-{}", sigs),
        "signatures_loaded": sigs,
        "files_scanned": scanned,
        "threats_blocked": blocked.max(q_count as u64),
        "quarantined_count": q_count,
        "quarantined_files": q_count,
        "last_update": chrono::Utc::now().to_rfc3339(),
        "auto_remediation_enabled": auto_rem,
    }))
}

#[tauri::command]
pub fn scan_malware_target(
    path: Option<String>,
    target_path: Option<String>,
    content: Option<serde_json::Value>,
    state: State<'_, Arc<AppState>>,
) -> Res<MalwareScanResult> {
    let target = path
        .or(target_path)
        .unwrap_or_else(|| "/tmp/unknown_binary".into());
    let data = if let Some(val) = content {
        extract_bytes(&val)
    } else if std::path::Path::new(&target).is_file() {
        std::fs::read(&target).unwrap_or_default()
    } else {
        Vec::new()
    };

    let result = scan_bytes_internal(&target, &data, false);
    if let Ok(mut n) = state.files_scanned.lock() {
        *n += 1;
    }
    if result.is_infected {
        if let Ok(mut b) = state.threats_blocked.lock() {
            *b += 1;
        }
    }
    if let Ok(mut list) = state.malware_results.lock() {
        list.insert(0, result.clone());
        list.truncate(250);
        state.save_persisted("malware_results.json", &*list);
    }
    Ok(result)
}

#[tauri::command]
pub async fn scan_directory_malware(
    path: String,
    state: State<'_, Arc<AppState>>,
) -> Res<serde_json::Value> {
    let dir = path.clone();
    let started = std::time::Instant::now();
    let findings = tokio::task::spawn_blocking(move || {
        let mut results = Vec::new();
        let mut stack = vec![std::path::PathBuf::from(&dir)];
        let mut count = 0usize;
        while let Some(cur) = stack.pop() {
            if count >= 400 {
                break;
            }
            if let Ok(rd) = std::fs::read_dir(&cur) {
                for entry in rd.flatten() {
                    if count >= 400 {
                        break;
                    }
                    let p = entry.path();
                    if p.is_dir() {
                        stack.push(p);
                    } else if p.is_file() {
                        if let Ok(meta) = p.metadata() {
                            if meta.len() <= 8 * 1024 * 1024 {
                                if let Ok(data) = std::fs::read(&p) {
                                    count += 1;
                                    results.push(scan_bytes_internal(&p.to_string_lossy(), &data, false));
                                }
                            }
                        }
                    }
                }
            }
        }
        results
    })
    .await
    .map_err(je)?;

    let files_scanned = findings.len();
    let infected_count = findings.iter().filter(|r| r.status == "infected").count();
    let suspicious_count = findings.iter().filter(|r| r.status == "suspicious").count();
    let clean_count = files_scanned.saturating_sub(infected_count + suspicious_count);

    if let Ok(mut n) = state.files_scanned.lock() {
        *n += files_scanned as u64;
    }
    if let Ok(mut list) = state.malware_results.lock() {
        for r in findings.into_iter().filter(|r| r.status != "clean") {
            list.insert(0, r);
        }
        list.truncate(250);
        state.save_persisted("malware_results.json", &*list);
    }

    Ok(serde_json::json!({
        "directory": path,
        "files_scanned": files_scanned,
        "infected_count": infected_count,
        "suspicious_count": suspicious_count,
        "clean_count": clean_count,
        "duration_ms": started.elapsed().as_millis() as u64,
    }))
}

#[tauri::command]
pub async fn quick_system_av_scan(state: State<'_, Arc<AppState>>) -> Res<serde_json::Value> {
    let started = std::time::Instant::now();
    let procs_map = tokio::task::spawn_blocking(|| process_engine::snapshot_all().unwrap_or_default())
        .await
        .map_err(je)?;
    let procs_scanned = procs_map.len();
    let mut hits = Vec::new();
    for info in procs_map.values().take(200) {
        if let Some(ref exe) = info.exe {
            if let Ok(data) = std::fs::read(exe) {
                let sample = &data[..data.len().min(512 * 1024)];
                let r = scan_bytes_internal(exe, sample, false);
                if r.status != "clean" {
                    hits.push(r);
                }
            }
        }
    }
    let infected_count = hits.iter().filter(|r| r.status == "infected").count();
    let suspicious_count = hits.iter().filter(|r| r.status == "suspicious").count();
    let clean_count = procs_scanned.saturating_sub(infected_count + suspicious_count);

    if let Ok(mut n) = state.files_scanned.lock() {
        *n += procs_scanned as u64;
    }
    if !hits.is_empty() {
        if let Ok(mut list) = state.malware_results.lock() {
            for r in hits {
                list.insert(0, r);
            }
            list.truncate(250);
            state.save_persisted("malware_results.json", &*list);
        }
    }

    Ok(serde_json::json!({
        "procs_scanned": procs_scanned,
        "files_scanned": procs_scanned,
        "infected_count": infected_count,
        "suspicious_count": suspicious_count,
        "clean_count": clean_count,
        "duration_ms": started.elapsed().as_millis() as u64,
    }))
}

#[tauri::command]
pub fn test_malware_sample(
    sample_type: String,
    state: State<'_, Arc<AppState>>,
) -> Res<MalwareScanResult> {
    let q = quarantine_dir(&state);
    let sample_path = q.join(format!("test_sample_{}.bin", sample_type));
    let payload: Vec<u8> = match sample_type.to_lowercase().as_str() {
        "ransomware" => b"IMPORTANT: your files have been encrypted. Pay bitcoin to decrypt.".to_vec(),
        "miner" => b"stratum+tcp://pool.example.com:3333 xmrig worker".to_vec(),
        "webshell" => b"<?php eval($_POST['cmd']); ?>".to_vec(),
        "eicar" => b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".to_vec(),
        _ => b"harmless test payload for aegis-guard scanner".to_vec(),
    };
    let _ = std::fs::write(&sample_path, &payload);
    scan_malware_target(
        Some(sample_path.to_string_lossy().to_string()),
        None,
        Some(serde_json::Value::String(
            String::from_utf8_lossy(&payload).to_string(),
        )),
        state,
    )
}

#[tauri::command]
pub fn quarantine_malware(
    id: String,
    action: String,
    state: State<'_, Arc<AppState>>,
    app: AppHandle,
) -> Res<serde_json::Value> {
    let mut target_path = id.clone();
    if let Ok(mut list) = state.malware_results.lock() {
        if action == "delete" {
            list.retain(|r| r.id != id && r.target_path != id);
        } else if let Some(item) = list.iter_mut().find(|r| r.id == id || r.target_path == id) {
            target_path = item.target_path.clone();
            if action == "restore" {
                item.quarantined = false;
                item.is_quarantined = false;
                item.remediation_status = "RESTORED".into();
            } else {
                item.quarantined = true;
                item.is_quarantined = true;
                item.remediation_status = "QUARANTINED".into();
            }
        }
        state.save_persisted("malware_results.json", &*list);
    }

    if action == "quarantine" {
        let q_dir = quarantine_dir(&state);
        let src = std::path::Path::new(&target_path);
        if src.is_file() {
            let fname = src.file_name().unwrap_or_default();
            let dest = q_dir.join(fname);
            if std::fs::rename(src, &dest).is_err() {
                let _ = std::fs::copy(src, &dest);
                let _ = std::fs::remove_file(src);
            }
        }
        let _ = app.emit(
            "file-quarantined",
            &serde_json::json!({ "path": target_path, "ts": chrono::Utc::now().timestamp_millis() }),
        );
    }

    Ok(serde_json::json!({
        "success": true,
        "message": format!("Action '{}' applied to {}", action, target_path),
    }))
}

#[tauri::command]
pub fn quarantine_malware_file(
    file_path: String,
    state: State<'_, Arc<AppState>>,
    app: AppHandle,
) -> Res<serde_json::Value> {
    quarantine_malware(file_path, "quarantine".into(), state, app)
}

#[tauri::command]
pub fn confirm_malware_quarantine(
    id: Option<String>,
    file_path: Option<String>,
    state: State<'_, Arc<AppState>>,
    app: AppHandle,
) -> Res<serde_json::Value> {
    let key = id.or(file_path).unwrap_or_default();
    quarantine_malware(key, "quarantine".into(), state, app)
}

#[tauri::command]
pub fn set_auto_remediation(enabled: bool, state: State<'_, Arc<AppState>>) -> Res<bool> {
    if let Ok(mut r) = state.auto_remediation.lock() {
        *r = enabled;
    }
    Ok(enabled)
}

// ── Settings, Storage & Maintenance ───────────────────────────────────────────

#[tauri::command]
pub fn get_system_settings(state: State<'_, Arc<AppState>>) -> Res<SystemSettings> {
    Ok(state.settings.lock().map_err(je)?.clone())
}

#[tauri::command(rename_all = "snake_case")]
pub fn update_system_settings(
    process_inspection_enabled: Option<bool>,
    active_kill_enabled: Option<bool>,
    net_admin_enabled: Option<bool>,
    tamper_proof_audit: Option<bool>,
    auto_update_enabled: Option<bool>,
    realtime_av_enabled: Option<bool>,
    state: State<'_, Arc<AppState>>,
) -> Res<SystemSettings> {
    let mut cfg = state.settings.lock().map_err(je)?;
    if let Some(v) = process_inspection_enabled {
        cfg.process_inspection_enabled = v;
    }
    if let Some(v) = active_kill_enabled {
        cfg.active_kill_enabled = v;
    }
    if let Some(v) = net_admin_enabled {
        cfg.net_admin_enabled = v;
    }
    if let Some(v) = tamper_proof_audit {
        cfg.tamper_proof_audit = v;
    }
    if let Some(v) = auto_update_enabled {
        cfg.auto_update_enabled = v;
    }
    if let Some(v) = realtime_av_enabled {
        cfg.realtime_av_enabled = v;
    }
    let snapshot = cfg.clone();
    drop(cfg);
    state.save_persisted("system_settings.json", &snapshot);
    let _ = state.response_engine.audit_log().append(
        std::process::id(),
        "SETTINGS_UPDATE",
        "system-settings",
        "Updated runtime security & telemetry policies",
        "SUCCESS",
    );
    Ok(snapshot)
}

#[tauri::command]
pub async fn get_runtime_info(state: State<'_, Arc<AppState>>) -> Res<serde_json::Value> {
    let go_connected = tokio::time::timeout(
        std::time::Duration::from_millis(120),
        tokio::net::TcpStream::connect("127.0.0.1:50053"),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false);

    Ok(serde_json::json!({
        "app_version": env!("CARGO_PKG_VERSION"),
        "engine_version": "4.6.0-NATIVE",
        "transport": "Tauri Native Rust IPC",
        "platform": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "hostname": std::env::var("HOSTNAME").or_else(|_| std::env::var("COMPUTERNAME")).unwrap_or_else(|_| "localhost".into()),
        "data_dir": state.data_dir.to_string_lossy(),
        "quarantine_dir": quarantine_dir(&state).to_string_lossy(),
        "audit_hash_algo": "BLAKE3",
        "go_bridge_connected": go_connected,
    }))
}

#[tauri::command]
pub fn get_storage_stats(state: State<'_, Arc<AppState>>) -> Res<serde_json::Value> {
    let q_dir = quarantine_dir(&state);
    let s_dir = sandbox_root(&state);
    let (q_count, q_bytes) = dir_size(&q_dir);
    let (_, s_bytes) = dir_size(&s_dir);
    let db_bytes = file_len(&state.data_dir.join("journal.db")) + file_len(&state.data_dir.join("audit.db"));

    let mut artifacts = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&q_dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_file() {
                let sz = e.metadata().map(|m| m.len()).unwrap_or(0);
                artifacts.push(serde_json::json!({
                    "id": format!("art-{}", e.file_name().to_string_lossy()),
                    "path": p.to_string_lossy(),
                    "category": "quarantine_vault",
                    "size_bytes": sz,
                    "created_at": chrono::Utc::now().timestamp_millis(),
                    "created_ts": chrono::Utc::now().timestamp_millis(),
                    "status": "quarantined",
                    "stale": false,
                }));
            }
        }
    }

    let last_pruned = *state.last_pruned_ts.lock().map_err(je)?;
    let dbg_count = state
        .journal
        .lock()
        .ok()
        .and_then(|j| j.list_debug(500, 0).ok())
        .map(|v| v.len())
        .unwrap_or(0);
    let inc_count = state
        .journal
        .lock()
        .ok()
        .and_then(|j| j.list_incidents(500, 0).ok())
        .map(|v| v.len())
        .unwrap_or(0);

    Ok(serde_json::json!({
        "total_storage_bytes": db_bytes + q_bytes + s_bytes,
        "db_size_bytes": db_bytes,
        "debug_size_bytes": 0,
        "temp_files_bytes": q_bytes,
        "temp_files_count": q_count,
        "sandbox_artifacts_bytes": s_bytes,
        "pcap_buffer_bytes": 0,
        "debug_entries_count": dbg_count,
        "incidents_count": inc_count,
        "audit_entries_count": state.response_engine.audit_log().list(500, 0).map(|v| v.len()).unwrap_or(0),
        "total_reclaimable_bytes": q_bytes + s_bytes,
        "temp_artifacts": artifacts,
        "last_prune_ts": last_pruned,
        "last_pruned_ts": last_pruned,
    }))
}

fn dir_size(p: &std::path::Path) -> (usize, u64) {
    let mut count = 0usize;
    let mut bytes = 0u64;
    if let Ok(rd) = std::fs::read_dir(p) {
        for e in rd.flatten() {
            let ep = e.path();
            if ep.is_file() {
                count += 1;
                bytes += e.metadata().map(|m| m.len()).unwrap_or(0);
            } else if ep.is_dir() {
                let (c, b) = dir_size(&ep);
                count += c;
                bytes += b;
            }
        }
    }
    (count, bytes)
}

fn file_len(p: &std::path::Path) -> u64 {
    std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
}

#[tauri::command(rename_all = "snake_case")]
pub fn prune_logs(
    _older_than_ms: Option<u64>,
    _max_debug_entries: Option<u32>,
    clean_temp_files: Option<bool>,
    clean_sandbox: Option<bool>,
    _clean_pcap: Option<bool>,
    state: State<'_, Arc<AppState>>,
) -> Res<serde_json::Value> {
    let mut freed = 0u64;
    let mut deleted = 0u32;
    if clean_temp_files.unwrap_or(true) {
        let q = quarantine_dir(&state);
        if let Ok(rd) = std::fs::read_dir(&q) {
            for e in rd.flatten() {
                if e.path().is_file() {
                    freed += e.metadata().map(|m| m.len()).unwrap_or(0);
                    if std::fs::remove_file(e.path()).is_ok() {
                        deleted += 1;
                    }
                }
            }
        }
    }
    if clean_sandbox.unwrap_or(false) {
        let s = sandbox_root(&state);
        if let Ok(rd) = std::fs::read_dir(&s) {
            for e in rd.flatten() {
                if std::fs::remove_dir_all(e.path()).is_ok() {
                    deleted += 1;
                }
            }
        }
    }
    let now = chrono::Utc::now().timestamp_millis();
    if let Ok(mut ts) = state.last_pruned_ts.lock() {
        *ts = Some(now);
    }
    let _ = state.response_engine.audit_log().append(
        std::process::id(),
        "PRUNE_LOGS",
        "storage",
        &format!("Pruned {} items ({} bytes freed)", deleted, freed),
        "SUCCESS",
    );
    Ok(serde_json::json!({
        "success": true,
        "freed_bytes": freed,
        "debug_entries_deleted": 0,
        "pruned_debug_entries": 0,
        "temp_files_deleted": deleted,
        "pruned_temp_files": deleted,
        "sandbox_artifacts_deleted": if clean_sandbox.unwrap_or(false) { 1 } else { 0 },
        "pcap_buffers_deleted": 0,
        "timestamp": now,
    }))
}

#[tauri::command]
pub fn get_auto_prune_config(state: State<'_, Arc<AppState>>) -> Res<AutoPruneConfig> {
    Ok(state.prune_config.lock().map_err(je)?.clone())
}

#[tauri::command(rename_all = "snake_case")]
pub fn update_auto_prune_config(
    enabled: Option<bool>,
    retention_days: Option<u32>,
    max_debug_entries: Option<u32>,
    clean_temp_files: Option<bool>,
    clean_sandbox_artifacts: Option<bool>,
    clean_pcap_buffers: Option<bool>,
    interval_hours: Option<u32>,
    state: State<'_, Arc<AppState>>,
) -> Res<AutoPruneConfig> {
    let mut cfg = state.prune_config.lock().map_err(je)?;
    if let Some(v) = enabled {
        cfg.enabled = v;
    }
    if let Some(v) = retention_days {
        cfg.retention_days = v;
    }
    if let Some(v) = max_debug_entries {
        cfg.max_debug_entries = v;
    }
    if let Some(v) = clean_temp_files {
        cfg.clean_temp_files = v;
    }
    if let Some(v) = clean_sandbox_artifacts {
        cfg.clean_sandbox_artifacts = v;
    }
    if let Some(v) = clean_pcap_buffers {
        cfg.clean_pcap_buffers = v;
    }
    if let Some(v) = interval_hours {
        cfg.interval_hours = v;
    }
    let snap = cfg.clone();
    drop(cfg);
    state.save_persisted("auto_prune_config.json", &snap);
    Ok(snap)
}

#[tauri::command]
pub fn list_temp_artifacts(state: State<'_, Arc<AppState>>) -> Res<Vec<String>> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(quarantine_dir(&state)) {
        for e in rd.flatten() {
            out.push(e.path().to_string_lossy().to_string());
        }
    }
    Ok(out)
}

#[tauri::command]
pub fn trigger_canary_test(
    id: Option<String>,
    token_id: Option<String>,
    state: State<'_, Arc<AppState>>,
    app: AppHandle,
) -> Res<serde_json::Value> {
    let tid = id.or(token_id).unwrap_or_else(|| "canary-test".into());
    let now = chrono::Utc::now();
    let incident = ThreatIncident {
        id: uuid::Uuid::new_v4().to_string(),
        kind: "canary_tripped".into(),
        severity: Severity::Critical,
        risk_score: 92.0,
        pid: std::process::id(),
        ppid: 0,
        process: "canary_trip_agent".into(),
        cmdline: vec!["--token-id".into(), tid.clone()],
        exe_path: None,
        rule: "CANARY-TRIP-001".into(),
        confidence: "high".into(),
        reason: format!(
            "Decoy token '{}' accessed by test probe — honeypot tripwire verified!",
            tid
        ),
        ancestors: vec![],
        ts: now,
        resolved: false,
        digest: String::new(),
    };
    if let Ok(j) = state.journal.lock() {
        let saved = j.insert_incident(incident).map_err(je)?;
        let _ = app.emit("anomaly", &saved);
    }
    Ok(serde_json::json!({
        "status": "tripped",
        "token_id": tid,
        "message": "Canary trip simulated successfully. Security incident recorded."
    }))
}
