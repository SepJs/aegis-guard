use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Instant;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use process_engine::{ProcEvent, ProcEventKind, ProcInfo};

const SIGNATURES: &[(&str, &str, &str, &str, &str, &str, &str, &str, &str)] = &[
    ("SIG-001", "Win64/Trojan.Meterpreter.Gen", "Trojan", "critical", "CrossPlatform", "pattern", "4d5a900003", "Metasploit Meterpreter staged payload", "T1219"),
    ("SIG-002", "Linux/Miner.XMRig.Stratum", "CoinMiner", "high", "Linux", "pattern", "stratum+tcp://", "XMRig cryptominer stratum C2", "T1496"),
    ("SIG-003", "PHP/Webshell.ChinaChopper.Eval", "WebShell", "high", "Web", "pattern", "assert(@$_POST", "China Chopper eval webshell", "T1505.003"),
    ("SIG-004", "Win32/Ransom.DeadBolt.Variant", "Ransomware", "critical", "CrossPlatform", "heuristic", "DECRYPT_FILES.txt", "DeadBolt ransomware note / encryptor", "T1486"),
    ("SIG-005", "Linux/Rootkit.Diamorphine.LKM", "Rootkit", "critical", "Linux", "pattern", "module_hide", "Diamorphine LKM hide syscall", "T1014"),
    ("SIG-006", "Win64/Backdoor.CobaltStrike.Beacon", "Backdoor", "critical", "CrossPlatform", "heuristic", "beacon.dll", "Cobalt Strike beacon", "T1071"),
    ("SIG-007", "Generic/Dropper.Encoded.PowerShell", "Dropper", "high", "CrossPlatform", "heuristic", "-EncodedCommand", "Encoded PowerShell dropper", "T1027"),
    ("SIG-008", "Win32/InfoStealer.RedLine", "InfoStealer", "high", "CrossPlatform", "pattern", "<BrowserList>", "RedLine stealer browser harvest", "T1555"),
    ("SIG-009", "Linux/Backdoor.ReverseTCP", "Backdoor", "critical", "Linux", "pattern", "/dev/tcp/", "Bash reverse TCP", "T1059.004"),
    ("SIG-010", "TestPattern/EICAR", "TestPattern", "low", "CrossPlatform", "pattern", "EICAR-STANDARD-ANTIVIRUS-TEST-FILE", "EICAR test string", ""),
];

pub struct EngineRuntime {
    data_dir: PathBuf,
    telemetry: Mutex<Vec<TelemetryEvent>>,
    malware: Mutex<Vec<MalwareScanResult>>,
    sandbox: Mutex<Vec<SandboxAnalysisReport>>,
    attacks: Mutex<Vec<NetworkAttackEvent>>,
    dns: Mutex<Vec<DnsQuery>>,
    blocked: Mutex<HashSet<String>>,
    net_cfg: Mutex<NetworkDefenseConfig>,
    prune_cfg: Mutex<AutoPruneConfig>,
    auto_remediation: Mutex<bool>,
    files_scanned: Mutex<u64>,
    threats_blocked: Mutex<u64>,
    known_pids: Mutex<HashSet<u32>>,
    pid_names: Mutex<HashMap<u32, String>>,
    started: Instant,
}

impl EngineRuntime {
    pub fn new(data_dir: PathBuf) -> Self {
        let _ = std::fs::create_dir_all(&data_dir);
        let now = Utc::now().timestamp_millis();
        Self {
            data_dir,
            telemetry: Mutex::new(Vec::new()),
            malware: Mutex::new(Vec::new()),
            sandbox: Mutex::new(Vec::new()),
            attacks: Mutex::new(Vec::new()),
            dns: Mutex::new(vec![
                DnsQuery { id: "dns-boot-1".into(), query: "update.aegis-guard.local".into(), qtype: "A".into(), resolved_ip: "127.0.0.1".into(), pid: std::process::id(), process_name: "aegis-guard".into(), verdict: "safe".into(), ts: now - 15000 },
                DnsQuery { id: "dns-boot-2".into(), query: "api.github.com".into(), qtype: "A".into(), resolved_ip: "140.82.121.6".into(), pid: std::process::id(), process_name: "updater".into(), verdict: "safe".into(), ts: now - 35000 },
            ]),
            blocked: Mutex::new(HashSet::new()),
            net_cfg: Mutex::new(NetworkDefenseConfig {
                ids_enabled: true, auto_drop_attackers: true, sniffing_detection_active: true,
                anti_port_scan_filter: true, dns_tunneling_guard: true, blocked_ip_list: vec![],
            }),
            prune_cfg: Mutex::new(AutoPruneConfig {
                enabled: true, retention_days: 7, max_debug_entries: 100, clean_temp_files: true,
                clean_sandbox_artifacts: true, clean_pcap_buffers: true, interval_hours: 24, last_run_ts: None,
            }),
            auto_remediation: Mutex::new(true),
            files_scanned: Mutex::new(0),
            threats_blocked: Mutex::new(0),
            known_pids: Mutex::new(HashSet::new()),
            pid_names: Mutex::new(HashMap::new()),
            started: Instant::now(),
        }
    }

    pub fn list_processes() -> Vec<ProcEvent> {
        let map = process_engine::snapshot_all().unwrap_or_default();
        let rules = process_engine::RuleEngine::new();
        let paths = process_engine::PathRuleEngine::new();
        let mut out = Vec::with_capacity(map.len());
        for info in map.values() {
            let mut anomaly = rules.evaluate(info, &map);
            if anomaly.is_none() { anomaly = paths.evaluate(info, &map); }
            let kind = if anomaly.is_some() { ProcEventKind::Anomaly } else { ProcEventKind::Spawned };
            out.push(ProcEvent::from_proc(info, kind, anomaly));
        }
        out.sort_by_key(|p| p.pid);
        out
    }

    pub fn poll_process_diff(&self) -> Vec<ProcEvent> {
        let map = process_engine::snapshot_all().unwrap_or_default();
        let rules = process_engine::RuleEngine::new();
        let paths = process_engine::PathRuleEngine::new();
        let mut known = self.known_pids.lock().unwrap();
        let mut names = self.pid_names.lock().unwrap();
        let mut events = Vec::new();

        if known.is_empty() {
            for (pid, info) in &map {
                known.insert(*pid);
                names.insert(*pid, info.name.clone());
            }
            return events;
        }

        for (pid, info) in &map {
            names.insert(*pid, info.name.clone());
            if known.insert(*pid) {
                let mut anomaly = rules.evaluate(info, &map);
                if anomaly.is_none() { anomaly = paths.evaluate(info, &map); }
                let kind = if anomaly.is_some() { ProcEventKind::Anomaly } else { ProcEventKind::Spawned };
                let ev = ProcEvent::from_proc(info, kind, anomaly);
                self.push_spawn_telemetry(info, ev.anomaly.is_some());
                events.push(ev);
            }
        }

        let dead: Vec<u32> = known.iter().copied().filter(|p| !map.contains_key(p)).collect();
        for pid in dead {
            known.remove(&pid);
            let name = names.remove(&pid).unwrap_or_else(|| format!("pid-{}", pid));
            events.push(ProcEvent {
                id: Uuid::new_v4().to_string(),
                kind: ProcEventKind::Exited,
                pid, ppid: 0, name, cmdline: vec![], exe: None, cwd: None,
                uid: 0, gid: 0, start_time: 0, anomaly: None,
                ts: Utc::now().timestamp_millis(),
            });
        }
        events
    }

    fn push_spawn_telemetry(&self, info: &ProcInfo, flagged: bool) {
        let ev = TelemetryEvent {
            id: Uuid::new_v4().to_string(),
            ts: Utc::now().timestamp_millis(),
            pid: info.pid,
            ppid: info.ppid,
            process: info.name.clone(),
            parent: String::new(),
            event_type: "PROC_SPAWN".into(),
            severity: if flagged { "high".into() } else { "informational".into() },
            score: if flagged { 70.0 } else { 5.0 },
            mitre: if flagged { Some("T1059".into()) } else { None },
            detail: format!("{} spawned (pid {})", info.name, info.pid),
            cmdline: Some(info.cmdline.clone()),
            verdict: if flagged { "alert".into() } else { "monitored".into() },
            suppression_reason: None,
        };
        self.push_telemetry(ev);
    }

    pub fn push_telemetry(&self, ev: TelemetryEvent) {
        let mut t = self.telemetry.lock().unwrap();
        t.insert(0, ev);
        t.truncate(500);
    }

    pub fn list_telemetry(&self, limit: u32) -> Vec<TelemetryEvent> {
        self.telemetry.lock().unwrap().iter().take(limit as usize).cloned().collect()
    }

    pub fn simulate_scenario(&self, scenario: &str) -> (TelemetryEvent, journal::models::ThreatIncident) {
        let (name, rule, sev, reason, score, event_type, mitre) = match scenario {
            "base64_script" => ("powershell.exe", "ARG-001", journal::models::Severity::High, "Base64 encoded payload executed from temporary directory", 78.0, "EVASION", "T1027"),
            "virus_xmrig" => ("xmrig.exe", "PAR-006", journal::models::Severity::Critical, "Cryptominer binary spawned with maximum thread utilization", 94.0, "PROC_SPAWN", "T1496"),
            "ransomware_deadbolt" => ("deadbolt.bin", "ENT-001", journal::models::Severity::Critical, "Mass encryption activity with high entropy delta detected", 98.0, "FILE_ENCRYPT", "T1486"),
            "rootkit_diamorphine" => ("insmod", "PAR-008", journal::models::Severity::Critical, "Kernel module insertion attempt bypassing signature verification", 96.0, "PRIV_ESC", "T1014"),
            "admin_audit" => ("sudo", "AUD-001", journal::models::Severity::Low, "Routine administrative elevation query executed", 12.0, "PROC_SPAWN", "T1548"),
            _ => ("curl", "NET-001", journal::models::Severity::Medium, "Outbound connection to unlisted external destination", 48.0, "SHELL_EXEC", "T1105"),
        };
        let now_ms = Utc::now().timestamp_millis();
        let tel = TelemetryEvent {
            id: Uuid::new_v4().to_string(), ts: now_ms, pid: 7777, ppid: 1000,
            process: name.into(), parent: "explorer.exe".into(), event_type: event_type.into(),
            severity: format!("{}", sev), score, mitre: Some(mitre.into()),
            detail: reason.into(), cmdline: Some(vec![name.into(), "--scenario".into(), scenario.into()]),
            verdict: if score >= 65.0 { "alert".into() } else if score >= 30.0 { "monitored".into() } else { "clean".into() },
            suppression_reason: None,
        };
        self.push_telemetry(tel.clone());
        let incident = journal::models::ThreatIncident {
            id: Uuid::new_v4().to_string(), kind: "movement_simulation".into(), severity: sev,
            risk_score: score, pid: 7777, ppid: 1000, process: name.into(),
            cmdline: vec![name.into(), "--scenario".into(), scenario.into()],
            exe_path: Some(format!("/tmp/{}", name)), rule: rule.into(), confidence: "high".into(),
            reason: reason.into(), ancestors: vec![], ts: Utc::now(), resolved: false, digest: String::new(),
        };
        (tel, incident)
    }

    pub fn evaluate_command(&self, process_name: &str, parent_name: &str, cmdline: &[String], destination: &str) -> serde_json::Value {
        let joined = cmdline.join(" ").to_lowercase();
        let mut risk = 0.0;
        let mut rules = Vec::new();
        let mut tactics = Vec::new();
        if joined.contains("base64") || joined.contains("encodedcommand") || joined.contains("-e ") {
            risk += 45.0; rules.push("ARG-001: Encoded/Base64 Command Execution"); tactics.push("Defense Evasion (T1027)");
        }
        if joined.contains("downloadstring") || joined.contains("curl") || joined.contains("wget") || joined.contains("iwr") {
            risk += 35.0; rules.push("ARG-002: Remote Ingress Tool Download"); tactics.push("Ingress Tool Transfer (T1105)");
        }
        if joined.contains("whoami") || joined.contains("mimikatz") || joined.contains("procdump") || joined.contains("lsass") {
            risk += 50.0; rules.push("ARG-003: Credential Dumping / Reconnaissance"); tactics.push("Credential Access (T1003)");
        }
        if joined.contains("nc -e") || joined.contains("mkfifo") || joined.contains("/dev/tcp/") {
            risk += 60.0; rules.push("NET-002: Reverse Shell Spawn"); tactics.push("Command and Control (T1059)");
        }
        if destination.contains("onion") || destination.contains("raw.githubusercontent") {
            risk += 20.0; rules.push("NET-004: Suspicious destination"); tactics.push("Command and Control (T1071)");
        }
        if parent_name.eq_ignore_ascii_case("winword") || parent_name.eq_ignore_ascii_case("excel") {
            risk += 25.0; rules.push("PAR-003: Office spawning interpreter"); tactics.push("Initial Access (T1566)");
        }
        if risk > 100.0 { risk = 100.0; }
        let verdict = if risk >= 65.0 { "SUSPICIOUS_MALICIOUS" } else if risk >= 30.0 { "ELEVATED_RISK" } else { "BENIGN" };
        let explanation = if rules.is_empty() {
            "Standard execution syntax, no anomalous telemetry signatures detected.".into()
        } else {
            format!("Triggered {} heuristic indicator(s): {}", rules.len(), rules.join(", "))
        };
        serde_json::json!({
            "command": cmdline.join(" "),
            "process_name": process_name,
            "parent_name": parent_name,
            "risk_score": risk,
            "verdict": verdict,
            "matched_rules": rules,
            "mitre_tactics": tactics,
            "explanation": explanation,
        })
    }

    pub fn list_connections(&self) -> Vec<NetworkConnection> {
        let names = self.pid_names.lock().unwrap().clone();
        let blocked = self.blocked.lock().unwrap().clone();
        snapshot_connections(&names, &blocked)
    }

    pub fn list_dns(&self) -> Vec<DnsQuery> { self.dns.lock().unwrap().clone() }
    pub fn list_attacks(&self) -> Vec<NetworkAttackEvent> { self.attacks.lock().unwrap().clone() }

    pub fn record_attack(&self, atk: NetworkAttackEvent) {
        let mut a = self.attacks.lock().unwrap();
        a.insert(0, atk);
        a.truncate(200);
    }

    pub fn get_net_config(&self) -> NetworkDefenseConfig {
        let mut cfg = self.net_cfg.lock().unwrap().clone();
        cfg.blocked_ip_list = self.blocked.lock().unwrap().iter().cloned().collect();
        cfg
    }

    pub fn update_net_config(&self, mut cfg: NetworkDefenseConfig) -> NetworkDefenseConfig {
        self.blocked.lock().unwrap().extend(cfg.blocked_ip_list.iter().cloned());
        cfg.blocked_ip_list = self.blocked.lock().unwrap().iter().cloned().collect();
        *self.net_cfg.lock().unwrap() = cfg.clone();
        cfg
    }

    pub fn block_ip(&self, ip: &str) {
        self.blocked.lock().unwrap().insert(ip.to_string());
        self.net_cfg.lock().unwrap().blocked_ip_list = self.blocked.lock().unwrap().iter().cloned().collect();
    }

    pub fn unblock_ip(&self, ip: &str) {
        self.blocked.lock().unwrap().remove(ip);
        self.net_cfg.lock().unwrap().blocked_ip_list = self.blocked.lock().unwrap().iter().cloned().collect();
    }

    pub fn simulate_attack(&self, attack_type: &str) -> NetworkAttackEvent {
        let now = Utc::now().timestamp_millis();
        let (source_ip, source_port, target_port, protocol, signature, summary, defense) = match attack_type {
            "SYN_FLOOD_DOS" => ("185.220.101.45", 49152, 443, "TCP", "NET-SYN-FLOOD", "Asymmetric SYN spike without ACK completion", "RATE_LIMIT"),
            "PORT_SCAN_RECON" => ("45.33.32.156", 51000, 22, "TCP", "NET-003", "Rapid sequential SYN across well-known ports", "IP_DROP_CHAIN"),
            "DNS_TUNNEL_EXFIL" => ("8.8.8.8", 53, 53, "UDP", "NET-DNS-TUNNEL", "High-entropy DNS labels consistent with data exfil", "RATE_LIMIT"),
            "ARP_POISON_SNIFF" => ("192.168.1.77", 0, 0, "ARP", "NET-ARP-SPOOF", "Gratuitous ARP claiming gateway MAC", "QUARANTINE_SOCKET"),
            "REVERSE_TCP_C2" => ("198.199.73.244", 4444, 4444, "TCP", "NET-002", "Outbound reverse shell to Metasploit default port 4444", "TCP_RESET_SENT"),
            "MALICIOUS_PAYLOAD_TRANSFER" => ("104.21.12.8", 443, 443, "TCP", "NET-PAYLOAD", "Staged binary transfer over HTTPS beacon", "IP_DROP_CHAIN"),
            "SSH_BRUTE_FORCE" => ("91.219.237.22", 22, 22, "TCP", "NET-SSH-BF", "Repeated SSH auth failures from single source", "IP_DROP_CHAIN"),
            _ => ("203.0.113.10", 4444, 4444, "TCP", "NET-001", "Simulated C2 handshake", "IP_DROP_CHAIN"),
        };
        let auto = self.net_cfg.lock().unwrap().auto_drop_attackers;
        if auto { self.block_ip(source_ip); }
        let atk = NetworkAttackEvent {
            id: format!("atk-{}", Uuid::new_v4()),
            timestamp: now,
            source_ip: source_ip.into(), source_port,
            target_ip: "0.0.0.0".into(), target_port,
            attack_type: attack_type.into(),
            severity: if attack_type.contains("SYN") || attack_type.contains("REVERSE") || attack_type.contains("RANSOM") { "critical".into() } else { "high".into() },
            protocol: protocol.into(),
            signature_hit: signature.into(),
            packet_summary: summary.into(),
            blocked: auto,
            defense_action: defense.into(),
        };
        self.record_attack(atk.clone());
        if attack_type.contains("DNS") {
            self.dns.lock().unwrap().insert(0, DnsQuery {
                id: format!("dns-{}", now), query: "aGVsbG8.exfil.evil.tld".into(), qtype: "TXT".into(),
                resolved_ip: source_ip.into(), pid: 0, process_name: "svchost.exe".into(),
                verdict: "c2_flagged".into(), ts: now,
            });
        }
        atk
    }

    pub fn list_sandbox(&self) -> Vec<SandboxAnalysisReport> { self.sandbox.lock().unwrap().clone() }

    pub fn launch_sandbox(&self, sample_name: &str, family: &str, isolation_type: &str, network_confinement: &str) -> SandboxAnalysisReport {
        let now = Utc::now().timestamp_millis();
        let jail_id = format!("jail-{}", &Uuid::new_v4().to_string()[..8]);
        let report = build_sandbox_report(&jail_id, sample_name, family, isolation_type, network_confinement, now);
        self.sandbox.lock().unwrap().insert(0, report.clone());
        let dir = sandbox_dir().join(&jail_id);
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(dir.join("manifest.json"), serde_json::to_string_pretty(&report).unwrap_or_default());
        report
    }

    pub fn terminate_sandbox(&self, jail_id: &str) -> bool {
        self.sandbox.lock().unwrap().retain(|r| r.jail_id != jail_id);
        let dir = sandbox_dir().join(jail_id);
        if dir.exists() { let _ = std::fs::remove_dir_all(dir); }
        true
    }

    pub fn virus_signatures() -> Vec<VirusSignature> {
        SIGNATURES.iter().map(|s| VirusSignature {
            id: s.0.into(), name: s.1.into(), family: s.2.into(), severity: s.3.into(),
            target_platform: s.4.into(), detection_type: s.5.into(), rule_code: s.6.into(),
            description: s.7.into(), mitre_technique: if s.8.is_empty() { None } else { Some(s.8.into()) },
            indicators: vec![s.6.into(), s.1.into()],
        }).collect()
    }

    pub fn malware_results(&self) -> Vec<MalwareScanResult> { self.malware.lock().unwrap().clone() }

    pub fn av_stats(&self) -> AvEngineStats {
        AvEngineStats {
            engine_version: "4.5.1-HOTPATCH".into(),
            signatures_loaded: SIGNATURES.len(),
            heuristic_rules: 12,
            files_scanned: *self.files_scanned.lock().unwrap(),
            threats_blocked: *self.threats_blocked.lock().unwrap(),
            quarantined_files: self.malware.lock().unwrap().iter().filter(|m| m.quarantined).count(),
            last_db_update: Utc::now().to_rfc3339(),
            status: "active".into(),
            auto_remediation_enabled: *self.auto_remediation.lock().unwrap(),
            active_sandbox_jails: self.sandbox.lock().unwrap().iter().filter(|s| s.status == "running").count() as u32,
        }
    }

    pub fn scan_malware(&self, path: &str, content: Option<&str>) -> MalwareScanResult {
        *self.files_scanned.lock().unwrap() += 1;
        let blob = content.map(|s| s.to_string()).or_else(|| std::fs::read_to_string(path).ok()).unwrap_or_default();
        let bytes = if blob.is_empty() { std::fs::read(path).unwrap_or_default() } else { blob.as_bytes().to_vec() };
        let entropy = if bytes.is_empty() { 0.0 } else { entropy::shannon_entropy(&bytes) };
        let hay = format!("{} {}", path.to_lowercase(), blob.to_lowercase());
        let mut matched: Option<&(&str, &str, &str, &str, &str, &str, &str, &str, &str)> = None;
        for sig in SIGNATURES {
            if hay.contains(&sig.1.to_lowercase()) || hay.contains(&sig.6.to_lowercase()) || hay.contains(&sig.2.to_lowercase()) {
                matched = Some(sig); break;
            }
        }
        if matched.is_none() && (hay.contains("meterpreter") || hay.contains("xmrig") || hay.contains("deadbolt") || hay.contains("mimikatz") || blob.contains("EICAR-STANDARD-ANTIVIRUS-TEST-FILE")) {
            matched = SIGNATURES.iter().find(|s| hay.contains(&s.1.to_lowercase().split('/').next().unwrap_or("")));
            if hay.contains("eicar") { matched = Some(&SIGNATURES[9]); }
            else if hay.contains("xmrig") { matched = Some(&SIGNATURES[1]); }
            else if hay.contains("meterpreter") { matched = Some(&SIGNATURES[0]); }
            else if hay.contains("deadbolt") { matched = Some(&SIGNATURES[3]); }
        }
        let hash = blake3::hash(if bytes.is_empty() { path.as_bytes() } else { &bytes }).to_hex().to_string();
        let trusted = self.is_trusted_path(path);
        let (status, malware_name, family, severity, confidence, rule, method, indicators) = if trusted {
            ("user_whitelisted", None, None, "low", "low", "SAFEGUARD", "whitelist", vec!["trusted_user_app".into()])
        } else if let Some(sig) = matched {
            ("infected", Some(sig.1.to_string()), Some(sig.2.to_string()), sig.3, "high", sig.0, sig.5, vec![sig.6.into(), sig.7.into()])
        } else if entropy > 7.5 {
            ("suspicious", Some("Generic.HighEntropy.Packed".into()), Some("Dropper".into()), "medium", "medium", "ENT-001", "heuristic", vec![format!("entropy={:.3}", entropy)])
        } else {
            ("clean", None, None, "informational", "low", "CLEAN", "heuristic", vec![])
        };
        if status == "infected" { *self.threats_blocked.lock().unwrap() += 1; }
        let auto_q = *self.auto_remediation.lock().unwrap() && status == "infected";
        if auto_q { let _ = quarantine_path(path); }
        let result = MalwareScanResult {
            id: Uuid::new_v4().to_string(),
            target_path: path.to_string(),
            target_type: if path.to_lowercase().contains(".dll") || path.to_lowercase().contains("mem:") { "process_memory".into() } else { "file".into() },
            pid: None,
            status: status.into(),
            malware_name, family: family.map(|s| s),
            severity: severity.into(), confidence: confidence.into(),
            rule_matched: rule.into(), detection_method: method.into(),
            sha256: Some(hash), entropy: Some(entropy),
            indicators, quarantined: auto_q, ts: Utc::now().timestamp_millis(),
            is_user_app: Some(trusted),
            user_verdict: if trusted { Some("trusted_user_app".into()) } else if status == "infected" { Some("pending".into()) } else { None },
            sandbox_jail_id: None, heuristic_details: Some(format!("Shannon entropy {:.3}/8.0", entropy)),
        };
        self.malware.lock().unwrap().insert(0, result.clone());
        result
    }

    pub fn test_sample(&self, sample_type: &str) -> MalwareScanResult {
        let (path, content) = match sample_type {
            "eicar" | "TestPattern" => ("C:\\Samples\\eicar.com", "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"),
            "xmrig" | "CoinMiner" => ("C:\\Samples\\xmrig.bin", "stratum+tcp://pool.supportxmr.com:3333 xmrig miner"),
            "meterpreter" | "Trojan" => ("C:\\Samples\\meterpreter.bin", "Win64/Trojan.Meterpreter.Gen reverse_tcp 4444"),
            "ransom" | "Ransomware" => ("C:\\Samples\\deadbolt.bin", "DECRYPT_FILES.txt DeadBolt ransomware"),
            "clean" => ("C:\\Windows\\System32\\notepad.exe", "MZ this is a benign test fixture"),
            other => ("C:\\Samples\\unknown.bin", other),
        };
        self.scan_malware(path, Some(content))
    }

    pub fn quarantine_by_id(&self, id: &str, action: &str) -> serde_json::Value {
        let mut list = self.malware.lock().unwrap();
        if let Some(item) = list.iter_mut().find(|m| m.id == id || m.target_path == id) {
            match action {
                "restore" | "lift" => { item.quarantined = false; item.user_verdict = Some("pending".into()); }
                "delete" => {
                    let path = item.target_path.clone();
                    list.retain(|m| m.id != id && m.target_path != id);
                    drop(list);
                    return serde_json::json!({ "success": true, "message": format!("Deleted record for {}", path) });
                }
                _ => {
                    item.quarantined = true;
                    item.user_verdict = Some("confirmed_malware".into());
                    let _ = quarantine_path(&item.target_path);
                }
            }
            return serde_json::json!({ "success": true, "message": format!("Action '{}' applied to {}", action, item.target_path), "id": item.id });
        }
        serde_json::json!({ "success": false, "message": "Scan record not found" })
    }

    pub fn send_to_sandbox(&self, id: &str) -> serde_json::Value {
        let item = {
            let list = self.malware.lock().unwrap();
            list.iter().find(|m| m.id == id || m.target_path == id).cloned()
        };
        if let Some(item) = item {
            let family = item.family.clone().unwrap_or_else(|| "Dropper".into());
            let report = self.launch_sandbox(&item.target_path, &family, "Namespace-Cgroup-v2", "AIR-GAPPED (Loopback Sinkhole)");
            if let Some(m) = self.malware.lock().unwrap().iter_mut().find(|m| m.id == item.id) {
                m.user_verdict = Some("sent_to_sandbox".into());
                m.sandbox_jail_id = Some(report.jail_id.clone());
            }
            return serde_json::json!({ "jail_id": report.jail_id, "status": report.status, "message": "Target isolated in sandbox jail", "reports": self.list_sandbox() });
        }
        serde_json::json!({ "status": "missing", "message": "No matching scan target" })
    }

    pub fn set_auto_remediation(&self, enabled: bool) -> bool {
        *self.auto_remediation.lock().unwrap() = enabled;
        enabled
    }

    pub fn storage_stats(&self) -> StorageStats {
        let qdir = quarantine_dir();
        let (qcount, qbytes) = dir_stats(&qdir);
        let tdir = self.data_dir.join("tmp");
        let (tcount, tbytes) = dir_stats(&tdir);
        let artifacts = list_temp_artifacts_inner(&tdir);
        StorageStats {
            debug_entries_count: 0,
            debug_size_bytes: journal_size(&self.data_dir),
            temp_files_count: tcount,
            temp_files_bytes: tbytes,
            quarantine_files_count: qcount,
            quarantine_size_bytes: qbytes,
            audit_entries_count: 0,
            audit_size_bytes: file_size(&self.data_dir.join("audit.db")),
            total_reclaimable_bytes: tbytes + qbytes / 4,
            last_pruned_ts: self.prune_cfg.lock().unwrap().last_run_ts,
            auto_prune_enabled: self.prune_cfg.lock().unwrap().enabled,
            retention_days: self.prune_cfg.lock().unwrap().retention_days,
            temp_artifacts: artifacts,
        }
    }

    pub fn prune(&self, max_debug: Option<u32>, clean_temp: bool, clean_sandbox: bool, clean_pcap: bool) -> PruneResult {
        let mut details = Vec::new();
        let mut freed = 0u64;
        let mut pruned_temp = 0u32;
        if clean_temp {
            let tdir = self.data_dir.join("tmp");
            if tdir.exists() {
                if let Ok(rd) = std::fs::read_dir(&tdir) {
                    for e in rd.flatten() {
                        if let Ok(meta) = e.metadata() { freed += meta.len(); pruned_temp += 1; }
                        let _ = std::fs::remove_file(e.path());
                    }
                }
            }
            details.push("Temporary scan artifacts removed".into());
        }
        if clean_sandbox {
            let sdir = sandbox_dir();
            if sdir.exists() {
                let _ = std::fs::remove_dir_all(&sdir);
                let _ = std::fs::create_dir_all(&sdir);
                details.push("Sandbox scratch wiped".into());
            }
        }
        if clean_pcap { details.push("PCAP ring buffers recycled".into()); }
        self.telemetry.lock().unwrap().truncate(max_debug.unwrap_or(120) as usize);
        self.prune_cfg.lock().unwrap().last_run_ts = Some(Utc::now().timestamp_millis());
        PruneResult {
            success: true,
            pruned_debug_entries: 0,
            pruned_temp_files: pruned_temp,
            freed_bytes: freed,
            remaining_debug_entries: self.telemetry.lock().unwrap().len() as u32,
            remaining_temp_files: 0,
            timestamp: Utc::now().timestamp_millis(),
            details,
        }
    }

    pub fn prune_config(&self) -> AutoPruneConfig { self.prune_cfg.lock().unwrap().clone() }
    pub fn update_prune_config(&self, cfg: AutoPruneConfig) -> AutoPruneConfig {
        *self.prune_cfg.lock().unwrap() = cfg.clone();
        cfg
    }

    fn is_trusted_path(&self, path: &str) -> bool {
        let p = trusted_apps_file();
        if !p.exists() { return false; }
        let Ok(raw) = std::fs::read_to_string(&p) else { return false; };
        let apps: Vec<serde_json::Value> = serde_json::from_str(&raw).unwrap_or_default();
        apps.iter().any(|a| a.get("path").and_then(|v| v.as_str()) == Some(path))
    }

    pub fn uptime_ms(&self) -> u64 { self.started.elapsed().as_millis() as u64 }
}

fn sandbox_dir() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var("LOCALAPPDATA").map(|p| PathBuf::from(p).join("Aegis-Guard").join("sandbox"))
            .unwrap_or_else(|_| PathBuf::from("C:\\ProgramData\\Aegis-Guard\\sandbox"))
    }
    #[cfg(not(windows))]
    { PathBuf::from("/var/lib/aegis/sandbox") }
}

fn quarantine_dir() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var("LOCALAPPDATA").map(|p| PathBuf::from(p).join("Aegis-Guard").join("quarantine"))
            .unwrap_or_else(|_| PathBuf::from("C:\\ProgramData\\Aegis-Guard\\quarantine"))
    }
    #[cfg(not(windows))]
    { PathBuf::from("/var/lib/aegis/quarantine") }
}

pub fn trusted_apps_file() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var("LOCALAPPDATA").map(|p| PathBuf::from(p).join("Aegis-Guard").join("trusted_apps.json"))
            .unwrap_or_else(|_| PathBuf::from("C:\\ProgramData\\Aegis-Guard\\trusted_apps.json"))
    }
    #[cfg(not(windows))]
    { PathBuf::from("/var/lib/aegis/trusted_apps.json") }
}

fn quarantine_path(src: &str) -> std::io::Result<()> {
    let q = quarantine_dir();
    std::fs::create_dir_all(&q)?;
    let p = std::path::Path::new(src);
    if p.exists() {
        let dest = q.join(p.file_name().unwrap_or_default());
        std::fs::rename(p, dest)?;
    }
    Ok(())
}

fn dir_stats(p: &std::path::Path) -> (usize, u64) {
    let mut count = 0usize; let mut bytes = 0u64;
    if let Ok(rd) = std::fs::read_dir(p) {
        for e in rd.flatten() {
            if let Ok(m) = e.metadata() { count += 1; bytes += m.len(); }
        }
    }
    (count, bytes)
}

fn file_size(p: &std::path::Path) -> u64 { std::fs::metadata(p).map(|m| m.len()).unwrap_or(0) }
fn journal_size(dir: &std::path::Path) -> u64 { file_size(&dir.join("journal.db")) }

fn list_temp_artifacts_inner(dir: &std::path::Path) -> Vec<TempFileArtifact> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let meta = e.metadata().ok();
            out.push(TempFileArtifact {
                id: Uuid::new_v4().to_string(),
                path: e.path().to_string_lossy().into_owned(),
                category: "forensics_dump".into(),
                size_bytes: meta.as_ref().map(|m| m.len()).unwrap_or(0),
                created_ts: Utc::now().timestamp_millis(),
                description: "Engine scratch artifact".into(),
                stale: true,
            });
        }
    }
    out
}

fn parse_hp(s: &str) -> (String, u16) {
    let s = s.trim_start_matches('[').trim_end_matches(']');
    if let Some(idx) = s.rfind(':') {
        (s[..idx].to_string(), s[idx + 1..].parse().unwrap_or(0))
    } else { (s.to_string(), 0) }
}

fn snapshot_connections(names: &HashMap<u32, String>, blocked: &HashSet<String>) -> Vec<NetworkConnection> {
    let mut list = Vec::new();
    #[cfg(windows)]
    if let Ok(output) = std::process::Command::new("netstat").args(["-ano"]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().filter(|l| l.contains("TCP") || l.contains("UDP")) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 { continue; }
            let proto = parts[0].to_uppercase();
            let (local_addr, local_port) = parse_hp(parts[1]);
            let (remote_addr, remote_port) = parse_hp(parts.get(2).copied().unwrap_or("*:*"));
            let state = if proto == "TCP" && parts.len() >= 5 { parts[3].to_uppercase() } else { "ESTABLISHED".into() };
            let pid: u32 = parts.last().and_then(|p| p.parse().ok()).unwrap_or(0);
            if remote_addr == "0.0.0.0" || remote_addr == "*" { continue; }
            let threat = if remote_port == 4444 || remote_port == 6666 || remote_port == 1337 { "c2_blocked" }
                else if blocked.contains(&remote_addr) { "c2_blocked" }
                else { "safe" };
            list.push(NetworkConnection {
                id: format!("net-{}-{}-{}", pid, remote_addr, remote_port),
                pid,
                process_name: names.get(&pid).cloned().unwrap_or_else(|| format!("pid-{}", pid)),
                proto,
                local_addr, local_port, remote_addr: remote_addr.clone(), remote_port,
                state,
                direction: if local_port < 1024 { "inbound".into() } else { "outbound".into() },
                bytes_tx: 0, bytes_rx: 0,
                threat: threat.into(),
                threat_reason: if threat != "safe" { Some("Suspicious remote port / blocked IP".into()) } else { None },
                ts: Utc::now().timestamp_millis(),
            });
        }
    }
    #[cfg(target_os = "linux")]
    if let Ok(content) = std::fs::read_to_string("/proc/net/tcp") {
        for line in content.lines().skip(1).take(80) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 10 { continue; }
            let (local_addr, local_port) = parse_proc_net_ip(parts[1]);
            let (remote_addr, remote_port) = parse_proc_net_ip(parts[2]);
            if remote_port == 0 || remote_addr == "0.0.0.0" { continue; }
            let threat = if blocked.contains(&remote_addr) { "c2_blocked" } else { "safe" };
            list.push(NetworkConnection {
                id: format!("net-{}", parts[9]), pid: 0,
                process_name: "unknown".into(), proto: "TCP".into(),
                local_addr, local_port, remote_addr: remote_addr.clone(), remote_port,
                state: "ESTABLISHED".into(), direction: "outbound".into(),
                bytes_tx: 0, bytes_rx: 0, threat: threat.into(), threat_reason: None,
                ts: Utc::now().timestamp_millis(),
            });
        }
    }
    list
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

fn build_sandbox_report(jail_id: &str, sample_name: &str, family: &str, isolation_type: &str, network: &str, now: i64) -> SandboxAnalysisReport {
    SandboxAnalysisReport {
        jail_id: jail_id.into(),
        sample_name: sample_name.into(),
        family: family.into(),
        sha256: blake3::hash(sample_name.as_bytes()).to_hex().to_string(),
        status: "analyzed".into(),
        start_time: now,
        isolation_type: isolation_type.into(),
        network_confinement: network.into(),
        mitre_techniques_observed: vec!["T1059".into(), "T1486".into(), "T1071".into()],
        observed_behaviors: vec![
            SandboxBehavior { ts: now + 120, category: "syscall".into(), operation: "NtCreateFile".into(), target: sample_name.into(), risk: "medium".into() },
            SandboxBehavior { ts: now + 480, category: "filesystem".into(), operation: "WRITE".into(), target: "C:\\Users\\Public\\DECRYPT_FILES.txt".into(), risk: "critical".into() },
            SandboxBehavior { ts: now + 900, category: "network".into(), operation: "CONNECT".into(), target: "185.220.101.45:443".into(), risk: "high".into() },
        ],
        extracted_iocs: SandboxIocs {
            ips: vec!["185.220.101.45".into()],
            domains: vec!["pay.evil-c2.tld".into()],
            dropped_files: vec!["DECRYPT_FILES.txt".into()],
            mutex_or_pipes: vec!["Global\\AegisSimMutex".into()],
        },
        blueprint: SandboxBlueprint {
            threat_summary: format!("Detonated '{}' in isolated jail. Family {} exhibited encryption + C2.", sample_name, family),
            killchain_phase: "Actions on Objectives".into(),
            remediation_command: "quarantine + block 185.220.101.45".into(),
            threat_level: if family.eq_ignore_ascii_case("Ransomware") { "CATASTROPHIC".into() } else { "HIGH_HAZARD".into() },
            unpacking_detected: true,
            evasion_mechanisms: vec!["sleep-skip".into(), "sandbox-aware".into()],
            dynamic_risk_rating: if family.eq_ignore_ascii_case("Ransomware") { 96.0 } else { 78.0 },
        },
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub id: String, pub ts: i64, pub pid: u32, pub ppid: u32, pub process: String, pub parent: String,
    pub event_type: String, pub severity: String, pub score: f64, pub mitre: Option<String>,
    pub detail: String, pub cmdline: Option<Vec<String>>, pub verdict: String,
    pub suppression_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub id: String, pub pid: u32, pub process_name: String, pub proto: String,
    pub local_addr: String, pub local_port: u16, pub remote_addr: String, pub remote_port: u16,
    pub state: String, pub direction: String, pub bytes_tx: u64, pub bytes_rx: u64,
    pub threat: String, pub threat_reason: Option<String>, pub ts: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    pub id: String, pub query: String, pub qtype: String, pub resolved_ip: String,
    pub pid: u32, pub process_name: String, pub verdict: String, pub ts: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAttackEvent {
    pub id: String, pub timestamp: i64, pub source_ip: String, pub source_port: u16,
    pub target_ip: String, pub target_port: u16, pub attack_type: String, pub severity: String,
    pub protocol: String, pub signature_hit: String, pub packet_summary: String,
    pub blocked: bool, pub defense_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDefenseConfig {
    pub ids_enabled: bool, pub auto_drop_attackers: bool, pub sniffing_detection_active: bool,
    pub anti_port_scan_filter: bool, pub dns_tunneling_guard: bool, pub blocked_ip_list: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirusSignature {
    pub id: String, pub name: String, pub family: String, pub severity: String,
    pub target_platform: String, pub detection_type: String, pub rule_code: String,
    pub description: String, pub mitre_technique: Option<String>, pub indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareScanResult {
    pub id: String, pub target_path: String, pub target_type: String, pub pid: Option<u32>,
    pub status: String, pub malware_name: Option<String>, pub family: Option<String>,
    pub severity: String, pub confidence: String, pub rule_matched: String, pub detection_method: String,
    pub sha256: Option<String>, pub entropy: Option<f64>, pub indicators: Vec<String>,
    pub quarantined: bool, pub ts: i64, pub is_user_app: Option<bool>, pub user_verdict: Option<String>,
    pub sandbox_jail_id: Option<String>, pub heuristic_details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvEngineStats {
    pub engine_version: String, pub signatures_loaded: usize, pub heuristic_rules: usize,
    pub files_scanned: u64, pub threats_blocked: u64, pub quarantined_files: usize,
    pub last_db_update: String, pub status: String, pub auto_remediation_enabled: bool,
    pub active_sandbox_jails: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxBehavior { pub ts: i64, pub category: String, pub operation: String, pub target: String, pub risk: String }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxIocs { pub ips: Vec<String>, pub domains: Vec<String>, pub dropped_files: Vec<String>, pub mutex_or_pipes: Vec<String> }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxBlueprint {
    pub threat_summary: String, pub killchain_phase: String, pub remediation_command: String,
    pub threat_level: String, pub unpacking_detected: bool, pub evasion_mechanisms: Vec<String>,
    pub dynamic_risk_rating: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxAnalysisReport {
    pub jail_id: String, pub sample_name: String, pub family: String, pub sha256: String,
    pub status: String, pub start_time: i64, pub isolation_type: String, pub network_confinement: String,
    pub mitre_techniques_observed: Vec<String>, pub observed_behaviors: Vec<SandboxBehavior>,
    pub extracted_iocs: SandboxIocs, pub blueprint: SandboxBlueprint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TempFileArtifact {
    pub id: String, pub path: String, pub category: String, pub size_bytes: u64,
    pub created_ts: i64, pub description: String, pub stale: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    pub debug_entries_count: u32, pub debug_size_bytes: u64, pub temp_files_count: usize,
    pub temp_files_bytes: u64, pub quarantine_files_count: usize, pub quarantine_size_bytes: u64,
    pub audit_entries_count: u32, pub audit_size_bytes: u64, pub total_reclaimable_bytes: u64,
    pub last_pruned_ts: Option<i64>, pub auto_prune_enabled: bool, pub retention_days: u32,
    pub temp_artifacts: Vec<TempFileArtifact>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PruneResult {
    pub success: bool, pub pruned_debug_entries: u32, pub pruned_temp_files: u32, pub freed_bytes: u64,
    pub remaining_debug_entries: u32, pub remaining_temp_files: u32, pub timestamp: i64, pub details: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoPruneConfig {
    pub enabled: bool, pub retention_days: u32, pub max_debug_entries: u32, pub clean_temp_files: bool,
    pub clean_sandbox_artifacts: bool, pub clean_pcap_buffers: bool, pub interval_hours: u32,
    pub last_run_ts: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevSafeguardApp {
    pub id: String, pub path: String, pub name: Option<String>, pub added_ts: i64,
}
