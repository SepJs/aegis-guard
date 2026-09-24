export type Confidence = "high" | "medium" | "low";
export type Severity = "critical" | "high" | "medium" | "low" | "informational";
export type ProcKind = "spawned" | "exited" | "anomaly" | "fork" | "exec" | "snapshot";

export interface ScoreFactor {
  name: string;
  impact: number;
  desc: string;
  category: "lineage" | "payload" | "path" | "behavior" | "network" | "suppression";
}

export interface MovementStep {
  ts: number;
  event: string;
  detail: string;
  delta: number;
}

export interface AnomalyDetail {
  rule: string;
  confidence: Confidence;
  reason: string;
  parent_exe: string | null;
  ancestors: number[];
  risk_score?: number;
  severity?: Severity;
  mitre_tactic?: string;
  mitre_technique?: string;
  factors?: ScoreFactor[];
  suppressed?: boolean;
  suppression_reason?: string;
  flags?: string[];
  virus_name?: string;
  virus_family?: string;
}

export interface ProcEvent {
  id: string;
  kind: ProcKind;
  pid: number;
  ppid: number;
  name: string;
  cmdline: string[];
  exe: string | null;
  cwd: string | null;
  uid: number;
  gid: number;
  start_time: number;
  anomaly: AnomalyDetail | null;
  ts: number;
  is_quarantined?: boolean;
}

export interface ThreatIncident {
  id: string;
  kind: string;
  severity: Severity;
  risk_score: number;
  pid: number;
  ppid: number;
  process: string;
  cmdline: string[];
  exe_path: string | null;
  rule: string;
  confidence: Confidence;
  reason: string;
  ancestors: number[];
  ts: string;
  resolved: boolean;
  digest: string;
  mitre_tactic?: string;
  mitre_technique?: string;
  factors?: ScoreFactor[];
  movement_steps?: MovementStep[];
  suppressed?: boolean;
  suppression_reason?: string;
  flags?: string[];
  virus_name?: string;
  virus_family?: string;
}

export interface TelemetryEvent {
  id: string;
  ts: number;
  pid: number;
  ppid: number;
  process: string;
  parent: string;
  event_type: "PROC_SPAWN" | "FILE_DROP" | "PRIV_ESC" | "MEM_ANOMALY" | "SHELL_EXEC" | "EVASION" | "CONFIG_TAMPER" | "CORRELATION" | "FILE_ENCRYPT";
  severity: Severity;
  score: number;
  mitre?: string;
  detail: string;
  cmdline?: string[];
  verdict: "clean" | "suppressed" | "monitored" | "alert";
  suppression_reason?: string;
}

export interface DebugEntry {
  id: string;
  rule: string;
  pid: number;
  process: string;
  ts: string;
  note: string;
  suppression_reason?: string;
  original_score?: number;
  adjusted_score?: number;
  category?: string;
}

export interface ProcessNode extends ProcEvent {
  children: ProcessNode[];
  flagged: boolean;
  seenAt: number;
}

export type RiskLevel = "high" | "medium" | "normal" | "low" | "skipped";
export interface ScanRequest { path: string; max_bytes: number; recursive: boolean }
export interface FileScanResult { path: string; size_bytes: number; entropy: number | null; risk: RiskLevel; mime_guess: string; note: string }
export interface ScanSummary { total_files: number; scanned_files: number; skipped_files: number; high_risk: number; medium_risk: number; results: FileScanResult[]; elapsed_ms: number }

export interface UpdateInfo {
  current_version: string;
  latest_version: string;
  engine_version?: string;
  release_url: string;
  release_notes: string;
  update_available: boolean;
  auto_update_enabled?: boolean;
}

export type ActionKind = "kill" | "quarantine" | "lift_quarantine" | "whitelist";
export interface ActionRequest { pid: number; process_name: string; exe_path: string | null; kind: ActionKind; incident_id: string | null; challenge: string; note: string }
export interface ActionResult { success: boolean; pid: number; action: ActionKind; message: string; ts: number }
export interface AuditEntry { id: string; action: string; pid: number; process: string; incident_id: string | null; note: string; status: string; outcome: string | null; ts_before: number; ts_after: number | null; prev_digest: string; digest: string }
export interface WhitelistEntry { pid: number; process_name: string; exe_path: string | null; added_at: number; note: string }

export interface NetworkConnection {
  id: string;
  pid: number;
  process_name: string;
  proto: "TCP" | "UDP";
  local_addr: string;
  local_port: number;
  remote_addr: string;
  remote_port: number;
  state: "ESTABLISHED" | "LISTEN" | "SYN_SENT" | "CLOSE_WAIT" | "TIME_WAIT";
  direction: "inbound" | "outbound" | "listen";
  bytes_tx: number;
  bytes_rx: number;
  threat: "safe" | "suspicious" | "c2_blocked" | "honeypot";
  threat_reason?: string;
  ts: number;
}

export interface DnsQuery {
  id: string;
  query: string;
  qtype: string;
  resolved_ip: string;
  pid: number;
  process_name: string;
  verdict: "safe" | "c2_flagged" | "suspicious";
  ts: number;
}

export type MalwareFamily =
  | "Trojan"
  | "Backdoor"
  | "CoinMiner"
  | "Ransomware"
  | "Rootkit"
  | "WebShell"
  | "Spyware"
  | "Botnet"
  | "Worm"
  | "InfoStealer"
  | "ExploitKit"
  | "Dropper"
  | "TestPattern"
  | "Adware"
  | "Clean";

export interface VirusSignature {
  id: string;
  name: string;
  family: MalwareFamily;
  severity: Severity;
  target_platform: "Linux" | "CrossPlatform" | "Web";
  detection_type: "hash" | "pattern" | "heuristic" | "yara";
  rule_code: string;
  description: string;
  mitre_technique?: string;
  indicators: string[];
}

export interface MalwareScanResult {
  id: string;
  target_path: string;
  target_type: "file" | "process_memory" | "daemon";
  pid?: number;
  status: "infected" | "suspicious" | "clean" | "user_whitelisted";
  malware_name?: string;
  family?: MalwareFamily;
  severity: Severity;
  confidence: Confidence;
  rule_matched: string;
  detection_method: string;
  sha256?: string;
  entropy?: number;
  indicators: string[];
  quarantined: boolean;
  ts: number;
  is_user_app?: boolean;
  user_verdict?: "pending" | "trusted_user_app" | "confirmed_malware" | "sent_to_sandbox";
  sandbox_jail_id?: string;
  heuristic_details?: string;
}

export interface UserAppWhitelistItem {
  id: string;
  path: string;
  name: string;
  sha256?: string;
  whitelisted_at: number;
  note: string;
}

export interface AvEngineStats {
  engine_version: string;
  signatures_loaded: number;
  heuristic_rules: number;
  files_scanned: number;
  threats_blocked: number;
  quarantined_files: number;
  last_db_update: string;
  status: "active" | "updating" | "paused";
  auto_remediation_enabled: boolean;
  active_sandbox_jails: number;
}

// Sandbox Isolated Execution Jail for Live Virus Analysis
export interface SandboxAnalysisReport {
  jail_id: string;
  sample_name: string;
  family: MalwareFamily;
  sha256: string;
  status: "running" | "analyzed" | "crashed" | "terminated";
  start_time: number;
  isolation_type: "Namespace-Cgroup-v2" | "Seccomp-BPF-Virtual" | "Chroot-Isolated-RAMFS";
  network_confinement: "AIR-GAPPED (Loopback Sinkhole)" | "HONEYPOT-INTERCEPT" | "OFFLINE";
  mitre_techniques_observed: string[];
  observed_behaviors: {
    ts: number;
    category: "syscall" | "filesystem" | "network" | "registry_or_config" | "injection";
    operation: string;
    target: string;
    risk: "critical" | "high" | "medium" | "low";
  }[];
  extracted_iocs: {
    ips: string[];
    domains: string[];
    dropped_files: string[];
    mutex_or_pipes: string[];
  };
  blueprint: {
    threat_summary: string;
    killchain_phase: string;
    remediation_command: string;
    threat_level: "CATASTROPHIC" | "HIGH_HAZARD" | "ELEVATED" | "GUARDED";
    unpacking_detected: boolean;
    evasion_mechanisms: string[];
    dynamic_risk_rating: number; // 0 - 100
  };
}

// Network IDS / Eavesdropping / Attack Packet Sniffing & Active Defense
export interface NetworkAttackEvent {
  id: string;
  timestamp: number;
  source_ip: string;
  source_port: number;
  target_ip: string;
  target_port: number;
  attack_type:
    | "SYN_FLOOD_DOS"
    | "PORT_SCAN_RECON"
    | "SSH_BRUTE_FORCE"
    | "DNS_TUNNEL_EXFIL"
    | "ARP_POISON_SNIFF"
    | "REVERSE_TCP_C2"
    | "MALICIOUS_PAYLOAD_TRANSFER";
  severity: Severity;
  protocol: "TCP" | "UDP" | "ICMP" | "ARP";
  signature_hit: string;
  packet_summary: string;
  blocked: boolean;
  defense_action: "IP_DROP_CHAIN" | "TCP_RESET_SENT" | "RATE_LIMIT" | "QUARANTINE_SOCKET";
}

export interface NetworkDefenseConfig {
  ids_enabled: boolean;
  auto_drop_attackers: boolean;
  sniffing_detection_active: boolean;
  anti_port_scan_filter: boolean;
  dns_tunneling_guard: boolean;
  blocked_ip_list: string[];
}

// Storage Management & Automated Pruning Utilities
export type TempArtifactCategory =
  | "forensics_dump"
  | "sandbox_scratch"
  | "debug_trace"
  | "pcap_buffer"
  | "sig_cache";

export interface TempFileArtifact {
  id: string;
  path: string;
  category: TempArtifactCategory;
  size_bytes: number;
  created_ts: number;
  description: string;
  stale: boolean;
}

export interface StorageStats {
  debug_entries_count: number;
  debug_size_bytes: number;
  temp_files_count: number;
  temp_files_bytes: number;
  quarantine_files_count: number;
  quarantine_size_bytes: number;
  audit_entries_count: number;
  audit_size_bytes: number;
  total_reclaimable_bytes: number;
  last_pruned_ts: number | null;
  auto_prune_enabled: boolean;
  retention_days: number;
  temp_artifacts: TempFileArtifact[];
}

export interface PruneOptions {
  older_than_ms?: number;
  max_debug_entries?: number;
  clean_temp_files?: boolean;
  clean_sandbox?: boolean;
  clean_pcap?: boolean;
}

export interface PruneResult {
  success: boolean;
  pruned_debug_entries: number;
  pruned_temp_files: number;
  freed_bytes: number;
  remaining_debug_entries: number;
  remaining_temp_files: number;
  timestamp: number;
  details: string[];
}

export interface AutoPruneConfig {
  enabled: boolean;
  retention_days: number;
  max_debug_entries: number;
  clean_temp_files: boolean;
  clean_sandbox_artifacts: boolean;
  clean_pcap_buffers: boolean;
  interval_hours: number;
  last_run_ts: number | null;
}


