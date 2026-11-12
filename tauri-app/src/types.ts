/** Shared TypeScript types for AegisGuard frontend */

export type MalwareFamily =
  | "Ransomware"
  | "Rootkit"
  | "WebShell"
  | "CoinMiner"
  | "Trojan"
  | "Backdoor"
  | "InfoStealer"
  | "Spyware"
  | string;

export interface SandboxBlueprint {
  dynamic_risk_rating: number;
  threat_level: string;
  threat_summary: string;
  killchain_phase: string;
  evasion_mechanisms: string[];
  unpacking_detected: boolean;
  remediation_command: string;
}

export interface ExtractedIocs {
  ips: string[];
  domains: string[];
  dropped_files: string[];
  mutex_or_pipes: string[];
}

export interface ObservedBehavior {
  timestamp: string;
  category?: string;
  description?: string;
  severity?: "low" | "medium" | "high" | "critical" | string;
  risk: "low" | "medium" | "high" | "critical" | string;
  operation?: string;
  target?: string;
  mitre?: string;
}

export interface SandboxAnalysisReport {
  jail_id: string;
  sample_name: string;
  family: MalwareFamily | string;
  status: "running" | "analyzed" | "terminated" | "failed" | string;
  isolation_type: string;
  network_confinement: string;
  sha?: string;
  sha256: string;
  created_at?: string;
  runtime_ms?: number;
  blueprint: SandboxBlueprint;
  extracted_iocs: ExtractedIocs;
  mitre_techniques_observed: string[];
  observed_behaviors: ObservedBehavior[];
}

export type Confidence =
  | "low"
  | "medium"
  | "high"
  | "critical"
  | "Low"
  | "Medium"
  | "High"
  | "Critical";

export type Severity =
  | "low"
  | "medium"
  | "high"
  | "critical"
  | "informational"
  | "Low"
  | "Medium"
  | "High"
  | "Critical"
  | "Informational";

export interface AnomalyFactor {
  name: string;
  impact: number;
  score?: number;
  desc?: string;
  description?: string;
}

export interface AnomalyDetail {
  rule: string;
  confidence: Confidence;
  reason: string;
  parent_exe?: string | null;
  ancestors: number[];
  risk_score?: number;
  severity?: Severity | string;
  virus_name?: string;
  virus_family?: string;
  flags: string[];
  factors: AnomalyFactor[];
  mitre_tactic?: string;
  mitre_technique?: string;
}

export interface ProcessNode {
  id: string;
  pid: number;
  ppid: number;
  uid: number;
  gid?: number;
  name: string;
  cmdline: string[];
  exe?: string | null;
  cwd?: string | null;
  start_time?: number;
  ts: number | string;
  flagged: boolean;
  is_quarantined?: boolean;
  children: ProcessNode[];
  anomaly?: AnomalyDetail | null;
}

export interface IncidentFactor {
  name: string;
  impact: number;
  description?: string;
  desc?: string;
  score?: number;
}

export interface MovementStep {
  step?: string;
  description?: string;
  ts: string | number;
  time?: string;
  event?: string;
  detail?: string;
  delta?: string | number;
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
  virus_name?: string;
  virus_family?: string;
  flags?: string[];
  factors?: IncidentFactor[];
  movement_steps?: MovementStep[];
}

export interface DebugEntry {
  id: string;
  process: string;
  rule: string;
  note: string;
  suppression_reason?: string;
  category?: string;
  ts: number | string;
  pid: number;
  ppid: number;
  cmdline: string[];
  raw_anomaly?: string;
  original_score?: number;
  adjusted_score?: number;
}

export interface TempArtifact {
  id: string;
  path: string;
  category: string;
  size_bytes: number;
  created_at: number | string;
  created_ts: number;
  status: string;
  stale: boolean;
}

export interface StorageStats {
  total_storage_bytes: number;
  db_size_bytes: number;
  debug_size_bytes: number;
  temp_files_bytes: number;
  temp_files_count: number;
  sandbox_artifacts_bytes: number;
  pcap_buffer_bytes: number;
  debug_entries_count: number;
  incidents_count: number;
  audit_entries_count: number;
  temp_artifacts: TempArtifact[];
  last_prune_ts?: number | null;
  last_pruned_ts?: number | null;
  total_reclaimable_bytes: number;
}

export interface AutoPruneConfig {
  enabled: boolean;
  retention_days: number;
  max_debug_entries: number;
  clean_temp_files: boolean;
  clean_sandbox_artifacts: boolean;
  clean_pcap_buffers: boolean;
  interval_hours: number;
}

export interface PruneResult {
  success: boolean;
  freed_bytes: number;
  debug_entries_deleted: number;
  pruned_debug_entries: number;
  temp_files_deleted: number;
  pruned_temp_files: number;
  sandbox_artifacts_deleted: number;
  pcap_buffers_deleted: number;
  timestamp: number | string;
}

export interface FileScanResult {
  path: string;
  entropy?: number | null;
  mime_guess: string;
  size_bytes: number;
  risk: "high" | "medium" | "normal" | "low" | "skipped" | string;
  note: string;
  is_packed?: boolean;
  is_encrypted?: boolean;
}

export interface ScanSummary {
  scanned_count: number;
  scanned_files: number;
  high_risk_count: number;
  high_risk: number;
  medium_risk_count: number;
  clean_count: number;
  skipped_count: number;
  total_bytes: number;
  duration_ms: number;
  elapsed_ms: number;
  results: FileScanResult[];
}

export interface VirusSignature {
  id: string;
  name: string;
  family: string;
  category: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | string;
  pattern: string;
  cve?: string | null;
  description: string;
  rule_code: string;
  target_platform: string;
  mitre_technique?: string;
}

export interface MalwareScanResult {
  id: string;
  target_path: string;
  file_path: string;
  is_infected: boolean;
  threat_name?: string | null;
  malware_name?: string;
  rule_matched: string;
  detection_method: string;
  user_verdict?: string;
  sandbox_jail_id?: string;
  family?: string;
  category?: string;
  confidence: string;
  entropy?: number;
  file_size?: number;
  is_quarantined?: boolean;
  quarantined: boolean;
  hash_sha256?: string;
  sha256?: string;
  indicators: string[];
  remediation_status?: string;
  quarantine_path?: string;
  scanned_at?: string | number;
  status: string;
}

export interface AvEngineStats {
  engine_status: string;
  engine_version: string;
  db_version: string;
  signatures_loaded: number;
  files_scanned: number;
  threats_blocked: number;
  quarantined_count: number;
  quarantined_files: number;
  last_update: string;
  auto_remediation_enabled: boolean;
}

export interface NetworkConnection {
  id: string;
  pid: number;
  process: string;
  process_name: string;
  protocol: string;
  proto: string;
  local_ip: string;
  local_addr: string;
  local_port: number;
  remote_ip: string;
  remote_addr: string;
  remote_port: number;
  state: string;
  direction: string;
  bytes_tx: number;
  bytes_rx: number;
  is_blocked: boolean;
  threat_flag?: string | null;
  threat: string;
  threat_reason?: string;
}

export interface DnsQuery {
  id: string;
  domain: string;
  query: string;
  query_type: string;
  qtype: string;
  client_pid: number;
  process: string;
  process_name: string;
  status: string;
  verdict: string;
  resolved_ip?: string | null;
  threat_score: number;
  ts: number | string;
}

export interface NetworkAttackEvent {
  id: string;
  attack_type: string;
  rule: string;
  severity: string;
  source_ip: string;
  source_port: number;
  target_ip: string;
  target_port: number;
  protocol: string;
  process: string;
  pid: number;
  blocked: boolean;
  details: string;
  packet_summary: string;
  signature_hit: string;
  defense_action: string;
  ts: number | string;
}

export interface NetworkDefenseConfig {
  ids_enabled: boolean;
  auto_drop_attackers?: boolean;
  auto_block_c2?: boolean;
  sniffing_detection_active?: boolean;
  anti_port_scan_filter?: boolean;
  port_scan_threshold?: number;
  syn_flood_protection?: boolean;
  dns_tunneling_guard: boolean;
  capture_interface?: string;
  blocked_ip_list: string[];
}

export interface TelemetryEvent {
  id: string;
  ts: number | string;
  event_type: string;
  process: string;
  parent: string;
  pid: number;
  ppid?: number;
  uid?: number;
  cmdline?: string[];
  exe_path?: string | null;
  score: number;
  verdict: "alert" | "monitored" | "suppressed" | "clean" | string;
  severity?: Severity;
  rule?: string;
  mitre_tactic?: string;
  mitre_technique?: string;
  mitre?: string;
  flags?: string[];
  factors?: { name: string; impact: number; desc?: string }[];
  explanation?: string;
  risk_score?: number;
  detail: string;
  suppression_reason?: string;
}

export interface UpdateInfo {
  current_version: string;
  engine_version: string;
  latest_version: string;
  update_available: boolean;
  release_url?: string;
  release_notes?: string;
  auto_update_enabled?: boolean;
}

export interface CanaryToken {
  id: string;
  token: string;
  file_path: string;
  description: string;
  created_ts: number;
  triggered: boolean;
}

export interface AuditEntry {
  id: string;
  action: string;
  pid: number;
  process: string;
  incident_id: string | null;
  note: string;
  status: string;
  outcome: string | null;
  ts_before: number;
  ts_after: number | null;
  prev_digest: string;
  digest: string;
}

export interface IocStats {
  ips: number;
  cidrs: number;
  domains: number;
  hashes: number;
}

export interface IocMatch {
  ioc: string;
  kind: string;
  threat_type: string;
  feed: string;
  confidence: number;
  context: string;
}
