export type Confidence = "high" | "medium" | "low";
export type Severity = "high" | "medium" | "low";
export type ProcKind = "spawned" | "exited" | "anomaly";

export interface AnomalyDetail { rule: string; confidence: Confidence; reason: string; parent_exe: string | null; ancestors: number[] }

export interface ProcEvent {
  id: string; kind: ProcKind; pid: number; ppid: number; name: string;
  cmdline: string[]; exe: string | null; cwd: string | null; uid: number; gid: number;
  start_time: number; anomaly: AnomalyDetail | null; ts: number;
}

export interface ThreatIncident {
  id: string; kind: string; severity: Severity; pid: number; ppid: number; process: string;
  cmdline: string[]; exe_path: string | null; rule: string; confidence: Confidence; reason: string;
  ancestors: number[]; ts: string; resolved: boolean; digest: string;
}

export interface DebugEntry { id: string; rule: string; pid: number; process: string; ts: string; note: string }

export interface ProcessNode extends ProcEvent { children: ProcessNode[]; flagged: boolean; seenAt: number }

export type RiskLevel = "high" | "medium" | "normal" | "low" | "skipped";
export interface ScanRequest { path: string; max_bytes: number; recursive: boolean }
export interface FileScanResult { path: string; size_bytes: number; entropy: number | null; risk: RiskLevel; mime_guess: string; note: string }
export interface ScanSummary { total_files: number; scanned_files: number; skipped_files: number; high_risk: number; medium_risk: number; results: FileScanResult[]; elapsed_ms: number }

export interface UpdateInfo { current_version: string; latest_version: string; release_url: string; release_notes: string; update_available: boolean }

export type ActionKind = "kill" | "quarantine" | "lift_quarantine" | "whitelist";
export interface ActionRequest { pid: number; process_name: string; exe_path: string | null; kind: ActionKind; incident_id: string | null; challenge: string; note: string }
export interface ActionResult { success: boolean; pid: number; action: ActionKind; message: string; ts: number }
export interface AuditEntry { id: string; action: string; pid: number; process: string; incident_id: string | null; note: string; status: string; outcome: string | null; ts_before: number; ts_after: number | null; prev_digest: string; digest: string }
export interface WhitelistEntry { pid: number; process_name: string; exe_path: string | null; added_at: number; note: string }
