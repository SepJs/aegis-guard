// types/index.ts — shared TypeScript types (mirrors Rust models)

export type Confidence = "high" | "medium" | "low";
export type Severity   = "high" | "medium" | "low";
export type ProcKind   = "spawned" | "exited" | "anomaly";

export interface AnomalyDetail {
  rule:       string;
  confidence: Confidence;
  reason:     string;
  parent_exe: string | null;
  ancestors:  number[];
}

// Live event from process-engine via IPC socket
export interface ProcEvent {
  id:         string;
  kind:       ProcKind;
  pid:        number;
  ppid:       number;
  name:       string;
  cmdline:    string[];
  exe:        string | null;
  cwd:        string | null;
  uid:        number;
  gid:        number;
  start_time: number;
  anomaly:    AnomalyDetail | null;
  ts:         number; // Unix ms
}

// Persisted threat record from SQLite journal
export interface ThreatIncident {
  id:         string;
  kind:       string;
  severity:   Severity;
  pid:        number;
  ppid:       number;
  process:    string;
  cmdline:    string[];
  exe_path:   string | null;
  rule:       string;
  confidence: Confidence;
  reason:     string;
  ancestors:  number[];
  ts:         string; // ISO datetime
  resolved:   boolean;
  digest:     string;
}

export interface DebugEntry {
  id:      string;
  rule:    string;
  pid:     number;
  process: string;
  ts:      string;
  note:    string;
}

// Process node for the live tree (built from ProcEvent stream)
export interface ProcessNode extends ProcEvent {
  children:  ProcessNode[];
  flagged:   boolean;
  seenAt:    number; // timestamp when first seen
}

// ── Entropy scanner types ─────────────────────────────────────────────────────

export type RiskLevel = "high" | "medium" | "normal" | "low" | "skipped";

export interface ScanRequest {
  path:      string;
  max_bytes: number;
  recursive: boolean;
}

export interface FileScanResult {
  path:       string;
  size_bytes: number;
  entropy:    number | null;
  risk:       RiskLevel;
  mime_guess: string;
  note:       string;
}

export interface ScanSummary {
  total_files:   number;
  scanned_files: number;
  skipped_files: number;
  high_risk:     number;
  medium_risk:   number;
  results:       FileScanResult[];
  elapsed_ms:    number;
}

// ── Updater types ─────────────────────────────────────────────────────────────

export interface UpdateInfo {
  current_version:  string;
  latest_version:   string;
  release_url:      string;
  release_notes:    string;
  update_available: boolean;
}
