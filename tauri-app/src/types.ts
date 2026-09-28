/** Shared TypeScript types for AegisGuard frontend */

export type MalwareFamily =
  | "Ransomware"
  | "Rootkit"
  | "WebShell"
  | "CoinMiner"
  | "Trojan"
  | "Backdoor"
  | "InfoStealer"
  | "Spyware";

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
  category: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
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
  created_at?: string;
  runtime_ms?: number;
  blueprint: SandboxBlueprint;
  extracted_iocs: ExtractedIocs;
  mitre_techniques_observed: string[];
  observed_behaviors: ObservedBehavior[];
}

export type Confidence = "Low" | "Medium" | "High" | "Critical";

export interface AnomalyDetail {
  rule: string;
  confidence: Confidence;
  reason: string;
  parent_exe?: string | null;
  ancestors: number[];
}
