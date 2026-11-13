import crypto from "crypto";
import path from "path";

export interface VirusSignature {
  id: string;
  name: string;
  family: string;
  category: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  pattern: string;
  description: string;
  rule_code: string;
  target_platform: string;
  mitre_technique: string;
}

export const VIRUS_SIGNATURES: VirusSignature[] = [
  { id: "AV-000", name: "Standard/Test.EICAR", family: "TestSample", category: "TestFile", severity: "HIGH", pattern: "EICAR-STANDARD-ANTIVIRUS", description: "Industry standard antivirus verification test signature.", rule_code: "AV-SIG-000", target_platform: "All", mitre_technique: "T1204" },
  { id: "AV-001", name: "Generic/Packed.UPX", family: "Packer", category: "Packer", severity: "MEDIUM", pattern: "UPX!", description: "UPX executable packer stub marker.", rule_code: "AV-SIG-001", target_platform: "Cross-Platform", mitre_technique: "T1027" },
  { id: "AV-002", name: "Linux/Miner.XMRig.Stratum", family: "CoinMiner", category: "CoinMiner", severity: "HIGH", pattern: "stratum+tcp://", description: "Cryptocurrency mining stratum pool network protocol.", rule_code: "AV-SIG-002", target_platform: "Linux/Windows", mitre_technique: "T1496" },
  { id: "AV-003", name: "PHP/Webshell.EvalPost", family: "WebShell", category: "WebShell", severity: "HIGH", pattern: "eval($_POST", description: "PHP remote webshell arbitrary execution backdoor.", rule_code: "AV-SIG-003", target_platform: "Web/Linux", mitre_technique: "T1505" },
  { id: "AV-004", name: "Generic/Ransom.DeadBolt", family: "Ransomware", category: "Ransomware", severity: "CRITICAL", pattern: "YOUR FILES HAVE BEEN ENCRYPTED", description: "Extortion ransomware note payload marker.", rule_code: "AV-SIG-004", target_platform: "Windows/Linux", mitre_technique: "T1486" },
  { id: "AV-005", name: "Linux/Ransom.LockBitESXi", family: "Ransomware", category: "Ransomware", severity: "CRITICAL", pattern: "LockBit_ESXi", description: "LockBit hypervisor & Linux ransomware marker.", rule_code: "AV-SIG-005", target_platform: "Linux/ESXi", mitre_technique: "T1486" },
  { id: "AV-006", name: "Linux/Rootkit.Diamorphine", family: "Rootkit", category: "Rootkit", severity: "CRITICAL", pattern: "diamorphine_init", description: "Kernel module LKM stealth rootkit hook.", rule_code: "AV-SIG-006", target_platform: "Linux Kernel", mitre_technique: "T1014" },
  { id: "AV-007", name: "Linux/Backdoor.BPFDoor", family: "Backdoor", category: "Backdoor", severity: "CRITICAL", pattern: "SO_ATTACH_FILTER_MAGIC", description: "BPFDoor stealth magic packet raw socket backdoor.", rule_code: "AV-SIG-007", target_platform: "Linux", mitre_technique: "T1205" },
  { id: "AV-008", name: "Linux/Botnet.Mirai", family: "Botnet", category: "Botnet", severity: "HIGH", pattern: "MIRAI_SCANNER_SYN", description: "Mirai IoT telnet/SSH brute-force botnet scanner.", rule_code: "AV-SIG-008", target_platform: "Linux/IoT", mitre_technique: "T1583" },
  { id: "AV-009", name: "Cloud/Stealer.TeamTNT", family: "InfoStealer", category: "InfoStealer", severity: "CRITICAL", pattern: "tntrecht", description: "TeamTNT cloud credential & worm payload marker.", rule_code: "AV-SIG-009", target_platform: "Linux/Cloud", mitre_technique: "T1552" },
  { id: "AV-010", name: "Linux/Exploit.PwnKit", family: "Exploit", category: "PrivilegeEscalation", severity: "CRITICAL", pattern: "GCONV_PATH=./pkexec", description: "PwnKit CVE-2021-4034 polkit local privilege escalation.", rule_code: "AV-SIG-010", target_platform: "Linux", mitre_technique: "T1068" },
  { id: "AV-011", name: "Shell/Reverse.Netcat", family: "Backdoor", category: "ReverseShell", severity: "CRITICAL", pattern: "nc -e /bin/sh", description: "Netcat spawned interactive reverse command shell.", rule_code: "AV-SIG-011", target_platform: "Linux/Unix", mitre_technique: "T1059" },
  { id: "AV-012", name: "PHP/Webshell.C99Base64", family: "WebShell", category: "WebShell", severity: "HIGH", pattern: "eval(base64_decode(", description: "Obfuscated C99 PHP webshell execution.", rule_code: "AV-SIG-012", target_platform: "Web/Linux", mitre_technique: "T1505.003" },
  { id: "AV-013", name: "Python/Backdoor.PtyRevShell", family: "Backdoor", category: "ReverseShell", severity: "CRITICAL", pattern: "pty.spawn(\"/bin/sh\")", description: "Python socket-to-PTY interactive reverse shell payload.", rule_code: "AV-SIG-013", target_platform: "Cross-Platform", mitre_technique: "T1059.006" },
  { id: "AV-014", name: "Shell/Reverse.DevTcp", family: "Backdoor", category: "ReverseShell", severity: "CRITICAL", pattern: "bash -i >& /dev/tcp/", description: "Bash /dev/tcp interactive C2 shell redirection.", rule_code: "AV-SIG-014", target_platform: "Linux/Unix", mitre_technique: "T1059.004" },
  { id: "AV-015", name: "Linux/Trojan.SliverImplant", family: "Backdoor", category: "C2Implant", severity: "CRITICAL", pattern: "sliverpb.Envelope", description: "Sliver C2 cross-platform implant protobuf envelope marker.", rule_code: "AV-SIG-015", target_platform: "Linux/Windows", mitre_technique: "T1071" },
  { id: "AV-016", name: "Generic/Trojan.ReflectiveLoader", family: "Trojan", category: "MemoryInjection", severity: "CRITICAL", pattern: "ReflectiveLoader", description: "Reflective DLL / in-memory payload loader stub.", rule_code: "AV-SIG-016", target_platform: "Windows/Cross", mitre_technique: "T1055" },
  { id: "AV-017", name: "Linux/Rootkit.LdPreloadShm", family: "Rootkit", category: "PreloadHijack", severity: "HIGH", pattern: "LD_PRELOAD=/dev/shm/", description: "Dynamic linker hijack loading shared library from /dev/shm.", rule_code: "AV-SIG-017", target_platform: "Linux", mitre_technique: "T1574.006" },
  { id: "AV-018", name: "Linux/Miner.KinsingDropper", family: "CoinMiner", category: "CoinMiner", severity: "CRITICAL", pattern: "kdevtmpfsi", description: "Kinsing cryptojacking malware binary & container escape worm marker.", rule_code: "AV-SIG-018", target_platform: "Linux/Container", mitre_technique: "T1496" },
  { id: "AV-019", name: "Perl/Backdoor.SocketShell", family: "Backdoor", category: "ReverseShell", severity: "CRITICAL", pattern: "exec(\"/bin/sh -i\")", description: "Perl interactive TCP socket reverse command shell.", rule_code: "AV-SIG-019", target_platform: "Linux/Unix", mitre_technique: "T1059" },
  { id: "AV-020", name: "Ruby/Backdoor.TCPShell", family: "Backdoor", category: "ReverseShell", severity: "CRITICAL", pattern: "TCPSocket.open(", description: "Ruby socket-redirected interactive remote shell payload.", rule_code: "AV-SIG-020", target_platform: "Cross-Platform", mitre_technique: "T1059" },
  { id: "AV-021", name: "Linux/Trojan.MemfdExec", family: "Trojan", category: "FilelessExec", severity: "CRITICAL", pattern: "memfd_create(", description: "Fileless ELF execution directly from anonymous memory file descriptor.", rule_code: "AV-SIG-021", target_platform: "Linux", mitre_technique: "T1620" },
  { id: "AV-022", name: "Linux/Credential.ShadowDump", family: "InfoStealer", category: "CredentialAccess", severity: "CRITICAL", pattern: "cat /etc/shadow", description: "Direct extraction attempt of host /etc/shadow password hashes.", rule_code: "AV-SIG-022", target_platform: "Linux", mitre_technique: "T1003.008" },
  { id: "AV-023", name: "Generic/Ransom.CobaltEncrypt", family: "Ransomware", category: "Ransomware", severity: "CRITICAL", pattern: "ChaCha20_EncryptDirectory", description: "Recursive stream-cipher ransomware file encryption routine marker.", rule_code: "AV-SIG-023", target_platform: "Cross-Platform", mitre_technique: "T1486" },
];

export function calculateShannonEntropy(buffer: Buffer): number {
  if (!buffer || buffer.length === 0) return 0;
  const freq = new Array<number>(256).fill(0);
  for (let i = 0; i < buffer.length; i++) {
    freq[buffer[i]]++;
  }
  let entropy = 0;
  const len = buffer.length;
  for (let i = 0; i < 256; i++) {
    if (freq[i] > 0) {
      const p = freq[i] / len;
      entropy -= p * Math.log2(p);
    }
  }
  return parseFloat(entropy.toFixed(3));
}

export function toBufferFromArg(content: any): Buffer | null {
  if (content === undefined || content === null) return null;
  if (Buffer.isBuffer(content)) return content;
  if (content instanceof Uint8Array) return Buffer.from(content);
  if (typeof content === "string") {
    if (content.startsWith("base64:")) {
      return Buffer.from(content.slice(7), "base64");
    }
    return Buffer.from(content, "utf8");
  }
  if (Array.isArray(content)) {
    return Buffer.from(content.map((n) => Number(n) & 0xff));
  }
  if (typeof content === "object") {
    const keys = Object.keys(content);
    if (keys.length > 0 && /^\d+$/.test(keys[0])) {
      const arr = new Uint8Array(keys.length);
      for (let i = 0; i < keys.length; i++) {
        arr[i] = Number(content[i] ?? 0) & 0xff;
      }
      return Buffer.from(arr);
    }
  }
  return null;
}

export interface DetectedFileFormat {
  format: string;
  isBenignCompressed: boolean;
  isExecutable: boolean;
  isElf: boolean;
  elfClass?: "32-bit" | "64-bit";
}

export function detectFileFormat(buf: Buffer, targetLabel = ""): DetectedFileFormat {
  const b = buf;
  if (b.length >= 4 && b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) {
    return {
      format: "ELF Binary",
      isBenignCompressed: false,
      isExecutable: true,
      isElf: true,
      elfClass: b.length > 4 && b[4] === 2 ? "64-bit" : "32-bit",
    };
  }
  if (b.length >= 2 && b[0] === 0x4d && b[1] === 0x5a) {
    return { format: "PE/COFF Executable", isBenignCompressed: false, isExecutable: true, isElf: false };
  }
  if (b.length >= 4 && b[0] === 0x50 && b[1] === 0x4b && (b[2] === 0x03 || b[2] === 0x05)) {
    return { format: "ZIP/OpenXML Archive", isBenignCompressed: true, isExecutable: false, isElf: false };
  }
  if (b.length >= 3 && b[0] === 0x1f && b[1] === 0x8b && b[2] === 0x08) {
    return { format: "GZIP Compressed Stream", isBenignCompressed: true, isExecutable: false, isElf: false };
  }
  if (b.length >= 3 && b[0] === 0x42 && b[1] === 0x5a && b[2] === 0x68) {
    return { format: "BZIP2 Archive", isBenignCompressed: true, isExecutable: false, isElf: false };
  }
  if (b.length >= 6 && b[0] === 0xfd && b[1] === 0x37 && b[2] === 0x7a && b[3] === 0x58 && b[4] === 0x5a && b[5] === 0x00) {
    return { format: "XZ Compressed Archive", isBenignCompressed: true, isExecutable: false, isElf: false };
  }
  if (b.length >= 4 && b[0] === 0x28 && b[1] === 0xb5 && b[2] === 0x2f && b[3] === 0xfd) {
    return { format: "Zstandard Archive", isBenignCompressed: true, isExecutable: false, isElf: false };
  }
  if (b.length >= 8 && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) {
    return { format: "PNG Image", isBenignCompressed: true, isExecutable: false, isElf: false };
  }
  if (b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) {
    return { format: "JPEG Image", isBenignCompressed: true, isExecutable: false, isElf: false };
  }
  if (b.length >= 4 && b[0] === 0x25 && b[1] === 0x50 && b[2] === 0x44 && b[3] === 0x46) {
    return { format: "PDF Document", isBenignCompressed: true, isExecutable: false, isElf: false };
  }
  if (b.length >= 4 && b[0] === 0x00 && b[1] === 0x61 && b[2] === 0x73 && b[3] === 0x6d) {
    return { format: "WebAssembly Module", isBenignCompressed: true, isExecutable: false, isElf: false };
  }
  if (b.length >= 15 && b.subarray(0, 15).toString("ascii") === "SQLite format 3") {
    return { format: "SQLite Database", isBenignCompressed: true, isExecutable: false, isElf: false };
  }
  const ext = path.extname(targetLabel).toLowerCase();
  if ([".woff2", ".mp4", ".mp3", ".webm", ".ogg", ".webp", ".avif"].includes(ext)) {
    return { format: `Media/Font (${ext})`, isBenignCompressed: true, isExecutable: false, isElf: false };
  }
  return { format: "Raw/Text Payload", isBenignCompressed: false, isExecutable: false, isElf: false };
}

export function scanBytesWithEngine(
  targetLabel: string,
  buf: Buffer,
  trustedApps: any[],
  threatIntelFeed: Array<{ ioc: string; kind: string; feed: string; threat_type: string; confidence: number }>
): any {
  const sha256 = crypto.createHash("sha256").update(buf).digest("hex");
  const md5 = crypto.createHash("md5").update(buf).digest("hex");
  const entropy = calculateShannonEntropy(buf);
  const format = detectFileFormat(buf, targetLabel);
  const latin1Content = buf.toString("latin1");

  const wl = trustedApps.find((a) => a.path === targetLabel || a.sha256 === sha256);
  if (wl) {
    return {
      id: `res-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      target_path: targetLabel,
      file_path: targetLabel,
      is_infected: false,
      rule_matched: "USER_SAFEGUARD_WHITELIST",
      detection_method: "Developer Safeguard Exclusion",
      user_verdict: "trusted_user_app",
      family: "Trusted",
      category: "Whitelisted",
      confidence: "HIGH",
      entropy,
      file_size: buf.length,
      is_quarantined: false,
      quarantined: false,
      hash_sha256: sha256,
      sha256,
      indicators: [`WHITELISTED:${wl.name || wl.path}`, `FORMAT:${format.format}`],
      remediation_status: "SAFEGUARDED",
      scanned_at: Date.now(),
      status: "user_whitelisted",
    };
  }

  // 1. Threat Intel Cryptographic Hashes (MD5/SHA256)
  const hashHit = threatIntelFeed.find((e) => (e.kind === "sha256" && e.ioc === sha256) || (e.kind === "md5" && e.ioc === md5));
  if (hashHit) {
    return {
      id: `res-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      target_path: targetLabel,
      file_path: targetLabel,
      is_infected: true,
      threat_name: `ThreatIntel/${hashHit.threat_type}`,
      malware_name: `ThreatIntel/${hashHit.threat_type}`,
      rule_matched: `IOC-HASH-${hashHit.kind.toUpperCase()}`,
      detection_method: "Cryptographic Hash Feed Match",
      family: hashHit.threat_type,
      category: hashHit.threat_type,
      confidence: "HIGH",
      entropy,
      file_size: buf.length,
      is_quarantined: false,
      quarantined: false,
      hash_sha256: sha256,
      sha256,
      indicators: [`${hashHit.kind.toUpperCase()}:${hashHit.ioc}`, `FEED:${hashHit.feed}`],
      remediation_status: "UNREMEDIATED",
      scanned_at: Date.now(),
      status: "infected",
    };
  }

  // 2. Binary & String Signature Inspection (skip false hits inside benign ZIP/PNG/PDF unless EICAR)
  for (const sig of VIRUS_SIGNATURES) {
    if (sig.id === "AV-001" && format.isBenignCompressed) continue; // Ignore UPX! inside non-executable compressed images
    if (buf.includes(Buffer.from(sig.pattern, "utf8")) || latin1Content.includes(sig.pattern)) {
      return {
        id: `res-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        target_path: targetLabel,
        file_path: targetLabel,
        is_infected: true,
        threat_name: sig.name,
        malware_name: sig.name,
        rule_matched: `${sig.rule_code}: ${sig.name}`,
        detection_method: "Deep Byte Signature Scan",
        family: sig.family,
        category: sig.category,
        confidence: "HIGH",
        entropy,
        file_size: buf.length,
        is_quarantined: false,
        quarantined: false,
        hash_sha256: sha256,
        sha256,
        indicators: [sig.pattern, `FORMAT:${format.format}`, `SHA256:${sha256.substring(0, 12)}...`, `ENTROPY:${entropy}`],
        remediation_status: "UNREMEDIATED",
        scanned_at: Date.now(),
        status: "infected",
      };
    }
  }

  // 3. ELF Multi-Signal Heuristic Check (memfd_create + ptrace + volatile path / packed ELF)
  if (format.isElf) {
    const hasMemfd = latin1Content.includes("memfd_create");
    const hasPtrace = latin1Content.includes("ptrace");
    const hasLdPreload = latin1Content.includes("LD_PRELOAD");
    const inVolatilePath = /^\/(tmp|dev\/shm|var\/tmp)\//.test(targetLabel);
    const elfSignals = [hasMemfd, hasPtrace, hasLdPreload, inVolatilePath].filter(Boolean).length;

    if (elfSignals >= 2 || (entropy >= 7.75 && buf.length > 2048)) {
      const reasons: string[] = [`FORMAT:ELF-${format.elfClass}`, `ENTROPY:${entropy}/8.0`];
      if (hasMemfd) reasons.push("API:memfd_create");
      if (hasPtrace) reasons.push("API:ptrace");
      if (hasLdPreload) reasons.push("ENV:LD_PRELOAD");
      if (inVolatilePath) reasons.push("PATH:TEMP_VOLATILE");

      return {
        id: `res-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        target_path: targetLabel,
        file_path: targetLabel,
        is_infected: false,
        malware_name: entropy >= 7.75 ? "Heuristic/PackedELF.Dropper" : "Heuristic/ELF.MultiIndicator",
        rule_matched: "HEUR-ELF-001",
        detection_method: "ELF Binary Structure & Entropy Inspection",
        family: "Suspicious",
        category: entropy >= 7.75 ? "PackedExecutable" : "SuspiciousELF",
        confidence: elfSignals >= 2 ? "HIGH" : "MEDIUM",
        entropy,
        file_size: buf.length,
        is_quarantined: false,
        quarantined: false,
        hash_sha256: sha256,
        sha256,
        indicators: reasons,
        remediation_status: "REVIEW_REQUIRED",
        scanned_at: Date.now(),
        status: "suspicious",
      };
    }
  }

  // 4. Legitimate high-entropy compressed formats (PNG/ZIP/GZIP/PDF/WASM) are CLEAN, never false-positived!
  return {
    id: `res-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
    target_path: targetLabel,
    file_path: targetLabel,
    is_infected: false,
    rule_matched: format.isBenignCompressed
      ? `CLEAN (${format.format} verified · ${VIRUS_SIGNATURES.length} signatures checked)`
      : `CLEAN (${VIRUS_SIGNATURES.length} signatures checked)`,
    detection_method: "Deep Byte, Magic Header & Hash Verification",
    family: "Benign",
    category: format.isBenignCompressed ? "CompressedVerified" : "Clean",
    confidence: "HIGH",
    entropy,
    file_size: buf.length,
    is_quarantined: false,
    quarantined: false,
    hash_sha256: sha256,
    sha256,
    indicators: [`FORMAT:${format.format}`, `SHA256:${sha256.substring(0, 12)}...`, `ENTROPY:${entropy}`],
    remediation_status: "CLEAN",
    scanned_at: Date.now(),
    status: "clean",
  };
}

export const BROWSER_NAMES = new Set(["firefox", "firefox-bin", "chromium", "chromium-browser", "chrome", "brave", "msedge", "opera"]);
export const SHELL_NAMES = new Set(["bash", "sh", "dash", "zsh", "fish", "ksh", "ash", "pwsh"]);
export const DEV_TOOLCHAIN_PROCS = new Set([
  "npm", "npx", "yarn", "pnpm", "bun", "node", "nodejs", "tsx", "vite", "esbuild",
  "tsc", "eslint", "jest", "vitest", "cargo", "rustc", "go", "git", "pip", "pip3",
  "ps", "ls", "cat", "head", "tail", "grep", "rg", "find", "awk", "sed", "ss", "ip", "top", "htop",
]);
export const SUSPICIOUS_PATHS = ["/tmp/", "/dev/shm/", "/var/tmp/"];
export const TRUSTED_REGISTRIES = ["registry.npmjs.org", "pypi.org", "github.com", "crates.io", "nodejs.org"];

export function hasOnlyLoopbackUrls(cmdStr: string): boolean {
  const urls = cmdStr.match(/https?:\/\/[^\s'"`]+/gi) || [];
  if (urls.length === 0) return false;
  return urls.every((u) => {
    try {
      const parsed = new URL(u);
      const h = parsed.hostname.toLowerCase();
      return h === "127.0.0.1" || h === "localhost" || h === "::1" || h === "[::1]";
    } catch {
      return false;
    }
  });
}

export function hasExternalRemoteFetch(cmdStr: string, destination = ""): boolean {
  if (!cmdStr.includes("curl") && !cmdStr.includes("wget") && !cmdStr.includes("downloadstring")) {
    return false;
  }
  const combined = `${cmdStr} ${destination}`.toLowerCase();
  if (hasOnlyLoopbackUrls(combined) && (!destination || destination === "127.0.0.1" || destination === "localhost" || destination === "::1")) {
    return false;
  }
  if (TRUSTED_REGISTRIES.some((r) => combined.includes(r))) {
    return false;
  }
  return true;
}

export interface EvalProcessInput {
  pid: number;
  ppid: number;
  uid?: number;
  name: string;
  cmdline: string[];
  exe: string | null;
}

export function shouldPromoteToIncident(anomaly: { risk_score?: number } | null): boolean {
  return Boolean(anomaly && (anomaly.risk_score || 0) >= 70);
}

export function evaluateProcessRules(
  p: EvalProcessInput,
  procByPid: Map<number, EvalProcessInput>
): any | null {
  const childName = p.name.toLowerCase();
  const parent = procByPid.get(p.ppid);
  const parentName = parent ? parent.name.toLowerCase() : "";
  const cmdStr = p.cmdline.join(" ").toLowerCase();
  const exeLower = (p.exe || "").toLowerCase();

  // Never flag standard inspection utilities reading commands (e.g. grep/ps/tail/aegis server itself)
  if (["grep", "rg", "ps", "top", "htop", "tail", "head"].includes(childName)) {
    return null;
  }

  const ancestors: number[] = [];
  let curPpid = p.ppid;
  const seen = new Set<number>();
  while (curPpid > 1 && !seen.has(curPpid)) {
    seen.add(curPpid);
    ancestors.push(curPpid);
    curPpid = procByPid.get(curPpid)?.ppid || 0;
  }

  let detected: any = null;

  // P1 CRITICAL (90-100): Confirmed active reverse shell / interactive C2 redirect
  if (
    /\bnc\s+-e\b/.test(cmdStr) ||
    /\bncat\s+-e\b/.test(cmdStr) ||
    cmdStr.includes("/dev/tcp/") ||
    (cmdStr.includes("mkfifo") && (cmdStr.includes("/bin/sh") || cmdStr.includes("/bin/bash") || cmdStr.includes("nc "))) ||
    (cmdStr.includes("python") && cmdStr.includes("socket") && cmdStr.includes("connect") && (cmdStr.includes("pty.spawn") || cmdStr.includes("dup2")))
  ) {
    detected = {
      rule: "PAR-012",
      confidence: "high",
      risk_score: 95,
      severity: "critical",
      reason: `Reverse shell / interactive C2 pattern detected in '${p.name}' (PID ${p.pid}).`,
      mitre_tactic: "Command and Control",
      mitre_technique: "Reverse Shell (T1059.004)",
      flags: ["REVERSE_SHELL_PATTERN", "P1_CRITICAL"],
      factors: [{ name: "Interactive Reverse Shell", impact: 85, desc: "Network shell redirection in cmdline" }],
    };
  }
  // P1 CRITICAL (90-100): Confirmed cryptominer signature
  else if (
    (childName.includes("xmrig") || cmdStr.includes("stratum+tcp://") || cmdStr.includes("minexmr")) &&
    !["node", "tsx", "vite"].includes(childName)
  ) {
    detected = {
      rule: "PAR-006",
      confidence: "high",
      risk_score: 94,
      severity: "critical",
      reason: `Cryptocurrency miner signature detected in '${p.name}' (PID ${p.pid}).`,
      virus_name: "Linux/Miner.XMRig.Stratum",
      virus_family: "CoinMiner",
      mitre_tactic: "Impact",
      mitre_technique: "Resource Hijacking (T1496)",
      flags: ["VIRUS_SIGNATURE_MATCHED", "STRATUM_PROTOCOL"],
      factors: [{ name: "CoinMiner Signature", impact: 80, desc: "Stratum mining pool indicator" }],
    };
  }
  // P2 HIGH (70-89): Browser spawning interactive shell
  else if (SHELL_NAMES.has(childName) && BROWSER_NAMES.has(parentName)) {
    detected = {
      rule: "PAR-001",
      confidence: "high",
      risk_score: 82,
      severity: "high",
      reason: `Shell '${p.name}' spawned directly by browser '${parent?.name}'. Monitored as High Risk (P2).`,
      mitre_tactic: "Execution",
      mitre_technique: "Command and Scripting Interpreter (T1059)",
      flags: ["BROWSER_TO_SHELL", "P2_HIGH"],
      factors: [{ name: "Browser Child Shell", impact: 65, desc: `${parentName} -> ${childName}` }],
    };
  }
  // P2 HIGH: Scratch space execution ONLY in volatile /dev/shm or hidden /tmp/.dotfile
  else if (
    (exeLower.startsWith("/dev/shm/") || (/^\/(tmp|var\/tmp)\/\./.test(exeLower))) &&
    !DEV_TOOLCHAIN_PROCS.has(childName)
  ) {
    detected = {
      rule: "PATH-001",
      confidence: "high",
      risk_score: 78,
      severity: "high",
      reason: `Executable '${p.name}' launched from volatile/hidden directory '${p.exe}'.`,
      mitre_tactic: "Defense Evasion",
      mitre_technique: "Masquerading (T1036)",
      flags: [exeLower.startsWith("/dev/shm/") ? "SHM_EXECUTION" : "HIDDEN_TMP_EXECUTION"],
      factors: [{ name: "Volatile/Hidden Binary", impact: 60, desc: p.exe || "" }],
    };
  }
  // ARG-001: Only HIGH (78) when corroborated with an EXTERNAL remote fetch + shell/decode pipe;
  // Localhost curls (127.0.0.1 / localhost) or standalone decodes never elevate to High!
  else if (
    !DEV_TOOLCHAIN_PROCS.has(childName) &&
    (cmdStr.includes("base64 -d") || cmdStr.includes("base64 --decode") || cmdStr.includes("frombase64string") || cmdStr.includes("-encodedcommand"))
  ) {
    const extFetch = hasExternalRemoteFetch(cmdStr);
    const hasShellPipe = /\|\s*(sh|bash|zsh|dash|python)/.test(cmdStr);
    if (extFetch && hasShellPipe) {
      detected = {
        rule: "ARG-001",
        confidence: "high",
        risk_score: 80,
        severity: "high",
        reason: `Process '${p.name}' executes external remote payload decoded via base64 into interpreter.`,
        mitre_tactic: "Defense Evasion",
        mitre_technique: "Deobfuscate/Decode Files (T1027)",
        flags: ["BASE64_OBFUSCATION", "EXTERNAL_DROPPER_PIPE"],
        factors: [{ name: "Corroborated Remote Dropper", impact: 68, desc: "External HTTP fetch + base64 decode + shell execution" }],
      };
    } else if (!hasOnlyLoopbackUrls(cmdStr)) {
      // Informational / Low only — NOT promoted to ThreatIncident
      detected = {
        rule: "ARG-001",
        confidence: "low",
        risk_score: 24,
        severity: "low",
        reason: `Process '${p.name}' invoked base64 decoding locally (no remote C2 channel).`,
        mitre_tactic: "Defense Evasion",
        mitre_technique: "Deobfuscate/Decode Files (T1027)",
        flags: ["LOCAL_BASE64_DECODE"],
        factors: [{ name: "Local Decode Utility", impact: 18, desc: "Single low-risk indicator without external fetch" }],
      };
    }
  }
  // P2 HIGH: Deleted executable ONLY if residing inside /tmp, /dev/shm, or /var/tmp (never normal OS/app updates)
  else if (exeLower.endsWith(" (deleted)") && SUSPICIOUS_PATHS.some((m) => exeLower.includes(m))) {
    detected = {
      rule: "PAR-005",
      confidence: "high",
      risk_score: 76,
      severity: "high",
      reason: `Process '${p.name}' (PID ${p.pid}) is running from an unlinked binary deleted from temporary directory: '${p.exe}'.`,
      mitre_tactic: "Defense Evasion",
      mitre_technique: "Indicator Removal (T1070)",
      flags: ["VOLATILE_DELETED_EXECUTABLE"],
      factors: [{ name: "Deleted Volatile Binary", impact: 58, desc: p.exe || "" }],
    };
  }

  if (!detected) return null;

  return {
    ...detected,
    parent_exe: parent?.exe || null,
    ancestors,
  };
}

export function evaluateCommandDryRun(
  args: { cmdline?: string[]; command?: string; process_name?: string; parent_name?: string; destination?: string; uid?: number },
  threatIntelFeed: Array<{ ioc: string; kind: string; feed: string; threat_type: string; confidence: number }>
) {
  const cmdArr: string[] = Array.isArray(args.cmdline)
    ? args.cmdline
    : typeof args.command === "string"
    ? args.command.trim().split(/\s+/)
    : [];
  const cmdStr = cmdArr.join(" ").toLowerCase();
  const procName = (args.process_name || cmdArr[0] || "unknown").toLowerCase();
  const parentName = (args.parent_name || "bash").toLowerCase();
  const dest = (args.destination || "").toLowerCase();
  const uid = Number(args.uid ?? 1000);

  let risk = 5;
  let primaryRule = "BASELINE";
  const flags: string[] = [];
  const factors: any[] = [];
  let mitre_tactic = "Execution";
  let mitre_technique = "Command and Scripting Interpreter (T1059)";
  let virus_match: any = null;

  const webParents = ["nginx", "apache2", "httpd", "php-fpm", "firefox", "chrome", "chromium"];
  const scriptInterpreters = new Set([...SHELL_NAMES, "php", "python", "python3", "perl", "ruby", "node"]);

  const hasDecode = cmdStr.includes("base64 -d") || cmdStr.includes("base64 --decode") || cmdStr.includes("base64_decode") || cmdStr.includes("-encodedcommand") || cmdStr.includes("frombase64string");
  const hasShellPipe = /\|\s*(sh|bash|zsh|dash|python)/.test(cmdStr);

  if (hasDecode) {
    const decodeImpact = hasShellPipe ? 42 : 20;
    risk += decodeImpact;
    primaryRule = "ARG-001";
    flags.push("BASE64_OBFUSCATION");
    factors.push({
      name: hasShellPipe ? "Base64 Execution Pipe" : "Standalone Base64 Decode",
      impact: decodeImpact,
      desc: hasShellPipe ? "Decoded output piped directly into interpreter" : "Local decoding without execution pipe",
    });
    mitre_tactic = "Defense Evasion";
    mitre_technique = "Deobfuscate/Decode Files (T1027)";
  }

  if (cmdStr.includes("curl") || cmdStr.includes("wget") || cmdStr.includes("downloadstring")) {
    const isLoopback = hasOnlyLoopbackUrls(cmdStr) && (!dest || dest === "127.0.0.1" || dest === "localhost" || dest === "::1");
    const fromTrusted = TRUSTED_REGISTRIES.some((r) => dest.includes(r) || cmdStr.includes(r));
    if (isLoopback) {
      flags.push("LOCAL_LOOPBACK_HTTP");
      factors.push({ name: "Loopback API Call", impact: 0, desc: "Localhost IPC/health check (no external ingress)" });
    } else if (fromTrusted && !webParents.includes(parentName)) {
      risk += 5;
      flags.push("DEV_REGISTRY_FETCH");
      factors.push({ name: "Trusted Package Registry Fetch", impact: 5, desc: `Approved registry destination (${dest || "npmjs/github"})` });
    } else {
      risk += 28;
      if (primaryRule === "BASELINE") primaryRule = "NET-001";
      flags.push("INGRESS_TRANSFER");
      factors.push({ name: "External Ingress Tool", impact: 28, desc: "Downloads payload from unverified external host" });
      mitre_tactic = "Command and Control";
      mitre_technique = "Ingress Tool Transfer (T1105)";
    }
  }

  if (cmdStr.includes("/dev/shm/") || /\/(tmp|var\/tmp)\/\./.test(cmdStr)) {
    risk += 35;
    primaryRule = "PATH-001";
    flags.push("EPHEMERAL_HIDDEN_DROP");
    factors.push({ name: "Ephemeral/Hidden Drop Path", impact: 35, desc: "Targets volatile /dev/shm or hidden /tmp dotfile" });
  }

  if (cmdStr.includes("xmrig") || cmdStr.includes("stratum+tcp") || cmdStr.includes("minexmr")) {
    risk += 85;
    primaryRule = "PAR-006";
    flags.push("VIRUS_SIGNATURE");
    factors.push({ name: "CoinMiner Signature", impact: 85, desc: "XMRig / Stratum mining protocol detected" });
    virus_match = { name: "Linux/Miner.XMRig.Stratum", family: "CoinMiner" };
    mitre_tactic = "Impact";
    mitre_technique = "Resource Hijacking (T1496)";
  }

  if (cmdStr.includes("eval($_") || cmdStr.includes("eval(base64_decode(") || cmdStr.includes("$_post")) {
    risk += 70;
    primaryRule = "AV-SIG-012";
    flags.push("WEBSHELL_EXEC", "VIRUS_SIGNATURE");
    factors.push({ name: "WebShell Code Execution", impact: 70, desc: "Obfuscated remote PHP/C99 webshell execution" });
    virus_match = {
      name: cmdStr.includes("base64_decode") ? "PHP/Webshell.C99Base64" : "PHP/Webshell.EvalPost",
      family: "WebShell",
    };
    mitre_tactic = "Persistence";
    mitre_technique = "Server Software Component: Web Shell (T1505.003)";
  }

  if (/\bnc\s+-e\b/.test(cmdStr) || cmdStr.includes("/dev/tcp/") || (cmdStr.includes("mkfifo") && cmdStr.includes("/bin/sh"))) {
    risk += 85;
    primaryRule = "PAR-012";
    flags.push("REVERSE_SHELL");
    factors.push({ name: "Reverse Shell", impact: 85, desc: "Interactive remote shell redirection" });
  }

  if (webParents.includes(parentName) && (scriptInterpreters.has(procName) || procName === "curl" || procName === "wget")) {
    risk += 35;
    if (primaryRule === "BASELINE") primaryRule = "PAR-001";
    flags.push("SUSPICIOUS_PARENTAGE");
    factors.push({ name: "Web/Browser Parentage", impact: 35, desc: `${parentName} (UID ${uid}) spawned ${procName}` });
  }

  const intelHit = dest ? threatIntelFeed.find((e) => e.ioc.toLowerCase() === dest) : null;
  if (intelHit || (dest && (dest.endsWith(".bad") || dest.includes("cobalt-strike") || dest.includes(".onion")))) {
    risk += 45;
    primaryRule = "IOC-C2";
    flags.push("THREAT_INTEL_HIT");
    factors.push({
      name: "Malicious C2 Destination",
      impact: 45,
      desc: intelHit ? `Matched ${dest} in ${intelHit.feed} feed` : `Known malicious host pattern (${dest})`,
    });
  }

  if (DEV_TOOLCHAIN_PROCS.has(procName) && risk <= 15) {
    risk = 5;
    primaryRule = "DEV-SAFE";
    flags.push("DEV_BENIGN");
    factors.push({ name: "Benign Utility Context", impact: -5, desc: "Standard developer/admin diagnostic invocation" });
  }

  const score = Math.min(100, Math.max(0, risk));
  const verdict = score >= 70 ? "alert" : score >= 35 ? "monitored" : flags.includes("DEV_BENIGN") || flags.includes("LOCAL_LOOPBACK_HTTP") ? "suppressed" : "clean";
  const severity =
    score >= 90 ? "critical" : score >= 70 ? "high" : score >= 35 ? "medium" : score >= 15 ? "low" : "informational";

  return {
    verdict,
    score,
    severity,
    rule: primaryRule,
    flags,
    factors,
    mitre_tactic,
    mitre_technique,
    explanation:
      factors.length > 0
        ? `Evaluated '${procName}' (parent: ${parentName}, uid: ${uid}) with ${factors.length} factor(s). Final risk score: ${score}/100.`
        : `No anomalous heuristics triggered for '${procName}'.`,
    virus_match,
  };
}

export interface ProcessAvVerdict {
  infected: boolean;
  suspicious: boolean;
  rule: string;
  threat_name: string;
  family: string;
  severity: "critical" | "high" | "medium";
  sha256: string;
  indicators: string[];
  method: string;
  mitre_technique: string;
}

export function scanProcessForMalware(
  proc: EvalProcessInput,
  exeBuf: Buffer | null,
  trustedApps: any[],
  threatIntelFeed: Array<{ ioc: string; kind: string; feed: string; threat_type: string; confidence: number }>
): ProcessAvVerdict | null {
  const procName = proc.name.toLowerCase();
  if (["grep", "rg", "ps", "top", "htop", "tail", "head", "aegis-process-engine"].includes(procName)) {
    return null;
  }

  const exePath = proc.exe || "";
  if (trustedApps.some((a) => (exePath && a.path === exePath) || a.name === proc.name)) {
    return null;
  }

  // 0. True fileless execution from anonymous memfd or /proc/self/fd/
  if (exePath.startsWith("/memfd:") || exePath.startsWith("memfd:") || exePath.startsWith("/proc/self/fd/")) {
    return {
      infected: true,
      suspicious: false,
      rule: "AV-SIG-021",
      threat_name: "Linux/Trojan.MemfdExec",
      family: "Trojan",
      severity: "critical",
      sha256: crypto.createHash("sha256").update(`${proc.pid}:${exePath}`).digest("hex"),
      indicators: [`EXE:${exePath}`, `PID:${proc.pid}`, "FILELESS_MEMFD_EXEC"],
      method: "Live /proc Exe Target Inspection",
      mitre_technique: "T1620",
    };
  }

  // 1. Scan live executable binary bytes on disk if available
  if (exeBuf && exeBuf.length > 0) {
    const scan = scanBytesWithEngine(exePath || proc.name, exeBuf, trustedApps, threatIntelFeed);
    if (scan.status === "user_whitelisted") return null;
    if (scan.is_infected || scan.status === "suspicious") {
      return {
        infected: Boolean(scan.is_infected),
        suspicious: scan.status === "suspicious",
        rule: scan.rule_matched,
        threat_name: scan.malware_name || scan.threat_name || "Unknown.Malware",
        family: scan.family || "Malware",
        severity: scan.is_infected ? "critical" : "high",
        sha256: scan.sha256,
        indicators: Array.isArray(scan.indicators) ? scan.indicators : [],
        method: scan.detection_method || "Live Process Binary AV Scan",
        mitre_technique: "T1204",
      };
    }
  }

  // 2. Scan runtime command line for explicit active malware payload markers
  const cmdStr = proc.cmdline.join(" ");
  if (cmdStr && !["node", "tsx", "vite", "esbuild"].includes(procName)) {
    for (const sig of VIRUS_SIGNATURES) {
      if (sig.id === "AV-001") continue; // Do not trigger UPX! marker on command-line strings alone
      if (cmdStr.includes(sig.pattern)) {
        return {
          infected: true,
          suspicious: false,
          rule: sig.rule_code,
          threat_name: sig.name,
          family: sig.family,
          severity: sig.severity === "CRITICAL" ? "critical" : "high",
          sha256: crypto.createHash("sha256").update(cmdStr).digest("hex"),
          indicators: [sig.pattern, `PID:${proc.pid}`, `CMD:${proc.name}`],
          method: "Live Runtime Process Signature Scan",
          mitre_technique: sig.mitre_technique,
        };
      }
    }
  }

  return null;
}
