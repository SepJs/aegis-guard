# Aegis-Guard — Endpoint Security, Antivirus & Network IDS Suite

[![App Version](https://img.shields.io/badge/App_Version-1.2.0-0d9488?style=flat-square)](https://github.com/SepJs/aegis-guard)
[![Engine Version](https://img.shields.io/badge/Core_Engine-v4.6.0-6366f1?style=flat-square)](https://github.com/SepJs/aegis-guard)
[![License](https://img.shields.io/badge/License-MIT_or_Apache_2.0-blue?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux_%7C_macOS_%7C_Windows-orange?style=flat-square)](https://github.com/SepJs/aegis-guard)

**Aegis-Guard** is a native endpoint detection, antivirus, and network intrusion detection suite built with **Rust, Go, TypeScript/Node.js, and React (Tauri v2)**. It combines live OS process and `/proc` behavioral telemetry, multi-signature byte and command-line malware detection, L3/L4 packet inspection, Shannon entropy forensics, canary tripwires, and tamper-evident audit chains.

---

## Architecture

```
                                  +-------------------------------+
                                  |      Dashboard & Console      |
                                  |  (Tauri v2 / React 18 / Web)  |
                                  +---------------+---------------+
                                                  | IPC (/api/ipc + SSE or Local Socket)
         +----------------------------------------+----------------------------------------+
         |                                        |                                        |
         v                                        v                                        v
+------------------+                    +------------------+                    +------------------+
|  Process & AV    |                    | Network Observer |                    |  Active Defense  |
|  Engine (Rust /  |                    | (Go + /proc/net  |                    |  & Audit Chain   |
|  Node Telemetry) |                    |   packet guard)  |                    |  (BLAKE3/SHA-256)|
+--------+---------+                    +--------+---------+                    +--------+---------+
         | /proc, exe bytes                      | socket, ARP, SNMP                     | SIGSTOP/KILL, null-route
         v                                       v                                       v
+--------------------------------------------------------------------------------------------------+
|                                    Host Operating System Kernel                                  |
+--------------------------------------------------------------------------------------------------+
```

1. **Native Engine & Daemon Mode (Desktop / System Service)**:
   - `aegis-process-engine` (Rust crates under `crates/`) inspects `/proc` lineage, CPU/RSS metrics, Shannon entropy, canary files, and maintains a BLAKE3 audit ledger over local IPC (`/run/aegis/engine.sock` on Linux, `\\.\pipe\aegis` on Windows).
   - `aegis-network-observer` (Go daemon under `network-observer/`) monitors L3/L4 flows, SYN floods, port sweeps, ARP collisions, and DNS tunneling via raw sockets / TCP bridge (`127.0.0.1:50053`).
2. **Console & Web Server Mode (`server.ts` + `server-security.ts`)**:
   - Serves the full dashboard on port `3000` with live host `/proc` polling, live process and binary antivirus scanning, directory & upload scanning, `/proc/net` + `/proc/net/snmp` inspection, Go TCP bridge forwarding, persisted system policy (`system_settings.json`), and SHA-256 chained audit records.

---

## Core Capabilities

### 1. Live Antivirus & Malware Detection Engine
- **24 Built-in Malware Signatures (`AV-000` to `AV-023`)**: Covers EICAR, packed UPX ELF binaries, XMRig cryptominers, Kinsing droppers, C99/Weevely webshells, Bash/Python/Perl/Ruby reverse shells, `memfd_create` fileless execution, LD_PRELOAD rootkits, Mirai/Cobalt Strike staging, `/etc/shadow` credential dumping, and AES/ChaCha20 ransomware routines.
- **Live `/proc` Executable & Command Inspection**: Continuously inspects active running processes (`cmdline` + bounded `/proc/<pid>/exe` reads) and flags malicious binaries or scripts with `VIRUS SIGNATURE` rules.
- **Quick System AV Scan & Host Scanner**: One-click full sweep over live `/proc` processes and volatile host staging paths (`/dev/shm`, `/var/tmp`, data vault), alongside recursive directory scanning and binary file upload inspection.
- **Three-Way Suspicious Software Triage**: Ambiguous or custom developer binaries can be moved to **User Apps Safeguard (Whitelist)** with SHA-256 pinning, isolated in a **Read-Only Byte Sandbox**, or confirmed into **`chmod 000` Quarantine**.

### 2. Network IDS & High-Performance Packet Inspector
- **Go Network Observer Bridge + `/proc/net/snmp` Fallback**: Real-time L3/L4 counters (segments/sec, TCP retransmits, SYN_RECV backlog, UDP/ICMP rates), ARP neighbor verification (`/proc/net/arp`), and per-socket process attribution.
- **Automated Anomaly Rules**: Detects SYN floods, horizontal port sweeps, reverse C2 ports, ARP MAC collisions, and high-entropy DNS tunneling queries with manual or automatic IP null-routing.

### 3. Noise-Filtered Behavioral Priority Engine
- Calibration rules distinguish standard system daemons, browsers, runtimes, and desktop services from suspicious execution chains (such as web servers spawning shells, `/tmp` or `/dev/shm` hidden execution, and privilege escalation) so routine workloads do not trigger false `CRITICAL` alerts.

### 4. Shannon Entropy Forensics & Isolated Byte Sandbox
- Computes exact byte-level Shannon entropy ($H(X) = -\sum_{i=0}^{255} P(x_i) \log_2 P(x_i)$) to spot packed executables and encrypted ransomware payloads.
- Isolates inspected targets into `chmod 0400` read-only sandbox vaults with automatic IP, domain, ELF/shebang header, and indicator extraction.

### 5. Runtime Settings & Cryptographic Audit Integrity
- **Persisted System Policies**: Toggle Real-Time Process & Binary AV, Active Process Kill, Syscall Audit, Log Pruner, and UI themes directly from **Settings**, persisted in host storage (`system_settings.json`) and enforced live by the backend.
- **Tamper-Evident Audit Chain**: Every kill, quarantine, whitelist, policy change, and engine update appends a hash-chained audit record (SHA-256 on the Node console server; BLAKE3 in the Rust `active-defense` crate) verifiable from genesis to head.

---

## Multi-Platform Installation (Console & Desktop)

### Linux (Debian / Ubuntu / Fedora / Arch / openSUSE)
```bash
git clone https://github.com/SepJs/aegis-guard.git
cd aegis-guard

# Console / headless server mode (non-interactive)
sudo bash installers/install-linux.sh --console --yes

# Or full native Desktop + Systemd services
sudo bash installers/install-linux.sh --desktop
```
Or run directly via curl:
```bash
curl -fsSL https://raw.githubusercontent.com/SepJs/aegis-guard/main/installers/install-linux.sh | sudo bash -s -- --console --yes
```
Installs the `aegis-guard` CLI command under `/usr/local/bin/aegis-guard`. Run `aegis-guard --console` anytime to launch the console suite on port `3000`.

### macOS (Apple Silicon & Intel)
```bash
git clone https://github.com/SepJs/aegis-guard.git
cd aegis-guard

# Console mode (auto-configures Homebrew Node/Rust/Go paths)
bash installers/install-macos.sh --console --yes

# Or native macOS Desktop build
bash installers/install-macos.sh --desktop
```
Installs `aegis-guard` into `/opt/homebrew/bin` (Apple Silicon) or `/usr/local/bin` (Intel).

### Windows 10 / 11 / Server (Administrator PowerShell)
```powershell
git clone https://github.com/SepJs/aegis-guard.git
cd aegis-guard

# Console mode (configures Defender exclusions, firewall port 3000, and PATH CLI)
powershell -NoProfile -ExecutionPolicy Bypass -File installers\install-windows.ps1 -ConsoleOnly

# Or Desktop + Windows Service mode
powershell -NoProfile -ExecutionPolicy Bypass -File installers\install-windows.ps1
```
You can also double-click or run `installers\install-windows.bat` as Administrator.

### Quick Cross-Platform Dev / Console Launch
```bash
bash aegis.sh --console
```

For full details, uninstall instructions, and per-OS filesystem paths, see [INSTALLATION.md](./INSTALLATION.md).

---

## Directory Structure

```
aegis-guard/
├── README.md
├── INSTALLATION.md
├── Cargo.toml                      # Rust workspace manifest
├── Makefile                        # Build & console targets (`make run-console`)
├── package.json                    # Root server & frontend scripts (v1.2.0)
├── aegis.sh                        # Cross-platform Unix console/desktop launcher
├── server.ts                       # Node/Express IPC, telemetry & live AV server
├── server-security.ts              # 24 AV signatures, Shannon entropy & threat scoring
├── server-security.test.ts         # Unit tests for AV detection & scoring logic
│
├── crates/                         # Native Rust security crates
│   ├── active-defense/             # Signal enforcement, quarantine & BLAKE3 ledger
│   ├── behavioral/                 # Baseline & anomaly scoring
│   ├── deception/                  # Canary tokens & tripwires
│   ├── entropy/                    # Shannon forensics & signatures
│   ├── ipc/                        # Local IPC protocol
│   ├── journal/                    # SQLite incident store
│   ├── process-engine/             # /proc lineage & rule engine
│   ├── self-protect/               # Anti-tamper guard
│   ├── threat-intel/               # IOC feeds & matcher
│   └── updater/                    # Release update verifier
│
├── network-observer/               # Go L3/L4 packet inspection & IDS daemon
├── tauri-app/                      # React 18 UI + Tauri v2 desktop wrapper
│   ├── src/                        # Components, hooks, IPC bridge, styles
│   └── src-tauri/                  # Rust Tauri command bindings
│
├── installers/                     # Platform installers & uninstaller
│   ├── install-linux.sh            # Linux Console & Desktop installer
│   ├── install-macos.sh            # macOS Console & Desktop installer
│   ├── install-windows.ps1         # Windows PowerShell installer
│   ├── install-windows.bat         # Windows batch wrapper
│   ├── install-desktop-launcher.sh # Linux .desktop shortcut helper
│   ├── setup-systemd.sh            # Systemd service setup
│   └── uninstall-linux.sh          # Clean Linux uninstaller
│
├── installer/                      # Interactive Rust terminal installer crate
├── resources/                      # Desktop entries & systemd templates
└── proto/                          # Shared protobuf definitions
```

---

## Verification & Safety Guarantees

- **Protected Kernel & System PIDs**: Active defense refuses to target PID `< 100`, kernel worker threads, `systemd`/`init`, or `aegis-*` processes.
- **Privilege Separation**: The web/desktop UI never runs with direct kernel privileges; operations pass through validated IPC endpoints and policy checks.
- **Cryptographic Auditability**: Remediation actions append tamper-evident records linked to prior digests.
