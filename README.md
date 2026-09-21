# Aegis-Guard — Native Endpoint Security & Intrusion Detection Suite

[![App Version](https://img.shields.io/badge/App_Version-1.0.0-0d9488?style=flat-square)](https://github.com/SepJs/aegis-guard)
[![Engine Version](https://img.shields.io/badge/Core_Engine-v4.5_%7C_Hotpatch_v4.5.1-6366f1?style=flat-square)](https://github.com/SepJs/aegis-guard)
[![License](https://img.shields.io/badge/License-MIT_or_Apache_2.0-blue?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux_%7C_Windows-orange?style=flat-square)](https://github.com/SepJs/aegis-guard)

**Aegis-Guard** is a high-performance, real-time native endpoint defense and network intrusion detection system (IDS) engineered in **Rust, Go, and React/TypeScript (Tauri v2)**. It provides deep behavioral telemetry, live process lineage inspection, Shannon entropy malware forensics, canary honeypots, and tamper-evident cryptographic audit logs.

---

## Architecture & Real Engine Execution

Aegis-Guard operates with zero mock dependencies:

```
                                  ┌───────────────────────────────┐
                                  │      Desktop Dashboard UI     │
                                  │   (Tauri v2 + React 18 / TS)  │
                                  └───────────────┬───────────────┘
                                                  │ IPC (Unix Socket / Named Pipe)
         ┌────────────────────────────────────────┼────────────────────────────────────────┐
         │                                        │                                        │
         ▼                                        ▼                                        ▼
┌──────────────────┐                    ┌──────────────────┐                    ┌──────────────────┐
│  Process Engine  │                    │ Network Observer │                    │  Active Defense  │
│  (Rust / procfs) │                    │(Go / Raw Sockets)│                    │(BLAKE3 + nsenter)│
└────────┬─────────┘                    └────────┬─────────┘                    └────────┬─────────┘
         │ /proc telemetry                       │ Promiscuous & PCAP                    │ SIGTERM / SIGKILL
         ▼                                       ▼                                       ▼
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    Host Operating System Kernel                                  │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

1. **Native Daemon Mode (Desktop / Production)**:
   - The core process engine runs as a native system daemon (`aegis-process-engine`) inspecting `/proc` lineage, CPU, and RSS memory.
   - The Go network observer (`aegis-network-observer`) attaches to raw network interfaces via PCAP/raw sockets to sniff anomalies and detect packet flooding.
   - The desktop client connects over high-speed IPC sockets (`/run/aegis/engine.sock` on Linux or `\\.\pipe\aegis` on Windows).
2. **Web / Air-Gapped Simulation Engine**:
   - When previewed in a sandboxed web browser, Aegis-Guard automatically activates its internal **Aegis Heuristic Security Engine** (`securityEngine.ts`), providing full live mathematical computation (such as true Shannon entropy $H = -\sum p_i \log_2(p_i)$), simulated process lineage, real-time IDS event emission, and BLAKE3 cryptographic hash verification.

---

## Core Capabilities & Subsystems

### 1. 🛡️ User Application Safeguard (Anti-False-Positive Triage)
- **Heuristic Doubt Engine**: Unlike aggressive commercial AVs that automatically wipe unknown developer scripts or compiled binaries, Aegis-Guard flags suspicious items as `suspicious` rather than instantly deleting them.
- **Three-Way User Verdict Workflow**:
  1. **Trust & Whitelist (Safeguard)**: Marks the binary as your trusted developer tool, exempting it from automated scans and recording its SHA-256 hash.
  2. **Isolate in Sandbox Jail**: Launches the sample inside an air-gapped Linux container (cgroups v2 + mount namespaces) to observe syscalls, dropped files, and network activity safely.
  3. **Confirm Threat & Quarantine**: Neutralizes verified malicious payloads into an encrypted AES-256 quarantine vault (`/var/lib/aegis/quarantine` on Linux, `C:\ProgramData\Aegis-Guard\quarantine` on Windows).

### 2. ⚡ Network Intrusion Detection System (IDS) & Anti-Sniffing
- **Real-Time Attack Detection**:
  - **Packet Sniffing / Promiscuous Mode**: Detects unauthorized packet capture tools (`tcpdump`, `wireshark`, raw AF_PACKET sockets).
  - **SYN Flood Denial-of-Service**: Detects asymmetric TCP half-open connection spikes.
  - **Stealth Port Scan**: Flags SYN/FIN stealth reconnaissance sweeps across system ports.
  - **Reverse TCP C2**: Identifies unauthorized outbound reverse shells connecting to external command-and-control servers.
  - **DNS Tunneling / Data Exfiltration**: Discovers base64-encoded binary exfiltration over recursive DNS queries.
- **Interactive Defense Actions**:
  - **One-Click IP Null-Routing**: Block attacking IP addresses on the host firewall.
  - **Unblock & Lift**: Instantly restore connectivity for false-flagged IPs.
  - **Attack Simulation Suite**: Built-in test buttons to safely trigger and verify each attack signature.

### 3. 🔬 Shannon Entropy File Forensics
- Calculates exact mathematical byte entropy:
  $$H(X) = -\sum_{i=0}^{255} P(x_i) \log_2 P(x_i)$$
- Detects obfuscated payloads, crypters, packed malware (UPX, Themida), and ransomware-encrypted files.
- Generates 256-byte frequency histograms and real-time entropy status classification.

### 4. 🔗 Cryptographic BLAKE3 Audit Chain
- Every remediation action (process kill, quarantine, whitelist, engine update) generates a block linked to the previous entry's cryptographic hash:
  $$\text{Digest}_n = \text{BLAKE3}(\text{Digest}_{n-1} \parallel \text{Action} \parallel \text{PID} \parallel \text{Timestamp})$$
- Built-in audit verifier traverses the chain from genesis to head, guaranteeing that forensic records have not been altered or tampered with.

### 5. 🍯 Canary Honeytokens & Deception Tripwires
- Deploys deceptive decoy files (`.aws/credentials`, `wallet.dat`, `id_rsa`) to detect unauthorized directory traversal or ransomware indexing before production files are touched.

### 6. 🔄 Live Engine Hotpatching & Auto-Update
- **Zero-Downtime Signature Engine**: Live-updates the core threat detection rules from **v4.5** to **v4.5.1-HOTPATCH** with a single click or automatically in the background.
- Logs hotpatch applications directly into the BLAKE3 audit ledger.

---

## Installation Guide

### Option A: Linux Automated 1-Click Install (Recommended)

Run the automated installer script:

```bash
curl -sSL https://raw.githubusercontent.com/SepJs/aegis-guard/main/installers/auto-install.sh | sudo bash
```

Or from a local clone:

```bash
git clone https://github.com/SepJs/aegis-guard.git
cd aegis-guard
sudo bash installers/install-linux.sh
```

**What the Linux installer does:**
1. Detects package manager (`apt`, `dnf`, `pacman`, `zypper`) and installs required native libraries (`webkit2gtk-4.1`, `gtk3`, `libayatana-appindicator3`).
2. Compiles Rust workspace release binaries (`aegis-process-engine`) and Go observer (`aegis-network-observer`).
3. Installs and enables `systemd` background services:
   - `aegis-process-engine.service` (runs as `root` for procfs inspection)
   - `aegis-network-observer.service` (runs as `root` for packet capture)
4. Configures persistent `/run/aegis` runtime socket permissions via `systemd-tmpfiles`.
5. Creates the desktop application launcher (`Aegis-Guard.desktop`).

To uninstall:
```bash
sudo bash installers/uninstall-linux.sh
```

---

### Option B: Windows Installation (Windows 10 / 11 / Server)

Open an **Elevated PowerShell** (Run as Administrator):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/SepJs/aegis-guard/main/installers/install-windows.ps1 | iex"
```

Or run the 1-click batch file:
1. Right-click `installers\1-CLICK-INSTALL-WINDOWS.bat`
2. Select **"Run as administrator"**

**What the Windows installer does:**
1. Requests UAC administrative elevation.
2. Checks for Evergreen Microsoft WebView2 runtime (automatically installs if missing).
3. Provisions secure quarantine paths (`C:\ProgramData\Aegis-Guard\quarantine`) with restrictive access control lists (`icacls`).
4. Registers and starts the `AegisGuardService` background service.
5. Adds Start Menu and Desktop shortcuts.

---

### Option C: Quick Development / Live Preview Mode

To launch and run Aegis-Guard locally without installing system-wide services:

```bash
# Clone the repository
git clone https://github.com/SepJs/aegis-guard.git
cd aegis-guard

# Install Node dependencies
npm install

# Start the live development server (bound to port 3000)
npm run dev
```

Or run the automated Unix launcher script:

```bash
bash aegis.sh
```

---

## Directory Structure

```
aegis-guard/
├── aegis.sh                    # One-command developer launcher
├── Cargo.toml                  # Root Rust workspace manifest
├── Makefile                    # Build & lint automation tasks
├── package.json                # Root npm scripts & dependencies
├── README.md                   # Complete architectural & deployment documentation
├── INSTALLATION.md             # Detailed installation instructions
├── metadata.json               # Application metadata configuration
│
├── crates/                     # Modular Rust backend crates
│   ├── active-defense/         # Process kill, quarantine vault, BLAKE3 audit trail
│   ├── behavioral/             # Process metrics baseline & Z-score anomaly detection
│   ├── deception/              # Canary honeypots & tripwire file monitoring
│   ├── entropy/                # Shannon entropy calculation & byte histogram analysis
│   ├── ipc/                    # Cross-platform IPC socket protocols (Protobuf / JSON)
│   ├── journal/                # SQLite persistent threat incident journal
│   ├── process-engine/         # Linux procfs process lineage & memory inspector
│   ├── self-protect/           # Anti-debugging, ptrace lock, binary tampering protection
│   ├── threat-intel/           # CTI feeds & IOC matching (IPs, domains, hashes)
│   └── updater/                # Semver update checker & GitHub release integration
│
├── network-observer/           # High-speed Go network monitor
│   ├── cmd/observer/           # Main Go daemon entry point
│   ├── internal/netmon/        # Raw socket listener & packet parser
│   └── internal/rules/         # Network attack signatures (SYN flood, DNS tunnel, etc.)
│
├── tauri-app/                  # Desktop application & user interface
│   ├── src/                    # React 18 + TypeScript user interface
│   │   ├── components/         # Modular security panels & dashboards
│   │   │   ├── ForensicsPanel.tsx      # Shannon entropy & User Safeguard triage
│   │   │   ├── NetworkObserverPanel.tsx# IDS attack monitor & IP null-routing
│   │   │   ├── ProcessList.tsx         # Real-time process lineage tree
│   │   │   ├── SandboxPanel.tsx        # Isolated sandbox container inspector
│   │   │   ├── AuditLogPanel.tsx       # Cryptographic BLAKE3 audit chain verifier
│   │   │   ├── CanaryPanel.tsx         # Canary honeypots & breach detection
│   │   │   ├── ThreatIntelPanel.tsx    # IOC threat lookup & intelligence
│   │   │   └── UpdateBanner.tsx        # Live engine hotpatch & update controller
│   │   ├── lib/
│   │   │   ├── engine/securityEngine.ts# Core heuristic security engine & mathematical models
│   │   │   └── ipc/core.ts             # IPC bridge supporting native & sandboxed runtimes
│   │   ├── types/                      # Shared TypeScript data models & interfaces
│   │   ├── App.tsx                     # Main application layout & route controller
│   │   └── styles.css                  # High-contrast dark security workstation theme
│   ├── src-tauri/              # Tauri v2 native Rust desktop wrapper
│   │   ├── src/commands.rs     # Tauri command handlers
│   │   ├── src/lib.rs          # Service bridge & IPC lifecycle manager
│   │   └── tauri.conf.json     # Tauri configuration
│   └── vite.config.ts          # Vite build configuration
│
└── installers/                 # Production deployment scripts
    ├── 1-CLICK-INSTALL-WINDOWS.bat  # Windows 1-click batch installer
    ├── auto-install.sh              # Universal curl-to-bash Linux installer
    ├── install-linux.sh             # Full Linux systemd service installer
    ├── install-windows.ps1          # Windows elevated PowerShell installer
    └── uninstall-linux.sh           # Clean uninstallation script
```

---

## Security Verification & Safety Guarantees

- **Privilege Separation**: The UI runs strictly under user privileges. Privileged operations are mediated across authenticated local IPC sockets.
- **Safety Boundaries**: The active defense engine enforces hard limits: it will never target PID < 100, kernel worker threads, or critical system processes (`systemd`, `init`, `aegis-*`).
- **Cryptographic Tamper-Evidence**: Incident logs and audit entries cannot be manipulated without invalidating the BLAKE3 hash chain.

---

*Aegis-Guard — High-assurance endpoint security and network intrusion defense.*
