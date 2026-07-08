<div align="center">

```
 █████╗ ███████╗ ██████╗ ██╗███████╗      ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
██╔══██╗██╔════╝██╔════╝ ██║██╔════╝     ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
███████║█████╗  ██║  ███╗██║███████╗     ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██╔══██║██╔══╝  ██║   ██║██║╚════██║     ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
██║  ██║███████╗╚██████╔╝██║███████║     ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝      ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
```

**Linux Endpoint Security Suite — Full Stack**

by **Vladimir Unknown**

![Phase](https://img.shields.io/badge/phase-5%20complete-7c3aed?style=flat-square)
![Platform](https://img.shields.io/badge/platform-linux-0d9488?style=flat-square)
![Stack](https://img.shields.io/badge/stack-Rust%20·%20Go%20·%20Tauri%20·%20React-dc2626?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-a78bfa?style=flat-square)

</div>

--- 

## Overview

Aegis-Guard is a modular, behavioral endpoint security suite for Linux. It goes beyond signature-based detection to implement **runtime behavioral analysis**, **network threat detection**, **active response**, and **threat intelligence correlation** — all from a single terminal-dark dashboard.

**No kernel modules. No eBPF. Distro-agnostic (kernel ≥ 4.9).**

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  /proc filesystem  ·  /proc/net  ·  kernel ≥ 4.9            │
└───────┬────────────────────────┬────────────────────────────┘
        │ poll 250ms             │ poll 500ms
        ▼                        ▼
┌───────────────┐    ┌───────────────────────┐
│ Process Engine│    │  Network Observer     │
│ Rust · procfs │    │  Go · /proc/net       │
│               │    │                       │
│ PAR-001..008  │    │  NET-001..005         │
│ PATH-001..004 │    │  IOC matching         │
│ ARG-001..003  │    │  Canary detection     │
│ ENV-001..002  │    └──────────┬────────────┘
│ BEH-001 (ML)  │               │ JSON TCP :50053
└───────┬───────┘               │
        │ Unix Socket           │
        │ /run/aegis/proc.sock  │
        ▼                       ▼
┌─────────────────────────────────────────────────────────────┐
│                    Tauri 2 Backend (Rust)                   │
│  IPC bridge  ·  Net bridge  ·  Phase 5 bridge               │
│  SQLite journal (BLAKE3)  ·  Response engine                │
│  Threat Intel  ·  Behavioral  ·  Self-protect  ·  Canary    │
└───────────────────────────┬─────────────────────────────────┘
                            │ Tauri events
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              Dashboard — React 18 · TypeScript              │
│  Processes  ·  Journal  ·  Forensics  ·  Debug              │
│  Audit Log  ·  Threat Intel  ·  Canary Tokens               │
└─────────────────────────────────────────────────────────────┘
```

---

## Detection Rules

### Phase 1-2: Process Monitoring

| Rule | Description | Confidence |
|------|-------------|------------|
| PAR-001 | Browser spawns shell | HIGH |
| PAR-002 | sshd → shell → network tool chain | HIGH |
| PAR-003 | Office app spawns interpreter | HIGH |
| PAR-004 | systemd --user spawns net process | MEDIUM |
| PAR-005 | Deleted binary still running | MEDIUM |
| PAR-006 | Shell with no TTY, child of PID 1 | MEDIUM |
| PAR-007 | Orphaned process (PPID gone) | LOW |
| PAR-008 | PPID reuse / name mismatch | LOW |
| PATH-001 | Executing from /tmp, /dev/shm | HIGH |
| PATH-002 | Executing from /proc/fd (memfd) | HIGH |
| PATH-003 | Working directory in temp location | MEDIUM |
| PATH-004 | Path contains .. or hidden dirs | MEDIUM |
| ARG-001 | base64/eval//dev/tcp in arguments | HIGH |
| ARG-002 | Shell -c with >256 char script | MEDIUM |
| ARG-003 | argv[0] whitespace / masquerade | LOW |
| ENV-001 | LD_PRELOAD set (library injection) | HIGH |
| ENV-002 | /tmp or . in PATH (hijack) | MEDIUM |

### Phase 3: Network

| Rule | Description | Confidence |
|------|-------------|------------|
| NET-001 | Connection to known C2 port | HIGH |
| NET-002 | Shell/interpreter outbound connection | HIGH |
| NET-003 | Port scan rate (≥20 conns/10s) | HIGH |
| NET-004 | Non-root → unusual privileged port | MEDIUM |
| NET-005 | Browser → RFC1918 (SSRF) | MEDIUM |

### Phase 5: Behavioral + Threat Intel

| Rule | Description | Confidence |
|------|-------------|------------|
| BEH-001 | Z-score deviation from process baseline | HIGH/MEDIUM |
| IOC-IP | IP matches threat intelligence feed | 85-99% |
| IOC-DOM | Domain matches threat intelligence feed | 85-99% |
| IOC-HASH | File hash matches known malware | 99% |
| CANARY | Canary token detected in network traffic | HIGH |

---

## Phase 4: Active Defense

All actions require **challenge token confirmation** and are **BLAKE3-chained audit logged**.

| Action | Mechanism | Reversible |
|--------|-----------|------------|
| Kill | SIGTERM → 5s grace → SIGKILL | ❌ No |
| Quarantine | Network namespace isolation | ✅ Yes |
| Whitelist | Signed allowlist (never flagged again) | ✅ Yes |

**Safety boundaries (hard limits, never bypassed):**
- Never target PID < 100 or kernel threads
- Never target `systemd`, `init`, or `aegis-*` processes
- Kill requires typed challenge token: `CONFIRM-KILL-{PID}`
- Every action written to immutable audit log **before** execution

---

## Quick Start

```bash
# Prerequisites
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
sudo apt install nodejs npm libwebkit2gtk-4.1-dev libgtk-3-dev \
  libayatana-appindicator3-dev libssl-dev --fix-missing

# Setup
sudo bash install/setup.sh

# Terminal 1 — Process Engine (Phase 1-2-5)
sudo AEGIS_LOG=info cargo run -p process-engine

# Terminal 2 — Network Observer (Phase 3-5)
cd network-observer && go mod download
go build -o ../target/aegis-network-observer ./cmd/observer
sudo AEGIS_LOG=info ../target/aegis-network-observer

# Terminal 3 — Dashboard
cd tauri-app && npm install
AEGIS_NET=1 cargo tauri dev
```

---

## Project Structure

```
aegis-guard/
├── crates/
│   ├── process-engine/    # PAR+PATH+ARG+ENV detection, /proc scanner
│   ├── ipc/               # Unix Domain Socket bridge
│   ├── journal/           # SQLite + BLAKE3 tamper-evident log
│   ├── entropy/           # Shannon entropy file scanner
│   ├── updater/           # GitHub release checker
│   ├── active-defense/    # Kill · Quarantine · Whitelist + audit chain
│   ├── threat-intel/      # CTI feed matching (IP/domain/hash)
│   ├── behavioral/        # Process baseline + Z-score anomaly detection
│   ├── deception/         # Canary token system
│   └── self-protect/      # Binary integrity · ptrace detection
├── network-observer/      # Go: /proc/net monitor + NET rules + JSON bridge
├── tauri-app/
│   ├── src-tauri/         # Rust backend: all bridges + Tauri commands
│   └── src/               # React dashboard (7 panel views)
├── proto/aegis.proto      # gRPC schema (Phase 3 full integration)
├── install/setup.sh       # System setup (dirs, systemd units)
└── Makefile
```

---

*Aegis-Guard by Vladimir Unknown — Defensive security for your own machine.*
