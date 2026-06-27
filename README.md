<div align="center">

```
 ▄▄▄       ▓█████   ▄████  ██▓  ██████
▒████▄     ▓█   ▀  ██▒ ▀█▒▓██▒▒██    ▒
▒██  ▀█▄   ▒███   ▒██░▄▄▄░▒██▒░ ▓██▄
░██▄▄▄▄██  ▒▓█  ▄ ░▓█  ██▓░██░  ▒   ██▒
 ▓█   ▓██▒ ░▒████▒░▒▓███▀▒░██░▒██████▒▒
 ▒▒   ▓▒█░ ░░ ▒░ ░ ░▒   ▒ ░▓  ▒ ▒▓▒ ▒ ░
  ▒   ▒▒ ░  ░ ░  ░  ░   ░  ▒ ░░ ░▒  ░ ░
  ░   ▒       ░   ░ ░   ░  ▒ ░░  ░  ░
      ░  ░    ░  ░      ░  ░        ░

         G U A R D
```

**Linux Endpoint Security Suite**
by **Vladimir Unknown**

![Phase](https://img.shields.io/badge/phase-2-7c3aed?style=flat-square)
![Platform](https://img.shields.io/badge/platform-linux-0d9488?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-a78bfa?style=flat-square)
![Stack](https://img.shields.io/badge/stack-Rust%20%2B%20Go%20%2B%20Tauri%20%2B%20React-dc2626?style=flat-square)

</div>

---

## What is Aegis-Guard?

Aegis-Guard is a modular, behavioral endpoint security suite for Linux. It moves beyond signature-based detection to implement **runtime behavioral analysis** — monitoring process lineage, execution paths, command-line patterns, and environment manipulation in real time.

**No kernel modules. No eBPF. No root required for most checks.**
Everything runs through standard `/proc` filesystem APIs — fully distro-agnostic on kernel ≥ 4.9.

---

## Detection Rules (Phase 2)

### PAR — Suspicious Process Parentage
| Rule | Pattern | Confidence |
|------|---------|------------|
| PAR-001 | Browser spawns shell (firefox → bash) | HIGH |
| PAR-002 | sshd → shell → network tool chain | HIGH |
| PAR-003 | Office app spawns interpreter | HIGH |
| PAR-004 | systemd --user spawns unlisted net process | MEDIUM |
| PAR-005 | Binary deleted from disk while running | MEDIUM |
| PAR-006 | Shell with no TTY, direct child of PID 1 | MEDIUM |
| PAR-007 | Orphaned process (PPID not in /proc) | LOW |
| PAR-008 | PPID reuse / parent name mismatch | LOW |

### PATH — Anomalous Execution Paths
| Rule | Pattern | Confidence |
|------|---------|------------|
| PATH-001 | Executing from /tmp, /dev/shm, /var/tmp | HIGH |
| PATH-002 | Executing from /proc/fd (memfd_create) | HIGH |
| PATH-003 | Working directory in temp location | MEDIUM |
| PATH-004 | Path contains .. or hidden directories | MEDIUM |

### ARG — Command-line Obfuscation
| Rule | Pattern | Confidence |
|------|---------|------------|
| ARG-001 | base64/eval//dev/tcp in arguments | HIGH |
| ARG-002 | Shell -c with >256 char inline script | MEDIUM |
| ARG-003 | argv[0] whitespace or comm mismatch | LOW |

### ENV — Environment Manipulation
| Rule | Pattern | Confidence |
|------|---------|------------|
| ENV-001 | LD_PRELOAD set (library injection) | HIGH |
| ENV-002 | . or /tmp in PATH (command hijack) | MEDIUM |

---

## Architecture

```
/proc filesystem
      │
      ▼ poll 250ms
┌─────────────────┐
│  Process Engine │  Rust · procfs 0.17
│  PAR + PATH     │
│  ARG + ENV rules│
└────────┬────────┘
         │ Unix Domain Socket
         │ /run/aegis/proc.sock
         │ 4-byte length prefix + JSON
         ▼
┌─────────────────┐
│  Tauri Backend  │  Rust · tokio
│  IPC bridge     │
│  SQLite journal │  BLAKE3 tamper-evident
└────────┬────────┘
         │ Tauri events
         ▼
┌─────────────────┐
│  Dashboard UI   │  React 18 · TypeScript
│  Process tree   │
│  Threat journal │
│  File forensics │
│  Debug log      │
└─────────────────┘
```

---

## Quick Start

```bash
# 1. Prerequisites
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
sudo apt install nodejs npm libwebkit2gtk-4.1-dev libgtk-3-dev \
                 libayatana-appindicator3-dev libssl-dev

# 2. First-time setup (creates /run/aegis/, systemd unit)
sudo bash install/setup.sh

# 3. Terminal 1 — start process engine
sudo AEGIS_LOG=info cargo run -p process-engine

# 4. Terminal 2 — start dashboard
cd tauri-app
npm install
cargo install tauri-cli --version "^2.0"
cargo tauri dev
```

---

## Project Structure

```
aegis-guard/
├── crates/
│   ├── process-engine/   # /proc scanner + all detection rules
│   ├── ipc/              # Unix Domain Socket bridge
│   ├── journal/          # SQLite + BLAKE3 threat journal
│   ├── entropy/          # Shannon entropy file scanner
│   └── updater/          # GitHub release version checker
├── tauri-app/
│   ├── src-tauri/        # Tauri/Rust backend + commands
│   └── src/              # React 18 + TypeScript dashboard
└── install/
    └── setup.sh          # Linux system setup script
```

---

## Roadmap

- [x] Phase 1 — Process monitoring (PAR rules) + SQLite journal + Entropy scanner
- [x] Phase 2 — Anomalous path detection (PATH + ARG + ENV rules)
- [x] Phase 3 — Network observer (Go + netlink) + gRPC transport
- [ ] Phase 4 — Response actions (Kill · Quarantine · Whitelist)
- [ ] Phase 5 — Active defense + kill switch (with safety boundaries)

---

## Caveats

- **Phase 1–2 is passive only** — detection, logging, and alerting. No process termination or blocking.
- Designed for **defensive security testing on your own machine**.
- Requires `root` to read `/proc` entries for all PIDs (or run process-engine as root only).

---

<div align="center">

**Aegis-Guard** · by Vladimir Unknown · MIT License

</div>
