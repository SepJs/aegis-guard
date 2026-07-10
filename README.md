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

</div>

---

## Quick Start — real installer (recommended)

```bash
bash installers/install-linux.sh
```

Detects your distro (with a manual override menu: Debian/Ubuntu, Fedora/RHEL,
Arch, openSUSE, Alpine), installs the right system packages, builds
everything, and installs it system-wide:

- `aegis-process-engine` + `aegis-network-observer` as **systemd services**
- `/run/aegis` socket directory made persistent across reboots via `systemd-tmpfiles`
- A desktop icon — **"Aegis-Guard"** — that starts both engines and the
  dashboard together with one click, and stops the engines again when you
  close the window
- A narrowly-scoped passwordless sudo rule limited to starting/stopping
  exactly those two services (nothing else)

To uninstall everything: `bash installers/uninstall-linux.sh`

### Alternative: quick dev-mode run (no system install)

```bash
bash aegis.sh
```
Runs everything from the project folder without installing binaries or
services system-wide — good for testing before committing to a full install.

---

## What it does

Behavioral endpoint security for Linux: process lineage, execution paths,
command-line patterns, environment manipulation, network anomalies, threat
intelligence correlation, and active response — all in one dashboard.

No kernel modules. No eBPF. Distro-agnostic (kernel ≥ 4.9).

## Detection Rules

**Process (PAR)** — suspicious parentage: browser→shell, sshd→shell→net-tool, maldoc→interpreter, orphans, PID reuse
**Path (PATH)** — execution from /tmp, memfd_create, path traversal
**Arguments (ARG)** — base64/eval obfuscation, long inline scripts, argv masquerading
**Environment (ENV)** — LD_PRELOAD injection, PATH hijacking
**Network (NET)** — C2 ports, port scans, SSRF, protocol tunnelling
**Behavioral (BEH)** — Z-score deviation from per-process resource baseline
**Threat Intel (IOC)** — IP/domain/hash correlation against CTI feeds
**Canary** — data exfiltration detection via embedded tokens

## Active Defense (Phase 4)

Kill (SIGTERM→grace→SIGKILL) · Quarantine (network isolation) · Whitelist —
all require a typed challenge token and are BLAKE3-chain audit-logged.
Hard safety limits: never targets PID < 100, kernel threads, or `systemd`/`init`/`aegis-*`.

---

## Manual setup (advanced / systemd)

```bash
sudo bash install/setup.sh          # installs systemd services
sudo systemctl start aegis-process-engine
sudo systemctl start aegis-network-observer
cd tauri-app && AEGIS_NET=1 cargo tauri dev
```

## Project Structure

```
aegis-guard/
├── aegis.sh                # ← one-button launcher (start here)
├── crates/                 # 10 Rust crates — engine, IPC, journal, entropy,
│                            #   updater, active-defense, threat-intel,
│                            #   behavioral, deception, self-protect
├── network-observer/        # Go: /proc/net monitor + NET rules
├── tauri-app/                # Rust backend + React 18 dashboard
├── installer/                # optional interactive TUI wizard
└── install/setup.sh          # systemd service installer
```

---

*Aegis-Guard by Vladimir Unknown — Defensive security for your own machine.*
