# Aegis-Guard Cross-Platform Deployment & Native Installation Guide

Aegis-Guard is an endpoint and network security defense suite engineered in **Rust, Go, and React/TypeScript (Tauri v2)**.
It does not require a browser or web server when installed locally; it runs directly as a native system daemon with root/administrator capabilities and a hardware-accelerated desktop UI.

---

## 1. Linux Installation (Debian, Ubuntu, Fedora, Arch, RHEL, openSUSE)

Linux systems require `root` or `sudo` to attach kernel eBPF probes, inspect unprivileged `/proc` file descriptors, and manipulate `iptables` / network namespaces.

### One-Command Quick Run (Zero Setup):
```bash
# Clone or navigate to the project directory:
cd aegis-guard

# Run the automated launcher (builds, configures permissions, and boots engine + UI):
bash aegis.sh
```

### Full Native System Installation (systemd service + desktop double-click launcher):
```bash
bash installers/install-linux.sh
```
What this automated script executes:
1. **Detects Distro & Installs Native Packages:**
   - Debian/Ubuntu/Mint: `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`, `libayatana-appindicator3-dev`, `libssl-dev`
   - Fedora/RHEL: `webkit2gtk4.1-devel`, `gtk3-devel`, `libappindicator-gtk3-devel`
   - Arch/Manjaro: `webkit2gtk-4.1`, `gtk3`, `libappindicator-gtk3`
2. **Builds Release Binaries:**
   - Compiles Rust workspace: `aegis-process-engine` (kernel/proc watcher)
   - Compiles Go network observer: `aegis-network-observer` (pcap socket watcher)
   - Compiles Tauri frontend & embeds UI into `/usr/local/bin/aegis-guard-dashboard`
3. **Registers systemd Services:**
   - `aegis-process-engine.service` (runs as `root` for kernel visibility)
   - `aegis-network-observer.service` (runs as `root` for promiscuous socket capture)
4. **Installs Desktop Launcher:**
   - Double-clicking the **Aegis-Guard** desktop icon starts both daemons seamlessly and launches the desktop app.

---

## 2. Windows Installation (Windows 10, 11, Windows Server)

Windows installations require Administrator rights to interact with the Service Control Manager (`sc.exe`), configure Windows Advanced Firewall, and restrict quarantine ACLs.

### Automated One-Click Install:
Option 1 — Elevated PowerShell One-Liner (No download required):
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/SepJs/aegis-guard/main/installers/install-windows.ps1 | iex"
```

Option 2 — Double-Click Local Batch:
1. Double-click `1-CLICK-INSTALL-WINDOWS.bat` (in the root or `installers/` folder).
2. Accept the Windows UAC Administrator prompt.

What the Windows installer executes:
1. **Elevates Privileges:** Automatically triggers UAC elevation if not already running as Admin.
2. **Verifies Evergreen WebView2:** Ensures the Microsoft WebView2 runtime is present (downloads and silently installs it if missing).
3. **Deploys Dashboard Assets & Native Executable:**
   - Installs the full production dashboard to `C:\Program Files\Aegis-Guard\resources\app\dist`.
   - Deploys `C:\Program Files\Aegis-Guard\Aegis-Guard.exe` (with pre-built release or native Windows host compiler).
4. **Provisions Secure Paths:**
   - Creates `C:\ProgramData\Aegis-Guard` for database logs, honeypot canaries, and audit logs.
   - Creates `C:\ProgramData\Aegis-Guard\quarantine` with strict `icacls` (read/write restricted exclusively to `SYSTEM` and `Administrators`, execution stripped).
5. **Configures Packet Inspection & Firewall:**
   - Adds loopback filtering rules for local IPC telemetry.
6. **Registers Windows Service:**
   - Installs `AegisGuardService` with auto-restart recovery on failure.
7. **Creates Verified Shortcuts:**
   - Installs Desktop and Start Menu shortcuts pointing directly to `Aegis-Guard.exe`.
8. **Instant Launch:**
   - Automatically starts the application window and arms endpoint defense.

---

## 3. Architecture & Engine Verification

| Component | Technology | Privilege | Real OS Interaction |
| :--- | :--- | :--- | :--- |
| **Process Monitor** | Rust (`procfs` + `nix`) | `root` / `SYSTEM` | Reads `/proc`, tracks process lineage trees, kills rogue PIDs via `SIGTERM`/`SIGKILL` |
| **Network Observer** | Go (`gopacket` / `pcap`) | `root` / `SYSTEM` | Sniffs raw sockets, detects ARP poisoning, DNS tunnels, and SYN flood attacks |
| **Active Defense** | Rust (`rusqlite` + `blake3`) | `root` / `SYSTEM` | Enforces namespace isolation (`nsenter`), writes tamper-evident cryptographic hash chains |
| **Shannon Forensics** | Rust (`entropy`) | User / Admin | Reads local files from disk, calculates mathematical entropy (0.0 to 8.0) to spot encrypted payloads |
| **Desktop UI** | Tauri v2 + React | User | Renders via native WebKitGTK (Linux) or WebView2 (Windows), communicating over local IPC sockets |

To build the native binary package for distribution (`.deb`, `.rpm`, or `.msi` / `.exe`):
```bash
cd tauri-app
cargo tauri build
```
The resulting installers will be generated under `tauri-app/src-tauri/target/release/bundle/`.
