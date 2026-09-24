# Aegis-Guard Cross-Platform Deployment & Native Installation Guide

Aegis-Guard is an endpoint and network security defense suite engineered in **Rust, Go, and React/TypeScript (Tauri v2)**.
It runs as a native system daemon with root/administrator capabilities, in-kernel eBPF socket filters, and a hardware-accelerated desktop UI.

### ⚡ Architecture: Direct In-Memory Native Runtime (Zero Localhost Web Server)
- **No Localhost Dependency:** Unlike web wrappers, the frontend assets are compiled and embedded directly inside the native binary (`tauri-app/dist` -> Rust executable).
- **Direct IPC / Memory Pointers:** IPC between the UI and security engines occurs via direct in-process pipes and native OS bindings, requiring **zero open localhost ports** and eliminating port hijacking vectors.
- **Embedded Webview:** Renders natively via Microsoft Edge WebView2 on Windows and WebKitGTK on Linux.

---

## Folder Structure Overview

```text
aegis-guard/
├── crates/                    # High-performance Rust security engines
│   ├── process-engine/        # Process lineage & memory anomaly watcher
│   ├── ebpf-filter/           # In-kernel eBPF socket filter (SO_ATTACH_BPF)
│   ├── behavioral/            # Multi-stage killchain & risk scoring
│   ├── active-defense/        # Mitigation, process isolation & quarantine
│   ├── threat-intel/          # Real-time IOC feeds & local bloom filter
│   ├── deception/             # Honeypot decoy canaries & tripwires
│   ├── entropy/               # Shannon entropy payload scanner
│   ├── journal/               # Cryptographic tamper-proof audit journal
│   ├── updater/               # In-place binary signature verification
│   └── installer/             # Rust native interactive installer CLI
├── network-observer/          # Go high-throughput network IDS & packet sniffer
├── tauri-app/                 # Desktop UI (React 18, TypeScript, Tailwind CSS, Recharts)
├── installers/                # Dedicated platform deployment suites
│   ├── windows/               # Windows deployment suites
│   │   ├── aegis-setup.iss    # Official Inno Setup 6 Wizard script (Industry Standard)
│   │   ├── AegisGuard.nsi     # Nullsoft Scriptable Install System (NSIS) script
│   │   ├── install-windows.ps1# PowerShell automated installer with service setup
│   │   └── install-windows.bat# Double-click UAC auto-elevating batch installer
│   └── linux/                 # Linux deployment suites
│       ├── install-linux.sh   # High-quality interactive console/CLI installer
│       ├── auto-install.sh    # Non-interactive 1-liner auto installer
│       └── uninstall-linux.sh # Complete uninstaller script
├── resources/                 # Icons, YARA rules, signatures, decoy templates
└── 1-CLICK-INSTALL-WINDOWS.bat# Convenience root launcher for Windows
```

---

## 1. Linux Installation (Debian, Ubuntu, Fedora, Arch, RHEL, openSUSE)

Linux systems require `root` or `sudo` to attach kernel eBPF probes, inspect unprivileged `/proc` file descriptors, and manipulate packet filters.

### Interactive Console / CLI Installer:
Run the high-quality interactive terminal installer:
```bash
sudo bash installers/linux/install-linux.sh
```

**Features of the Linux Console Installer:**
- **Terminal UI (TUI):** Aesthetic Unicode box-drawing banners, color-coded status pills, and progress indicators.
- **Hardware & Distro Auto-Detection:** Automatically detects architecture (`x86_64`, `aarch64`, `armv7l`) and package manager (`apt`, `dnf`, `pacman`, `zypper`, `apk`).
- **Interactive Profiles:**
  1. Full Production Suite (EDR Daemon + eBPF Observer + Desktop GUI App)
  2. Headless Server Agent (Background daemons and systemd services only)
  3. Development Mode (Live compile & hot-reload)
  4. Complete Uninstaller
- **Systemd Daemon Integration:**
  - Installs and enables `aegis-guard.service` and `aegis-observer.service` with `Restart=always`.
- **Zero-Leak Vault Provisioning:**
  - Configures `/var/lib/aegis-guard/quarantine` and `sandbox` with strict `0700` permissions.
- **Desktop Application Integration:**
  - Installs `/usr/share/applications/aegis-guard.desktop` and application launcher icon.

### Non-Interactive 1-Liner (Automated Script):
```bash
curl -fsSL https://raw.githubusercontent.com/SepJs/aegis-guard/main/installers/linux/auto-install.sh | sudo bash
```

### Uninstallation on Linux:
```bash
sudo aegis-uninstall
# or:
sudo bash installers/linux/uninstall-linux.sh
```

---

## 2. Windows Installation (Windows 10, 11, Windows Server)

Windows installations require Administrator rights to interact with the Service Control Manager (`sc.exe`), configure Windows Defender Firewall, and secure quarantine directories.

### Method A — Standard Inno Setup Installer (`.iss`):
Inno Setup is the official open-source Windows installer technology used by Microsoft VS Code, Git for Windows, and Notepad++.
To compile the installer executable:
```cmd
iscc installers\windows\aegis-setup.iss
```
This produces a certified Windows setup wizard: `AegisGuard-Setup-x64.exe` with:
- Standard Windows wizard pages (License, Destination folder, Desktop icon, Service configuration).
- Automatic stop of running instances before update.
- Windows Defender Firewall rules for the Go network observer.
- Background service registration (`AegisProcessEngine`).
- Clean uninstallation via Windows "Add or Remove Programs" (Control Panel).

### Method B — Nullsoft Scriptable Install System (`.nsi`):
Compile with NSIS:
```cmd
makensis installers\windows\AegisGuard.nsi
```
Generates `AegisGuard-Setup-NSIS-x64.exe`.

### Method C — Automated 1-Click PowerShell / Batch Install:
1. Double-click `1-CLICK-INSTALL-WINDOWS.bat` from the root directory or run:
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/SepJs/aegis-guard/main/installers/windows/install-windows.ps1 | iex"
```
2. Accept the Windows UAC Administrator prompt.
The script automatically builds release binaries, registers Windows Services, creates Start Menu & Desktop shortcuts, and launches the application.

---

## 3. Verification & Diagnostics

After installation, verify that all security subsystems are operating at 100% integrity:
- **GUI:** Navigate to `Settings` -> Click **`⚡ RUN FULL ENGINE SELF-TEST`** (evaluates all 11 security engines).
- **Linux CLI:** `systemctl status aegis-guard.service aegis-observer.service`
- **Windows CLI:** `sc.exe query AegisProcessEngine`
