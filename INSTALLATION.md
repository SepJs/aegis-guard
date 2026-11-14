# Aegis-Guard — Installation Guide (v1.2.0)

Aegis-Guard supports **Console Mode** (headless/terminal web server on port `3000` with live host telemetry, antivirus scanning, and Go/kernel network inspection) and **Desktop Mode** (native Tauri v2 desktop window + background system daemons) across **Linux, macOS, and Windows**.

---

## 1. Cross-Platform GTK3 GUI Installer (Recommended)

Launch the visual GTK3 setup wizard from the cloned repository (auto-installs GTK3/Rust build headers on Linux & macOS):
```bash
bash install-gui.sh
```
Or download the prebuilt GTK3 installer for your OS from **GitHub Releases**:
- **Windows**: `aegis-installer-gtk-windows-amd64.zip` → extract and double-click `aegis-installer.exe`
- **Linux**: `aegis-installer-gtk-linux-amd64` → `chmod +x ./aegis-installer-gtk-linux-amd64 && ./aegis-installer-gtk-linux-amd64`
- **macOS**: `aegis-installer-gtk-macos.tar.gz` → extract and run `./aegis-installer`

| Platform | Console Mode | Desktop Mode | CLI Command Installed |
|----------|--------------|--------------|-----------------------|
| **Linux** (Ubuntu, Debian, Fedora, Arch, openSUSE) | `sudo bash installers/install-linux.sh --console --yes` | `sudo bash installers/install-linux.sh --desktop` | `/usr/local/bin/aegis-guard` (`aegis-guard-desktop`) |
| **macOS** (Apple Silicon & Intel) | `bash installers/install-macos.sh --console --yes` | `bash installers/install-macos.sh --desktop` | `/opt/homebrew/bin/aegis-guard` or `/usr/local/bin/aegis-guard` |
| **Windows 10 / 11 / Server** | `installers\install-windows.ps1 -ConsoleOnly` | `installers\install-windows.ps1` | `%ProgramFiles%\Aegis-Guard\aegis-guard.cmd` |

---

## 2. Linux Installation

### Console Mode (Fastest, Headless / Server / Container Friendly)
```bash
git clone https://github.com/SepJs/aegis-guard.git
cd aegis-guard
sudo bash installers/install-linux.sh --console --yes
```

Or one-line remote install:
```bash
curl -fsSL https://raw.githubusercontent.com/SepJs/aegis-guard/main/installers/install-linux.sh | sudo bash -s -- --console --yes
```

After installation:
```bash
aegis-guard --console
```

### Desktop & Systemd Service Mode
```bash
sudo bash installers/install-linux.sh --desktop
```
The Linux installer automatically:
1. Detects `apt`, `dnf`, `yum`, `pacman`, or `zypper`.
2. Installs Node.js, Go (optional daemon), and Rust/GTK/WebKit2GTK dependencies when building Desktop mode.
3. Builds the Go `aegis-network-observer` binary if `go` is present.
4. Installs `/usr/local/bin/aegis-guard` (and `.desktop` launcher + `systemd` units in Desktop mode).

### Uninstall (Linux)
```bash
sudo bash installers/uninstall-linux.sh
```

---

## 3. macOS Installation

Supports both Apple Silicon (`/opt/homebrew`) and Intel (`/usr/local`) Homebrew environments.

### Console Mode
```bash
git clone https://github.com/SepJs/aegis-guard.git
cd aegis-guard
bash installers/install-macos.sh --console --yes
```

Start anytime:
```bash
aegis-guard --console
```

### Native Desktop Build
```bash
bash installers/install-macos.sh --desktop
```

---

## 4. Windows Installation

Open **PowerShell as Administrator**:

### Console Mode
```powershell
git clone https://github.com/SepJs/aegis-guard.git
cd aegis-guard
powershell -NoProfile -ExecutionPolicy Bypass -File installers\install-windows.ps1 -ConsoleOnly
```

### Desktop + Windows Service Mode
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File installers\install-windows.ps1
```

Or right-click `installers\install-windows.bat` and select **Run as administrator**.

The Windows installer:
1. Installs Node.js dependencies and builds the production UI bundle (`dist/`).
2. Compiles `Aegis-Guard.exe` (`cargo build --release -p aegis-guard`) and `aegis-network-observer.exe` in Desktop mode.
3. Provisions `%ProgramData%\Aegis-Guard\quarantine` and `logs`.
4. Opens inbound localhost rule on TCP port `3000` (Console mode) and registers `aegis-guard` in System `PATH`.

---

## 5. Quick Local Launch & Makefile Targets

Without running a system-wide install, you can launch directly from the repository root:

```bash
# Auto-detect console or desktop mode
bash aegis.sh --console

# Or via npm / Make
npm install
npm run build
make run-console
```

The GTK3 GUI installer (`installer/`) can also be launched directly with Cargo:
```bash
cargo run --release -p aegis-installer -- --gui
```

---

## 6. Installed Paths Reference

| Platform | Binaries / App | Data, Quarantine & Logs |
|----------|----------------|-------------------------|
| **Linux** | `/opt/aegis-guard`, `/usr/local/bin/aegis-guard` | `/var/lib/aegis` or `/tmp/aegis_guard_data` |
| **macOS** | `/usr/local/opt/aegis-guard` (or `~/Library/Application Support/Aegis-Guard`), `aegis-guard` in Homebrew bin | `~/Library/Application Support/Aegis-Guard/data` |
| **Windows** | `C:\Program Files\Aegis-Guard\` | `C:\ProgramData\Aegis-Guard\` |

---

## 7. Troubleshooting

- **Port 3000 already in use**: Set `PORT=3100 aegis-guard --console` or stop the previous instance.
- **Go Packet Daemon unavailable**: The backend seamlessly falls back to Linux `/proc/net/snmp`, `/proc/net/tcp`, and `/proc/net/arp` live inspection. When `go` is installed, `network-observer` binds `127.0.0.1:50053` for enhanced packet monitoring.
- **Tauri Linux desktop build fails**: Ensure `libwebkit2gtk-4.1-dev` (or distro equivalent) and `pkg-config` are installed; or run `--console` mode for zero-dependency deployment.
