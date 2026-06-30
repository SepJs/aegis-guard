# Aegis-Guard — Installation Guide

**by Vladimir Unknown**

---

## Prerequisites

### Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### Node.js 20+
```bash
# Ubuntu / Debian
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo bash -
sudo apt-get install -y nodejs

# Arch
sudo pacman -S nodejs npm

# Fedora
sudo dnf install nodejs
```

### System libraries (Ubuntu / Debian)
```bash
sudo apt-get install -y \
  libwebkit2gtk-4.1-dev \
  libgtk-3-dev \
  libayatana-appindicator3-dev \
  libssl-dev \
  build-essential \
  pkg-config
```

### System libraries (Arch)
```bash
sudo pacman -S webkit2gtk-4.1 gtk3 libayatana-appindicator openssl
```

### System libraries (Fedora)
```bash
sudo dnf install webkit2gtk4.1-devel gtk3-devel \
  libayatana-appindicator-devel openssl-devel
```

---

## Build & Run

### 1. First-time system setup
```bash
cd aegis-guard
sudo bash install/setup.sh
```

This creates:
- `/run/aegis/` — runtime socket directory
- `/var/lib/aegis/` — database directory
- `/etc/systemd/system/aegis-process-engine.service` — systemd unit

### 2. Build all Rust crates
```bash
cargo build --release
```

### 3. Install Tauri CLI
```bash
cargo install tauri-cli --version "^2.0"
```

### 4. Install npm dependencies
```bash
cd tauri-app && npm install
```

---

## Running in Development Mode

Open two terminals:

**Terminal 1 — Process Engine**
```bash
sudo AEGIS_LOG=info ./target/release/aegis-process-engine
# Or with debug logging:
sudo AEGIS_LOG=debug ./target/release/aegis-process-engine
```

**Terminal 2 — Dashboard**
```bash
cd tauri-app
cargo tauri dev
```

---

## Running as a Service

```bash
# Start
sudo systemctl start aegis-process-engine

# Enable on boot
sudo systemctl enable aegis-process-engine

# View logs
sudo journalctl -u aegis-process-engine -f

# Stop
sudo systemctl stop aegis-process-engine
```

---

## Building for Distribution

```bash
cd tauri-app
cargo tauri build
```

Output:
- `.deb` → `tauri-app/src-tauri/target/release/bundle/deb/`
- `.rpm` → `tauri-app/src-tauri/target/release/bundle/rpm/`
- `.AppImage` → `tauri-app/src-tauri/target/release/bundle/appimage/`

---

## Testing Detections

### PAR-001 — Browser spawns shell
```bash
# In a terminal while firefox is running:
# (DevTools → Console → fetch abuse simulation)
bash -c "echo test"   # with firefox as parent via scripting
```

### PATH-001 — Execute from /tmp
```bash
cp /bin/bash /tmp/test_dropper
/tmp/test_dropper -c "echo hello"
rm /tmp/test_dropper
```

### ARG-001 — Base64 obfuscation
```bash
bash -c "echo aGVsbG8gd29ybGQ= | base64 -d"
```

### ENV-001 — LD_PRELOAD injection
```bash
LD_PRELOAD=/tmp/fake.so ls
```

### ENV-002 — PATH hijack
```bash
PATH=/tmp:$PATH bash -c "ls"
```

---

## Environment Variables

| Variable        | Default                    | Description                        |
|----------------|----------------------------|------------------------------------|
| `AEGIS_LOG`     | `info`                     | Log level: trace/debug/info/warn   |
| `AEGIS_SOCKET`  | `/run/aegis/proc.sock`     | Unix socket path                   |

---

## Troubleshooting

**"Permission denied" reading /proc entries**
→ Run process-engine as root: `sudo ./aegis-process-engine`

**Socket connection failed**
→ Ensure `/run/aegis/` exists: `sudo mkdir -p /run/aegis`

**Dashboard shows "Waiting for engine"**
→ Start process-engine first, then the dashboard

**GTK errors on Wayland**
```bash
export GDK_BACKEND=x11
cargo tauri dev
```

---

*Aegis-Guard by Vladimir Unknown — Passive monitoring. No blocking. No kernel modules.*
