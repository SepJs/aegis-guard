#!/usr/bin/env bash
# installers/install-linux.sh — Aegis-Guard full Linux installer
# by Vladimir Unknown
#
# Detects your distro (with manual override menu), installs the right
# system packages, builds everything, installs binaries + systemd services,
# and sets up a double-click launcher that starts BOTH engines
# (process-engine + network-observer) together with the dashboard.
#
# Usage:  bash installers/install-linux.sh

set -e

VIOLET='\033[35m'; BOLD='\033[1m'; RESET='\033[0m'
GREEN='\033[32m'; CYAN='\033[36m'; YELLOW='\033[33m'; RED='\033[31m'; DIM='\033[2m'

cd "$(dirname "$0")/.."   # project root
PROJECT_ROOT="$(pwd)"

clear
echo -e "${VIOLET}${BOLD}"
echo "  ╔═══════════════════════════════════════════╗"
echo "  ║     AEGIS-GUARD  —  LINUX INSTALLER       ║"
echo "  ║          by Vladimir Unknown              ║"
echo "  ╚═══════════════════════════════════════════╝"
echo -e "${RESET}"

if [ ! -f "Cargo.toml" ] || [ ! -d "tauri-app" ]; then
    echo -e "${RED}Error: run this from inside the aegis-guard project (bash installers/install-linux.sh){RESET}"
    exit 1
fi

# ── Step 1: Detect architecture (informational) ───────────────────────────────
ARCH="$(uname -m)"
echo -e "${CYAN}Detected CPU architecture:${RESET} ${BOLD}${ARCH}${RESET}"
case "$ARCH" in
    x86_64)          echo -e "  ${DIM}→ standard 64-bit (Intel/AMD){RESET}" ;;
    aarch64|arm64)   echo -e "  ${DIM}→ 64-bit ARM (Raspberry Pi 4/5, ARM servers, etc.){RESET}" ;;
    armv7l)          echo -e "  ${DIM}→ 32-bit ARM — build will just take longer{RESET}" ;;
    *)               echo -e "  ${YELLOW}→ unrecognised — build will still attempt to proceed{RESET}" ;;
esac
echo ""

# ── Step 2: Detect distro, offer override menu ────────────────────────────────
DETECTED_ID=""; DETECTED_LIKE=""
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DETECTED_ID="${ID:-}"; DETECTED_LIKE="${ID_LIKE:-}"
fi

detected_family="unknown"
case "$DETECTED_ID $DETECTED_LIKE" in
    *ubuntu*|*debian*)          detected_family="debian" ;;
    *fedora*|*rhel*|*centos*)   detected_family="fedora" ;;
    *arch*|*manjaro*)           detected_family="arch"   ;;
    *opensuse*|*suse*)          detected_family="suse"   ;;
    *alpine*)                   detected_family="alpine" ;;
esac

echo -e "${CYAN}Detected distro:${RESET} ${BOLD}${DETECTED_ID:-unknown}${RESET} ${DIM}(family: $detected_family)${RESET}"
echo ""
echo -e "${BOLD}Select package manager to use:${RESET}"
echo -e "  ${DIM}(Press Enter to use detected){RESET}"
echo ""
echo -e "  ${VIOLET}[1]${RESET} Debian / Ubuntu / Mint / Pop!_OS      (apt)"
echo -e "  ${VIOLET}[2]${RESET} Fedora / RHEL / CentOS / Rocky        (dnf)"
echo -e "  ${VIOLET}[3]${RESET} Arch / Manjaro / EndeavourOS          (pacman)"
echo -e "  ${VIOLET}[4]${RESET} openSUSE                              (zypper)"
echo -e "  ${VIOLET}[5]${RESET} Alpine                                (apk)"
echo -e "  ${VIOLET}[6]${RESET} Skip — system packages already installed"
echo ""
printf "${BOLD}Choice [1-6, Enter = auto]:${RESET} "
read -r choice

case "$choice" in
    1) family="debian" ;; 2) family="fedora" ;; 3) family="arch" ;;
    4) family="suse"   ;; 5) family="alpine" ;; 6) family="skip" ;;
    "") family="$detected_family" ;;
    *) echo -e "${RED}Invalid choice — using detected: $detected_family${RESET}"; family="$detected_family" ;;
esac

if [ "$family" = "unknown" ]; then
    echo -e "${YELLOW}Could not detect your distro. Pick a number 1-6 next time, or install these manually:${RESET}"
    echo -e "${DIM}  webkit2gtk 4.1, gtk3, libappindicator3, librsvg2, openssl-dev, build tools${RESET}"
    family="skip"
fi

# ── Step 3: Install system dependencies for the chosen family ─────────────────
echo ""
echo -e "${CYAN}[1/6] Installing system dependencies (${family})...${RESET}"

case "$family" in
    debian)
        sudo apt-get update -q
        sudo apt-get install -y -q \
            build-essential curl git pkg-config \
            libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev \
            librsvg2-dev libssl-dev patchelf \
            --fix-missing
        ;;
    fedora)
        sudo dnf install -y \
            gcc gcc-c++ make curl git pkgconf-pkg-config \
            webkit2gtk4.1-devel gtk3-devel libappindicator-gtk3-devel \
            librsvg2-devel openssl-devel
        ;;
    arch)
        sudo pacman -Sy --noconfirm --needed \
            base-devel curl git pkgconf \
            webkit2gtk-4.1 gtk3 libappindicator-gtk3 \
            librsvg openssl
        ;;
    suse)
        sudo zypper install -y \
            curl git pkg-config gcc gcc-c++ make \
            webkit2gtk3-devel gtk3-devel libappindicator3-devel \
            librsvg-devel libopenssl-devel
        ;;
    alpine)
        sudo apk add --no-cache \
            build-base curl git pkgconf \
            webkit2gtk-dev gtk+3.0-dev libappindicator-dev \
            librsvg-dev openssl-dev
        ;;
    skip)
        echo -e "  ${YELLOW}Skipped — assuming system packages are already present.${RESET}"
        ;;
esac
echo -e "  ${GREEN}✓${RESET} system dependencies ready"

# ── Step 4: Rust / Node / Go toolchains ────────────────────────────────────────
echo -e "${CYAN}[2/6] Checking toolchains...${RESET}"
source "$HOME/.cargo/env" 2>/dev/null || true

if ! command -v cargo &>/dev/null; then
    echo -e "  ${YELLOW}Installing Rust...${RESET}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi
echo -e "  ${GREEN}✓${RESET} Rust: $(rustc --version)"

if ! command -v node &>/dev/null; then
    echo -e "  ${RED}Node.js not found. Install it (e.g. https://nodejs.org) then re-run this script.${RESET}"
    exit 1
fi
echo -e "  ${GREEN}✓${RESET} Node: $(node --version)"

HAVE_GO=0
if command -v go &>/dev/null; then
    HAVE_GO=1
    echo -e "  ${GREEN}✓${RESET} Go: $(go version | awk '{print $3}')"
else
    echo -e "  ${YELLOW}⚠ Go not found — network-observer will be skipped (install: https://go.dev/dl){RESET}"
fi

# ── Step 5: Build everything ───────────────────────────────────────────────────
echo -e "${CYAN}[3/6] Building Rust workspace (release, ${ARCH})...${RESET}"
cargo build --release --workspace
echo -e "  ${GREEN}✓${RESET} Rust build complete"

if [ "$HAVE_GO" = "1" ]; then
    echo -e "${CYAN}[4/6] Building network-observer...${RESET}"
    mkdir -p target
    (cd network-observer && go build -o ../target/aegis-network-observer ./cmd/observer)
    echo -e "  ${GREEN}✓${RESET} network-observer built"
fi

echo -e "${CYAN}[5/6] Building dashboard...${RESET}"
(cd tauri-app && npm install)
if ! command -v cargo-tauri &>/dev/null; then
    cargo install tauri-cli --version "^2.0" --locked
fi
(cd tauri-app && cargo tauri build --bundles none)   # build binary only; skip .deb/.rpm packaging for a direct local install
echo -e "  ${GREEN}✓${RESET} dashboard built"

DASH_BIN="$PROJECT_ROOT/tauri-app/src-tauri/target/release/aegis-tauri"
if [ ! -f "$DASH_BIN" ]; then
    echo -e "${RED}Could not find built dashboard binary at $DASH_BIN${RESET}"
    exit 1
fi

# ── Step 6: System install (binaries, tmpfiles, systemd, launcher) ────────────
echo -e "${CYAN}[6/6] Installing system-wide...${RESET}"

sudo install -m 755 target/release/aegis-process-engine /usr/local/bin/
[ -f target/aegis-network-observer ] && sudo install -m 755 target/aegis-network-observer /usr/local/bin/
sudo install -m 755 "$DASH_BIN" /usr/local/bin/aegis-guard-dashboard

sudo install -d -m 750 /var/lib/aegis /var/lib/aegis/quarantine /var/lib/aegis/canaries

# /run is a tmpfs and is wiped on every reboot — a tmpfiles.d rule is the
# correct, persistent way to recreate /run/aegis with the right permissions
# on every boot (sticky + world-writable, like /tmp, so the non-root
# dashboard can bind the socket while the root-run engine connects to it).
sudo tee /etc/tmpfiles.d/aegis-guard.conf > /dev/null << 'TMPFILES'
d /run/aegis 1777 root root -
TMPFILES
sudo systemd-tmpfiles --create /etc/tmpfiles.d/aegis-guard.conf

sudo tee /etc/systemd/system/aegis-process-engine.service > /dev/null << 'UNIT'
[Unit]
Description=Aegis-Guard Process Engine — by Vladimir Unknown
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/aegis-process-engine
Restart=on-failure
RestartSec=5
Environment=AEGIS_LOG=info
Environment=AEGIS_SOCKET=/run/aegis/proc.sock
User=root
[Install]
WantedBy=multi-user.target
UNIT

if [ -f /usr/local/bin/aegis-network-observer ]; then
sudo tee /etc/systemd/system/aegis-network-observer.service > /dev/null << 'UNIT'
[Unit]
Description=Aegis-Guard Network Observer — by Vladimir Unknown
After=network.target aegis-process-engine.service
[Service]
Type=simple
ExecStart=/usr/local/bin/aegis-network-observer
Restart=on-failure
RestartSec=5
Environment=AEGIS_LOG=info
User=root
[Install]
WantedBy=multi-user.target
UNIT
fi
sudo systemctl daemon-reload

# Narrowly-scoped passwordless sudo: this user may only start/stop the two
# named Aegis-Guard services — nothing else. This is what lets clicking the
# desktop icon start both engines without a password prompt every time.
SUDOERS_FILE="/etc/sudoers.d/aegis-guard"
{
  echo "$(whoami) ALL=(root) NOPASSWD: /usr/bin/systemctl start aegis-process-engine"
  echo "$(whoami) ALL=(root) NOPASSWD: /usr/bin/systemctl stop aegis-process-engine"
  echo "$(whoami) ALL=(root) NOPASSWD: /usr/bin/systemctl start aegis-network-observer"
  echo "$(whoami) ALL=(root) NOPASSWD: /usr/bin/systemctl stop aegis-network-observer"
} | sudo tee "$SUDOERS_FILE" > /dev/null
sudo chmod 440 "$SUDOERS_FILE"
sudo visudo -c -f "$SUDOERS_FILE" > /dev/null || { echo -e "${RED}sudoers syntax check failed — removing.${RESET}"; sudo rm -f "$SUDOERS_FILE"; }
echo -e "  ${GREEN}✓${RESET} passwordless start/stop configured (scoped to Aegis-Guard services only)"

# Launcher: starts BOTH engines via systemd + dashboard together, and stops
# the engines again when the dashboard window closes.
sudo tee /usr/local/bin/aegis-guard-launch > /dev/null << 'LAUNCH_EOF'
#!/usr/bin/env bash
set -e

cleanup() {
    sudo -n systemctl stop aegis-process-engine    2>/dev/null || true
    sudo -n systemctl stop aegis-network-observer  2>/dev/null || true
}
trap cleanup EXIT INT TERM

sudo -n systemctl start aegis-process-engine
[ -f /etc/systemd/system/aegis-network-observer.service ] && \
    sudo -n systemctl start aegis-network-observer

sleep 1
AEGIS_NET=1 /usr/local/bin/aegis-guard-dashboard
LAUNCH_EOF
sudo chmod +x /usr/local/bin/aegis-guard-launch
echo -e "  ${GREEN}✓${RESET} combined launcher installed"

# Desktop icon
mkdir -p "$HOME/.local/share/applications" "$HOME/.local/share/icons"
cp tauri-app/src-tauri/icons/icon.png "$HOME/.local/share/icons/aegis-guard.png"
cat > "$HOME/.local/share/applications/aegis-guard.desktop" << DESK
[Desktop Entry]
Type=Application
Name=Aegis-Guard
Comment=Endpoint Security Suite — Process Engine + Network Observer + Dashboard
Exec=/usr/local/bin/aegis-guard-launch
Icon=$HOME/.local/share/icons/aegis-guard.png
Terminal=false
Categories=System;Security;
DESK
chmod +x "$HOME/.local/share/applications/aegis-guard.desktop"
update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true
echo -e "  ${GREEN}✓${RESET} desktop launcher installed"

echo ""
echo -e "${GREEN}${BOLD}━━━ Installation Complete ━━━${RESET}"
echo ""
echo -e "  ${BOLD}Find 'Aegis-Guard' in your applications menu${RESET} — one click"
echo -e "  starts the process engine, network observer, and dashboard together,"
echo -e "  and stops the engines again when you close the window."
echo ""
echo -e "  ${DIM}Or from a terminal:${RESET} aegis-guard-launch"
echo -e "  ${DIM}To uninstall:${RESET} bash installers/uninstall-linux.sh"
echo ""
echo -e "${VIOLET}${BOLD}Aegis-Guard — by Vladimir Unknown${RESET}"
