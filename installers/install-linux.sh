#!/usr/bin/env bash
# installers/install-linux.sh — Aegis-Guard Multi-Distro Linux Console & Desktop Installer
# Supports both local clone execution and non-interactive `curl | bash` console runs.
# Usage:
#   bash installers/install-linux.sh [--console | --desktop] [--yes]
#   curl -sSL https://raw.githubusercontent.com/SepJs/aegis-guard/main/installers/install-linux.sh | sudo bash -s -- --yes

set -euo pipefail

VIOLET='\033[35m'; BOLD='\033[1m'; RESET='\033[0m'
GREEN='\033[32m'; CYAN='\033[36m'; YELLOW='\033[33m'; RED='\033[31m'; DIM='\033[2m'

MODE="auto"
AUTO_YES=0
for arg in "$@"; do
    case "$arg" in
        --console|--web|--headless) MODE="console" ;;
        --desktop|--gui)            MODE="desktop" ;;
        -y|--yes)                   AUTO_YES=1 ;;
    esac
done
[ ! -t 0 ] && AUTO_YES=1

echo -e "${VIOLET}${BOLD}"
echo "  ┌─────────────────────────────────────────────┐"
echo "  │       AEGIS-GUARD — LINUX INSTALLER         │"
echo "  │               Version 1.2.0                 │"
echo "  └─────────────────────────────────────────────┘"
echo -e "${RESET}"

if [ -f "/.flatpak-info" ]; then
    echo -e "${RED}${BOLD}Flatpak sandbox detected.${RESET}"
    echo -e "${YELLOW}Run this installer from a host terminal (GNOME Terminal, Konsole, SSH, or TTY).${RESET}"
    exit 1
fi

SUDO=""
if [ "$EUID" -ne 0 ]; then
    if command -v sudo &>/dev/null; then
        SUDO="sudo"
    else
        echo -e "${RED}Error: root privileges or 'sudo' are required.${RESET}"
        exit 1
    fi
fi

# Locate repo root or clone cleanly when invoked via `curl | bash`
SCRIPT_DIR=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/../package.json" ] && [ -d "$SCRIPT_DIR/../tauri-app" ]; then
    PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
elif [ -f "./package.json" ] && [ -d "./tauri-app" ]; then
    PROJECT_ROOT="$(pwd)"
else
    PROJECT_ROOT="/opt/aegis-guard"
    echo -e "${CYAN}[0/6] Cloning Aegis-Guard source to ${PROJECT_ROOT}...${RESET}"
    if ! command -v git &>/dev/null; then
        echo -e "${RED}Error: 'git' is required for remote installation.${RESET}"
        exit 1
    fi
    if [ -d "$PROJECT_ROOT/.git" ]; then
        $SUDO git -C "$PROJECT_ROOT" pull --ff-only || true
    else
        $SUDO rm -rf "$PROJECT_ROOT"
        $SUDO git clone --depth 1 https://github.com/SepJs/aegis-guard.git "$PROJECT_ROOT"
    fi
fi

cd "$PROJECT_ROOT"
ARCH="$(uname -m)"
echo -e "${CYAN}Target Root:${RESET} ${BOLD}${PROJECT_ROOT}${RESET} (${ARCH})"

# Decide desktop vs console mode automatically if "auto"
if [ "$MODE" = "auto" ]; then
    if [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ]; then
        MODE="desktop"
    else
        MODE="console"
    fi
fi
echo -e "${CYAN}Install Profile:${RESET} ${BOLD}${MODE^^}${RESET}"

# Detect distro
DETECTED_ID=""; DETECTED_LIKE=""
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DETECTED_ID="${ID:-}"; DETECTED_LIKE="${ID_LIKE:-}"
fi

family="unknown"
case "$DETECTED_ID $DETECTED_LIKE" in
    *ubuntu*|*debian*|*pop*|*mint*) family="debian" ;;
    *fedora*|*rhel*|*centos*|*rocky*) family="fedora" ;;
    *arch*|*manjaro*|*endeavour*) family="arch" ;;
    *opensuse*|*suse*) family="suse" ;;
    *alpine*) family="alpine" ;;
esac

if [ "$AUTO_YES" -eq 0 ] && [ "$MODE" = "desktop" ]; then
    echo ""
    echo -e "${CYAN}Detected distro:${RESET} ${BOLD}${DETECTED_ID:-unknown}${RESET} (${family})"
    echo -e "  [1] Debian / Ubuntu (apt)   [2] Fedora / RHEL (dnf)"
    echo -e "  [3] Arch Linux (pacman)     [4] openSUSE (zypper)"
    echo -e "  [5] Alpine (apk)            [6] Skip OS packages"
    printf "${BOLD}Choice [Enter = auto]:${RESET} "
    read -r choice || choice=""
    case "$choice" in
        1) family="debian" ;; 2) family="fedora" ;; 3) family="arch" ;;
        4) family="suse" ;; 5) family="alpine" ;; 6) family="skip" ;;
    esac
fi

echo -e "${CYAN}[1/6] Installing system prerequisites (${family}, mode=${MODE})...${RESET}"
case "$family" in
    debian)
        $SUDO apt-get update -qq
        if [ "$MODE" = "desktop" ]; then
            $SUDO apt-get install -y -qq build-essential curl git pkg-config \
                libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev \
                librsvg2-dev libssl-dev patchelf || true
        else
            $SUDO apt-get install -y -qq build-essential curl git pkg-config libssl-dev || true
        fi
        ;;
    fedora)
        if [ "$MODE" = "desktop" ]; then
            $SUDO dnf install -y gcc gcc-c++ make curl git pkgconf-pkg-config \
                webkit2gtk4.1-devel gtk3-devel libappindicator-gtk3-devel librsvg2-devel openssl-devel || true
        else
            $SUDO dnf install -y gcc gcc-c++ make curl git pkgconf-pkg-config openssl-devel || true
        fi
        ;;
    arch)
        if [ "$MODE" = "desktop" ]; then
            $SUDO pacman -Sy --noconfirm --needed base-devel curl git pkgconf \
                webkit2gtk-4.1 gtk3 libappindicator-gtk3 librsvg openssl || true
        else
            $SUDO pacman -Sy --noconfirm --needed base-devel curl git pkgconf openssl || true
        fi
        ;;
    suse)
        $SUDO zypper install -y curl git pkg-config gcc gcc-c++ make openssl-devel || true
        ;;
    alpine)
        $SUDO apk add --no-cache build-base curl git pkgconf openssl-dev || true
        ;;
    *)
        echo -e "  ${YELLOW}Skipping OS package installation.${RESET}"
        ;;
esac
echo -e "  ${GREEN}✓${RESET} system dependencies ready"

echo -e "${CYAN}[2/6] Checking Node.js, Rust, and Go toolchains...${RESET}"
if ! command -v node &>/dev/null; then
    echo -e "${RED}Node.js 20+ not found. Please install Node.js first (https://nodejs.org).${RESET}"
    exit 1
fi
echo -e "  ${GREEN}✓${RESET} Node: $(node --version)"

[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env" || true
HAVE_CARGO=0
if command -v cargo &>/dev/null; then
    HAVE_CARGO=1
    echo -e "  ${GREEN}✓${RESET} Rust: $(rustc --version)"
elif [ "$MODE" = "desktop" ]; then
    echo -e "  ${YELLOW}Installing Rust toolchain via rustup...${RESET}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    [ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"
    command -v cargo &>/dev/null && HAVE_CARGO=1
else
    echo -e "  ${YELLOW}Rust not found — console mode will run Node/Express kernel telemetry + Go observer if available.${RESET}"
fi

HAVE_GO=0
if command -v go &>/dev/null; then
    HAVE_GO=1
    echo -e "  ${GREEN}✓${RESET} Go: $(go version | awk '{print $3}')"
else
    echo -e "  ${YELLOW}Go not found — Go packet bridge optional (kernel /proc/net/snmp inspector stays active).${RESET}"
fi

echo -e "${CYAN}[3/6] Installing npm dependencies & building dashboard assets...${RESET}"
npm install --no-audit --no-fund
npm run build
echo -e "  ${GREEN}✓${RESET} dashboard frontend built"

if [ "$HAVE_CARGO" -eq 1 ]; then
    echo -e "${CYAN}[4/6] Building native Rust engine (aegis-process-engine)...${RESET}"
    cargo build --release -p process-engine
    if [ "$MODE" = "desktop" ]; then
        if ! command -v cargo-tauri &>/dev/null; then
            cargo install tauri-cli --version "^2.0" --locked || true
        fi
        cargo clean --release -p aegis-guard 2>/dev/null || true
        (cd tauri-app && cargo tauri build --bundles appimage) || cargo build --release -p aegis-guard || true
    fi
    echo -e "  ${GREEN}✓${RESET} Rust components built"
else
    echo -e "${CYAN}[4/6] Skipping native Rust binary build (console telemetry mode).${RESET}"
fi

if [ "$HAVE_GO" -eq 1 ] && [ -d "network-observer" ]; then
    echo -e "${CYAN}[5/6] Building Go network packet observer...${RESET}"
    mkdir -p target
    (cd network-observer && go build -o ../target/aegis-network-observer ./cmd/observer)
    echo -e "  ${GREEN}✓${RESET} network-observer built"
else
    echo -e "${CYAN}[5/6] Skipping Go binary build.${RESET}"
fi

echo -e "${CYAN}[6/6] Installing binaries, data paths & console CLI (${PROJECT_ROOT})...${RESET}"
$SUDO install -d -m 750 /var/lib/aegis
$SUDO install -d -m 1777 /var/lib/aegis/quarantine /var/lib/aegis/canaries /tmp/aegis_guard_data

[ -f target/release/aegis-process-engine ] && $SUDO install -m 755 target/release/aegis-process-engine /usr/local/bin/
[ -f target/aegis-network-observer ] && $SUDO install -m 755 target/aegis-network-observer /usr/local/bin/
[ -f target/release/Aegis-Guard ] && $SUDO install -m 755 target/release/Aegis-Guard /usr/local/bin/aegis-guard-desktop

# Always install reliable CLI command `aegis-guard`
$SUDO tee /usr/local/bin/aegis-guard > /dev/null << CLI_EOF
#!/usr/bin/env bash
cd "$PROJECT_ROOT"
exec bash "$PROJECT_ROOT/aegis.sh" "\$@"
CLI_EOF
$SUDO chmod 755 /usr/local/bin/aegis-guard

if command -v systemctl &>/dev/null && [ -d /etc/systemd/system ]; then
    $SUDO tee /etc/tmpfiles.d/aegis-guard.conf > /dev/null << 'TMPFILES'
d /run/aegis 1777 root root -
TMPFILES
    $SUDO systemd-tmpfiles --create /etc/tmpfiles.d/aegis-guard.conf 2>/dev/null || true

    if [ -f /usr/local/bin/aegis-process-engine ]; then
        $SUDO tee /etc/systemd/system/aegis-process-engine.service > /dev/null << 'UNIT'
[Unit]
Description=Aegis-Guard Process Engine
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
    fi

    if [ -f /usr/local/bin/aegis-network-observer ]; then
        $SUDO tee /etc/systemd/system/aegis-network-observer.service > /dev/null << 'UNIT'
[Unit]
Description=Aegis-Guard Network Observer
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
    $SUDO systemctl daemon-reload 2>/dev/null || true
fi

if [ "$MODE" = "desktop" ] && [ -f /usr/local/bin/aegis-guard-desktop ]; then
    mkdir -p "$HOME/.local/share/applications" "$HOME/.local/share/icons"
    [ -f tauri-app/src-tauri/icons/icon.png ] && cp tauri-app/src-tauri/icons/icon.png "$HOME/.local/share/icons/aegis-guard.png"
    cat > "$HOME/.local/share/applications/aegis-guard.desktop" << DESK
[Desktop Entry]
Type=Application
Name=Aegis-Guard
Comment=Endpoint Security & Network IDS Suite
Exec=/usr/local/bin/aegis-guard-desktop
Icon=$HOME/.local/share/icons/aegis-guard.png
Terminal=false
Categories=System;Security;
DESK
    chmod +x "$HOME/.local/share/applications/aegis-guard.desktop"
    update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true
fi

echo ""
echo -e "${GREEN}${BOLD}━━━ Aegis-Guard v1.2.0 Installation Complete ━━━${RESET}"
echo -e "  Console mode (any terminal): ${CYAN}aegis-guard --console${RESET}  (http://127.0.0.1:3000)"
if [ -f /usr/local/bin/aegis-guard-desktop ]; then
    echo -e "  Desktop UI:                  ${CYAN}aegis-guard --desktop${RESET}"
fi
echo -e "  Uninstall:                   ${DIM}sudo bash ${PROJECT_ROOT}/installers/uninstall-linux.sh${RESET}"
echo ""