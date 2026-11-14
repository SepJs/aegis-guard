#!/usr/bin/env bash
# installers/launch-gtk-installer.sh — Ensures GTK3 + Rust are available, compiles aegis-installer, and opens the GTK3 GUI window.
set -euo pipefail

VIOLET='\033[35m'; GREEN='\033[32m'; CYAN='\033[36m'; YELLOW='\033[33m'; RED='\033[31m'; BOLD='\033[1m'; RESET='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$PROJECT_ROOT"

if [ -f "/.flatpak-info" ]; then
    echo -e "${RED}Flatpak sandbox detected. Run this script from a host terminal.${RESET}"
    exit 1
fi

# 1. Reuse prebuilt installer binary if present
for cand in \
    "${PROJECT_ROOT}/target/release/aegis-installer" \
    "/usr/local/bin/aegis-installer" \
    "${HOME}/.local/bin/aegis-installer"; do
    if [ -x "$cand" ]; then
        exec "$cand" --gui "$@"
    fi
done

echo -e "${VIOLET}${BOLD}Aegis-Guard v1.2.0 — GTK3 Graphical Installer Bootstrap${RESET}"

# 2. Ensure GTK3 development libraries are available on Linux/macOS
OS="$(uname -s)"
if [ "$OS" = "Linux" ]; then
    if ! command -v pkg-config &>/dev/null || ! pkg-config --exists gtk+-3.0 2>/dev/null; then
        echo -e "${CYAN}[1/3] Installing GTK3 development headers for GUI installer...${RESET}"
        SUDO=""
        [ "$EUID" -ne 0 ] && command -v sudo &>/dev/null && SUDO="sudo"
        if command -v apt-get &>/dev/null; then
            $SUDO apt-get update -qq
            $SUDO apt-get install -y -qq build-essential pkg-config libgtk-3-dev libglib2.0-dev
        elif command -v dnf &>/dev/null; then
            $SUDO dnf install -y gcc pkgconf-pkg-config gtk3-devel glib2-devel
        elif command -v pacman &>/dev/null; then
            $SUDO pacman -Sy --noconfirm --needed base-devel pkgconf gtk3
        elif command -v zypper &>/dev/null; then
            $SUDO zypper install -y gcc pkg-config gtk3-devel
        else
            echo -e "${RED}Please install GTK3 development headers (libgtk-3-dev / gtk3-devel) and retry.${RESET}"
            exit 1
        fi
    fi
elif [ "$OS" = "Darwin" ]; then
    ARCH="$(uname -m)"
    BREW_PREFIX="/usr/local"
    [ "$ARCH" = "arm64" ] && [ -d "/opt/homebrew" ] && BREW_PREFIX="/opt/homebrew"
    export PATH="${BREW_PREFIX}/bin:${BREW_PREFIX}/sbin:$PATH"
    if ! command -v pkg-config &>/dev/null || ! pkg-config --exists gtk+-3.0 2>/dev/null; then
        if command -v brew &>/dev/null; then
            echo -e "${CYAN}[1/3] Installing GTK+3 via Homebrew...${RESET}"
            brew install gtk+3 pkg-config
        else
            echo -e "${RED}Homebrew + gtk+3 are required to compile the GTK installer on macOS.${RESET}"
            exit 1
        fi
    fi
    export PKG_CONFIG_PATH="${BREW_PREFIX}/lib/pkgconfig:${BREW_PREFIX}/opt/gtk+3/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
fi

# 3. Ensure Rust/Cargo exists
[ -f "${HOME}/.cargo/env" ] && source "${HOME}/.cargo/env" || true
if ! command -v cargo &>/dev/null; then
    echo -e "${CYAN}[2/3] Installing Rust toolchain via rustup...${RESET}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    [ -f "${HOME}/.cargo/env" ] && source "${HOME}/.cargo/env" || true
fi

if ! command -v cargo &>/dev/null; then
    echo -e "${YELLOW}Cargo unavailable — falling back to console script installer.${RESET}"
    if [ "$OS" = "Darwin" ]; then
        exec bash "${PROJECT_ROOT}/installers/install-macos.sh" "$@"
    else
        exec bash "${PROJECT_ROOT}/installers/install-linux.sh" "$@"
    fi
fi

# 4. Build and launch GTK3 GUI installer
echo -e "${CYAN}[3/3] Compiling GTK3 installer (aegis-installer)...${RESET}"
cargo build --release -p aegis-installer
exec "${PROJECT_ROOT}/target/release/aegis-installer" --gui "$@"
