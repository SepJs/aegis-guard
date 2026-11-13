#!/usr/bin/env bash
# aegis.sh — Cross-Platform Console & Desktop Launcher for Aegis-Guard
#
# Usage:
#   bash aegis.sh               auto-detect console vs native Tauri desktop
#   bash aegis.sh --console     start headless Express + SSE backend & UI on http://127.0.0.1:3000
#   bash aegis.sh --desktop     build & launch native Tauri v2 desktop suite
#   AEGIS_NET=1 bash aegis.sh   also launch Go raw-socket packet observer daemon

set -euo pipefail

VIOLET='\033[35m'; BOLD='\033[1m'; RESET='\033[0m'
GREEN='\033[32m'; CYAN='\033[36m'; YELLOW='\033[33m'; RED='\033[31m'

cd "$(dirname "$0")"

if [ ! -f "package.json" ] || [ ! -d "tauri-app" ]; then
    echo -e "${RED}Error: run this script from the aegis-guard project root.${RESET}"
    exit 1
fi

LAUNCH_MODE="auto"
for arg in "$@"; do
    case "$arg" in
        --console|--web|--headless) LAUNCH_MODE="console" ;;
        --desktop|--gui)            LAUNCH_MODE="desktop" ;;
        --net)                      export AEGIS_NET=1 ;;
        -h|--help)
            echo "Aegis-Guard v1.2.0 Launcher"
            echo "Usage: bash aegis.sh [--console | --desktop] [--net]"
            exit 0
            ;;
    esac
done

echo -e "${VIOLET}${BOLD}"
echo "  ┌─────────────────────────────────────────────┐"
echo "  │             AEGIS-GUARD v1.2.0              │"
echo "  │    Endpoint Security & Network IDS Suite    │"
echo "  └─────────────────────────────────────────────┘"
echo -e "${RESET}"

ENGINE_PID=""
OBSERVER_PID=""
cleanup() {
    if [ -n "$ENGINE_PID" ]; then kill "$ENGINE_PID" 2>/dev/null || true; fi
    if [ -n "$OBSERVER_PID" ]; then kill "$OBSERVER_PID" 2>/dev/null || true; fi
}
trap cleanup INT TERM EXIT

# Auto-detect console mode if no display server or Rust/Cargo absent
if [ "$LAUNCH_MODE" = "auto" ]; then
    if ! command -v cargo &>/dev/null || { [ "$(uname -s)" = "Linux" ] && [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; }; then
        LAUNCH_MODE="console"
    else
        LAUNCH_MODE="desktop"
    fi
fi

# Start optional Go Packet Observer when Go binary or Go toolchain exists
if [ "${AEGIS_NET:-1}" = "1" ]; then
    if [ ! -f "target/aegis-network-observer" ] && command -v go &>/dev/null && [ -d "network-observer" ]; then
        echo -e "${CYAN}[net] Building Go packet observer...${RESET}"
        mkdir -p target
        (cd network-observer && go build -o ../target/aegis-network-observer ./cmd/observer) || true
    fi
    if [ -f "target/aegis-network-observer" ]; then
        AEGIS_LOG="${AEGIS_LOG:-info}" ./target/aegis-network-observer > /tmp/aegis-observer.log 2>&1 &
        OBSERVER_PID=$!
        echo -e "  ${GREEN}✓${RESET} Go packet observer started (pid $OBSERVER_PID)"
    fi
fi

if [ "$LAUNCH_MODE" = "console" ]; then
    echo -e "${CYAN}[console] Starting Aegis-Guard Web/Console Engine on http://127.0.0.1:3000 ...${RESET}"
    if [ ! -d "node_modules" ]; then
        echo -e "${YELLOW}Installing root npm dependencies...${RESET}"
        npm install --no-audit --no-fund
    fi
    if [ -f "dist/index.html" ] && [ "${AEGIS_DEV:-0}" != "1" ]; then
        NODE_ENV=production npm start
    else
        npm run dev
    fi
    exit 0
fi

# Desktop (Tauri v2 + Rust engine) mode
SOCKET_DIR="/run/aegis"
if [ "$(uname -s)" = "Linux" ]; then
    if [ "$EUID" -eq 0 ] || command -v sudo &>/dev/null; then
        sudo mkdir -p "$SOCKET_DIR" 2>/dev/null || true
        sudo chmod 1777 "$SOCKET_DIR" 2>/dev/null || true
    fi
fi

[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env" || true
if [ ! -f "target/release/aegis-process-engine" ]; then
    echo -e "${CYAN}[1/3] Building Rust process-engine...${RESET}"
    cargo build --release -p process-engine
fi

if [ -f "target/release/aegis-process-engine" ]; then
    AEGIS_LOG="${AEGIS_LOG:-info}" AEGIS_SOCKET="$SOCKET_DIR/proc.sock" \
        ./target/release/aegis-process-engine > /tmp/aegis-engine.log 2>&1 &
    ENGINE_PID=$!
    echo -e "  ${GREEN}✓${RESET} Rust process-engine started (pid $ENGINE_PID)"
fi

cd tauri-app
if [ ! -d "node_modules" ] || [ ! -f "node_modules/.bin/vite" ]; then
    npm install --no-audit --no-fund
fi
if ! command -v cargo-tauri &>/dev/null; then
    cargo install tauri-cli --version "^2.0" --locked
fi

echo -e "${CYAN}[3/3] Launching Aegis-Guard Desktop UI...${RESET}"
AEGIS_SOCKET="$SOCKET_DIR/proc.sock" AEGIS_NET="${AEGIS_NET:-1}" cargo tauri dev
