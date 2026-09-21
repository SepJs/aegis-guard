#!/usr/bin/env bash
# aegis.sh — THE one-button launcher for Aegis-Guard
# by Vladimir Unknown
#
# Usage:
#   bash aegis.sh              engine + dashboard
#   AEGIS_NET=1 bash aegis.sh  engine + network observer + dashboard
#
# This single command:
#   1. Fixes the IPC socket directory permissions (self-healing)
#   2. Builds any missing binaries / npm packages (first run only)
#   3. Starts process-engine (and optionally network-observer) in the background
#   4. Starts the dashboard in the foreground
#   5. Cleans up background services when the dashboard closes / Ctrl+C
#
# Nothing to configure. Just run it.

set -e

VIOLET='\033[35m'; BOLD='\033[1m'; RESET='\033[0m'
GREEN='\033[32m'; CYAN='\033[36m'; YELLOW='\033[33m'; RED='\033[31m'

cd "$(dirname "$0")"

if [ ! -f "Cargo.toml" ] || [ ! -d "tauri-app" ]; then
    echo -e "${RED}Error: run this from the aegis-guard project root${RESET}"
    exit 1
fi

clear
echo -e "${VIOLET}${BOLD}"
echo "  ╔═══════════════════════════════════════════╗"
echo "  ║              AEGIS-GUARD                  ║"
echo "  ║        by Vladimir Unknown                ║"
echo "  ╚═══════════════════════════════════════════╝"
echo -e "${RESET}"

SOCKET_DIR="/run/aegis"
ENGINE_PID=""
OBSERVER_PID=""

cleanup() {
    echo ""
    echo -e "${YELLOW}Shutting down...${RESET}"
    [ -n "$ENGINE_PID" ]   && { sudo kill "$ENGINE_PID"   2>/dev/null || true; echo -e "  ${GREEN}✓${RESET} process-engine stopped"; }
    [ -n "$OBSERVER_PID" ] && { sudo kill "$OBSERVER_PID" 2>/dev/null || true; echo -e "  ${GREEN}✓${RESET} network-observer stopped"; }
    exit 0
}
trap cleanup INT TERM EXIT

# ── 1. Socket directory — self-healing permission fix ────────────────────────
# The dashboard (runs as your normal user) must be able to create the IPC
# socket here; the engine (root, since it reads other users' /proc entries)
# must be able to connect to it. Sticky + world-writable, like /tmp.
echo -e "${CYAN}[1/5] Fixing socket permissions...${RESET}"
sudo mkdir -p "$SOCKET_DIR"
sudo chmod 1777 "$SOCKET_DIR"
echo -e "  ${GREEN}✓${RESET} $SOCKET_DIR ready"

# ── 2. Rust toolchain ──────────────────────────────────────────────────────────
source "$HOME/.cargo/env" 2>/dev/null || true
if ! command -v cargo &>/dev/null; then
    echo -e "${YELLOW}Rust not found — installing...${RESET}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# ── 3. Build binaries if missing ──────────────────────────────────────────────
echo -e "${CYAN}[2/5] Checking binaries...${RESET}"
if [ ! -f "target/release/aegis-process-engine" ]; then
    echo -e "  ${YELLOW}Building process-engine (first run, ~1-2 min)...${RESET}"
    cargo build --release -p process-engine
fi
echo -e "  ${GREEN}✓${RESET} process-engine ready"

if [ "${AEGIS_NET:-0}" = "1" ]; then
    if [ ! -f "target/aegis-network-observer" ]; then
        if command -v go &>/dev/null; then
            echo -e "  ${YELLOW}Building network-observer...${RESET}"
            mkdir -p target
            (cd network-observer && go build -o ../target/aegis-network-observer ./cmd/observer)
        else
            echo -e "  ${YELLOW}⚠ Go not found — skipping network-observer (Go: https://go.dev/dl){RESET}"
        fi
    fi
    [ -f "target/aegis-network-observer" ] && echo -e "  ${GREEN}✓${RESET} network-observer ready"
fi

# ── 4. Launch background services (root) ──────────────────────────────────────
echo -e "${CYAN}[3/5] Starting background services...${RESET}"
echo -e "  ${YELLOW}(sudo password may be requested once){RESET}"
sudo -v

sudo AEGIS_LOG="${AEGIS_LOG:-info}" AEGIS_SOCKET="$SOCKET_DIR/proc.sock" \
    ./target/release/aegis-process-engine > /tmp/aegis-engine.log 2>&1 &
ENGINE_PID=$!
echo -e "  ${GREEN}✓${RESET} process-engine started (pid $ENGINE_PID)"

if [ "${AEGIS_NET:-0}" = "1" ] && [ -f "target/aegis-network-observer" ]; then
    sudo AEGIS_LOG="${AEGIS_LOG:-info}" ./target/aegis-network-observer > /tmp/aegis-observer.log 2>&1 &
    OBSERVER_PID=$!
    echo -e "  ${GREEN}✓${RESET} network-observer started (pid $OBSERVER_PID)"
fi

sleep 1

# ── 5. Launch dashboard (foreground) ──────────────────────────────────────────
echo -e "${CYAN}[4/5] Preparing dashboard...${RESET}"
cd tauri-app

if [ ! -d "node_modules" ] || [ ! -f "node_modules/.bin/vite" ]; then
    echo -e "  ${YELLOW}Installing npm packages (first run, ~1 min)...${RESET}"
    npm install
fi

if ! command -v cargo-tauri &>/dev/null; then
    echo -e "  ${YELLOW}Installing Tauri CLI (first run)...${RESET}"
    cargo install tauri-cli --version "^2.0" --locked
fi

echo -e "  ${GREEN}✓${RESET} dashboard ready"
echo ""
echo -e "${CYAN}[5/5] Launching Aegis-Guard...${RESET}"
echo ""

AEGIS_SOCKET="$SOCKET_DIR/proc.sock" AEGIS_NET="${AEGIS_NET:-0}" cargo tauri dev

# cleanup() runs automatically via the EXIT trap when the window closes.
