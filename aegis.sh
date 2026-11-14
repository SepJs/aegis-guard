#!/usr/bin/env bash
# aegis.sh — Cross-Platform Console & Desktop Launcher for Aegis-Guard v1.2.0
#
# Usage:
#   bash aegis.sh               auto-detect desktop binary vs console server
#   bash aegis.sh --desktop     launch native Tauri v2 desktop suite (installed binary first)
#   bash aegis.sh --console     start headless Express + SSE backend & UI on http://127.0.0.1:3000
#   bash aegis.sh --open        open http://127.0.0.1:3000 in browser when starting console mode

set -euo pipefail

VIOLET='\033[35m'; BOLD='\033[1m'; RESET='\033[0m'
GREEN='\033[32m'; CYAN='\033[36m'; YELLOW='\033[33m'; RED='\033[31m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f "package.json" ]; then
    echo -e "${RED}Error: package.json not found in ${SCRIPT_DIR}.${RESET}"
    exit 1
fi

LAUNCH_MODE="auto"
OPEN_BROWSER=0
for arg in "$@"; do
    case "$arg" in
        --console|--web|--headless) LAUNCH_MODE="console" ;;
        --desktop|--gui)            LAUNCH_MODE="desktop" ;;
        --open)                     OPEN_BROWSER=1 ;;
        --net)                      export AEGIS_NET=1 ;;
        -h|--help)
            echo "Aegis-Guard v1.2.0 Launcher"
            echo "Usage: bash aegis.sh [--desktop | --console] [--open] [--net]"
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

# Locate prebuilt desktop binary if installed
DESKTOP_BIN=""
for candidate in \
    "/usr/local/bin/aegis-guard-bin" \
    "${HOME}/.local/bin/aegis-guard-bin" \
    "/usr/local/bin/Aegis-Guard" \
    "${SCRIPT_DIR}/target/release/Aegis-Guard" \
    "${SCRIPT_DIR}/tauri-app/src-tauri/target/release/Aegis-Guard" \
    "/Applications/Aegis-Guard.app/Contents/MacOS/Aegis-Guard"; do
    if [ -x "$candidate" ]; then
        DESKTOP_BIN="$candidate"
        break
    fi
done

# Auto-detect desktop vs console mode
if [ "$LAUNCH_MODE" = "auto" ]; then
    if [ "$(uname -s)" = "Linux" ] && [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
        LAUNCH_MODE="console"
    elif [ -n "$DESKTOP_BIN" ]; then
        LAUNCH_MODE="desktop"
    elif command -v cargo &>/dev/null && command -v cargo-tauri &>/dev/null; then
        LAUNCH_MODE="desktop"
    else
        LAUNCH_MODE="console"
    fi
fi

# Resolve writable runtime socket path for process-engine
SOCKET_DIR="/run/aegis"
if [ ! -d "$SOCKET_DIR" ] || [ ! -w "$SOCKET_DIR" ]; then
    SOCKET_DIR="${XDG_RUNTIME_DIR:-/tmp}"
fi
export AEGIS_SOCKET="${AEGIS_SOCKET:-$SOCKET_DIR/aegis-proc.sock}"

# Start optional Go Packet Observer when binary exists
if [ "${AEGIS_NET:-1}" = "1" ]; then
    OBSERVER_BIN=""
    for c in "/usr/local/bin/aegis-network-observer" "${SCRIPT_DIR}/target/aegis-network-observer" "${SCRIPT_DIR}/target/release/aegis-network-observer"; do
        [ -x "$c" ] && OBSERVER_BIN="$c" && break
    done
    if [ -z "$OBSERVER_BIN" ] && command -v go &>/dev/null && [ -d "network-observer" ]; then
        mkdir -p target
        (cd network-observer && go build -o ../target/aegis-network-observer ./cmd/observer) && OBSERVER_BIN="${SCRIPT_DIR}/target/aegis-network-observer" || true
    fi
    if [ -n "$OBSERVER_BIN" ]; then
        AEGIS_LOG="${AEGIS_LOG:-info}" "$OBSERVER_BIN" > /tmp/aegis-observer.log 2>&1 &
        OBSERVER_PID=$!
        echo -e "  ${GREEN}✓${RESET} Go packet observer started (pid $OBSERVER_PID)"
    fi
fi

# Start optional Rust process-engine daemon when binary exists
PROC_BIN=""
for c in "/usr/local/bin/aegis-process-engine" "${SCRIPT_DIR}/target/release/aegis-process-engine"; do
    [ -x "$c" ] && PROC_BIN="$c" && break
done
if [ -n "$PROC_BIN" ]; then
    AEGIS_LOG="${AEGIS_LOG:-info}" AEGIS_SOCKET="$AEGIS_SOCKET" \
        "$PROC_BIN" > /tmp/aegis-engine.log 2>&1 &
    ENGINE_PID=$!
    echo -e "  ${GREEN}✓${RESET} Rust process-engine started (pid $ENGINE_PID)"
fi

if [ "$LAUNCH_MODE" = "desktop" ]; then
    if [ "$(uname -s)" = "Linux" ]; then
        export WEBKIT_DISABLE_DMABUF_RENDERER="${WEBKIT_DISABLE_DMABUF_RENDERER:-1}"
    fi
    if [ -n "$DESKTOP_BIN" ]; then
        echo -e "${CYAN}[desktop] Launching native Aegis-Guard binary (${DESKTOP_BIN})...${RESET}"
        "$DESKTOP_BIN"
        exit $?
    fi

    [ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env" || true
    if command -v cargo &>/dev/null && [ -d "tauri-app" ]; then
        if [ ! -f "tauri-app/dist/index.html" ]; then
            echo -e "${CYAN}[desktop] Building frontend UI assets...${RESET}"
            npm --prefix tauri-app install --no-audit --no-fund || true
            npm --prefix tauri-app run build || true
        fi
        if [ -f "tauri-app/dist/index.html" ]; then
            echo -e "${CYAN}[desktop] Building native Aegis-Guard binary with cargo...${RESET}"
            if cargo build --release -p aegis-guard; then
                for built in "${SCRIPT_DIR}/target/release/Aegis-Guard" "${SCRIPT_DIR}/tauri-app/src-tauri/target/release/Aegis-Guard"; do
                    if [ -x "$built" ]; then
                        echo -e "${GREEN}[desktop] Launching native Aegis-Guard (${built})...${RESET}"
                        "$built"
                        exit $?
                    fi
                done
            fi
        fi
        if command -v cargo-tauri &>/dev/null; then
            echo -e "${CYAN}[desktop] Starting Tauri dev shell via cargo-tauri...${RESET}"
            (cd tauri-app && AEGIS_SOCKET="$AEGIS_SOCKET" AEGIS_NET="${AEGIS_NET:-1}" cargo tauri dev) && exit 0 || true
        elif [ -x "tauri-app/node_modules/.bin/tauri" ]; then
            echo -e "${CYAN}[desktop] Starting Tauri dev shell via local @tauri-apps/cli...${RESET}"
            (cd tauri-app && AEGIS_SOCKET="$AEGIS_SOCKET" AEGIS_NET="${AEGIS_NET:-1}" ./node_modules/.bin/tauri dev) && exit 0 || true
        fi
    fi
    echo -e "${YELLOW}[desktop] Native desktop unavailable — falling back to web console UI on http://127.0.0.1:${PORT:-3000}${RESET}"
    OPEN_BROWSER=1
fi

echo -e "${CYAN}[console] Starting Aegis-Guard Engine & UI on http://127.0.0.1:${PORT:-3000} ...${RESET}"
if [ ! -d "node_modules" ] && [ -w "$SCRIPT_DIR" ]; then
    echo -e "${YELLOW}Installing root npm dependencies...${RESET}"
    npm install --no-audit --no-fund
fi

if [ "$OPEN_BROWSER" -eq 1 ]; then
    (
        sleep 2
        if command -v xdg-open &>/dev/null; then
            xdg-open "http://127.0.0.1:${PORT:-3000}" >/dev/null 2>&1 || true
        elif command -v open &>/dev/null; then
            open "http://127.0.0.1:${PORT:-3000}" >/dev/null 2>&1 || true
        fi
    ) &
fi

run_tsx_server() {
    if [ -x "./node_modules/.bin/tsx" ]; then
        exec ./node_modules/.bin/tsx server.ts
    elif command -v tsx &>/dev/null; then
        exec tsx server.ts
    else
        exec npx --yes tsx server.ts
    fi
}

export AEGIS_DATA_DIR="${AEGIS_DATA_DIR:-$HOME/.local/share/aegis-guard}"
if [ -f "tauri-app/dist/index.html" ] || [ -f "dist/index.html" ]; then
    if [ "${AEGIS_DEV:-0}" != "1" ]; then
        export NODE_ENV=production
        run_tsx_server
    fi
fi
run_tsx_server
