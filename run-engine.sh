#!/usr/bin/env bash
# Aegis-Guard — run process engine
set -e

VIOLET='\033[35m'; BOLD='\033[1m'; RESET='\033[0m'
GREEN='\033[32m'; CYAN='\033[36m'; YELLOW='\033[33m'; RED='\033[31m'

cd "$(dirname "$0")"

echo -e "${VIOLET}${BOLD}AEGIS-GUARD Process Engine — by Vladimir Unknown${RESET}"
echo ""

source "$HOME/.cargo/env" 2>/dev/null || true

# Check if binary exists, build if not
if [ ! -f "target/release/aegis-process-engine" ]; then
    echo -e "${CYAN}Building process engine (first run)...${RESET}"
    cargo build --release -p process-engine
fi

# Must run as root for /proc access
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}Process engine needs root to read /proc for all PIDs.${RESET}"
    echo -e "${YELLOW}Re-running with sudo...${RESET}"
    exec sudo AEGIS_LOG="${AEGIS_LOG:-info}" \
        AEGIS_SOCKET="${AEGIS_SOCKET:-/run/aegis/proc.sock}" \
        "$(realpath target/release/aegis-process-engine)"
fi

echo -e "${GREEN}Starting process engine...${RESET}"
AEGIS_LOG="${AEGIS_LOG:-info}" \
AEGIS_SOCKET="${AEGIS_SOCKET:-/run/aegis/proc.sock}" \
./target/release/aegis-process-engine
