#!/usr/bin/env bash
# Aegis-Guard — run network observer
set -e

VIOLET='\033[35m'; BOLD='\033[1m'; RESET='\033[0m'
GREEN='\033[32m'; CYAN='\033[36m'; YELLOW='\033[33m'

cd "$(dirname "$0")"

echo -e "${VIOLET}${BOLD}AEGIS-GUARD Network Observer — by Vladimir Unknown${RESET}"
echo ""

# Build if not present
if [ ! -f "target/aegis-network-observer" ]; then
    echo -e "${CYAN}Building network observer...${RESET}"
    if ! command -v go &>/dev/null; then
        echo -e "${YELLOW}Go not found. Install from: https://go.dev/dl${RESET}"
        exit 1
    fi
    cd network-observer && go build -o ../target/aegis-network-observer ./cmd/observer
    cd ..
fi

if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}Network observer needs root for /proc/net access.${RESET}"
    exec sudo AEGIS_LOG="${AEGIS_LOG:-info}" "$(realpath target/aegis-network-observer)"
fi

echo -e "${GREEN}Starting network observer (listening on :50053)...${RESET}"
AEGIS_LOG="${AEGIS_LOG:-info}" ./target/aegis-network-observer
