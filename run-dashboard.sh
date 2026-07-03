#!/usr/bin/env bash
# Aegis-Guard — run dashboard (handles npm install automatically)
set -e

VIOLET='\033[35m'; BOLD='\033[1m'; RESET='\033[0m'; GREEN='\033[32m'
CYAN='\033[36m'; YELLOW='\033[33m'

cd "$(dirname "$0")/tauri-app"

echo -e "${CYAN}Checking Node.js dependencies...${RESET}"
if [ ! -d "node_modules" ] || [ ! -f "node_modules/.bin/vite" ]; then
    echo -e "${YELLOW}Installing npm packages (first run)...${RESET}"
    npm install
fi

echo -e "${GREEN}Starting Aegis-Guard dashboard...${RESET}"
echo -e "${VIOLET}${BOLD}by Vladimir Unknown${RESET}"
echo ""

# Check if process engine is requested
if [ "${AEGIS_NET:-0}" = "1" ]; then
    echo -e "${CYAN}Network observer bridge enabled (port 50053)${RESET}"
fi

source "$HOME/.cargo/env" 2>/dev/null || true
AEGIS_NET="${AEGIS_NET:-0}" cargo tauri dev
