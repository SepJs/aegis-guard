#!/usr/bin/env bash
# Aegis-Guard — quick local install script
# Usage: bash install.sh
# Runs the Rust installer wizard

set -e

# Colors
VIOLET='\033[35m'; BOLD='\033[1m'; GREEN='\033[32m'
YELLOW='\033[33m'; RESET='\033[0m'; CYAN='\033[36m'

echo -e "${VIOLET}${BOLD}"
echo "  ╔═══════════════════════════════════════════╗"
echo "  ║     AEGIS-GUARD  INSTALLER  v0.1.0       ║"
echo "  ║     by Vladimir Unknown                   ║"
echo "  ╚═══════════════════════════════════════════╝"
echo -e "${RESET}"

# Check Rust
if ! command -v cargo &>/dev/null; then
    echo -e "${YELLOW}Rust not found. Installing...${RESET}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# Check Node
if ! command -v node &>/dev/null; then
    echo -e "${YELLOW}Node.js required. Install from: https://nodejs.org${RESET}"
    exit 1
fi

echo -e "${CYAN}Building installer...${RESET}"
source "$HOME/.cargo/env" 2>/dev/null || true
cargo build --release -p aegis-installer 2>&1 | tail -3

echo -e "${GREEN}Launching installer wizard...${RESET}"
echo ""
./target/release/aegis-installer
