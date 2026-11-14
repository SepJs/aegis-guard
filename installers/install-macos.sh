#!/usr/bin/env bash
# installers/install-macos.sh — Aegis-Guard macOS Console & Desktop Installer
# Supports Apple Silicon (arm64) and Intel (x86_64) Macs via Homebrew.
# Usage:
#   bash installers/install-macos.sh [--console | --desktop] [--yes]

set -euo pipefail

VIOLET='\033[35m'; BOLD='\033[1m'; RESET='\033[0m'
GREEN='\033[32m'; CYAN='\033[36m'; YELLOW='\033[33m'; RED='\033[31m'; DIM='\033[2m'

MODE="desktop"
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
echo "  │       AEGIS-GUARD — macOS INSTALLER         │"
echo "  │               Version 1.2.0                 │"
echo "  └─────────────────────────────────────────────┘"
echo -e "${RESET}"

if [ "$(uname -s)" != "Darwin" ]; then
    echo -e "${RED}Error: this installer targets macOS (Darwin). Use install-linux.sh on Linux.${RESET}"
    exit 1
fi

ARCH="$(uname -m)"
BREW_PREFIX="/usr/local"
[ "$ARCH" = "arm64" ] && [ -d "/opt/homebrew" ] && BREW_PREFIX="/opt/homebrew"
export PATH="${BREW_PREFIX}/bin:${BREW_PREFIX}/sbin:$PATH"

SCRIPT_DIR=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/../package.json" ] && [ -d "$SCRIPT_DIR/../tauri-app" ]; then
    PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
elif [ -f "./package.json" ] && [ -d "./tauri-app" ]; then
    PROJECT_ROOT="$(pwd)"
else
    PROJECT_ROOT="$HOME/.local/share/aegis-guard"
    echo -e "${CYAN}[0/5] Cloning Aegis-Guard source to ${PROJECT_ROOT}...${RESET}"
    mkdir -p "$(dirname "$PROJECT_ROOT")"
    if [ -d "$PROJECT_ROOT/.git" ]; then
        git -C "$PROJECT_ROOT" pull --ff-only || true
    else
        rm -rf "$PROJECT_ROOT"
        git clone --depth 1 https://github.com/SepJs/aegis-guard.git "$PROJECT_ROOT"
    fi
fi

cd "$PROJECT_ROOT"
echo -e "${CYAN}Target Root:${RESET} ${BOLD}${PROJECT_ROOT}${RESET} (macOS ${ARCH})"

# 1. Xcode Command Line Tools & Homebrew
echo -e "${CYAN}[1/5] Checking Xcode CLT & Homebrew...${RESET}"
if ! xcode-select -p &>/dev/null; then
    echo -e "${YELLOW}Xcode Command Line Tools missing. Triggering xcode-select --install...${RESET}"
    xcode-select --install || true
    echo -e "${YELLOW}Re-run this installer after Xcode CLT finishes installing.${RESET}"
    exit 1
fi

if ! command -v brew &>/dev/null; then
    if [ "$AUTO_YES" -eq 1 ]; then
        NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    else
        echo -e "${YELLOW}Homebrew not found. Installing Homebrew...${RESET}"
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    eval "$(${BREW_PREFIX}/bin/brew shellenv)" 2>/dev/null || true
fi
echo -e "  ${GREEN}✓${RESET} Homebrew ready"

# 2. Node.js, Go, Rust
echo -e "${CYAN}[2/5] Checking Node.js, Go, and Rust toolchains...${RESET}"
if ! command -v node &>/dev/null; then
    brew install node
fi
echo -e "  ${GREEN}✓${RESET} Node: $(node --version)"

if ! command -v go &>/dev/null; then
    brew install go || true
fi
HAVE_GO=0
if command -v go &>/dev/null; then
    HAVE_GO=1
    echo -e "  ${GREEN}✓${RESET} Go: $(go version | awk '{print $3}')"
fi

[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env" || true
HAVE_CARGO=0
if command -v cargo &>/dev/null; then
    HAVE_CARGO=1
elif [ "$MODE" = "desktop" ]; then
    echo -e "  ${YELLOW}Installing Rust toolchain...${RESET}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    [ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"
    command -v cargo &>/dev/null && HAVE_CARGO=1
fi
[ "$HAVE_CARGO" -eq 1 ] && echo -e "  ${GREEN}✓${RESET} Rust: $(rustc --version)"

# 3. Build Web Dashboard & Express Runtime
echo -e "${CYAN}[3/5] Installing npm packages & building UI...${RESET}"
npm install --no-audit --no-fund
npm run build
echo -e "  ${GREEN}✓${RESET} frontend built"

# 4. Build Go Network Observer & Optional Native Tauri Bundle
echo -e "${CYAN}[4/5] Building native Go & Rust components...${RESET}"
if [ "$HAVE_GO" -eq 1 ] && [ -d "network-observer" ]; then
    mkdir -p target
    (cd network-observer && go build -ldflags="-s -w" -o ../target/aegis-network-observer ./cmd/observer)
    echo -e "  ${GREEN}✓${RESET} Go network-observer built"
fi

APP_BUNDLE_DST="/Applications/Aegis-Guard.app"
if [ "$HAVE_CARGO" -eq 1 ] && [ "$MODE" = "desktop" ]; then
    cargo build --release -p process-engine || true
    cargo build --release -p aegis-guard || true
    if command -v pkg-config &>/dev/null && pkg-config --exists gtk+-3.0 2>/dev/null; then
        cargo build --release -p aegis-installer || true
    fi
    if ! command -v cargo-tauri &>/dev/null; then
        cargo install tauri-cli --version "^2.0" --locked || true
    fi
    (cd tauri-app && cargo tauri build --bundles app) || true
    BUILT_APP="$(find target tauri-app/src-tauri/target -maxdepth 6 -name "Aegis-Guard.app" -type d 2>/dev/null | head -n 1 || true)"
    if [ -n "$BUILT_APP" ]; then
        rm -rf "$APP_BUNDLE_DST"
        cp -R "$BUILT_APP" "$APP_BUNDLE_DST"
        xattr -cr "$APP_BUNDLE_DST" 2>/dev/null || true
        echo -e "  ${GREEN}✓${RESET} Installed macOS App: $APP_BUNDLE_DST"
    fi
fi

# 5. Install CLI wrapper + Local Data Vault
echo -e "${CYAN}[5/5] Configuring macOS CLI & data vault...${RESET}"
BIN_TARGET="${BREW_PREFIX}/bin"
mkdir -p "$BIN_TARGET" "$HOME/.local/share/aegis-guard/quarantine" "$HOME/.local/share/aegis-guard/canaries"

cat > "${BIN_TARGET}/aegis-guard" << CLI_EOF
#!/usr/bin/env bash
cd "$PROJECT_ROOT"
exec bash "$PROJECT_ROOT/aegis.sh" "\$@"
CLI_EOF
chmod 755 "${BIN_TARGET}/aegis-guard"

cat > "${BIN_TARGET}/aegis-guard-desktop" << DESK_EOF
#!/usr/bin/env bash
if [ -d "$APP_BUNDLE_DST" ]; then
    open "$APP_BUNDLE_DST"
else
    cd "$PROJECT_ROOT"
    exec bash "$PROJECT_ROOT/aegis.sh" --desktop "\$@"
fi
DESK_EOF
chmod 755 "${BIN_TARGET}/aegis-guard-desktop"

[ -f target/aegis-network-observer ] && install -m 755 target/aegis-network-observer "${BIN_TARGET}/"
[ -f target/release/aegis-process-engine ] && install -m 755 target/release/aegis-process-engine "${BIN_TARGET}/"
[ -f target/release/Aegis-Guard ] && install -m 755 target/release/Aegis-Guard "${BIN_TARGET}/aegis-guard-bin"
[ -f target/release/aegis-installer ] && install -m 755 target/release/aegis-installer "${BIN_TARGET}/"

echo ""
echo -e "${GREEN}${BOLD}━━━ Aegis-Guard v1.2.0 macOS Setup Complete ━━━${RESET}"
echo -e "  Console mode: ${CYAN}aegis-guard --console${RESET}  (http://127.0.0.1:3000)"
if [ -d "$APP_BUNDLE_DST" ]; then
    echo -e "  Desktop App:  ${CYAN}open /Applications/Aegis-Guard.app${RESET}"
else
    echo -e "  Desktop UI:   ${CYAN}aegis-guard-desktop${RESET}"
fi
echo ""
