#!/usr/bin/env bash
# ==============================================================================
#  Aegis-Guard — 1-Line Non-Interactive Auto Installer for Linux
# ==============================================================================

set -e

if [ "$EUID" -ne 0 ]; then
    echo "[!] Root access required. Prompting for sudo..."
    exec sudo bash "$0" "$@"
fi

DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$DIR/install-linux.sh" ]; then
    bash "$DIR/install-linux.sh" --unattended
elif [ -f "$DIR/linux/install-linux.sh" ]; then
    bash "$DIR/linux/install-linux.sh" --unattended
else
    echo "[*] Downloading official Aegis-Guard installer..."
    TMP_DIR="$(mktemp -d)"
    git clone --depth 1 https://github.com/SepJs/aegis-guard.git "$TMP_DIR/aegis-guard"
    bash "$TMP_DIR/aegis-guard/installers/linux/install-linux.sh" --unattended
    rm -rf "$TMP_DIR"
fi
