#!/usr/bin/env bash
# install-gui.sh — Build & Open the Cross-Platform GTK3 Visual Installer for Aegis-Guard v1.2.0
# Works on Linux and macOS (and MSYS2/Git Bash on Windows).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "${SCRIPT_DIR}/installers/launch-gtk-installer.sh" "$@"
