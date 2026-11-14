#!/usr/bin/env bash
# install-desktop-launcher.sh — installs a double-clickable "Aegis-Guard" launcher
# to the current user's desktop and applications menu.

set -euo pipefail
cd "$(dirname "$0")/.."
PROJECT_DIR="$(pwd)"
DESKTOP_DIR="$HOME/.local/share/applications"
ICON_DIR="$HOME/.local/share/icons"

mkdir -p "$DESKTOP_DIR" "$ICON_DIR"
cp tauri-app/src-tauri/icons/icon.png "$ICON_DIR/aegis-guard.png"

cat > "$DESKTOP_DIR/aegis-guard.desktop" << DESK
[Desktop Entry]
Type=Application
Name=Aegis-Guard
Comment=Endpoint Security & Network IDS Suite
Exec=bash -c 'export WEBKIT_DISABLE_DMABUF_RENDERER="\${WEBKIT_DISABLE_DMABUF_RENDERER:-1}"; cd "$PROJECT_DIR" && exec bash "$PROJECT_DIR/aegis.sh" --desktop'
Icon=$ICON_DIR/aegis-guard.png
Terminal=false
Categories=System;Security;
StartupNotify=true
DESK

chmod +x "$DESKTOP_DIR/aegis-guard.desktop"
update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true

echo "✓ Aegis-Guard launcher installed."
echo "  Find it in your applications menu, or double-click:"
echo "  $DESKTOP_DIR/aegis-guard.desktop"
