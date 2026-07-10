#!/usr/bin/env bash
# install-desktop-launcher.sh — adds a double-clickable "Aegis-Guard" launcher
# to your applications menu. By Vladimir Unknown.

set -e
cd "$(dirname "$0")"
PROJECT_DIR="$(pwd)"
DESKTOP_DIR="$HOME/.local/share/applications"
ICON_DIR="$HOME/.local/share/icons"

mkdir -p "$DESKTOP_DIR" "$ICON_DIR"
cp tauri-app/src-tauri/icons/icon.png "$ICON_DIR/aegis-guard.png"

cat > "$DESKTOP_DIR/aegis-guard.desktop" << DESK
[Desktop Entry]
Type=Application
Name=Aegis-Guard
Comment=Endpoint Security Suite — by Vladimir Unknown
Exec=bash -c 'cd "$PROJECT_DIR" && x-terminal-emulator -e bash aegis.sh || xterm -e bash aegis.sh'
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
