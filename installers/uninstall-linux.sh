#!/usr/bin/env bash
# installers/uninstall-linux.sh — cleanly removes Aegis-Guard binaries, services, and launchers.

set -e
GREEN='\033[32m'; CYAN='\033[36m'; YELLOW='\033[33m'; RESET='\033[0m'; BOLD='\033[1m'

REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME="$HOME"
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    REAL_HOME="$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6 || echo "/home/$SUDO_USER")"
fi

echo -e "${CYAN}${BOLD}Aegis-Guard — Uninstaller${RESET}"
echo ""
printf "This removes binaries, services, and desktop entries. Continue? [y/N]: "
read -r confirm
[ "$confirm" = "y" ] || [ "$confirm" = "Y" ] || { echo "Cancelled."; exit 0; }

sudo systemctl stop aegis-process-engine aegis-network-observer 2>/dev/null || true
sudo systemctl disable aegis-process-engine aegis-network-observer 2>/dev/null || true
sudo rm -f /etc/systemd/system/aegis-process-engine.service
sudo rm -f /etc/systemd/system/aegis-network-observer.service
sudo systemctl daemon-reload 2>/dev/null || true

sudo rm -f /usr/local/bin/aegis-process-engine
sudo rm -f /usr/local/bin/aegis-network-observer
sudo rm -f /usr/local/bin/aegis-guard
sudo rm -f /usr/local/bin/aegis-guard-bin
sudo rm -f /usr/local/bin/aegis-guard-desktop
sudo rm -f /usr/local/bin/aegis-guard-dashboard
sudo rm -f /usr/local/bin/aegis-guard-launch
sudo rm -f /usr/local/bin/aegis-installer
sudo rm -f /etc/tmpfiles.d/aegis-guard.conf
sudo rm -f /etc/sudoers.d/aegis-guard
sudo rm -f /usr/share/applications/aegis-guard.desktop
sudo rm -f /usr/share/icons/hicolor/128x128/apps/aegis-guard.png

rm -f "$REAL_HOME/.local/share/applications/aegis-guard.desktop"
rm -f "$REAL_HOME/.local/share/icons/aegis-guard.png"
rm -f "$REAL_HOME/.local/bin/aegis-guard" "$REAL_HOME/.local/bin/aegis-guard-bin" "$REAL_HOME/.local/bin/aegis-guard-desktop"
update-desktop-database "$REAL_HOME/.local/share/applications" 2>/dev/null || true
sudo update-desktop-database /usr/share/applications 2>/dev/null || true

echo ""
echo -e "${YELLOW}Note: data in /var/lib/aegis (journal, canaries, whitelist) was kept.${RESET}"
printf "Also remove /var/lib/aegis? [y/N]: "
read -r rmdata
if [ "$rmdata" = "y" ] || [ "$rmdata" = "Y" ]; then
    sudo rm -rf /var/lib/aegis
    echo -e "  ${GREEN}✓${RESET} /var/lib/aegis removed"
fi

echo -e "${GREEN}${BOLD}Uninstalled.${RESET}"
