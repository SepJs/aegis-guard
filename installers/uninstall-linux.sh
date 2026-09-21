#!/usr/bin/env bash
# installers/uninstall-linux.sh — removes everything install-linux.sh set up
# by Vladimir Unknown

set -e
GREEN='\033[32m'; CYAN='\033[36m'; YELLOW='\033[33m'; RESET='\033[0m'; BOLD='\033[1m'

echo -e "${CYAN}${BOLD}Aegis-Guard — Uninstaller${RESET}"
echo ""
printf "This removes binaries, services, and the desktop icon. Continue? [y/N]: "
read -r confirm
[ "$confirm" = "y" ] || [ "$confirm" = "Y" ] || { echo "Cancelled."; exit 0; }

sudo systemctl stop aegis-process-engine aegis-network-observer 2>/dev/null || true
sudo systemctl disable aegis-process-engine aegis-network-observer 2>/dev/null || true
sudo rm -f /etc/systemd/system/aegis-process-engine.service
sudo rm -f /etc/systemd/system/aegis-network-observer.service
sudo systemctl daemon-reload

sudo rm -f /usr/local/bin/aegis-process-engine
sudo rm -f /usr/local/bin/aegis-network-observer
sudo rm -f /usr/local/bin/aegis-guard-dashboard
sudo rm -f /usr/local/bin/aegis-guard-launch
sudo rm -f /etc/tmpfiles.d/aegis-guard.conf
sudo rm -f /etc/sudoers.d/aegis-guard

rm -f "$HOME/.local/share/applications/aegis-guard.desktop"
rm -f "$HOME/.local/share/icons/aegis-guard.png"
update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true

echo ""
echo -e "${YELLOW}Note: data in /var/lib/aegis (journal, canaries, whitelist) was kept.${RESET}"
printf "Also remove /var/lib/aegis? [y/N]: "
read -r rmdata
if [ "$rmdata" = "y" ] || [ "$rmdata" = "Y" ]; then
    sudo rm -rf /var/lib/aegis
    echo -e "  ${GREEN}✓${RESET} /var/lib/aegis removed"
fi

echo -e "${GREEN}${BOLD}Uninstalled.${RESET}"
