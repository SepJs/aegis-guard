#!/usr/bin/env bash
# ==============================================================================
#  Aegis-Guard — Uninstaller for Linux
# ==============================================================================

set -e

if [ "$EUID" -ne 0 ]; then
    echo "[!] Root access required to remove system services. Elevating..."
    exec sudo bash "$0" "$@"
fi

echo "[*] Stopping Aegis-Guard background services..."
systemctl stop aegis-guard.service aegis-observer.service 2>/dev/null || true
systemctl disable aegis-guard.service aegis-observer.service 2>/dev/null || true

echo "[*] Removing systemd unit files..."
rm -f /etc/systemd/system/aegis-guard.service /etc/systemd/system/aegis-observer.service
systemctl daemon-reload 2>/dev/null || true

echo "[*] Removing binaries and wrappers..."
rm -f /usr/local/bin/aegis-guard /usr/local/bin/aegis-process-engine /usr/local/bin/aegis-network-observer /usr/local/bin/aegis-uninstall

echo "[*] Removing desktop shortcuts..."
rm -f /usr/share/applications/aegis-guard.desktop /usr/share/icons/hicolor/scalable/apps/aegis-guard.svg

echo "[✓] Aegis-Guard software has been successfully removed."
echo "    Note: Logs and quarantine vault in /var/lib/aegis-guard were preserved for security audits."
echo "    To purge them manually, run: sudo rm -rf /var/lib/aegis-guard /var/log/aegis-guard /etc/aegis-guard"
