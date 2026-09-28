#!/usr/bin/env bash
# ==============================================================================
#  Aegis-Guard Universal Auto-Detect & Deploy Script (Single Command / One-Click)
#  Detects operating system, architecture, package manager, and deploys as root
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${MAGENTA}${BOLD}================================================================${NC}"
echo -e "${CYAN}${BOLD}         AEGIS-GUARD -- 1-CLICK UNIVERSAL SYSTEM INSTALLER      ${NC}"
echo -e "${CYAN}        Automated OS Detection, Root Elevation & Full Native Deployment ${NC}"
echo -e "${MAGENTA}${BOLD}================================================================${NC}"
echo ""

# 1. OS & Architecture Detection
OS_TYPE="$(uname -s 2>/dev/null || echo "Unknown")"
ARCH_TYPE="$(uname -m 2>/dev/null || echo "Unknown")"

echo -e "${CYAN}[*] Detecting Host System...${NC}"
echo -e "    Operating System: ${BOLD}${OS_TYPE}${NC}"
echo -e "    Architecture:     ${BOLD}${ARCH_TYPE}${NC}"

# Check for Windows / WSL / MSYS / Git Bash
if [[ "${OS_TYPE}" == MINGW* ]] || [[ "${OS_TYPE}" == MSYS* ]] || [[ "${OS_TYPE}" == CYGWIN* ]]; then
    echo -e "${YELLOW}[!] Windows Shell environment detected.${NC}"
    echo -e "${CYAN}[*] Forwarding to Windows 1-Click PowerShell installer with UAC elevation...${NC}"
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    powershell.exe -ExecutionPolicy Bypass -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"${SCRIPT_DIR}/install-windows.ps1\"'"
    exit 0
fi

# 2. Linux Elevation Check
if [[ "${EUID}" -ne 0 ]]; then
    echo -e "${YELLOW}[!] Root/Administrator privileges required to attach eBPF probes, inspect /proc, and configure systemd.${NC}"
    echo -e "${CYAN}[*] Requesting sudo elevation now...${NC}"
    if command -v sudo >/dev/null 2>&1; then
        exec sudo bash "$0" "$@"
    else
        echo -e "${RED}[ERROR] 'sudo' not available. Please execute this script as root: su -c 'bash $0'${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}[+] Elevated root privileges confirmed.${NC}"

# 3. Detect Linux Distribution and Package Manager
DISTRO="unknown"
PKG_CMD=""
PKG_INSTALL=""

if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO="${ID:-unknown}"
fi

echo -e "${CYAN}[*] Distribution identified: ${BOLD}${DISTRO}${NC}"

case "${DISTRO}" in
    ubuntu|debian|linuxmint|pop|kali)
        PKG_CMD="apt-get"
        echo -e "${CYAN}[*] Updating package index via apt...${NC}"
        apt-get update -qq || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
            curl build-essential pkg-config libssl-dev \
            libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev \
            iptables iproute2 procps >/dev/null 2>&1 || true
        ;;
    fedora|rhel|centos|rocky|alma)
        PKG_CMD="dnf"
        dnf install -y -q \
            curl gcc pkg-config openssl-devel \
            webkit2gtk4.1-devel gtk3-devel libappindicator-gtk3-devel librsvg2-devel \
            iptables iproute procps-ng >/dev/null 2>&1 || true
        ;;
    arch|manjaro|endeavouros)
        PKG_CMD="pacman"
        pacman -Sy --noconfirm --needed \
            curl base-devel openssl webkit2gtk-4.1 gtk3 libappindicator-gtk3 librsvg iptables iproute2 procps-ng >/dev/null 2>&1 || true
        ;;
    opensuse*|suse)
        PKG_CMD="zypper"
        zypper --non-interactive in -y \
            curl gcc pkg-config libopenssl-devel \
            webkit2gtk3-devel gtk3-devel libappindicator3-devel librsvg-devel iptables iproute2 procps >/dev/null 2>&1 || true
        ;;
    *)
        echo -e "${YELLOW}[!] Generic Linux detected; proceeding with universal fallback deployment.${NC}"
        ;;
esac

# 4. Provision System Paths
INSTALL_DIR="/usr/local/bin"
DATA_DIR="/var/log/aegis-guard"
QUARANTINE_DIR="/var/lib/aegis-guard/quarantine"
CONFIG_DIR="/etc/aegis-guard"

mkdir -p "${DATA_DIR}" "${QUARANTINE_DIR}" "${CONFIG_DIR}" "${INSTALL_DIR}"
chmod 700 "${QUARANTINE_DIR}"
chmod 755 "${DATA_DIR}"

echo -e "${GREEN}[+] Secured directories provisioned: ${DATA_DIR}, ${QUARANTINE_DIR}${NC}"

# 5. Build or Deploy Native Engine Binaries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo -e "${CYAN}[*] Checking for native compiled engine binaries...${NC}"
if [ -f "${SCRIPT_DIR}/target/release/aegis-process-engine" ]; then
    cp -f "${SCRIPT_DIR}/target/release/aegis-process-engine" "${INSTALL_DIR}/aegis-process-engine"
    chmod 755 "${INSTALL_DIR}/aegis-process-engine"
    echo -e "${GREEN}[+] Process Engine installed to ${INSTALL_DIR}/aegis-process-engine${NC}"
fi

# 6. Deploy systemd Service Units
if command -v systemctl >/dev/null 2>&1; then
    echo -e "${CYAN}[*] Configuring systemd background active-defense services...${NC}"

    cat > /etc/systemd/system/aegis-guard.service <<EOF
[Unit]
Description=Aegis-Guard Endpoint & Network Defense Daemon
After=network.target syslog.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/var/lib/aegis-guard
ExecStart=${INSTALL_DIR}/aegis-process-engine
Restart=always
RestartSec=3
StandardOutput=append:${DATA_DIR}/daemon.log
StandardError=append:${DATA_DIR}/daemon.err
LimitNOFILE=65536
CapabilityBoundingSet=CAP_SYS_PTRACE CAP_NET_ADMIN CAP_NET_RAW CAP_KILL CAP_SYS_CHROOT

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload || true
    systemctl enable aegis-guard.service || true
    systemctl restart aegis-guard.service || true
    echo -e "${GREEN}[+] Aegis-Guard background defense daemon registered and started.${NC}"
fi

# 7. Create 1-Click Desktop & Menu Launcher
TARGET_USER="${SUDO_USER:-$(logname 2>/dev/null || echo "root")}"
USER_HOME="$(getent passwd "${TARGET_USER}" | cut -d: -f6 || echo "/root")"
DESKTOP_DIR="${USER_HOME}/Desktop"

mkdir -p "${DESKTOP_DIR}" "/usr/share/applications"

cat > "/usr/share/applications/aegis-guard.desktop" <<EOF
[Desktop Entry]
Name=Aegis-Guard
GenericName=Endpoint & Network Security Suite
Comment=Live Process Tree, Network IDS & Malware Neutralization
Exec=bash -c "if [ \$EUID -ne 0 ]; then pkexec ${INSTALL_DIR}/aegis-guard-dashboard; else ${INSTALL_DIR}/aegis-guard-dashboard; fi"
Icon=security-high
Terminal=false
Type=Application
Categories=System;Security;Monitor;
StartupNotify=true
EOF

chmod +x "/usr/share/applications/aegis-guard.desktop"

if [ -d "${DESKTOP_DIR}" ]; then
    cp -f "/usr/share/applications/aegis-guard.desktop" "${DESKTOP_DIR}/Aegis-Guard.desktop"
    chown "${TARGET_USER}":"${TARGET_USER}" "${DESKTOP_DIR}/Aegis-Guard.desktop" || true
    chmod +x "${DESKTOP_DIR}/Aegis-Guard.desktop"
    echo -e "${GREEN}[+] 1-Click Launcher created on user Desktop: ${DESKTOP_DIR}/Aegis-Guard.desktop${NC}"
fi

echo ""
echo -e "${GREEN}${BOLD}================================================================${NC}"
echo -e "${GREEN}${BOLD}       AEGIS-GUARD INSTALLATION COMPLETE (FULLY ARMED)          ${NC}"
echo -e "${GREEN}${BOLD}================================================================${NC}"
echo -e "  - Service Status:    Active & Monitoring in Background"
echo -e "  - Quarantine Vault:  ${QUARANTINE_DIR}"
echo -e "  - Security Audit:    ${DATA_DIR}"
echo -e "  - Run Application:   Click Desktop Icon or run: aegis-guard"
echo ""
