#!/usr/bin/env bash
# Aegis-Guard — Linux setup script
# Run once as root before starting the process engine.
# Compatible with all systemd-based distros (Debian/Ubuntu/Arch/Fedora/etc.)

set -euo pipefail

AEGIS_USER="${AEGIS_USER:-$SUDO_USER}"
SOCKET_DIR="/run/aegis"
DATA_DIR="/var/lib/aegis"
SYSTEMD_DIR="/etc/systemd/system"
BIN_DIR="/usr/local/bin"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

info()  { echo -e "${GREEN}[aegis]${NC} $*"; }
warn()  { echo -e "${YELLOW}[aegis]${NC} $*"; }
error() { echo -e "${RED}[aegis]${NC} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || error "Run as root: sudo ./setup.sh"

# ── Directories ───────────────────────────────────────────────────────────────
info "Creating runtime directories..."
install -d -m 750 "$SOCKET_DIR"
install -d -m 750 "$DATA_DIR"
chown root:root "$SOCKET_DIR" "$DATA_DIR"

# ── Binary ────────────────────────────────────────────────────────────────────
if [[ -f ./target/release/aegis-process-engine ]]; then
    info "Installing binary..."
    install -m 755 ./target/release/aegis-process-engine "$BIN_DIR/"
else
    warn "Binary not found — build first: cargo build --release -p process-engine"
fi

# ── systemd unit ──────────────────────────────────────────────────────────────
info "Installing systemd service..."
cat > "$SYSTEMD_DIR/aegis-process-engine.service" << 'UNIT'
[Unit]
Description=Aegis-Guard Process Engine
Documentation=https://github.com/SepJs/aegis-guard
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/aegis-process-engine
Restart=on-failure
RestartSec=5
Environment=AEGIS_LOG=info
Environment=AEGIS_SOCKET=/run/aegis/proc.sock
# Run as root — needed to read /proc for all PIDs
User=root
Group=root
RuntimeDirectory=aegis
StateDirectory=aegis
# Harden what we can while keeping /proc access
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
NoNewPrivileges=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
info "systemd unit installed: aegis-process-engine.service"
info ""
info "To start:   systemctl start aegis-process-engine"
info "To enable:  systemctl enable aegis-process-engine"
info "To monitor: journalctl -u aegis-process-engine -f"
