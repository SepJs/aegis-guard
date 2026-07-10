#!/usr/bin/env bash
# Aegis-Guard — system setup (systemd services). By Vladimir Unknown.
# For a quick one-shot run without systemd, use ../aegis.sh instead.

set -euo pipefail

SOCKET_DIR="/run/aegis"
DATA_DIR="/var/lib/aegis"
QUARANTINE_DIR="/var/lib/aegis/quarantine"
SYSTEMD_DIR="/etc/systemd/system"
BIN_DIR="/usr/local/bin"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[aegis]${NC} $*"; }
warn()  { echo -e "${YELLOW}[aegis]${NC} $*"; }
error() { echo -e "${RED}[aegis]${NC} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || error "Run as root: sudo bash install/setup.sh"

info "Creating runtime directories..."
install -d -m 1777 "$SOCKET_DIR"     # 1777: sticky + world-writable, like /tmp —
                                       # lets the non-root dashboard bind the IPC
                                       # socket while root (engine) can still connect.
install -d -m 750  "$DATA_DIR"
install -d -m 750  "$QUARANTINE_DIR"
chown root:root "$DATA_DIR" "$QUARANTINE_DIR"

if [[ -f ./target/release/aegis-process-engine ]]; then
    info "Installing process engine binary..."
    install -m 755 ./target/release/aegis-process-engine "$BIN_DIR/"
else
    warn "Process engine binary not found — run: cargo build --release -p process-engine"
fi

if [[ -f ./target/aegis-network-observer ]]; then
    info "Installing network observer binary..."
    install -m 755 ./target/aegis-network-observer "$BIN_DIR/"
else
    warn "Network observer not found — run: cd network-observer && go build -o ../target/aegis-network-observer ./cmd/observer"
fi

info "Installing systemd service: aegis-process-engine..."
cat > "$SYSTEMD_DIR/aegis-process-engine.service" << 'UNIT'
[Unit]
Description=Aegis-Guard Process Engine — by Vladimir Unknown
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/aegis-process-engine
Restart=on-failure
RestartSec=5
Environment=AEGIS_LOG=info
Environment=AEGIS_SOCKET=/run/aegis/proc.sock
User=root
Group=root
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT

info "Installing systemd service: aegis-network-observer..."
cat > "$SYSTEMD_DIR/aegis-network-observer.service" << 'UNIT'
[Unit]
Description=Aegis-Guard Network Observer — by Vladimir Unknown
After=network.target aegis-process-engine.service
Wants=aegis-process-engine.service

[Service]
Type=simple
ExecStart=/usr/local/bin/aegis-network-observer
Restart=on-failure
RestartSec=5
Environment=AEGIS_LOG=info
User=root
Group=root

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload

info ""
info "Setup complete."
info ""
info "Start services:"
info "  systemctl start aegis-process-engine"
info "  systemctl start aegis-network-observer"
info ""
info "Run dashboard (as your normal user, NOT root):"
info "  cd tauri-app && AEGIS_NET=1 cargo tauri dev"
info ""
info "Or for a one-shot run of everything together:"
info "  bash aegis.sh"
