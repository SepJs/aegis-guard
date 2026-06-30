# Aegis-Guard Makefile — by Vladimir Unknown
# Phase 4: Active Defense + Network Observer

.PHONY: build release engine observer dev dev-net check fix install clean

CARGO := cargo
GO    := go

# ── Build ─────────────────────────────────────────────────────────────────────
build:
	$(CARGO) build --workspace

release:
	$(CARGO) build --workspace --release

build-observer:
	mkdir -p target
	cd network-observer && $(GO) build -o ../target/aegis-network-observer ./cmd/observer
	@echo "→ target/aegis-network-observer"

# ── Check / lint ──────────────────────────────────────────────────────────────
check:
	$(CARGO) check --workspace
	$(CARGO) clippy --workspace -- -D warnings

fix:
	$(CARGO) fix --workspace --allow-dirty
	$(CARGO) clippy --workspace --fix --allow-dirty -- -D warnings

# ── Run (development) ─────────────────────────────────────────────────────────
engine: build
	sudo AEGIS_LOG=info ./target/debug/aegis-process-engine

engine-debug: build
	sudo AEGIS_LOG=debug ./target/debug/aegis-process-engine

observer: build-observer
	sudo AEGIS_LOG=info ./target/aegis-network-observer

dev:
	cd tauri-app && cargo tauri dev

# Phase 4: all three components
dev-full: build build-observer
	@echo "Starting all Aegis-Guard components..."
	@sudo ./target/debug/aegis-process-engine &
	@sudo ./target/aegis-network-observer &
	@cd tauri-app && AEGIS_NET=1 cargo tauri dev

# ── Install ───────────────────────────────────────────────────────────────────
install: release build-observer
	sudo bash install/setup.sh
	sudo install -m 755 target/release/aegis-process-engine /usr/local/bin/
	sudo install -m 755 target/aegis-network-observer /usr/local/bin/
	@echo ""
	@echo "Installed. Run:"
	@echo "  sudo systemctl start aegis-process-engine"
	@echo "  sudo systemctl start aegis-network-observer"
	@echo "  cd tauri-app && AEGIS_NET=1 cargo tauri dev"

# ── Clean ─────────────────────────────────────────────────────────────────────
clean:
	$(CARGO) clean
	rm -f target/aegis-network-observer

# ── Phase 5 ───────────────────────────────────────────────────────────────────
test-ioc:
	cargo test -p threat-intel -- --nocapture

test-behavioral:
	cargo test -p behavioral -- --nocapture

# Custom IOC file template
init-custom-iocs:
	mkdir -p /var/lib/aegis
	cat > /var/lib/aegis/custom_iocs.json << 'JSON'
[
  {"ioc":"192.0.2.1","kind":"ip","feed":"custom","threat_type":"test","confidence":100,"added_ts":0},
  {"ioc":"evil-test.local","kind":"domain","feed":"custom","threat_type":"test","confidence":100,"added_ts":0}
]
JSON
	@echo "Custom IOC file created at /var/lib/aegis/custom_iocs.json"
