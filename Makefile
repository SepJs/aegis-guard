# Aegis-Guard Makefile — by Vladimir Unknown
# Usage:
#   make build          build all Rust crates (debug)
#   make release        build all Rust crates (release)
#   make engine         build + run process engine
#   make observer       build + run network observer (requires Go)
#   make dev            run Tauri dashboard in dev mode
#   make check          cargo check + clippy (no warnings)
#   make fix            auto-fix lints

.PHONY: build release engine observer dev check fix clean

CARGO := cargo
GO    := go

# ── Rust ──────────────────────────────────────────────────────────────────────

build:
	$(CARGO) build --workspace

release:
	$(CARGO) build --workspace --release

check:
	$(CARGO) check --workspace
	$(CARGO) clippy --workspace -- -D warnings

fix:
	$(CARGO) fix --workspace --allow-dirty
	$(CARGO) clippy --workspace --fix --allow-dirty

# ── Run targets ───────────────────────────────────────────────────────────────

engine: build
	sudo AEGIS_LOG=info ./target/debug/aegis-process-engine

engine-debug: build
	sudo AEGIS_LOG=debug ./target/debug/aegis-process-engine

observer:
	cd network-observer && $(GO) build -o ../target/aegis-network-observer ./cmd/observer
	sudo AEGIS_LOG=info ./target/aegis-network-observer

dev:
	cd tauri-app && cargo tauri dev

dev-net:
	cd tauri-app && AEGIS_NET=1 cargo tauri dev

# ── Build observer binary ─────────────────────────────────────────────────────

build-observer:
	mkdir -p target
	cd network-observer && $(GO) build -o ../target/aegis-network-observer ./cmd/observer
	@echo "→ target/aegis-network-observer"

# ── Install ───────────────────────────────────────────────────────────────────

install: release build-observer
	sudo bash install/setup.sh
	sudo install -m 755 target/release/aegis-process-engine /usr/local/bin/
	sudo install -m 755 target/aegis-network-observer /usr/local/bin/
	@echo "Installed. Start with: sudo systemctl start aegis-process-engine"

# ── Clean ─────────────────────────────────────────────────────────────────────

clean:
	$(CARGO) clean
	rm -f target/aegis-network-observer
