# Aegis-Guard Makefile — by Vladimir Unknown

.PHONY: run build release check fix install clean

run:
	bash aegis.sh

run-net:
	AEGIS_NET=1 bash aegis.sh

build:
	cargo build --workspace

release:
	cargo build --workspace --release

check:
	cargo check --workspace
	cargo clippy --workspace -- -D warnings

fix:
	cargo fix --workspace --allow-dirty
	cargo clippy --workspace --fix --allow-dirty -- -D warnings

install: release
	mkdir -p target
	cd network-observer && go build -o ../target/aegis-network-observer ./cmd/observer
	sudo bash install/setup.sh
	sudo install -m 755 target/release/aegis-process-engine /usr/local/bin/
	sudo install -m 755 target/aegis-network-observer /usr/local/bin/

clean:
	cargo clean
	rm -f target/aegis-network-observer
