# Network Observer — Phase 3

**by Vladimir Unknown**

Go service that monitors Linux kernel TCP/UDP connections and streams anomaly
events to the Tauri dashboard backend.

## Detection Rules

| Rule    | Pattern                                              | Confidence |
|---------|------------------------------------------------------|------------|
| NET-001 | Connection to known C2 port (4444, 1337, 31337…)    | HIGH       |
| NET-002 | Shell/interpreter initiating outbound connection     | HIGH       |
| NET-003 | High-frequency connections (≥20 in 10s)             | HIGH       |
| NET-004 | Non-root process connecting to unusual privileged port | MEDIUM   |
| NET-005 | Browser connecting to RFC1918 range (SSRF pattern)   | MEDIUM     |

## Architecture

```
/proc/net/tcp + /proc/net/tcp6
/proc/net/udp + /proc/net/udp6
        │
        ▼ poll 500ms
┌─────────────────────┐
│   netmon.Monitor    │  correlates inodes → PIDs via /proc/[pid]/fd/
│   NET-001..005      │
└──────────┬──────────┘
           │ chan NetEvent
           ▼
┌─────────────────────┐
│   JSON Bridge       │  length-prefixed JSON over TCP :50053
│   (Phase 3 boot)    │  → Tauri net_bridge.rs reads here
└─────────────────────┘
           │ (Phase 3 complete)
           ▼
┌─────────────────────┐
│   gRPC Server       │  proto-generated stubs → :50052
│   (Phase 3 full)    │  uses aegis.proto NetworkObserverService
└─────────────────────┘
```

## Build & Run

```bash
# Requires Go 1.23+
cd network-observer
go mod download
go build -o ../target/aegis-network-observer ./cmd/observer

# Run (needs root for /proc/[pid]/fd access)
sudo AEGIS_LOG=info ../target/aegis-network-observer
```

## Enable in Dashboard

```bash
# Terminal 1
sudo ./target/debug/aegis-process-engine

# Terminal 2
sudo ./target/aegis-network-observer

# Terminal 3 — dashboard with network enabled
cd tauri-app && AEGIS_NET=1 cargo tauri dev
```
