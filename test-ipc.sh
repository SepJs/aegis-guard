#!/usr/bin/env bash
# test-ipc.sh — manual end-to-end IPC test
#
# Terminal 1: ./test-ipc.sh listen    (simulates Tauri backend reader)
# Terminal 2: ./test-ipc.sh send      (simulates process-engine writer)
#
# Or run the real engine:
#   Terminal 1: ./test-ipc.sh listen
#   Terminal 2: sudo AEGIS_LOG=debug cargo run -p process-engine

set -euo pipefail
SOCK="/tmp/aegis-test.sock"

case "${1:-}" in
listen)
    echo "[test] Listening on $SOCK ..."
    rm -f "$SOCK"
    # nc reads length-prefixed frames — we strip the 4-byte header and pipe to jq
    socat UNIX-LISTEN:"$SOCK",fork - | while read -r -n4 header; do
        python3 -c "
import sys, struct, json
data = sys.stdin.buffer.read(struct.unpack('>I', b'$header'.encode('latin1')[:4])[0])
print(json.dumps(json.loads(data), indent=2))
        "
    done
    ;;
send)
    echo "[test] Sending test event to $SOCK ..."
    python3 - << 'PY'
import socket, json, struct, time

payload = json.dumps({
    "id":   "test-uuid-0001",
    "kind": "anomaly",
    "pid":  12345,
    "ppid": 99,
    "name": "bash",
    "cmdline": ["bash", "-i"],
    "exe":  "/usr/bin/bash",
    "cwd":  "/tmp",
    "uid":  1000,
    "gid":  1000,
    "start_time": 0,
    "ts":   int(time.time() * 1000),
    "anomaly": {
        "rule":       "PAR-001",
        "confidence": "high",
        "reason":     "Shell 'bash' spawned by browser 'firefox'. Test event.",
        "parent_exe": "/usr/lib/firefox/firefox",
        "ancestors":  [99, 1]
    }
}).encode()

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
    s.connect("/tmp/aegis-test.sock")
    s.sendall(struct.pack(">I", len(payload)) + payload)
    print("[test] Sent PAR-001 test event")
PY
    ;;
*)
    echo "Usage: $0 [listen|send]"
    exit 1
    ;;
esac
