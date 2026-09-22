package grpc

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/SepJs/aegis-guard/network-observer/internal/netmon"
	"github.com/SepJs/aegis-guard/network-observer/internal/rules"
)

const jsonBridgeAddr = "127.0.0.1:50053"

type JSONBridge struct {
	eventCh chan netmon.NetEvent
	conns   map[net.Conn]struct{}
	mu      sync.Mutex
}

func NewJSONBridge(ch chan netmon.NetEvent) *JSONBridge {
	return &JSONBridge{eventCh: ch, conns: make(map[net.Conn]struct{})}
}

func (b *JSONBridge) Run() {
	lis, err := net.Listen("tcp", jsonBridgeAddr)
	if err != nil {
		slog.Error("JSON bridge listen failed", "err", err)
		return
	}
	slog.Info("JSON bridge listening", "addr", jsonBridgeAddr)
	go b.broadcast()
	for {
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		slog.Info("Tauri backend connected to JSON bridge", "remote", conn.RemoteAddr())
		b.mu.Lock()
		b.conns[conn] = struct{}{}
		b.mu.Unlock()

		go func(c net.Conn) {
			b.handleIncomingCommands(c)
			b.mu.Lock()
			delete(b.conns, c)
			b.mu.Unlock()
			slog.Info("Tauri backend disconnected from JSON bridge")
		}(conn)
	}
}

func (b *JSONBridge) handleIncomingCommands(c net.Conn) {
	for {
		lenBuf := make([]byte, 4)
		if _, err := io.ReadFull(c, lenBuf); err != nil {
			break
		}
		length := binary.BigEndian.Uint32(lenBuf)
		if length == 0 || length > 1024*1024 {
			break
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(c, payload); err != nil {
			break
		}
		var cmd map[string]interface{}
		if err := json.Unmarshal(payload, &cmd); err != nil {
			continue
		}
		action, _ := cmd["action"].(string)
		switch action {
		case "block_ip":
			if ip, ok := cmd["ip"].(string); ok && ip != "" {
				slog.Info("executing firewall block for IP", "ip", ip)
				executeBlockIP(ip)
			}
		case "unblock_ip":
			if ip, ok := cmd["ip"].(string); ok && ip != "" {
				slog.Info("executing firewall unblock for IP", "ip", ip)
				executeUnblockIP(ip)
			}
		case "simulate":
			if attackType, ok := cmd["attack_type"].(string); ok {
				slog.Info("injecting simulated network threat", "type", attackType)
				b.injectSimulation(attackType)
			}
		}
	}
}

func executeBlockIP(ip string) {
	if runtime.GOOS == "windows" {
		ruleName := fmt.Sprintf("Aegis-Block-%s", ip)
		_ = exec.Command("netsh", "advfirewall", "firewall", "add", "rule", fmt.Sprintf("name=%s-in", ruleName), "dir=in", "action=block", fmt.Sprintf("remoteip=%s", ip)).Run()
		_ = exec.Command("netsh", "advfirewall", "firewall", "add", "rule", fmt.Sprintf("name=%s-out", ruleName), "dir=out", "action=block", fmt.Sprintf("remoteip=%s", ip)).Run()
	} else {
		_ = exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP").Run()
		_ = exec.Command("iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP").Run()
	}
}

func executeUnblockIP(ip string) {
	if runtime.GOOS == "windows" {
		ruleName := fmt.Sprintf("Aegis-Block-%s", ip)
		_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=%s-in", ruleName)).Run()
		_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=%s-out", ruleName)).Run()
	} else {
		_ = exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP").Run()
		_ = exec.Command("iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP").Run()
	}
}

func (b *JSONBridge) injectSimulation(attackType string) {
	now := time.Now().UnixMilli()
	var ev netmon.NetEvent
	switch attackType {
	case "metasploit_c2":
		ev = netmon.NetEvent{
			ID: fmt.Sprintf("sim-net-%d", now), Kind: "net_alert", PID: 1337,
			Process: "meterpreter_payload", Protocol: "tcp", Direction: "outbound",
			LocalIP: "192.168.1.50", LocalPort: 54123, RemoteIP: "198.199.73.244", RemotePort: 4444,
			BytesTX: 4520, BytesRX: 8940, TsMs: now,
			Alert: &rules.NetAlert{Rule: "NET-001", Confidence: "high", Reason: "Process 'meterpreter_payload' (pid 1337) connected to port 4444 (Metasploit default C2).", Category: "NET"},
		}
	case "reverse_shell":
		proc := "bash"
		if runtime.GOOS == "windows" {
			proc = "powershell.exe"
		}
		ev = netmon.NetEvent{
			ID: fmt.Sprintf("sim-net-%d", now), Kind: "net_alert", PID: 2048,
			Process: proc, Protocol: "tcp", Direction: "outbound",
			LocalIP: "192.168.1.50", LocalPort: 58912, RemoteIP: "45.33.32.156", RemotePort: 6666,
			BytesTX: 1200, BytesRX: 3400, TsMs: now,
			Alert: &rules.NetAlert{Rule: "NET-002", Confidence: "high", Reason: fmt.Sprintf("Process '%s' (pid 2048) initiated outbound connection to 45.33.32.156:6666 (common reverse shell port).", proc), Category: "NET"},
		}
	case "port_scan":
		ev = netmon.NetEvent{
			ID: fmt.Sprintf("sim-net-%d", now), Kind: "net_alert", PID: 4096,
			Process: "nmap_probe", Protocol: "tcp", Direction: "outbound",
			LocalIP: "192.168.1.50", LocalPort: 49000, RemoteIP: "10.0.0.1", RemotePort: 80,
			BytesTX: 800, BytesRX: 40, TsMs: now,
			Alert: &rules.NetAlert{Rule: "NET-003", Confidence: "high", Reason: "Process 'nmap_probe' (pid 4096) initiated >20 rapid connections in 10s — port scan detected.", Category: "NET"},
		}
	default:
		ev = netmon.NetEvent{
			ID: fmt.Sprintf("sim-net-%d", now), Kind: "net_alert", PID: 9999,
			Process: "browser_ssrf", Protocol: "tcp", Direction: "outbound",
			LocalIP: "192.168.1.50", LocalPort: 52100, RemoteIP: "192.168.1.1", RemotePort: 80,
			BytesTX: 400, BytesRX: 1200, TsMs: now,
			Alert: &rules.NetAlert{Rule: "NET-005", Confidence: "medium", Reason: "Browser process connected to internal router/gateway IP 192.168.1.1 — SSRF indicator.", Category: "NET"},
		}
	}
	select {
	case b.eventCh <- ev:
	default:
	}
}

func (b *JSONBridge) broadcast() {
	for ev := range b.eventCh {
		payload, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		lenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBuf, uint32(len(payload)))
		msg := append(lenBuf, payload...)
		b.mu.Lock()
		for conn := range b.conns {
			if _, err := conn.Write(msg); err != nil {
				conn.Close()
				delete(b.conns, conn)
			}
		}
		b.mu.Unlock()
	}
}
