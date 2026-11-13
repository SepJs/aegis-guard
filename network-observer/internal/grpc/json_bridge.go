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

	"github.com/SepJs/aegis-guard/network-observer/internal/inspector"
	"github.com/SepJs/aegis-guard/network-observer/internal/netmon"
)

const jsonBridgeAddr = "127.0.0.1:50053"

type JSONBridge struct {
	eventCh   chan netmon.NetEvent
	inspector *inspector.PacketInspector
	rpc       *InspectorServer
	conns     map[net.Conn]struct{}
	mu        sync.Mutex
}

func NewJSONBridge(ch chan netmon.NetEvent, insp *inspector.PacketInspector) *JSONBridge {
	return &JSONBridge{
		eventCh:   ch,
		inspector: insp,
		rpc:       NewInspectorServer(insp),
		conns:     make(map[net.Conn]struct{}),
	}
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
		slog.Info("Backend client connected to Go JSON bridge", "remote", conn.RemoteAddr())
		b.mu.Lock()
		b.conns[conn] = struct{}{}
		b.mu.Unlock()

		go func(c net.Conn) {
			b.handleIncomingCommands(c)
			b.mu.Lock()
			delete(b.conns, c)
			b.mu.Unlock()
			_ = c.Close()
			slog.Info("Backend client disconnected from Go JSON bridge")
		}(conn)
	}
}

func writeFramed(c net.Conn, payload []byte) error {
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(payload)))
	msg := append(lenBuf, payload...)
	_, err := c.Write(msg)
	return err
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

		// Dispatch RPC query messages first
		if respBytes, handled := b.rpc.HandleRequest(payload); handled {
			if err := writeFramed(c, respBytes); err != nil {
				break
			}
			continue
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
				_ = conn.Close()
				delete(b.conns, conn)
			}
		}
		b.mu.Unlock()
	}
}
