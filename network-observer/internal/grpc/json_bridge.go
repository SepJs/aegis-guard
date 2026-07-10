package grpc

import ("encoding/binary"; "encoding/json"; "log/slog"; "net"; "sync"
	"github.com/SepJs/aegis-guard/network-observer/internal/netmon")

const jsonBridgeAddr = "127.0.0.1:50053"

type JSONBridge struct { eventCh <-chan netmon.NetEvent; conns map[net.Conn]struct{}; mu sync.Mutex }

func NewJSONBridge(ch <-chan netmon.NetEvent) *JSONBridge { return &JSONBridge{eventCh: ch, conns: make(map[net.Conn]struct{})} }

func (b *JSONBridge) Run() {
	lis, err := net.Listen("tcp", jsonBridgeAddr)
	if err != nil { slog.Error("JSON bridge listen failed", "err", err); return }
	slog.Info("JSON bridge listening", "addr", jsonBridgeAddr)
	go b.broadcast()
	for {
		conn, err := lis.Accept()
		if err != nil { return }
		slog.Info("Tauri backend connected to JSON bridge", "remote", conn.RemoteAddr())
		b.mu.Lock(); b.conns[conn] = struct{}{}; b.mu.Unlock()
		go func(c net.Conn) {
			buf := make([]byte, 1)
			for { if _, err := c.Read(buf); err != nil { break } }
			b.mu.Lock(); delete(b.conns, c); b.mu.Unlock()
			slog.Info("Tauri backend disconnected from JSON bridge")
		}(conn)
	}
}

func (b *JSONBridge) broadcast() {
	for ev := range b.eventCh {
		payload, err := json.Marshal(ev)
		if err != nil { continue }
		lenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBuf, uint32(len(payload)))
		msg := append(lenBuf, payload...)
		b.mu.Lock()
		for conn := range b.conns { if _, err := conn.Write(msg); err != nil { conn.Close(); delete(b.conns, conn) } }
		b.mu.Unlock()
	}
}
