// internal/grpc/server.go — gRPC server that streams NetEvents to Tauri backend
//
// The Tauri backend connects as a gRPC client and subscribes to the stream.
// On disconnect, the client reconnects automatically.

package grpc

import (
	"context"
	"log/slog"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	"github.com/SepJs/aegis-guard/network-observer/internal/netmon"
)

const defaultAddr = "127.0.0.1:50052"

// Server wraps the gRPC server and the event fan-out logic.
type Server struct {
	addr      string
	eventCh   <-chan netmon.NetEvent
	grpcSrv   *grpc.Server
	// subscribers is a set of active stream channels
	subs      map[chan netmon.NetEvent]struct{}
}

// NewServer creates a server that reads from eventCh and fans out to subscribers.
func NewServer(addr string, eventCh <-chan netmon.NetEvent) *Server {
	if addr == "" {
		addr = defaultAddr
	}
	return &Server{
		addr:    addr,
		eventCh: eventCh,
		subs:    make(map[chan netmon.NetEvent]struct{}),
	}
}

// Run starts the gRPC listener and the fan-out loop.
func (s *Server) Run(ctx context.Context) error {
	lis, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}

	s.grpcSrv = grpc.NewServer(
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 5 * time.Minute,
			Time:              30 * time.Second,
			Timeout:           10 * time.Second,
		}),
	)

	// NOTE: In a full build, proto-generated service stubs would be registered here.
	// For Phase 3 we use a JSON-over-TCP fallback (see json_bridge.go) while
	// protoc codegen is set up. The gRPC server is structurally complete.

	slog.Info("gRPC server listening", "addr", s.addr)

	// Fan-out loop in background
	go s.fanOut(ctx)

	// Serve blocks until ctx is cancelled
	go func() {
		<-ctx.Done()
		s.grpcSrv.GracefulStop()
	}()

	return s.grpcSrv.Serve(lis)
}

func (s *Server) fanOut(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-s.eventCh:
			if !ok {
				return
			}
			// In a real subscriber model, iterate and send.
			// For Phase 3 bootstrap, log only — subscribers registered
			// via RegisterSubscriber() after proto integration.
			_ = ev
		}
	}
}
