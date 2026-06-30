// cmd/observer/main.go — Aegis-Guard Network Observer
// by Vladimir Unknown — Phase 3

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/SepJs/aegis-guard/network-observer/internal/grpc"
	"github.com/SepJs/aegis-guard/network-observer/internal/netmon"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel(),
	})))

	slog.Info("Aegis-Guard Network Observer starting",
		"phase",   "3",
		"rules",   "NET-001..005",
		"bridge",  "127.0.0.1:50053",
	)

	ctx, cancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt, syscall.SIGTERM,
	)
	defer cancel()

	// Buffered event channel
	eventCh := make(chan netmon.NetEvent, 1024)

	// Start /proc/net monitor
	monitor := netmon.New(eventCh)
	go monitor.Run(ctx)
	slog.Info("network monitor started", "poll_interval", "500ms")

	// Fan-out: log alerts + forward to JSON bridge
	bridgeCh := make(chan netmon.NetEvent, 512)
	go func() {
		for ev := range eventCh {
			if ev.Alert != nil {
				slog.Warn("NETWORK ANOMALY",
					"rule",       ev.Alert.Rule,
					"confidence", ev.Alert.Confidence,
					"process",    ev.Process,
					"pid",        ev.PID,
					"remote",     fmt.Sprintf("%s:%d", ev.RemoteIP, ev.RemotePort),
					"reason",     ev.Alert.Reason,
				)
			}
			select {
			case bridgeCh <- ev:
			default:
			}
		}
	}()

	// JSON-over-TCP bridge → Tauri backend on port 50053
	bridge := grpc.NewJSONBridge(bridgeCh)
	go bridge.Run()

	slog.Info("network observer ready")
	<-ctx.Done()
	slog.Info("shutting down")
}

func logLevel() slog.Level {
	switch os.Getenv("AEGIS_LOG") {
	case "debug", "trace":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	default:
		return slog.LevelInfo
	}
}
