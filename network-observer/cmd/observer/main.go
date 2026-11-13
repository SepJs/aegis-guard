package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/SepJs/aegis-guard/network-observer/internal/grpc"
	"github.com/SepJs/aegis-guard/network-observer/internal/inspector"
	"github.com/SepJs/aegis-guard/network-observer/internal/netmon"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel()})))
	slog.Info("Aegis-Guard Go Packet Inspector & Network Observer starting", "bridge", "127.0.0.1:50053")

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	packetInspector := inspector.New()
	eventCh := make(chan netmon.NetEvent, 1024)
	monitor := netmon.New(eventCh, packetInspector)
	go monitor.Run(ctx)
	slog.Info("network monitor + packet inspector started", "poll_interval", "500ms")

	bridgeCh := make(chan netmon.NetEvent, 512)
	go func() {
		for ev := range eventCh {
			if ev.Alert != nil {
				slog.Warn("NETWORK ANOMALY", "rule", ev.Alert.Rule, "confidence", ev.Alert.Confidence, "process", ev.Process, "pid", ev.PID, "remote", fmt.Sprintf("%s:%d", ev.RemoteIP, ev.RemotePort), "reason", ev.Alert.Reason)
			}
			select {
			case bridgeCh <- ev:
			default:
			}
		}
	}()

	bridge := grpc.NewJSONBridge(bridgeCh, packetInspector)
	go bridge.Run()

	slog.Info("go network observer & packet inspector ready")
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
