// Command wanopt-client is the ingress side of the tunnel. Run it on Windows.
// It exposes local SOCKS5 and/or HTTP proxies and forwards traffic to the
// server over an authenticated QUIC tunnel.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"wanopt/internal/client"
	"wanopt/internal/config"
	"wanopt/internal/metrics"
	"wanopt/internal/proxy"
)

func main() {
	cfgPath := flag.String("config", "client.yaml", "path to client config file")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.LoadClient(*cfgPath)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}
	psk, _ := config.DecodePSK(cfg.PSK)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var m *metrics.Metrics
	if cfg.MetricsListen != "" {
		m = metrics.New("client")
		go func() {
			if err := m.Serve(ctx, cfg.MetricsListen); err != nil {
				log.Error("metrics server", "err", err)
			}
		}()
		log.Info("metrics listening", "addr", cfg.MetricsListen)
	}

	c := client.New(client.Options{
		Server:              cfg.Server,
		PSK:                 psk,
		Pin:                 cfg.Pin,
		ALPN:                cfg.ALPNOrDefault(),
		IdleTimeout:         time.Duration(cfg.IdleTimeoutSec) * time.Second,
		Enable0RTT:          cfg.Enable0RTT,
		Compression:         cfg.Compression,
		Metrics:             m,
		MaxStreamRecvWindow: uint64(cfg.MaxStreamRecvWindowMB) << 20,
		MaxConnRecvWindow:   uint64(cfg.MaxConnRecvWindowMB) << 20,
		Log:                 log,
	})
	go c.Run(ctx) // background connection maintainer (dial + reconnect with backoff)

	p := proxy.New(c, log)
	errCh := make(chan error, 2)
	if cfg.SOCKSListen != "" {
		go func() { errCh <- p.ServeSOCKS(ctx, cfg.SOCKSListen) }()
	}
	if cfg.HTTPListen != "" {
		go func() { errCh <- p.ServeHTTP(ctx, cfg.HTTPListen) }()
	}

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil {
			log.Error("proxy stopped", "err", err)
			os.Exit(1)
		}
	}
}
