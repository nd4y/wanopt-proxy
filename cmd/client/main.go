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

	idle := time.Duration(cfg.IdleTimeoutSec) * time.Second
	c := client.New(cfg.Server, psk, cfg.Pin, idle, log)
	defer c.Close()
	p := proxy.New(c, log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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
