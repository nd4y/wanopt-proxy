// Command wanopt-server is the egress side of the tunnel. Run it on Linux
// (Docker). It accepts authenticated QUIC connections and relays traffic out.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"wanopt/internal/config"
	"wanopt/internal/server"
	"wanopt/internal/tunnel"
)

func main() {
	cfgPath := flag.String("config", "server.yaml", "path to server config file")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.LoadServer(*cfgPath)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}
	psk, _ := config.DecodePSK(cfg.PSK)

	var certPEM, keyPEM []byte
	if cfg.CertFile != "" {
		if certPEM, err = os.ReadFile(cfg.CertFile); err != nil {
			log.Error("read cert", "err", err)
			os.Exit(1)
		}
		if keyPEM, err = os.ReadFile(cfg.KeyFile); err != nil {
			log.Error("read key", "err", err)
			os.Exit(1)
		}
	}
	cert, pin, err := tunnel.LoadOrCreateCert(certPEM, keyPEM)
	if err != nil {
		log.Error("certificate", "err", err)
		os.Exit(1)
	}
	log.Info("server certificate pin (copy into client config)", "pin", pin)

	idle := time.Duration(cfg.IdleTimeoutSec) * time.Second
	srv := server.New(psk, cert, idle, log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := srv.ListenAndServe(ctx, cfg.Listen); err != nil && ctx.Err() == nil {
		log.Error("server stopped", "err", err)
		os.Exit(1)
	}
}
