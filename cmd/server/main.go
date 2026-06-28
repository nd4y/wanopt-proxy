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

	"wanopt/internal/acl"
	"wanopt/internal/config"
	"wanopt/internal/decoy"
	"wanopt/internal/metrics"
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

	policy, err := acl.New(cfg.ACL.Allow, cfg.ACL.Deny, cfg.ACL.AllowPorts, cfg.ACL.DenyPorts)
	if err != nil {
		log.Error("acl", "err", err)
		os.Exit(1)
	}

	decoyHandler, err := decoy.Handler(decoy.Config{
		Enabled:  cfg.Decoy.Mode != "off",
		Mode:     cfg.Decoy.Mode,
		Upstream: cfg.Decoy.Upstream,
		Dir:      cfg.Decoy.Dir,
		SiteName: cfg.Decoy.SiteName,
	})
	if err != nil {
		log.Error("decoy", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var m *metrics.Metrics
	if cfg.MetricsListen != "" {
		m = metrics.New("server")
		go func() {
			if err := m.Serve(ctx, cfg.MetricsListen); err != nil {
				log.Error("metrics server", "err", err)
			}
		}()
		log.Info("metrics listening", "addr", cfg.MetricsListen)
	}

	srv := server.New(server.Options{
		PSK:                 psk,
		Cert:                cert,
		ALPN:                cfg.ALPNOrDefault(),
		IdleTimeout:         time.Duration(cfg.IdleTimeoutSec) * time.Second,
		ACL:                 policy,
		Allow0RTT:           cfg.Allow0RTT,
		Compression:         cfg.Compression,
		Metrics:             m,
		Decoy:               decoyHandler,
		MaxStreamRecvWindow: uint64(cfg.MaxStreamRecvWindowMB) << 20,
		MaxConnRecvWindow:   uint64(cfg.MaxConnRecvWindowMB) << 20,
		Log:                 log,
	})
	if err := srv.ListenAndServe(ctx, cfg.Listen); err != nil && ctx.Err() == nil {
		log.Error("server stopped", "err", err)
		os.Exit(1)
	}
}
