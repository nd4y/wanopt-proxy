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
	"sync"
	"syscall"
	"time"

	"wanopt/internal/client"
	"wanopt/internal/config"
	"wanopt/internal/metrics"
	"wanopt/internal/proxy"
	"wanopt/internal/tunnel"
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
	if !tunnel.CongestionAvailable(cfg.CongestionControl) {
		log.Error("requested congestion controller is unavailable in this build")
		os.Exit(1)
	}
	psk, _ := config.DecodePSK(cfg.PSK)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var workers sync.WaitGroup
	var m *metrics.Metrics
	if cfg.MetricsListen != "" {
		m = metrics.New("client")
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := m.Serve(ctx, cfg.MetricsListen); err != nil {
				log.Error("metrics server", "err", err)
			}
		}()
		log.Info("metrics listening", "addr", cfg.MetricsListen)
	}

	c := client.New(client.Options{CongestionControl: cfg.CongestionControl,
		Server:           cfg.Server,
		MaxActiveStreams: cfg.MaxActiveStreams, MaxCompressedStreams: cfg.MaxCompressedStreams,
		PSK:                      psk,
		HandshakeTimeout:         time.Duration(cfg.HandshakeTimeoutSec) * time.Second,
		RequestTimeout:           time.Duration(cfg.RequestTimeoutSec) * time.Second,
		MaxPendingRequests:       cfg.MaxPendingRequests,
		MaxUDPSessions:           cfg.MaxUDPSessions,
		DisableSessionResumption: cfg.DisableSessionResumption,
		Pin:                      cfg.Pin,
		NextPin:                  cfg.NextPin, NextPinExpires: cfg.NextPinExpires,
		ALPN:                cfg.ALPNOrDefault(),
		IdleTimeout:         time.Duration(cfg.IdleTimeoutSec) * time.Second,
		Enable0RTT:          cfg.Enable0RTT,
		Compression:         cfg.Compression,
		Metrics:             m,
		MaxStreamRecvWindow: uint64(cfg.MaxStreamRecvWindowMB) << 20,
		MaxConnRecvWindow:   uint64(cfg.MaxConnRecvWindowMB) << 20,
		Log:                 log,
	})
	workers.Add(1)
	go func() { defer workers.Done(); c.Run(ctx) }()

	p := proxy.NewWithOptions(c, log, proxy.Options{
		MaxConnections:            cfg.MaxConnections,
		HandshakeTimeout:          time.Duration(cfg.HandshakeTimeoutSec) * time.Second,
		IdleTimeout:               time.Duration(cfg.ProxyIdleTimeoutSec) * time.Second,
		HTTPResponseHeaderTimeout: time.Duration(cfg.HTTPResponseHeaderTimeoutSec) * time.Second,
		MaxHeaderBytes:            cfg.MaxHeaderBytes,
	})
	errCh := make(chan error, 2)
	if cfg.SOCKSListen != "" {
		workers.Add(1)
		go func() { defer workers.Done(); errCh <- p.ServeSOCKS(ctx, cfg.SOCKSListen) }()
	}
	if cfg.HTTPListen != "" {
		workers.Add(1)
		go func() { defer workers.Done(); errCh <- p.ServeHTTP(ctx, cfg.HTTPListen) }()
	}

	failed := false
	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil {
			log.Error("proxy stopped", "err", err)
			failed = true
		}
	}
	stop()
	workers.Wait()
	if failed {
		os.Exit(1)
	}
}
