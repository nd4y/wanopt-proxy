// Command wanopt-server is the egress side of the tunnel. Run it on Linux
// (Docker). It accepts authenticated QUIC connections and relays traffic out.
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
	if !tunnel.CongestionAvailable(cfg.CongestionControl) {
		log.Error("requested congestion controller is unavailable in this build")
		os.Exit(1)
	}
	psk, _ := config.DecodePSK(cfg.PSK)
	var previousPSK []byte
	if cfg.PreviousPSK != "" {
		previousPSK, _ = config.DecodePSK(cfg.PreviousPSK)
	}

	var certPEM, keyPEM []byte
	if cfg.CertFile != "" {
		if certPEM, err = readCredentialFile(cfg.CertFile); err != nil {
			log.Error("read cert", "err", err)
			os.Exit(1)
		}
		if keyPEM, err = readCredentialFile(cfg.KeyFile); err != nil {
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

	var workers sync.WaitGroup
	var m *metrics.Metrics
	if cfg.MetricsListen != "" {
		m = metrics.New("server")
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := m.Serve(ctx, cfg.MetricsListen); err != nil {
				log.Error("metrics server", "err", err)
			}
		}()
		log.Info("metrics listening", "addr", cfg.MetricsListen)
	}

	srv := server.New(server.Options{CongestionControl: cfg.CongestionControl,
		MaxActiveStreams: cfg.MaxActiveStreams, MaxCompressedStreams: cfg.MaxCompressedStreams,
		PSK:         psk,
		PreviousPSK: previousPSK, PreviousPSKExpires: cfg.PreviousPSKExpires,
		HandshakeTimeout:        time.Duration(cfg.HandshakeTimeoutSec) * time.Second,
		RequestTimeout:          time.Duration(cfg.RequestTimeoutSec) * time.Second,
		MaxConnections:          cfg.MaxConnections,
		MaxStreamsPerConnection: cfg.MaxStreamsPerConnection,
		Resolver:                acl.NewResolver(policy, time.Duration(cfg.DNSTimeoutSec)*time.Second, cfg.DNSConcurrency),
		UDP:                     server.UDPOptions{MaxFlows: cfg.UDP.MaxFlows, QueueSize: cfg.UDP.QueueSize, Workers: cfg.UDP.Workers, NewFlowsPerSecond: cfg.UDP.NewFlowsPerSecond, MaxPayload: cfg.UDP.MaxPayload, IdleTimeout: time.Duration(cfg.UDP.IdleTimeoutSec) * time.Second},
		Cert:                    cert,
		ALPN:                    cfg.ALPNOrDefault(),
		IdleTimeout:             time.Duration(cfg.IdleTimeoutSec) * time.Second,
		ACL:                     policy,
		Allow0RTT:               cfg.Allow0RTT,
		Compression:             cfg.Compression,
		Metrics:                 m,
		Decoy:                   decoyHandler,
		MaxStreamRecvWindow:     uint64(cfg.MaxStreamRecvWindowMB) << 20,
		MaxConnRecvWindow:       uint64(cfg.MaxConnRecvWindowMB) << 20,
		Log:                     log,
	})
	reloadSignals := make(chan os.Signal, 1)
	signal.Notify(reloadSignals, syscall.Signal(1))
	defer signal.Stop(reloadSignals)
	workers.Add(1)
	go func() { defer workers.Done(); watchCredentials(ctx, *cfgPath, *cfg, srv, log, reloadSignals) }()
	err = srv.ListenAndServe(ctx, cfg.Listen)
	failed := err != nil && ctx.Err() == nil
	stop()
	workers.Wait()
	if failed {
		log.Error("server stopped", "err", err)
		os.Exit(1)
	}
}
