// Package metrics exposes Prometheus instrumentation for the tunnel and wires a
// quic-go connection tracer so per-connection RTT, congestion window and packet
// loss become observable (these are not available through quic-go's regular
// API, only via the tracing hooks).
package metrics

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
)

// Metrics holds the collectors and the registry they are registered on.
type Metrics struct {
	reg *prometheus.Registry

	ActiveStreams prometheus.Gauge
	StreamsTotal  prometheus.Counter
	DialErrors    prometheus.Counter
	Bytes         *prometheus.CounterVec // labeled by direction: up/down
	Reconnects    prometheus.Counter
	ZeroRTT       prometheus.Counter
	Connections   prometheus.Gauge

	RTTSeconds  prometheus.Gauge
	CwndBytes   prometheus.Gauge
	LostPackets prometheus.Counter
}

// New builds and registers the collectors. side is "server" or "client", used
// as a constant label so a shared Prometheus can scrape both.
func New(side string) *Metrics {
	reg := prometheus.NewRegistry()
	cl := prometheus.Labels{"side": side}
	f := promauto(reg, cl)
	m := &Metrics{
		reg:           reg,
		ActiveStreams: f.gauge("wanopt_active_streams", "Currently open proxy streams"),
		StreamsTotal:  f.counter("wanopt_streams_total", "Total proxy streams opened"),
		DialErrors:    f.counter("wanopt_dial_errors_total", "Failed dial/connect attempts"),
		Bytes:         f.counterVec("wanopt_relay_bytes_total", "Relayed payload bytes", "dir"),
		Reconnects:    f.counter("wanopt_tunnel_reconnects_total", "Tunnel reconnect attempts"),
		ZeroRTT:       f.counter("wanopt_zero_rtt_total", "Connections resumed with 0-RTT"),
		Connections:   f.gauge("wanopt_tunnel_connections", "Active tunnel connections"),
		RTTSeconds:    f.gauge("wanopt_tunnel_rtt_seconds", "Smoothed tunnel RTT"),
		CwndBytes:     f.gauge("wanopt_congestion_window_bytes", "Congestion window size"),
		LostPackets:   f.counter("wanopt_lost_packets_total", "Packets declared lost"),
	}
	reg.MustRegister(prometheus.NewGoCollector())
	return m
}

// AddUp/AddDown record relayed payload bytes.
func (m *Metrics) AddUp(n int64)   { m.Bytes.WithLabelValues("up").Add(float64(n)) }
func (m *Metrics) AddDown(n int64) { m.Bytes.WithLabelValues("down").Add(float64(n)) }

// Tracer returns a value suitable for quic.Config.Tracer that feeds RTT, cwnd
// and loss into the metrics.
func (m *Metrics) Tracer() func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer {
	return func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer {
		return &logging.ConnectionTracer{
			UpdatedMetrics: func(rtt *logging.RTTStats, cwnd, _ logging.ByteCount, _ int) {
				m.RTTSeconds.Set(rtt.SmoothedRTT().Seconds())
				m.CwndBytes.Set(float64(cwnd))
			},
			LostPacket: func(logging.EncryptionLevel, logging.PacketNumber, logging.PacketLossReason) {
				m.LostPackets.Inc()
			},
		}
	}
}

// Serve exposes /metrics on addr until ctx is cancelled. A blank addr is a no-op.
func (m *Metrics) Serve(ctx context.Context, addr string) error {
	if addr == "" {
		return nil
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{}))
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { <-ctx.Done(); srv.Close() }()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// --- small registration helpers ---

type factory struct {
	reg *prometheus.Registry
	cl  prometheus.Labels
}

func promauto(reg *prometheus.Registry, cl prometheus.Labels) factory { return factory{reg, cl} }

func (f factory) gauge(name, help string) prometheus.Gauge {
	g := prometheus.NewGauge(prometheus.GaugeOpts{Name: name, Help: help, ConstLabels: f.cl})
	f.reg.MustRegister(g)
	return g
}

func (f factory) counter(name, help string) prometheus.Counter {
	c := prometheus.NewCounter(prometheus.CounterOpts{Name: name, Help: help, ConstLabels: f.cl})
	f.reg.MustRegister(c)
	return c
}

func (f factory) counterVec(name, help string, labels ...string) *prometheus.CounterVec {
	c := prometheus.NewCounterVec(prometheus.CounterOpts{Name: name, Help: help, ConstLabels: f.cl}, labels)
	f.reg.MustRegister(c)
	return c
}
