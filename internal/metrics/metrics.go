// Package metrics exposes bounded-cardinality Prometheus counters and samples
// QUIC connection statistics on scrape, without packet-level tracing overhead.
package metrics

import (
	"context"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/quic-go/quic-go"
)

type statsSource interface{ ConnectionStats() quic.ConnectionStats }
type Metrics struct {
	reg                                                                                 *prometheus.Registry
	ActiveBudget, CodecBudget                                                           prometheus.Gauge
	controller                                                                          *prometheus.GaugeVec
	latency                                                                             *prometheus.HistogramVec
	rejected, failures                                                                  *prometheus.CounterVec
	codecFallback                                                                       prometheus.Counter
	codecInput, codecOutput, codecAttempts, codecSkipped, codecCompressed, codecSeconds prometheus.Counter
	ActiveStreams                                                                       prometheus.Gauge
	StreamsTotal                                                                        prometheus.Counter
	DialErrors                                                                          prometheus.Counter
	Bytes                                                                               *prometheus.CounterVec
	Reconnects                                                                          prometheus.Counter
	TLSResumptions                                                                      prometheus.Counter
	Connections                                                                         prometheus.Gauge
	udpDrops                                                                            *prometheus.CounterVec
	udpPackets                                                                          *prometheus.CounterVec
	udpFlows                                                                            prometheus.Gauge
	up                                                                                  prometheus.Counter
	down                                                                                prometheus.Counter
	mu                                                                                  sync.Mutex
	connections                                                                         map[statsSource]struct{}
}

func New(side string) *Metrics {
	reg := prometheus.NewRegistry()
	cl := prometheus.Labels{"side": side}
	f := promauto(reg, cl)
	m := &Metrics{
		ActiveBudget:    f.gauge("wanopt_admitted_streams", "Active process-wide stream leases"),
		CodecBudget:     f.gauge("wanopt_admitted_codecs", "Active compressed-stream leases"),
		rejected:        f.counterVec("wanopt_admission_rejected_total", "Immediate capacity rejections", "resource"),
		failures:        f.counterVec("wanopt_operation_failures_total", "Operation failures by bounded stage and reason", "stage", "reason"),
		codecFallback:   f.counter("wanopt_codec_capacity_fallback_total", "Streams using raw mode because codec capacity is full"),
		codecInput:      f.counter("wanopt_compression_input_bytes_total", "Payload bytes evaluated by the block encoder"),
		codecOutput:     f.counter("wanopt_compression_output_bytes_total", "Encoded bytes including framing"),
		codecAttempts:   f.counter("wanopt_compression_attempts_total", "DEFLATE attempts"),
		codecSkipped:    f.counter("wanopt_compression_skipped_total", "Blocks sent raw without attempting DEFLATE"),
		codecCompressed: f.counter("wanopt_compression_blocks_total", "Blocks sent compressed"),
		codecSeconds:    f.counter("wanopt_compression_encode_seconds_total", "Wall time spent encoding attempted blocks"),
		reg:             reg, connections: make(map[statsSource]struct{}),
		ActiveStreams:  f.gauge("wanopt_active_streams", "Currently open proxy streams"),
		StreamsTotal:   f.counter("wanopt_streams_total", "Total proxy streams opened"),
		DialErrors:     f.counter("wanopt_dial_errors_total", "Failed dial/connect attempts"),
		Bytes:          f.counterVec("wanopt_relay_bytes_total", "Successfully relayed TCP and UDP payload bytes", "dir"),
		Reconnects:     f.counter("wanopt_tunnel_reconnects_total", "Tunnel reconnect attempts"),
		TLSResumptions: f.counter("wanopt_tls_resumptions_total", "Authenticated connections resumed with TLS session tickets"),
		Connections:    f.gauge("wanopt_tunnel_connections", "Authenticated active tunnel connections"),
		udpDrops:       f.counterVec("wanopt_udp_dropped_total", "Dropped UDP datagrams by bounded reason", "reason"),
		udpPackets:     f.counterVec("wanopt_udp_datagrams_total", "Successfully relayed UDP datagrams", "dir"),
		udpFlows:       f.gauge("wanopt_udp_flows", "Active outbound UDP sockets"),
	}
	m.controller = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "wanopt_congestion_controller", Help: "Configured userspace QUIC congestion controller", ConstLabels: cl}, []string{"algorithm"})
	reg.MustRegister(m.controller)
	m.latency = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "wanopt_operation_seconds", Help: "Operation duration including bounded admission wait", ConstLabels: cl, Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2, 5, 10, 30}}, []string{"stage"})
	reg.MustRegister(m.latency)
	m.up = m.Bytes.WithLabelValues("up")
	m.down = m.Bytes.WithLabelValues("down")
	reg.MustRegister(&connectionCollector{m: m,
		rtt:  prometheus.NewDesc("wanopt_tunnel_rtt_seconds", "Maximum smoothed RTT among active authenticated tunnels", nil, cl),
		cwnd: prometheus.NewDesc("wanopt_congestion_window_bytes", "Sum of congestion windows of active authenticated tunnels", nil, cl),
		lost: prometheus.NewDesc("wanopt_lost_packets", "Cumulative packet loss declarations summed across active authenticated tunnels; decreases on disconnect", nil, cl),
	})
	reg.MustRegister(prometheus.NewGoCollector())
	return m
}

// Gatherer exposes collected metrics without allowing external registration.
func (m *Metrics) Gatherer() prometheus.Gatherer { return m.reg }

func (m *Metrics) AddUp(n int64) {
	if m != nil && n > 0 {
		m.up.Add(float64(n))
	}
}
func (m *Metrics) AddDown(n int64) {
	if m != nil && n > 0 {
		m.down.Add(float64(n))
	}
}

// Writer accounts bytes at every successful write, including long-lived streams.
func (m *Metrics) Writer(w io.Writer, direction string) io.Writer {
	if m == nil {
		return w
	}
	counter := m.down
	if direction == "up" {
		counter = m.up
	}
	return &countWriter{Writer: w, counter: counter}
}

type countWriter struct {
	io.Writer
	counter prometheus.Counter
}

func (w *countWriter) Write(b []byte) (int, error) {
	n, err := w.Writer.Write(b)
	if n > 0 {
		w.counter.Add(float64(n))
	}
	return n, err
}
func (m *Metrics) UDPDrop(reason string) {
	if m == nil {
		return
	}
	switch reason {
	case "invalid", "source", "size", "send", "receive", "queue", "auth", "acl", "dns", "limit", "rate", "closed":
	default:
		reason = "other"
	}
	m.udpDrops.WithLabelValues(reason).Inc()
}

// UDPDatagram includes successful payload bytes in the shared relay counters.
func (m *Metrics) UDPDatagram(direction string, n int) {
	if m == nil {
		return
	}
	if direction != "up" {
		direction = "down"
	}
	m.udpPackets.WithLabelValues(direction).Inc()
	if direction == "up" {
		m.AddUp(int64(n))
	} else {
		m.AddDown(int64(n))
	}
}
func (m *Metrics) UDPFlow(delta int) {
	if m != nil {
		m.udpFlows.Add(float64(delta))
	}
}

// TrackConnection must be called once after successful authentication. The
// returned idempotent cleanup owns both gauge decrement and statistics removal.
func (m *Metrics) TrackConnection(conn *quic.Conn) func() { return m.trackConnection(conn) }
func (m *Metrics) trackConnection(conn statsSource) func() {
	if m == nil {
		return func() {}
	}
	m.mu.Lock()
	_, exists := m.connections[conn]
	if !exists {
		m.connections[conn] = struct{}{}
		m.Connections.Inc()
		if state, ok := conn.(interface{ ConnectionState() quic.ConnectionState }); ok && state.ConnectionState().TLS.DidResume {
			m.TLSResumptions.Inc()
		}
	}
	m.mu.Unlock()
	if exists {
		return func() {}
	}
	var once sync.Once
	return func() {
		once.Do(func() { m.mu.Lock(); delete(m.connections, conn); m.Connections.Dec(); m.mu.Unlock() })
	}
}

type connectionCollector struct {
	m               *Metrics
	rtt, cwnd, lost *prometheus.Desc
}

func (c *connectionCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.rtt
	ch <- c.cwnd
	ch <- c.lost
}
func (c *connectionCollector) Collect(ch chan<- prometheus.Metric) {
	var maxRTT time.Duration
	var cwnd, lost uint64
	c.m.mu.Lock()
	for conn := range c.m.connections {
		stats := conn.ConnectionStats()
		if stats.SmoothedRTT > maxRTT {
			maxRTT = stats.SmoothedRTT
		}
		cwnd += stats.CongestionWindow
		lost += stats.PacketsLost
	}
	c.m.mu.Unlock()
	ch <- prometheus.MustNewConstMetric(c.rtt, prometheus.GaugeValue, maxRTT.Seconds())
	ch <- prometheus.MustNewConstMetric(c.cwnd, prometheus.GaugeValue, float64(cwnd))
	ch <- prometheus.MustNewConstMetric(c.lost, prometheus.GaugeValue, float64(lost))
}
func (m *Metrics) Serve(ctx context.Context, addr string) error {
	if addr == "" {
		return nil
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{MaxRequestsInFlight: 2, Timeout: 5 * time.Second}))
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	stop := context.AfterFunc(ctx, func() { srv.Close() })
	defer stop()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

type factory struct {
	reg *prometheus.Registry
	cl  prometheus.Labels
}

func promauto(reg *prometheus.Registry, cl prometheus.Labels) factory {
	return factory{reg: reg, cl: cl}
}

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
