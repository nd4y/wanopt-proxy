package metrics

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/quic-go/quic-go"
)

type fakeStats struct {
	mu    sync.Mutex
	stats quic.ConnectionStats
}

func (f *fakeStats) ConnectionStats() quic.ConnectionStats {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stats
}
func metricValue(t *testing.T, m *Metrics, name string) float64 {
	t.Helper()
	all, err := m.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range all {
		if family.GetName() == name {
			item := family.Metric[0]
			if item.Gauge != nil {
				return item.Gauge.GetValue()
			}
			return item.Counter.GetValue()
		}
	}
	t.Fatalf("metric missing %s", name)
	return 0
}
func TestConnectionMetricsAggregateAndCleanUp(t *testing.T) {
	m := New("server")
	a := &fakeStats{stats: quic.ConnectionStats{SmoothedRTT: 10 * time.Millisecond, CongestionWindow: 100, PacketsLost: 4}}
	b := &fakeStats{stats: quic.ConnectionStats{SmoothedRTT: 30 * time.Millisecond, CongestionWindow: 200, PacketsLost: 2}}
	removeA := m.trackConnection(a)
	removeB := m.trackConnection(b)
	if got := scalar(t, m.Connections); got != 2 {
		t.Fatal(got)
	}
	if got := metricValue(t, m, "wanopt_tunnel_rtt_seconds"); got != 0.03 {
		t.Fatal(got)
	}
	if got := metricValue(t, m, "wanopt_congestion_window_bytes"); got != 300 {
		t.Fatal(got)
	}
	a.mu.Lock()
	a.stats.PacketsLost = 1
	a.mu.Unlock()
	if got := metricValue(t, m, "wanopt_lost_packets"); got != 3 {
		t.Fatalf("loss recovery must reduce gauge: %v", got)
	}
	removeA()
	removeA()
	removeB()
	if got := scalar(t, m.Connections); got != 0 {
		t.Fatal(got)
	}
	if got := metricValue(t, m, "wanopt_tunnel_rtt_seconds"); got != 0 {
		t.Fatalf("stale RTT: %v", got)
	}
}
func TestByteCountersAdvanceBeforeStreamEnds(t *testing.T) {
	m := New("client")
	var b bytes.Buffer
	w := m.Writer(&b, "up")
	w.Write([]byte("first"))
	if got := scalar(t, m.up); got != 5 {
		t.Fatal(got)
	}
	w.Write([]byte("second"))
	if got := scalar(t, m.up); got != 11 {
		t.Fatal(got)
	}
	m.UDPDatagram("down", 7)
	if got := scalar(t, m.down); got != 7 {
		t.Fatal(got)
	}
}
func TestDropLabelsAreBounded(t *testing.T) {
	m := New("server")
	for _, r := range []string{"arbitrary-host-1", "arbitrary-host-2"} {
		m.UDPDrop(r)
	}
	if got := scalar(t, m.udpDrops.WithLabelValues("other")); got != 2 {
		t.Fatal(got)
	}
}

func scalar(t *testing.T, m prometheus.Metric) float64 {
	t.Helper()
	var out dto.Metric
	if err := m.Write(&out); err != nil {
		t.Fatal(err)
	}
	if out.Gauge != nil {
		return out.Gauge.GetValue()
	}
	return out.Counter.GetValue()
}
