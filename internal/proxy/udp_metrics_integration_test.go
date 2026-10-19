package proxy

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"wanopt/internal/client"
	"wanopt/internal/metrics"
	"wanopt/internal/protocol"
	"wanopt/internal/server"
	"wanopt/internal/tunnel"
)

func TestSOCKSUDPMetricsCountEachDatagramOnce(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cm, sm := metrics.New("client"), metrics.New("server")
	cert, pin, err := tunnel.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	psk := bytes.Repeat([]byte{11}, 32)
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New(server.Options{Cert: cert, PSK: psk, Metrics: sm, Log: log})
	ctx, cancel := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	go func() { serverDone <- srv.ServePacketConn(ctx, packet) }()
	c := client.New(client.Options{Server: packet.LocalAddr().String(), PSK: psk, Pin: pin, Metrics: cm, Log: log, RequestTimeout: 3 * time.Second})
	clientDone := make(chan struct{})
	go func() { defer close(clientDone); c.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-clientDone:
		case <-time.After(3 * time.Second):
			t.Error("client cleanup timeout")
		}
		select {
		case <-serverDone:
		case <-time.After(3 * time.Second):
			t.Error("server cleanup timeout")
		}
	})
	origin := localUDP(t)
	originDone := make(chan error, 1)
	go func() {
		origin.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 2048)
		n, from, e := origin.ReadFromUDP(buf)
		if e == nil {
			_, e = origin.WriteToUDP(buf[:n], from)
		}
		originDone <- e
	}()
	app, ctrl := tcpPair(t)
	p := New(c, log)
	proxyDone := make(chan struct{})
	go func() { defer close(proxyDone); p.handleSOCKS(ctx, ctrl) }()
	app.Write([]byte{5, 1, 0})
	var method [2]byte
	if _, err = io.ReadFull(app, method[:]); err != nil || method != [2]byte{5, 0} {
		t.Fatalf("method=%x err=%v", method, err)
	}
	requested := protocol.Address{Atyp: protocol.AtypIPv4, IP: net.IPv4zero}
	app.Write(requested.Encode([]byte{5, 3, 0}))
	var header [3]byte
	if _, err = io.ReadFull(app, header[:]); err != nil || header[1] != 0 {
		t.Fatalf("association=%x err=%v", header, err)
	}
	bound, err := protocol.ReadAddress(app)
	if err != nil {
		t.Fatal(err)
	}
	udpApp := localUDP(t)
	udpApp.SetDeadline(time.Now().Add(5 * time.Second))
	target, err := protocol.ParseAddress(origin.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("one UDP datagram")
	if _, err = udpApp.WriteToUDP(buildSOCKSUDP(target, payload), &net.UDPAddr{IP: bound.IP, Port: int(bound.Port)}); err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 2048)
	n, _, err := udpApp.ReadFromUDP(out)
	if err != nil {
		t.Fatal(err)
	}
	_, reply, err := parseSOCKSUDP(out[:n])
	if err != nil || !bytes.Equal(reply, payload) {
		t.Fatalf("reply=%q err=%v", reply, err)
	}
	if err = <-originDone; err != nil {
		t.Fatal(err)
	}
	for _, m := range []*metrics.Metrics{cm, sm} {
		deadline := time.Now().Add(time.Second)
		for {
			values := udpMetricCounters(t, m)
			complete := true
			for _, dir := range []string{"up", "down"} {
				packets := values["wanopt_udp_datagrams_total|"+dir]
				count := values["wanopt_relay_bytes_total|"+dir]
				if packets > 1 || count > float64(len(payload)) {
					t.Fatalf("duplicate metrics %s: packets=%v payload_bytes=%v", dir, packets, count)
				}
				if packets != 1 || count != float64(len(payload)) {
					complete = false
				}
			}
			if complete {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("missing metrics: %v", values)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	app.Close()
	select {
	case <-proxyDone:
	case <-time.After(time.Second):
		t.Fatal("SOCKS UDP association did not stop")
	}
}

func udpMetricCounters(t *testing.T, m *metrics.Metrics) map[string]float64 {
	t.Helper()
	families, err := m.Gatherer().Gather()
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[string]float64)
	for _, family := range families {
		if family.GetName() != "wanopt_udp_datagrams_total" && family.GetName() != "wanopt_relay_bytes_total" {
			continue
		}
		for _, metric := range family.Metric {
			for _, label := range metric.Label {
				if label.GetName() == "dir" {
					result[family.GetName()+"|"+label.GetValue()] = metric.GetCounter().GetValue()
				}
			}
		}
	}
	return result
}
