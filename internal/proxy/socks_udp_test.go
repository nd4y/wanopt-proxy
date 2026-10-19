package proxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"wanopt/internal/protocol"
)

type fakeUDPSession struct {
	recv   chan protocol.Datagram
	sent   chan protocol.Datagram
	closed atomic.Bool
}

func (s *fakeUDPSession) Send(ctx context.Context, a protocol.Address, p []byte) error {
	select {
	case s.sent <- protocol.Datagram{Addr: a, Payload: bytes.Clone(p)}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *fakeUDPSession) Recv() <-chan protocol.Datagram { return s.recv }
func (s *fakeUDPSession) Close()                         { s.closed.Store(true) }

func startAssociation(t *testing.T, timeout time.Duration, requested protocol.Address) (*net.TCPConn, *net.UDPAddr, *fakeUDPSession, <-chan struct{}, context.CancelFunc) {
	t.Helper()
	app, ctrl := tcpPair(t)
	p := NewWithOptions(nil, nil, Options{IdleTimeout: timeout})
	session := &fakeUDPSession{recv: make(chan protocol.Datagram, 4), sent: make(chan protocol.Datagram, 4)}
	p.newUDPSession = func() (udpSession, error) { return session, nil }
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan struct{})
	go func() { p.socksUDPAssociate(ctx, ctrl, requested); close(done) }()
	var hdr [3]byte
	if _, err := io.ReadFull(app, hdr[:]); err != nil {
		t.Fatal(err)
	}
	if hdr[1] != repSuccess {
		t.Fatalf("association reply %x", hdr)
	}
	bound, err := protocol.ReadAddress(app)
	if err != nil {
		t.Fatal(err)
	}
	return app, &net.UDPAddr{IP: bound.IP, Port: int(bound.Port)}, session, done, cancel
}
func localUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	s, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func waitUDPForward(t *testing.T, s *fakeUDPSession, want string) {
	t.Helper()
	select {
	case dg := <-s.sent:
		if string(dg.Payload) != want {
			t.Fatalf("payload %q", dg.Payload)
		}
	case <-time.After(time.Second):
		t.Fatal("datagram not forwarded")
	}
}

func TestUDPSourcePinnedAfterValidPacket(t *testing.T) {
	requested := protocol.Address{Atyp: protocol.AtypIPv4, IP: net.IPv4zero}
	app, relay, s, done, _ := startAssociation(t, 2*time.Second, requested)
	legitimate, other := localUDP(t), localUDP(t)
	target := protocol.Address{Atyp: protocol.AtypIPv4, IP: net.IPv4(192, 0, 2, 1), Port: 53}
	// A malformed packet must not claim the as-yet unspecified source port.
	malformed := buildSOCKSUDP(target, []byte("malformed"))
	malformed[2] = 1
	other.WriteToUDP(malformed, relay)
	legitimate.WriteToUDP(buildSOCKSUDP(target, []byte("first")), relay)
	waitUDPForward(t, s, "first")
	other.WriteToUDP(buildSOCKSUDP(target, []byte("hijack")), relay)
	select {
	case dg := <-s.sent:
		t.Fatalf("source changed: %q", dg.Payload)
	case <-time.After(75 * time.Millisecond):
	}
	s.recv <- protocol.Datagram{Addr: target, Payload: []byte("reply")}
	legitimate.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 2048)
	n, _, err := legitimate.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	_, payload, err := parseSOCKSUDP(buf[:n])
	if err != nil || string(payload) != "reply" {
		t.Fatalf("reply=%q err=%v", payload, err)
	}
	app.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("control close did not end association")
	}
	if !s.closed.Load() {
		t.Fatal("session route leaked")
	}
}

func TestUDPRequestedSourcePortEnforced(t *testing.T) {
	legitimate, other := localUDP(t), localUDP(t)
	requested := protocol.Address{Atyp: protocol.AtypIPv4, IP: net.IPv4zero, Port: uint16(legitimate.LocalAddr().(*net.UDPAddr).Port)}
	_, relay, s, done, cancel := startAssociation(t, 2*time.Second, requested)
	target := protocol.Address{Atyp: protocol.AtypIPv4, IP: net.IPv4(192, 0, 2, 1), Port: 53}
	other.WriteToUDP(buildSOCKSUDP(target, []byte("wrong")), relay)
	legitimate.WriteToUDP(buildSOCKSUDP(target, []byte("right")), relay)
	waitUDPForward(t, s, "right")
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancel did not end association")
	}
}

func TestUDPIdleClosesControlAndAllPumps(t *testing.T) {
	requested := protocol.Address{Atyp: protocol.AtypIPv4, IP: net.IPv4zero}
	app, _, s, done, _ := startAssociation(t, 80*time.Millisecond, requested)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("idle association leaked")
	}
	app.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := app.Read(b[:]); err != io.EOF {
		t.Fatalf("control remained open: %v", err)
	}
	if !s.closed.Load() {
		t.Fatal("UDP session not closed")
	}
}

func TestUDPRequestedSourceIPEnforced(t *testing.T) {
	p := New(nil, nil)
	for _, tc := range []struct {
		ip      string
		allowed bool
	}{{"0.0.0.0", true}, {"127.0.0.1", true}, {"127.0.0.2", false}, {"::", true}, {"::1", false}} {
		a := protocol.Address{Atyp: protocol.AtypIPv4, IP: net.ParseIP(tc.ip)}
		if got := p.validUDPSource(context.Background(), a, net.IPv4(127, 0, 0, 1)); got != tc.allowed {
			t.Errorf("%s allowed=%v", tc.ip, got)
		}
	}
}

func TestSOCKSHandshakeTimeoutAndCancellation(t *testing.T) {
	for _, cancelEarly := range []bool{false, true} {
		app, ctrl := tcpPair(t)
		p := NewWithOptions(nil, nil, Options{HandshakeTimeout: 75 * time.Millisecond})
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { p.handleSOCKS(ctx, ctrl); close(done) }()
		if cancelEarly {
			cancel()
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("incomplete SOCKS handshake leaked")
		}
		cancel()
		app.Close()
	}
}
