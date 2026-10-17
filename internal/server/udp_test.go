package server

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"wanopt/internal/acl"
	"wanopt/internal/protocol"
)

type captureDatagrams struct{ sent chan []byte }

func (c *captureDatagrams) SendDatagram(b []byte) error {
	c.sent <- append([]byte(nil), b...)
	return nil
}
func udpFixture(t *testing.T, policy *acl.List, opt UDPOptions) (*udpNAT, *net.UDPConn, chan struct{}, *captureDatagrams) {
	t.Helper()
	target, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	auth := make(chan struct{})
	conn := &captureDatagrams{sent: make(chan []byte, 16)}
	n := makeUDPNAT(context.Background(), conn, acl.NewResolver(policy, time.Second, 2), auth, opt, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { n.close(); target.Close() })
	return n, target, auth, conn
}
func udpTarget(target *net.UDPConn) protocol.Address {
	return protocol.Address{Atyp: protocol.AtypIPv4, IP: net.IPv4(127, 0, 0, 1), Port: uint16(target.LocalAddr().(*net.UDPAddr).Port)}
}
func readUDP(t *testing.T, target *net.UDPConn) ([]byte, *net.UDPAddr) {
	t.Helper()
	target.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 2048)
	nr, from, e := target.ReadFromUDP(b)
	if e != nil {
		t.Fatal(e)
	}
	return b[:nr], from
}
func noUDP(t *testing.T, target *net.UDPConn) {
	t.Helper()
	target.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	b := make([]byte, 2048)
	if _, _, e := target.ReadFromUDP(b); e == nil {
		t.Fatal("unexpected forwarded packet")
	}
}
func TestUDPAuthenticationRequiredBeforeAnyEgress(t *testing.T) {
	n, target, auth, conn := udpFixture(t, nil, UDPOptions{})
	dg := protocol.Datagram{SessionID: 1, Addr: udpTarget(target), Payload: []byte("before auth")}
	n.forward(dg)
	noUDP(t, target)
	close(auth)
	dg.Payload = []byte("after auth")
	n.forward(dg)
	b, from := readUDP(t, target)
	if string(b) != "after auth" {
		t.Fatalf("pre-auth packet retained: %q", b)
	}
	target.WriteToUDP([]byte("reply"), from)
	select {
	case raw := <-conn.sent:
		d, e := protocol.DecodeDatagram(raw)
		if e != nil || string(d.Payload) != "reply" {
			t.Fatalf("bad reply %v %v", d, e)
		}
	case <-time.After(time.Second):
		t.Fatal("reply not forwarded")
	}
}
func TestUDPDomainFormCannotBypassCIDR(t *testing.T) {
	policy, _ := acl.New(nil, []string{"127.0.0.0/8"}, nil, nil)
	n, target, auth, _ := udpFixture(t, policy, UDPOptions{})
	close(auth)
	a := udpTarget(target)
	a.Atyp = protocol.AtypDomain
	a.Host = "127.0.0.1"
	a.IP = nil
	n.forward(protocol.Datagram{SessionID: 1, Addr: a, Payload: []byte("must be blocked")})
	noUDP(t, target)
}
func TestUDPFlowLimitAndShutdownJoinsPumps(t *testing.T) {
	n, target, auth, _ := udpFixture(t, nil, UDPOptions{MaxFlows: 1, Workers: 1})
	close(auth)
	dg := protocol.Datagram{SessionID: 1, Addr: udpTarget(target), Payload: []byte("first")}
	n.forward(dg)
	readUDP(t, target)
	dg.SessionID = 2
	n.forward(dg)
	noUDP(t, target)
	n.mu.Lock()
	count := len(n.flows)
	n.mu.Unlock()
	if count != 1 {
		t.Fatalf("flow bound broken: %d", count)
	}
	done := make(chan struct{})
	go func() { n.close(); n.close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("closed UDP sockets left spinning workers")
	}
	n.mu.Lock()
	count = len(n.flows)
	n.mu.Unlock()
	if count != 0 {
		t.Fatalf("shutdown leaked %d flows", count)
	}
}
func TestUDPFlowCreationRateBound(t *testing.T) {
	n, target, auth, _ := udpFixture(t, nil, UDPOptions{MaxFlows: 10, NewFlowsPerSecond: 1, Workers: 1})
	close(auth)
	dg := protocol.Datagram{SessionID: 1, Addr: udpTarget(target), Payload: []byte("first")}
	n.forward(dg)
	readUDP(t, target)
	dg.SessionID = 2
	n.forward(dg)
	noUDP(t, target)
	n.mu.Lock()
	count := len(n.flows)
	n.mu.Unlock()
	if count != 1 {
		t.Fatalf("creation rate unbounded: %d", count)
	}
}
func TestUDPIdleFlowExpires(t *testing.T) {
	n, target, auth, _ := udpFixture(t, nil, UDPOptions{IdleTimeout: 30 * time.Millisecond})
	close(auth)
	n.forward(protocol.Datagram{SessionID: 1, Addr: udpTarget(target), Payload: []byte("once")})
	readUDP(t, target)
	deadline := time.After(time.Second)
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		n.mu.Lock()
		count := len(n.flows)
		n.mu.Unlock()
		if count == 0 {
			return
		}
		select {
		case <-deadline:
			t.Fatal("idle flow not reclaimed")
		case <-tick.C:
		}
	}
}
func TestUDPPayloadLimitBothDirections(t *testing.T) {
	n, target, auth, conn := udpFixture(t, nil, UDPOptions{})
	close(auth)
	dg := protocol.Datagram{SessionID: 1, Addr: udpTarget(target), Payload: make([]byte, protocol.MaxUDPPayload+1)}
	n.forward(dg)
	noUDP(t, target)
	dg.Payload = []byte("open")
	n.forward(dg)
	_, from := readUDP(t, target)
	// Exceed the receive buffer too: Windows returns WSAEMSGSIZE, unlike Linux.
	if _, err := target.WriteToUDP(make([]byte, 1200), from); err != nil {
		t.Fatal(err)
	}
	select {
	case <-conn.sent:
		t.Fatal("oversized response forwarded")
	case <-time.After(50 * time.Millisecond):
	}
	if _, err := target.WriteToUDP(make([]byte, protocol.MaxUDPPayload), from); err != nil {
		t.Fatal(err)
	}
	select {
	case raw := <-conn.sent:
		d, e := protocol.DecodeDatagram(raw)
		if e != nil || len(d.Payload) != protocol.MaxUDPPayload {
			t.Fatal("valid maximum response dropped")
		}
	case <-time.After(time.Second):
		t.Fatal("maximum response not forwarded")
	}
}

func TestUDPEstablishedFlowBypassesFullAdmissionQueue(t *testing.T) {
	target, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	sock, e := net.DialUDP("udp4", nil, target.LocalAddr().(*net.UDPAddr))
	if e != nil {
		t.Fatal(e)
	}
	defer sock.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	auth := make(chan struct{})
	close(auth)
	addr := udpTarget(target)
	flow := &udpFlow{sock: sock, sessionID: 1, target: addr, lastSeen: time.Now()}
	n := &udpNAT{ctx: ctx, cancel: cancel, auth: auth, opt: UDPOptions{}.defaults(), queue: make(chan protocol.Datagram, 1), packets: make(chan udpPacket, 1), flows: map[string]*udpFlow{flowKey(1, addr.String()): flow}}
	// A full admission queue models every DNS worker being occupied. Existing
	// flows must make progress independently of the admission workers.
	n.queue <- protocol.Datagram{}
	n.wg.Add(1)
	go n.packetWorker()
	defer n.close()
	n.forward(protocol.Datagram{SessionID: 1, Addr: addr, Payload: []byte("established")})
	b, _ := readUDP(t, target)
	if string(b) != "established" {
		t.Fatalf("existing flow failed: %q", b)
	}
}
