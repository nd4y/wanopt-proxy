package server

import (
	"bytes"
	"context"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
	"wanopt/internal/client"
	"wanopt/internal/tunnel"
)

func TestUnauthenticatedKeepaliveCannotHoldConnectionCapacity(t *testing.T) {
	cert, pin, err := tunnel.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	srv := New(Options{Cert: cert, PSK: bytes.Repeat([]byte{7}, 32), MaxConnections: 1, HandshakeTimeout: 500 * time.Millisecond, IdleTimeout: 5 * time.Second, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.ServePacketConn(ctx, packet) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("server workers leaked")
		}
	})
	peer, err := quic.DialAddr(context.Background(), packet.LocalAddr().String(), tunnel.ClientTLSConfig(pin, "h3", nil), &quic.Config{KeepAlivePeriod: 10 * time.Millisecond, MaxIdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.CloseWithError(0, "")
	hc := (&http3.Transport{}).NewClientConn(peer)
	req := &http.Request{Method: "GET", URL: &url.URL{Scheme: "https", Host: "cover.example", Path: "/"}, Header: make(http.Header)}
	resp, err := hc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	select {
	case <-peer.Context().Done():
		if err := context.Cause(peer.Context()); err == nil || !strings.Contains(err.Error(), "authentication timeout") {
			t.Fatalf("unexpected close reason %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("unauthenticated keepalive held the only connection slot beyond authentication deadline")
	}
	eventuallyAdmission(t, func() bool { return len(srv.slots) == 0 })
	f := &testTunnel{server: srv, addr: packet.LocalAddr().String(), pin: pin}
	valid := secondClient(t, f, client.Options{})
	target := tcpOrigin(t, func(c net.Conn) { io.Copy(io.Discard, c) })
	requestCtx, requestCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer requestCancel()
	stream, err := valid.OpenTCP(requestCtx, target, false)
	if err != nil {
		t.Fatal("capacity did not recover for authenticated client", err)
	}
	stream.Close()
	srv.mu.Lock()
	var authenticated *quic.Conn
	for conn := range srv.states {
		authenticated = conn
	}
	srv.mu.Unlock()
	if authenticated == nil {
		t.Fatal("authenticated connection missing")
	}
	time.Sleep(600 * time.Millisecond)
	srv.mu.Lock()
	_, stillPresent := srv.states[authenticated]
	srv.mu.Unlock()
	if !stillPresent {
		t.Fatal("authentication deadline closed an authenticated connection")
	}
}
