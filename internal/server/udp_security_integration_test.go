package server

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"wanopt/internal/protocol"
	"wanopt/internal/tunnel"
)

func securityServerFixture(t *testing.T, s *Server) string {
	t.Helper()
	ln, e := quic.ListenAddr("127.0.0.1:0", s.tlsConf, s.quicConfig())
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("server cleanup did not join")
		}
	})
	return ln.Addr().String()
}
func securityOptions(t *testing.T) Options {
	t.Helper()
	cert, _, e := tunnel.GenerateSelfSigned()
	if e != nil {
		t.Fatal(e)
	}
	return Options{Cert: cert, PSK: []byte("review-test-random-independent-PSK"), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}
func TestRealQUICUnauthenticatedUDPDoesNotReachNetwork(t *testing.T) {
	target, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	s := New(securityOptions(t))
	address := securityServerFixture(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, e := quic.DialAddr(ctx, address, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true})
	if e != nil {
		t.Fatal(e)
	}
	defer conn.CloseWithError(0, "")
	if e = conn.SendDatagram(protocol.EncodeDatagram(1, udpTarget(target), []byte("unauthenticated"))); e != nil {
		t.Fatal(e)
	}
	target.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	var b [128]byte
	if _, _, e = target.ReadFromUDP(b[:]); e == nil {
		t.Fatal("unauthenticated QUIC packet reached egress")
	}
}
func TestQPACKDecodedHeaderLimitEnforced(t *testing.T) {
	reached := make(chan struct{}, 1)
	opt := securityOptions(t)
	opt.Decoy = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached <- struct{}{}
		w.WriteHeader(http.StatusNoContent)
	})
	s := New(opt)
	s.h3.MaxHeaderBytes = 2048
	address := securityServerFixture(t, s)
	transport := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	defer transport.Close()
	req, e := http.NewRequest(http.MethodGet, "https://"+address+"/", nil)
	if e != nil {
		t.Fatal(e)
	}
	// QPACK's repeated name/value representation is below the encoded cap but
	// the expanded field section is over it. The old dependency accepted it.
	for i := 0; i < 200; i++ {
		req.Header.Add("Access-Control-Allow-Credentials", "true")
	}
	client := http.Client{Transport: transport, Timeout: 2 * time.Second}
	response, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("decoded oversized headers status=%d", response.StatusCode)
	}
	select {
	case <-reached:
		t.Fatal("oversized decoded headers reached handler")
	default:
	}
}
