package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"wanopt/internal/protocol"
	"wanopt/internal/tunnel"
)

func testPeer(t *testing.T, handler http.HandlerFunc) (string, string) {
	t.Helper()
	cert, pin, err := tunnel.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := quic.ListenAddr("127.0.0.1:0", tunnel.ServerTLSConfig(cert, "h3"), &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http3.Server{Handler: handler, EnableDatagrams: false}
	done := make(chan error, 1)
	go func() { done <- srv.ServeListener(ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		ln.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("peer did not stop")
		}
	})
	return ln.Addr().String(), pin
}
func testClient(addr, pin string) *Client {
	return New(Options{Server: addr, Pin: pin, PSK: bytes.Repeat([]byte{7}, 32), HandshakeTimeout: time.Second, RequestTimeout: time.Second, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
}
func authenticatePeer(w http.ResponseWriter, r *http.Request) *http3.Stream {
	s := w.(http3.HTTPStreamer).HTTPStream()
	exporter, err := r.TLS.ExportKeyingMaterial(tunnel.ExporterLabel, nil, 32)
	if err != nil || tunnel.ServerAuth(s, bytes.Repeat([]byte{7}, 32), exporter, nil) != nil {
		tunnel.Abort(s)
		return nil
	}
	return s
}

func TestAuthenticationCancellationInterruptsRead(t *testing.T) {
	gotProof := make(chan struct{})
	addr, pin := testPeer(t, func(w http.ResponseWriter, r *http.Request) {
		s := w.(http3.HTTPStreamer).HTTPStream()
		defer tunnel.Abort(s)
		if _, err := io.ReadFull(s, make([]byte, 32)); err != nil {
			return
		}
		close(gotProof)
		<-r.Context().Done()
	})
	c := testClient(addr, pin)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, _, err := c.dialAuth(ctx); result <- err }()
	select {
	case <-gotProof:
	case <-time.After(time.Second):
		t.Fatal("auth not started")
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled auth succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("auth read ignored cancellation")
	}
}

func TestOpenTCPReplyTimeoutReleasesRequestSlot(t *testing.T) {
	addr, pin := testPeer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Host == tunnel.ControlAuthority {
			s := authenticatePeer(w, r)
			if s != nil {
				defer tunnel.Abort(s)
				_, _ = io.Copy(io.Discard, s)
			}
			return
		}
		s := w.(http3.HTTPStreamer).HTTPStream()
		defer tunnel.Abort(s)
		_, _ = protocol.ReadStreamRequest(s)
		<-r.Context().Done()
	})
	c := testClient(addr, pin)
	c.opt.RequestTimeout = 80 * time.Millisecond
	live, _, err := c.dialAuth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer live.conn.CloseWithError(0, "")
	c.setConn(live)
	target, _ := protocol.ParseAddress("example.test:80")
	for i := 0; i < 2; i++ {
		start := time.Now()
		_, err = c.OpenTCP(context.Background(), target, false)
		if err == nil || time.Since(start) > time.Second {
			t.Fatalf("timeout not enforced: %v", err)
		}
		if len(c.pending) != 0 {
			t.Fatal("pending request slot leaked")
		}
	}
}

func TestPendingAndUDPSessionLimits(t *testing.T) {
	c := New(Options{MaxPendingRequests: 1, MaxUDPSessions: 1, RequestTimeout: time.Second})
	target, _ := protocol.ParseAddress("127.0.0.1:80")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := c.OpenTCP(ctx, target, false); done <- err }()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for len(c.pending) == 0 {
		select {
		case <-deadline.C:
			t.Fatal("pending request missing")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if _, err := c.OpenTCP(context.Background(), target, false); !errors.Is(err, ErrCapacity) {
		t.Fatalf("pending limit: %v", err)
	}
	cancel()
	<-done
	s, err := c.NewUDPSession()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.NewUDPSession(); !errors.Is(err, ErrCapacity) {
		t.Fatalf("session limit: %v", err)
	}
	s.Close()
	s.Close()
	if err = s.Send(context.Background(), target, nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("send on closed session: %v", err)
	}
	next, err := c.NewUDPSession()
	if err != nil {
		t.Fatal(err)
	}
	next.Close()
}

type observedSessionCache struct {
	tls.ClientSessionCache
	once   sync.Once
	stored chan struct{}
}

func (c *observedSessionCache) Put(key string, state *tls.ClientSessionState) {
	c.ClientSessionCache.Put(key, state)
	if state != nil {
		c.once.Do(func() { close(c.stored) })
	}
}

func TestTLSResumptionStillAuthenticatesWithoutEarlyData(t *testing.T) {
	addr, pin := testPeer(t, func(w http.ResponseWriter, r *http.Request) {
		s := authenticatePeer(w, r)
		if s != nil {
			defer tunnel.Abort(s)
			_, _ = io.Copy(io.Discard, s)
		}
	})
	c := testClient(addr, pin)
	cache := &observedSessionCache{ClientSessionCache: tls.NewLRUClientSessionCache(2), stored: make(chan struct{})}
	c.tlsConf.ClientSessionCache = cache
	first, _, err := c.dialAuth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-cache.stored:
	case <-time.After(time.Second):
		first.conn.CloseWithError(0, "")
		t.Fatal("session ticket not received")
	}
	first.conn.CloseWithError(0, "")
	second, _, err := c.dialAuth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer second.conn.CloseWithError(0, "")
	if !second.conn.ConnectionState().TLS.DidResume {
		t.Fatal("TLS session did not resume")
	}
	if second.conn.ConnectionState().Used0RTT {
		t.Fatal("application used early data")
	}
}

func TestPinAndPSKMismatchRejectAuthentication(t *testing.T) {
	addr, pin := testPeer(t, func(w http.ResponseWriter, r *http.Request) {
		s := authenticatePeer(w, r)
		if s != nil {
			defer tunnel.Abort(s)
			_, _ = io.Copy(io.Discard, s)
		}
	})
	c := testClient(addr, "wrong pin")
	if live, _, err := c.dialAuth(context.Background()); err == nil {
		live.conn.CloseWithError(0, "")
		t.Fatal("wrong pin accepted")
	}
	c = testClient(addr, pin)
	c.opt.PSK = bytes.Repeat([]byte{8}, 32)
	if live, _, err := c.dialAuth(context.Background()); err == nil {
		live.conn.CloseWithError(0, "")
		t.Fatal("wrong PSK accepted")
	}
}
