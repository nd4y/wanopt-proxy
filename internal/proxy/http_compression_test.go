package proxy

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
	"wanopt/internal/client"
	"wanopt/internal/compress"
	"wanopt/internal/protocol"
	"wanopt/internal/server"
	"wanopt/internal/tunnel"
)

func TestHTTPCompressionNegotiationAndRoundTrip(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "fallback", true: "compressed"}[enabled], func(t *testing.T) {
			log := slog.New(slog.NewTextHandler(io.Discard, nil))
			cert, pin, err := tunnel.GenerateSelfSigned()
			if err != nil {
				t.Fatal(err)
			}
			psk := bytes.Repeat([]byte{19}, 32)
			packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			srv := server.New(server.Options{Cert: cert, PSK: psk, Compression: enabled, Log: log})
			sd := make(chan error, 1)
			go func() { sd <- srv.ServePacketConn(ctx, packet) }()
			c := client.New(client.Options{Server: packet.LocalAddr().String(), PSK: psk, Pin: pin, Compression: true, Log: log, RequestTimeout: time.Second})
			cd := make(chan struct{})
			go func() { defer close(cd); c.Run(ctx) }()
			t.Cleanup(func() {
				cancel()
				for _, done := range []<-chan struct{}{cd} {
					select {
					case <-done:
					case <-time.After(3 * time.Second):
						t.Error("client shutdown")
					}
				}
				select {
				case <-sd:
				case <-time.After(3 * time.Second):
					t.Error("server shutdown")
				}
			})
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.Copy(w, r.Body) }))
			defer origin.Close()
			p := New(c, log)
			dial := p.dialStream
			var negotiated atomic.Bool
			p.dialStream = func(ctx context.Context, a protocol.Address, want bool) (net.Conn, bool, error) {
				if !want {
					t.Error("HTTP ignored compression option")
				}
				s, ok, e := dial(ctx, a, want)
				negotiated.Store(ok)
				return s, ok, e
			}
			tr, closeTransport := p.httpTransport(ctx)
			defer closeTransport()
			proxy := httptest.NewServer(p.httpHandler(tr))
			defer proxy.Close()
			u, _ := url.Parse(proxy.URL)
			apptr := &http.Transport{Proxy: http.ProxyURL(u)}
			defer apptr.CloseIdleConnections()
			app := &http.Client{Transport: apptr, Timeout: 5 * time.Second}
			payload := bytes.Repeat([]byte("varying framed HTTP body;"), 12000)
			for i := 0; i < 3; i++ {
				r, e := app.Post(origin.URL, "text/plain", bytes.NewReader(payload))
				if e != nil {
					t.Fatal(e)
				}
				body, e := io.ReadAll(r.Body)
				r.Body.Close()
				if e != nil || !bytes.Equal(body, payload) {
					t.Fatalf("HTTP body mismatch: %v", e)
				}
			}
			if negotiated.Load() != enabled {
				t.Fatalf("negotiated=%v want=%v", negotiated.Load(), enabled)
			}
		})
	}
}

func TestCompressedHTTPConnCloseUnblocksWorkers(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	c := newCompressedHTTPConn(a)
	done := make(chan struct{})
	go func() { defer close(done); c.Close(); c.Close() }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("codec workers survived Close")
	}
}

func TestCompressedHTTPConnPreservesEOFAndRejectsCorruption(t *testing.T) {
	for _, bad := range []bool{false, true} {
		a, b := net.Pipe()
		c := newCompressedHTTPConn(a)
		payload := bytes.Repeat([]byte("close-delimited body\n"), 4000)
		go func() {
			defer b.Close()
			if bad {
				b.Write([]byte{1, 0, 1, 0, 1, 0})
			} else {
				compress.Copy(b, bytes.NewReader(payload))
			}
		}()
		c.SetReadDeadline(time.Now().Add(time.Second))
		got, err := io.ReadAll(c)
		c.Close()
		if bad {
			if err == nil {
				t.Fatal("malformed frame became clean EOF")
			}
		} else if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("clean EOF: got=%d err=%v", len(got), err)
		}
	}
}
