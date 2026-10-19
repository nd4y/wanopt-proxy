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
	"testing"
	"time"
	"wanopt/internal/client"
	"wanopt/internal/protocol"
	"wanopt/internal/server"
	"wanopt/internal/tunnel"
)

func TestHTTPIdlePoolCannotExhaustAdmissionAcrossDestinations(t *testing.T) {
	for _, limit := range []int{1, 2} {
		t.Run(string(rune('0'+limit)), func(t *testing.T) {
			log := slog.New(slog.NewTextHandler(io.Discard, nil))
			cert, pin, err := tunnel.GenerateSelfSigned()
			if err != nil {
				t.Fatal(err)
			}
			psk := bytes.Repeat([]byte{5}, 32)
			packet, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			sd, cd := make(chan struct{}), make(chan struct{})
			srv := server.New(server.Options{Cert: cert, PSK: psk, Compression: true, Log: log})
			go func() { defer close(sd); srv.ServePacketConn(ctx, packet) }()
			c := client.New(client.Options{Server: packet.LocalAddr().String(), Pin: pin, PSK: psk, Compression: true, MaxActiveStreams: limit, MaxCompressedStreams: 1, Log: log})
			go func() { defer close(cd); c.Run(ctx) }()
			t.Cleanup(func() {
				cancel()
				for _, ch := range []chan struct{}{cd, sd} {
					select {
					case <-ch:
					case <-time.After(3 * time.Second):
						t.Error("workers leaked")
					}
				}
			})
			a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "first") }))
			defer a.Close()
			b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "second") }))
			defer b.Close()
			p := New(c, log)
			tr, closeTransport := p.httpTransport(ctx)
			defer closeTransport()
			proxy := httptest.NewServer(p.httpHandler(tr))
			defer proxy.Close()
			u, _ := url.Parse(proxy.URL)
			apptr := &http.Transport{Proxy: http.ProxyURL(u)}
			defer apptr.CloseIdleConnections()
			app := &http.Client{Transport: apptr, Timeout: 3 * time.Second}
			for _, target := range []struct{ url, body string }{{a.URL, "first"}, {b.URL, "second"}, {a.URL, "first"}, {b.URL, "second"}} {
				resp, err := app.Get(target.url)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil || resp.StatusCode != 200 || string(body) != target.body {
					t.Fatalf("idle connections starved target: %s %d %v", body, resp.StatusCode, err)
				}
			}
		})
	}
}

func TestHTTPReportsCapacityAsServiceUnavailable(t *testing.T) {
	p := New(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.dialStream = func(context.Context, protocol.Address, bool) (net.Conn, bool, error) {
		return nil, false, client.ErrCapacity
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tr, closeTransport := p.httpTransport(ctx)
	defer closeTransport()
	for _, method := range []string{"GET", "CONNECT"} {
		r := httptest.NewRequest(method, "http://origin.test:80/", nil)
		r.Host = "origin.test:80"
		w := httptest.NewRecorder()
		p.httpHandler(tr).ServeHTTP(w, r)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s overload returned %d", method, w.Code)
		}
	}
}
