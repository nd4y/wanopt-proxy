package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"wanopt/internal/metrics"
	"wanopt/internal/protocol"
)

type delayedUnwindConn struct {
	net.Conn
	entered, unwinding, release chan struct{}
	enterOnce, unwindOnce       sync.Once
}

func (c *delayedUnwindConn) Read(b []byte) (int, error) {
	c.enterOnce.Do(func() { close(c.entered) })
	n, err := c.Conn.Read(b)
	if err != nil {
		c.unwindOnce.Do(func() { close(c.unwinding) })
		<-c.release
	}
	return n, err
}
func (c *delayedUnwindConn) CloseWrite() error { return closeWrite(c.Conn) }

func TestListenersJoinActiveRelayHandlers(t *testing.T) {
	for _, kind := range []string{"socks", "http_connect"} {
		for _, failListener := range []bool{false, true} {
			name := kind + "/cancel"
			if failListener {
				name = kind + "/listener_failure"
			}
			t.Run(name, func(t *testing.T) {
				remote, _ := tcpPair(t)
				delayed := &delayedUnwindConn{Conn: remote, entered: make(chan struct{}), unwinding: make(chan struct{}), release: make(chan struct{})}
				releaseOnce := sync.Once{}
				release := func() { releaseOnce.Do(func() { close(delayed.release) }) }
				defer release()
				p := New(nil, nil)
				p.m = metrics.New("client")
				p.dialStream = func(context.Context, protocol.Address, bool) (net.Conn, bool, error) { return delayed, false, nil }
				ln, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				defer ln.Close()
				done := make(chan error, 1)
				go func() {
					if kind == "socks" {
						done <- p.serveSOCKS(ctx, ln)
					} else {
						done <- p.serveHTTP(ctx, ln)
					}
				}()
				app, err := net.Dial("tcp", ln.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer app.Close()
				app.SetDeadline(time.Now().Add(3 * time.Second))
				if kind == "socks" {
					app.Write([]byte{5, 1, 0})
					var method [2]byte
					if _, err = io.ReadFull(app, method[:]); err != nil {
						t.Fatal(err)
					}
					a := protocol.Address{Atyp: protocol.AtypIPv4, IP: net.IPv4(192, 0, 2, 1), Port: 443}
					app.Write(a.Encode([]byte{5, 1, 0}))
					var reply [3]byte
					if _, err = io.ReadFull(app, reply[:]); err != nil || reply[1] != 0 {
						t.Fatalf("SOCKS=%x %v", reply, err)
					}
					if _, err = protocol.ReadAddress(app); err != nil {
						t.Fatal(err)
					}
				} else {
					io.WriteString(app, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
					response, err := http.ReadResponse(bufio.NewReader(app), &http.Request{Method: "CONNECT"})
					if err != nil || response.StatusCode != 200 {
						t.Fatalf("CONNECT=%v %v", response, err)
					}
				}
				select {
				case <-delayed.entered:
				case <-time.After(time.Second):
					t.Fatal("relay did not start")
				}
				if failListener {
					ln.Close()
				} else {
					cancel()
				}
				select {
				case <-delayed.unwinding:
				case <-time.After(time.Second):
					t.Fatal("shutdown did not close active relay")
				}
				select {
				case err = <-done:
					t.Fatalf("listener returned before handler exit: %v", err)
				default:
				}
				release()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("listener did not join relay")
				}
				families, err := p.m.Gatherer().Gather()
				if err != nil {
					t.Fatal(err)
				}
				for _, family := range families {
					if family.GetName() == "wanopt_active_streams" {
						for _, metric := range family.Metric {
							if got := metric.GetGauge().GetValue(); got != 0 {
								t.Fatalf("active streams after listener returned: %v", got)
							}
						}
					}
				}
				if len(p.slots) != 0 {
					t.Fatal("admission slot survived listener shutdown")
				}
			})
		}
	}
}

func TestHTTPShutdownCancelsAndJoinsPendingTransportDial(t *testing.T) {
	p := New(nil, nil)
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	once := sync.Once{}
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	p.dialStream = func(ctx context.Context, _ protocol.Address, _ bool) (net.Conn, bool, error) {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		<-release
		return nil, false, ctx.Err()
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- p.serveHTTP(ctx, ln) }()
	app, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	io.WriteString(app, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("dial did not start")
	}
	ln.Close()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("listener failure did not cancel transport dial")
	}
	select {
	case <-done:
		t.Fatal("HTTP server returned before pending dial finished")
	default:
	}
	unblock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("pending dial not joined")
	}
}
