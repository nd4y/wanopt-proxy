package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"wanopt/internal/acl"
	"wanopt/internal/client"
	"wanopt/internal/compress"
	"wanopt/internal/protocol"
	"wanopt/internal/tunnel"
)

type testTunnel struct {
	server        *Server
	client        *client.Client
	addr          string
	pin           string
	cert          tls.Certificate
	stopServer    context.CancelFunc
	serverDone    chan error
	serverStopped chan struct{}
}

func startTunnel(t *testing.T, opt Options) *testTunnel {
	t.Helper()
	cert, pin, err := tunnel.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	opt.Cert = cert
	opt.PSK = bytes.Repeat([]byte{7}, 32)
	opt.Log = log
	if opt.RequestTimeout == 0 {
		opt.RequestTimeout = time.Second
	}
	if opt.HandshakeTimeout == 0 {
		opt.HandshakeTimeout = time.Second
	}
	srv := New(opt)
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	f := &testTunnel{server: srv, addr: ln.LocalAddr().String(), pin: pin, cert: cert, stopServer: cancel, serverDone: make(chan error, 1), serverStopped: make(chan struct{})}
	go func() { defer close(f.serverStopped); f.serverDone <- srv.ServePacketConn(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-f.serverDone:
		case <-time.After(3 * time.Second):
			t.Error("server shutdown did not join workers")
		}
	})
	c := client.New(client.Options{Server: f.addr, PSK: opt.PSK, Pin: pin, Log: log, RequestTimeout: time.Second, HandshakeTimeout: time.Second, Compression: opt.Compression})
	f.client = c
	cctx, ccancel := context.WithCancel(context.Background())
	clientDone := make(chan struct{})
	go func() { defer close(clientDone); c.Run(cctx) }()
	t.Cleanup(func() {
		ccancel()
		select {
		case <-clientDone:
		case <-time.After(3 * time.Second):
			t.Error("client shutdown did not join workers")
		}
	})
	return f
}

func tcpOrigin(t *testing.T, handler func(net.Conn)) protocol.Address {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				handler(c)
			}()
		}
	}()
	t.Cleanup(func() { ln.Close(); <-done; wg.Wait() })
	addr, err := protocol.ParseAddress(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

func TestTCPHalfClosePreservesDelayedResponse(t *testing.T) {
	for _, compression := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "compressed"}[compression], func(t *testing.T) {
			reply := bytes.Repeat([]byte("delayed origin response\n"), 10000)
			target := tcpOrigin(t, func(c net.Conn) {
				data, err := io.ReadAll(c)
				if err != nil || string(data) != "request" {
					return
				}
				time.Sleep(25 * time.Millisecond)
				_, _ = c.Write(reply)
			})
			f := startTunnel(t, Options{Compression: compression})
			stream, err := f.client.OpenTCP(context.Background(), target, true)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			if compression {
				_, err = compress.Copy(stream, bytes.NewReader([]byte("request")))
			} else {
				_, err = stream.Write([]byte("request"))
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = stream.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			_ = stream.SetReadDeadline(time.Now().Add(3 * time.Second))
			var out bytes.Buffer
			if compression {
				_, err = compress.Decopy(&out, stream)
			} else {
				_, err = io.Copy(&out, stream)
			}
			data := out.Bytes()
			if err != nil || !bytes.Equal(data, reply) {
				t.Fatalf("response truncated: got %d want %d err=%v", len(data), len(reply), err)
			}
		})
	}
}

func TestDeniedAndRefusedRequestsReleaseStreams(t *testing.T) {
	policy, _ := acl.New(nil, nil, nil, []int{9})
	f := startTunnel(t, Options{ACL: policy, MaxStreamsPerConnection: 4})
	denied, _ := protocol.ParseAddress("127.0.0.1:9")
	// Reserve and close a port so the second failure path is an actual dial refusal.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refused, _ := protocol.ParseAddress(ln.Addr().String())
	ln.Close()
	for i := 0; i < 40; i++ {
		for _, target := range []protocol.Address{denied, refused} {
			_, err := f.client.OpenTCP(context.Background(), target, false)
			var de *client.DialError
			if !errors.As(err, &de) {
				t.Fatalf("request %d exhausted stream capacity: %v", i, err)
			}
			if target.Port == 9 && de.Status != protocol.StatusNotAllowed {
				t.Fatalf("wrong ACL status: %v", de)
			}
		}
	}
	target := tcpOrigin(t, func(c net.Conn) { _, _ = c.Write([]byte("ok")) })
	stream, err := f.client.OpenTCP(context.Background(), target, false)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	_ = stream.SetReadDeadline(time.Now().Add(time.Second))
	data, err := io.ReadAll(stream)
	if err != nil || string(data) != "ok" {
		t.Fatalf("valid request after denials: %q %v", data, err)
	}
}

func TestDatagramsRequireAuthentication(t *testing.T) {
	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	target, _ := protocol.ParseAddress(sink.LocalAddr().String())
	f := startTunnel(t, Options{})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	raw, err := quic.DialAddr(ctx, f.addr, tunnel.ClientTLSConfig(f.pin, "h3", nil), &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer raw.CloseWithError(0, "")
	_ = (&http3.Transport{}).NewClientConn(raw)
	if err = raw.SendDatagram(protocol.EncodeDatagram(1, target, []byte("unauthenticated"))); err != nil {
		t.Fatal(err)
	}
	_ = sink.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 100)
	if _, _, err = sink.ReadFromUDP(buf); err == nil {
		t.Fatal("unauthenticated datagram reached destination")
	}
	session, err := f.client.NewUDPSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err = session.Send(ctx, target, []byte("authenticated")); err != nil {
		t.Fatal(err)
	}
	_ = sink.SetReadDeadline(time.Now().Add(time.Second))
	n, from, err := sink.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "authenticated" {
		t.Fatalf("unexpected payload %q", buf[:n])
	}
	_, _ = sink.WriteToUDP([]byte("reply"), from)
	select {
	case dg := <-session.Recv():
		if string(dg.Payload) != "reply" {
			t.Fatalf("reply %q", dg.Payload)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// Cleanup closes this active NAT flow and must join its reader without spinning.
}

func TestShutdownClosesIdleTCPRelay(t *testing.T) {
	target := tcpOrigin(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	f := startTunnel(t, Options{})
	stream, err := f.client.OpenTCP(context.Background(), target, false)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	f.stopServer()
	_ = stream.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = stream.Read(make([]byte, 1)); err == nil {
		t.Fatal("stream stayed open after server shutdown")
	}
}

func TestHTTP3DecoyStillServes(t *testing.T) {
	f := startTunnel(t, Options{Decoy: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "cover") })})
	tr := &http3.Transport{TLSClientConfig: tunnel.ClientTLSConfig(f.pin, "h3", nil)}
	defer tr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+f.addr+"/", nil)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "cover" {
		t.Fatalf("decoy: %q %v", body, err)
	}
}

func TestClientReconnectsAfterServerRestart(t *testing.T) {
	target := tcpOrigin(t, func(c net.Conn) { _, _ = c.Write([]byte("ok")) })
	f := startTunnel(t, Options{})
	first, err := f.client.OpenTCP(context.Background(), target, false)
	if err != nil {
		t.Fatal(err)
	}
	_ = first.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = io.ReadAll(first)
	first.Close()
	f.stopServer()
	select {
	case <-f.serverStopped:
	case <-time.After(time.Second):
		t.Fatal("old server did not stop")
	}
	replacement := New(f.server.opt)
	ln, err := net.ListenPacket("udp", f.addr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- replacement.ServePacketConn(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("replacement server did not stop")
		}
	})
	deadline := time.Now().Add(4 * time.Second)
	var stream *client.Stream
	for time.Now().Before(deadline) {
		stream, err = f.client.OpenTCP(context.Background(), target, false)
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("new connection did not recover: %v", err)
	}
	defer stream.Close()
	_ = stream.SetReadDeadline(time.Now().Add(time.Second))
	data, err := io.ReadAll(stream)
	if err != nil || string(data) != "ok" {
		t.Fatalf("restarted relay: %q %v", data, err)
	}
}

func TestConnectionAndStreamLimitsReleaseCapacity(t *testing.T) {
	target := tcpOrigin(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	f := startTunnel(t, Options{MaxConnections: 1, MaxStreamsPerConnection: 2})
	first, err := f.client.OpenTCP(context.Background(), target, false)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := f.client.OpenTCP(context.Background(), target, false)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	if stream, err := f.client.OpenTCP(ctx, target, false); err == nil {
		stream.Close()
		cancel()
		t.Fatal("stream limit exceeded")
	}
	cancel()
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	raw, err := quic.DialAddr(ctx, f.addr, tunnel.ClientTLSConfig(f.pin, "h3", nil), &quic.Config{EnableDatagrams: true})
	if err == nil {
		defer raw.CloseWithError(0, "")
		select {
		case <-raw.Context().Done():
		case <-ctx.Done():
			t.Fatal("connection limit exceeded")
		}
	}
	first.Close()
	replacement, err := f.client.OpenTCP(context.Background(), target, false)
	if err != nil {
		t.Fatalf("closed stream did not release capacity: %v", err)
	}
	replacement.Close()
}

// Closing a caller-owned listener must terminate Serve even while its parent
// context and an authenticated client's control stream are still alive.
func TestServeClosesConnectionsOnListenerFailure(t *testing.T) {
	cert, pin, err := tunnel.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := acl.New(nil, []string{"127.0.0.1/32"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	psk := bytes.Repeat([]byte{9}, 32)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(Options{Cert: cert, PSK: psk, ACL: policy, Log: log})
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	transport := &quic.Transport{Conn: packet}
	defer transport.Close()
	ln, err := transport.Listen(srv.tlsConf, srv.quicConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverDone := make(chan struct{})
	var serveErr error
	go func() {
		defer close(serverDone)
		serveErr = srv.Serve(ctx, ln)
	}()
	defer func() {
		cancel()
		select {
		case <-serverDone:
		case <-time.After(3 * time.Second):
			t.Error("Serve did not join during cleanup")
		}
	}()

	clientCtx, stopClient := context.WithCancel(context.Background())
	c := client.New(client.Options{Server: packet.LocalAddr().String(), PSK: psk, Pin: pin, Log: log, RequestTimeout: time.Second, HandshakeTimeout: time.Second})
	clientDone := make(chan struct{})
	go func() { defer close(clientDone); c.Run(clientCtx) }()
	defer func() {
		stopClient()
		select {
		case <-clientDone:
		case <-time.After(3 * time.Second):
			t.Error("client did not join during cleanup")
		}
	}()
	target, err := protocol.ParseAddress("127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	stream, err := c.OpenTCP(ctx, target, false)
	if stream != nil {
		_ = stream.Close()
	}
	var denied *client.DialError
	if !errors.As(err, &denied) || denied.Status != protocol.StatusNotAllowed {
		t.Fatalf("client did not authenticate: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve hung after listener closed with its parent context still live")
	}
	if serveErr == nil || ctx.Err() != nil {
		t.Fatalf("expected independent listener failure, got Serve=%v parent=%v", serveErr, ctx.Err())
	}
	srv.mu.Lock()
	active := len(srv.states)
	srv.mu.Unlock()
	if active != 0 || len(srv.slots) != 0 {
		t.Fatalf("workers remained after Serve returned: states=%d slots=%d", active, len(srv.slots))
	}
}
