// Package client implements the ingress side of the tunnel. It maintains a
// single authenticated QUIC connection to the server in the background —
// reconnecting with exponential backoff and using a control-stream heartbeat to
// detect dead tunnels — and exposes helpers for the local SOCKS5/HTTP proxies
// to open TCP streams and relay UDP datagrams.
//
// Note: in-flight TCP streams cannot survive a tunnel drop, because the remote
// socket state lives on the server and is lost with the connection. What the
// background maintainer guarantees is that a fresh connection is re-established
// quickly (helped by 0-RTT resumption) so *new* streams recover with minimal
// delay rather than failing until the next request races a lazy redial.
package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"

	"wanopt/internal/metrics"
	"wanopt/internal/protocol"
	"wanopt/internal/tunnel"
)

const (
	initialBackoff    = 500 * time.Millisecond
	maxBackoff        = 30 * time.Second
	heartbeatInterval = 5 * time.Second
	heartbeatTimeout  = 3 * time.Second
)

// Options configures a Client.
type Options struct {
	Server              string
	PSK                 []byte
	Pin                 string
	ALPN                string
	IdleTimeout         time.Duration
	Enable0RTT          bool
	Compression         bool
	Metrics             *metrics.Metrics
	MaxStreamRecvWindow uint64
	MaxConnRecvWindow   uint64
	Log                 *slog.Logger
}

// Client owns the tunnel connection and multiplexes proxy traffic over it.
type Client struct {
	opt      Options
	tlsConf  *tls.Config
	quicConf *quic.Config

	mu    sync.Mutex
	conn  quic.Connection
	ready chan struct{} // closed when a new connection becomes available

	sessionSeq atomic.Uint64
	udpMu      sync.Mutex
	udpRoutes  map[uint64]chan protocol.Datagram
}

// New creates a Client. Call Run to start the background connection maintainer.
func New(opt Options) *Client {
	if opt.IdleTimeout <= 0 {
		opt.IdleTimeout = 60 * time.Second
	}
	if opt.ALPN == "" {
		opt.ALPN = tunnel.DefaultALPN
	}
	var sessionCache tls.ClientSessionCache
	var tokenStore quic.TokenStore
	if opt.Enable0RTT {
		sessionCache = tls.NewLRUClientSessionCache(32)
		tokenStore = quic.NewLRUTokenStore(8, 8)
	}
	qopt := tunnel.QUICOptions{
		EnableDatagrams:     true,
		IdleTimeout:         opt.IdleTimeout,
		MaxStreamRecvWindow: opt.MaxStreamRecvWindow,
		MaxConnRecvWindow:   opt.MaxConnRecvWindow,
		TokenStore:          tokenStore,
	}
	if opt.Metrics != nil {
		qopt.Tracer = opt.Metrics.Tracer()
	}
	return &Client{
		opt:       opt,
		tlsConf:   tunnel.ClientTLSConfig(opt.Pin, opt.ALPN, sessionCache),
		quicConf:  tunnel.NewQUICConfig(qopt),
		ready:     make(chan struct{}),
		udpRoutes: make(map[uint64]chan protocol.Datagram),
	}
}

// Metrics exposes the metrics sink (may be nil) for the proxy layer.
func (c *Client) Metrics() *metrics.Metrics { return c.opt.Metrics }

// CompressionEnabled reports whether the client advertises compression.
func (c *Client) CompressionEnabled() bool { return c.opt.Compression }

// Run drives the background connection maintainer until ctx is cancelled.
func (c *Client) Run(ctx context.Context) {
	backoff := initialBackoff
	for ctx.Err() == nil {
		conn, ctrl, err := c.dialAuth(ctx)
		if err != nil {
			c.opt.Log.Warn("tunnel dial failed", "err", err)
			if c.opt.Metrics != nil {
				c.opt.Metrics.Reconnects.Inc()
			}
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			if backoff *= 2; backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		backoff = initialBackoff
		c.setConn(conn)
		go c.dispatchDatagrams(conn)
		c.runHeartbeat(ctx, conn, ctrl)
		c.clearConn(conn)
		conn.CloseWithError(0, "")
	}
}

// dialAuth dials the server and performs the PSK handshake on the control stream.
func (c *Client) dialAuth(ctx context.Context) (quic.Connection, quic.Stream, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	var conn quic.Connection
	var err error
	if c.opt.Enable0RTT {
		conn, err = quic.DialAddrEarly(dialCtx, c.opt.Server, c.tlsConf, c.quicConf)
	} else {
		conn, err = quic.DialAddr(dialCtx, c.opt.Server, c.tlsConf, c.quicConf)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("dial %s: %w", c.opt.Server, err)
	}
	// The PSK proof is derived from the TLS exporter, which is only available
	// once the 1-RTT handshake completes. With 0-RTT (DialAddrEarly) the
	// connection is usable for early data immediately, so we must explicitly
	// wait for the handshake before authenticating. This also keeps the auth
	// (and all proxy traffic) off replayable 0-RTT early data.
	if ec, ok := conn.(quic.EarlyConnection); ok {
		select {
		case <-ec.HandshakeComplete():
		case <-dialCtx.Done():
			conn.CloseWithError(0, "")
			return nil, nil, dialCtx.Err()
		}
	}
	// Present ourselves as a genuine HTTP/3 client (send a SETTINGS control
	// stream and drain the server's), so the connection is indistinguishable
	// from a real h3 session to anyone inspecting it.
	if err := c.h3Handshake(dialCtx, conn); err != nil {
		conn.CloseWithError(0, "")
		return nil, nil, err
	}
	ctrl, err := openTunnelStream(dialCtx, conn, protocol.KindControl)
	if err != nil {
		conn.CloseWithError(0, "")
		return nil, nil, err
	}
	tlsState := conn.ConnectionState().TLS
	exporter, err := tlsState.ExportKeyingMaterial(tunnel.ExporterLabel, nil, 32)
	if err != nil {
		conn.CloseWithError(0, "")
		return nil, nil, err
	}
	if err := tunnel.ClientAuth(ctrl, c.opt.PSK, exporter); err != nil {
		conn.CloseWithError(1, "auth failed")
		return nil, nil, err
	}
	c.opt.Log.Info("tunnel established", "server", c.opt.Server, "0rtt", conn.ConnectionState().Used0RTT)
	if c.opt.Metrics != nil && conn.ConnectionState().Used0RTT {
		c.opt.Metrics.ZeroRTT.Inc()
	}
	return conn, ctrl, nil
}

// h3Handshake opens the client's HTTP/3 control stream with an (empty) SETTINGS
// frame and starts draining the server's unidirectional streams. This makes the
// client look like an ordinary HTTP/3 client to the server's h3 layer (and to
// any observer), which is required for the camouflage to hold.
func (c *Client) h3Handshake(ctx context.Context, conn quic.Connection) error {
	ctrl, err := conn.OpenUniStreamSync(ctx)
	if err != nil {
		return err
	}
	buf := quicvarint.Append(nil, 0x00) // unidirectional stream type: control
	buf = quicvarint.Append(buf, 0x04)  // frame type: SETTINGS
	buf = quicvarint.Append(buf, 0x00)  // settings payload length: 0
	if _, err := ctrl.Write(buf); err != nil {
		return err
	}
	// Hold the control stream open and drain inbound uni streams for the life
	// of the connection.
	go func() {
		<-conn.Context().Done()
		runtime.KeepAlive(ctrl)
	}()
	go func() {
		for {
			str, err := conn.AcceptUniStream(context.Background())
			if err != nil {
				return
			}
			go io.Copy(io.Discard, str)
		}
	}()
	return nil
}

// openTunnelStream opens a bidirectional stream and writes the tunnel preamble:
// the magic HTTP/3 frame type followed by the stream kind. The server's
// StreamHijacker recognises the magic value and routes the stream to the relay.
func openTunnelStream(ctx context.Context, conn quic.Connection, kind byte) (quic.Stream, error) {
	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	buf := quicvarint.Append(nil, protocol.MagicFrameType)
	buf = append(buf, kind)
	if _, err := str.Write(buf); err != nil {
		str.Close()
		return nil, err
	}
	return str, nil
}

// runHeartbeat pings the server over the control stream and tears the
// connection down if a pong does not arrive in time.
func (c *Client) runHeartbeat(ctx context.Context, conn quic.Connection, ctrl quic.Stream) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	buf := make([]byte, 1)
	for {
		select {
		case <-ctx.Done():
			return
		case <-conn.Context().Done():
			return
		case <-ticker.C:
			ctrl.SetWriteDeadline(time.Now().Add(heartbeatTimeout))
			if _, err := ctrl.Write([]byte{protocol.CtrlPing}); err != nil {
				conn.CloseWithError(0, "")
				return
			}
			ctrl.SetReadDeadline(time.Now().Add(heartbeatTimeout))
			if _, err := ctrl.Read(buf); err != nil {
				c.opt.Log.Warn("heartbeat timeout, dropping tunnel")
				conn.CloseWithError(0, "")
				return
			}
		}
	}
}

func (c *Client) setConn(conn quic.Connection) {
	c.mu.Lock()
	c.conn = conn
	old := c.ready
	c.ready = make(chan struct{})
	c.mu.Unlock()
	close(old) // wake any waiters
}

func (c *Client) clearConn(conn quic.Connection) {
	c.mu.Lock()
	if c.conn == conn {
		c.conn = nil
	}
	c.mu.Unlock()
}

// getConn returns a live connection, waiting for the maintainer to (re)establish
// one if necessary, bounded by ctx.
func (c *Client) getConn(ctx context.Context) (quic.Connection, error) {
	for {
		c.mu.Lock()
		conn := c.conn
		ready := c.ready
		c.mu.Unlock()
		if conn != nil {
			select {
			case <-conn.Context().Done():
			default:
				return conn, nil
			}
		}
		select {
		case <-ready:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// Stream is a proxy stream plus the negotiated compression flag.
type Stream struct {
	quic.Stream
	Compressed bool
}

// OpenTCP opens a proxy stream and asks the server to connect to target.
// wantCompress requests adaptive compression (effective only if the client and
// server both enable it).
func (c *Client) OpenTCP(ctx context.Context, target protocol.Address, wantCompress bool) (*Stream, error) {
	// getConn only returns connections that have completed authentication (and
	// therefore the TLS handshake), so proxy streams never ride 0-RTT early data.
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := openTunnelStream(ctx, conn, protocol.KindProxy)
	if err != nil {
		return nil, err
	}
	req := protocol.StreamRequest{Cmd: protocol.CmdTCPConnect, Addr: target}
	if wantCompress && c.opt.Compression {
		req.Flags |= protocol.FlagCompress
	}
	if _, err := req.WriteTo(stream); err != nil {
		stream.Close()
		return nil, err
	}
	status, flags, err := protocol.ReadReply(stream)
	if err != nil {
		stream.Close()
		return nil, err
	}
	if status != protocol.StatusOK {
		stream.Close()
		return nil, &DialError{Status: status}
	}
	return &Stream{Stream: stream, Compressed: flags&protocol.FlagCompress != 0}, nil
}

// DialError reports a non-OK status returned by the server for a TCP connect.
type DialError struct{ Status byte }

func (e *DialError) Error() string {
	return fmt.Sprintf("server dial failed (status %d)", e.Status)
}

// --- UDP relay ---

// UDPSession is a per-association handle for relaying UDP via QUIC datagrams.
type UDPSession struct {
	c    *Client
	id   uint64
	recv chan protocol.Datagram
}

// NewUDPSession allocates a session ID and registers a route for replies.
func (c *Client) NewUDPSession() *UDPSession {
	id := c.sessionSeq.Add(1)
	ch := make(chan protocol.Datagram, 64)
	c.udpMu.Lock()
	c.udpRoutes[id] = ch
	c.udpMu.Unlock()
	return &UDPSession{c: c, id: id, recv: ch}
}

// Send relays a UDP payload to target through the tunnel.
func (s *UDPSession) Send(ctx context.Context, target protocol.Address, payload []byte) error {
	conn, err := s.c.getConn(ctx)
	if err != nil {
		return err
	}
	return conn.SendDatagram(protocol.EncodeDatagram(s.id, target, payload))
}

// Recv returns the channel of inbound datagrams for this session.
func (s *UDPSession) Recv() <-chan protocol.Datagram { return s.recv }

// Close unregisters the session route.
func (s *UDPSession) Close() {
	s.c.udpMu.Lock()
	delete(s.c.udpRoutes, s.id)
	s.c.udpMu.Unlock()
}

// dispatchDatagrams routes inbound datagrams to the owning UDP session by ID.
func (c *Client) dispatchDatagrams(conn quic.Connection) {
	for {
		data, err := conn.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		dg, err := protocol.DecodeDatagram(data)
		if err != nil {
			continue
		}
		c.udpMu.Lock()
		ch := c.udpRoutes[dg.SessionID]
		c.udpMu.Unlock()
		if ch == nil {
			continue
		}
		dg.Payload = append([]byte(nil), dg.Payload...)
		select {
		case ch <- dg:
		default: // slow consumer: drop, as UDP semantics permit
		}
	}
}
