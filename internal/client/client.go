// Package client implements the ingress side of the tunnel: it maintains a
// single authenticated QUIC connection to the server and exposes helpers for
// the local SOCKS5/HTTP proxies to open TCP streams and relay UDP datagrams.
package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"wanopt/internal/protocol"
	"wanopt/internal/tunnel"
)

// Client owns the tunnel connection and multiplexes proxy traffic over it.
type Client struct {
	server      string
	psk         []byte
	tlsConf     *tls.Config
	idleTimeout time.Duration
	log         *slog.Logger

	mu      sync.Mutex
	conn    quic.Connection
	ctrl    quic.Stream
	dialing bool

	sessionSeq atomic.Uint64
	udpMu      sync.Mutex
	udpRoutes  map[uint64]chan protocol.Datagram
}

// New creates a Client. psk is the raw shared secret, pin the server SPKI hash.
func New(server string, psk []byte, pin string, idleTimeout time.Duration, log *slog.Logger) *Client {
	if idleTimeout <= 0 {
		idleTimeout = 60 * time.Second
	}
	return &Client{
		server:      server,
		psk:         psk,
		tlsConf:     tunnel.ClientTLSConfig(pin),
		idleTimeout: idleTimeout,
		log:         log,
		udpRoutes:   make(map[uint64]chan protocol.Datagram),
	}
}

// ensureConn returns a live, authenticated connection, dialing a new one if the
// current one is missing or dead.
func (c *Client) ensureConn(ctx context.Context) (quic.Connection, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		select {
		case <-c.conn.Context().Done(): // connection closed; fall through to redial
		default:
			return c.conn, nil
		}
	}

	conn, err := quic.DialAddr(ctx, c.server, c.tlsConf, &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  c.idleTimeout,
		KeepAlivePeriod: c.idleTimeout / 2,
	})
	if err != nil {
		return nil, fmt.Errorf("client: dial %s: %w", c.server, err)
	}

	// Open the control stream first and authenticate before anything else.
	ctrl, err := conn.OpenStreamSync(ctx)
	if err != nil {
		conn.CloseWithError(0, "")
		return nil, err
	}
	tlsState := conn.ConnectionState().TLS
	exporter, err := tlsState.ExportKeyingMaterial(tunnel.ExporterLabel, nil, 32)
	if err != nil {
		conn.CloseWithError(0, "")
		return nil, err
	}
	if err := tunnel.ClientAuth(ctrl, c.psk, exporter); err != nil {
		conn.CloseWithError(1, "auth failed")
		return nil, err
	}

	c.conn = conn
	c.ctrl = ctrl
	c.log.Info("tunnel established", "server", c.server)
	go c.dispatchDatagrams(conn)
	return conn, nil
}

// OpenTCP opens a proxy stream and asks the server to connect to target. It
// returns the ready stream, or an error carrying the server's status code.
func (c *Client) OpenTCP(ctx context.Context, target protocol.Address) (quic.Stream, error) {
	conn, err := c.ensureConn(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	req := protocol.StreamRequest{Cmd: protocol.CmdTCPConnect, Addr: target}
	if _, err := req.WriteTo(stream); err != nil {
		stream.Close()
		return nil, err
	}
	status, err := protocol.ReadReply(stream)
	if err != nil {
		stream.Close()
		return nil, err
	}
	if status != protocol.StatusOK {
		stream.Close()
		return nil, &DialError{Status: status}
	}
	return stream, nil
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
	conn, err := s.c.ensureConn(ctx)
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

// dispatchDatagrams reads inbound datagrams and routes them to the owning UDP
// session by ID. It exits when the connection closes.
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
		// Copy payload out of the receive buffer before handing it off.
		dg.Payload = append([]byte(nil), dg.Payload...)
		select {
		case ch <- dg:
		default: // slow consumer: drop, as UDP semantics permit
		}
	}
}

// Close tears down the tunnel connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn.CloseWithError(0, "")
	}
	return nil
}

var errNoConn = errors.New("client: no active connection")
