// Package server implements the egress side of the tunnel. To outside observers
// it is an ordinary HTTP/3 server that hosts a self-hosted file-cloud site (the
// decoy). Tunnel clients hide their streams behind an unregistered HTTP/3 frame
// type, which the server's StreamHijacker routes to the relay; every other
// request is served by the decoy handler. This makes the tunnel and a real
// HTTP/3 site indistinguishable to a prober.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"wanopt/internal/acl"
	"wanopt/internal/compress"
	"wanopt/internal/metrics"
	"wanopt/internal/protocol"
	"wanopt/internal/tunnel"
)

// Options configures a Server.
type Options struct {
	PSK                 []byte
	Cert                tls.Certificate
	ALPN                string
	IdleTimeout         time.Duration
	ACL                 *acl.List
	Allow0RTT           bool
	Compression         bool
	Metrics             *metrics.Metrics
	Decoy               http.Handler
	MaxStreamRecvWindow uint64
	MaxConnRecvWindow   uint64
	Log                 *slog.Logger
}

// Server relays authenticated tunnel traffic and fronts a decoy site.
type Server struct {
	opt     Options
	tlsConf *tls.Config
	h3      *http3.Server
	log     *slog.Logger

	mu     sync.Mutex
	states map[quic.ConnectionTracingID]*connState
}

// New builds a Server from Options.
func New(opt Options) *Server {
	if opt.IdleTimeout <= 0 {
		opt.IdleTimeout = 60 * time.Second
	}
	if opt.ALPN == "" {
		opt.ALPN = tunnel.DefaultALPN
	}
	s := &Server{
		opt:     opt,
		tlsConf: tunnel.ServerTLSConfig(opt.Cert, opt.ALPN),
		log:     opt.Log,
		states:  make(map[quic.ConnectionTracingID]*connState),
	}
	s.h3 = &http3.Server{
		Handler:         opt.Decoy,
		EnableDatagrams: false, // we own the connection's datagrams for UDP relay
		StreamHijacker:  s.hijack,
	}
	return s
}

func (s *Server) quicConfig() *quic.Config {
	o := tunnel.QUICOptions{
		EnableDatagrams:     true,
		IdleTimeout:         s.opt.IdleTimeout,
		MaxStreamRecvWindow: s.opt.MaxStreamRecvWindow,
		MaxConnRecvWindow:   s.opt.MaxConnRecvWindow,
		Allow0RTT:           s.opt.Allow0RTT,
	}
	if s.opt.Metrics != nil {
		o.Tracer = s.opt.Metrics.Tracer()
	}
	return tunnel.NewQUICConfig(o)
}

// ListenAndServe binds the QUIC listener and serves until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	conf := s.quicConfig()
	s.log.Info("server listening", "addr", addr, "alpn", s.opt.ALPN, "0rtt", s.opt.Allow0RTT)

	accept, closeLn, err := s.listen(addr, conf)
	if err != nil {
		return err
	}
	defer closeLn()
	go func() { <-ctx.Done(); closeLn() }()

	for {
		conn, err := accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			s.log.Warn("accept failed", "err", err)
			continue
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *Server) listen(addr string, conf *quic.Config) (func(context.Context) (quic.Connection, error), func(), error) {
	if s.opt.Allow0RTT {
		ln, err := quic.ListenAddrEarly(addr, s.tlsConf, conf)
		if err != nil {
			return nil, nil, err
		}
		return func(ctx context.Context) (quic.Connection, error) {
			return ln.Accept(ctx)
		}, func() { ln.Close() }, nil
	}
	ln, err := quic.ListenAddr(addr, s.tlsConf, conf)
	if err != nil {
		return nil, nil, err
	}
	return ln.Accept, func() { ln.Close() }, nil
}

// handleConn registers per-connection state, starts the UDP datagram pump, and
// hands the connection to the HTTP/3 server (which serves the decoy for normal
// requests and calls our StreamHijacker for tunnel streams).
func (s *Server) handleConn(ctx context.Context, conn quic.Connection) {
	tid, ok := conn.Context().Value(quic.ConnectionTracingKey).(quic.ConnectionTracingID)
	if !ok {
		conn.CloseWithError(0, "")
		return
	}
	cs := &connState{s: s, conn: conn, authed: make(chan struct{}), log: s.log}
	cs.nat = newUDPNAT(conn, s.opt.ACL, s.log)

	s.mu.Lock()
	s.states[tid] = cs
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.states, tid)
		s.mu.Unlock()
		cs.nat.close()
		conn.CloseWithError(0, "")
	}()

	go s.serveDatagrams(ctx, conn, cs.nat)
	// ServeQUICConn blocks until the connection is closed.
	s.h3.ServeQUICConn(conn)
}

func (s *Server) lookup(tid quic.ConnectionTracingID) *connState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.states[tid]
}

// hijack is the http3.Server StreamHijacker. Streams whose first frame type is
// our magic value are tunnel streams; everything else is left to HTTP/3.
func (s *Server) hijack(ft http3.FrameType, tid quic.ConnectionTracingID, str quic.Stream, _ error) (bool, error) {
	if uint64(ft) != protocol.MagicFrameType {
		return false, nil
	}
	cs := s.lookup(tid)
	if cs == nil {
		str.CancelRead(0)
		str.Close()
		return true, nil
	}
	go cs.handleStream(str)
	return true, nil
}

// connState is the per-connection tunnel context.
type connState struct {
	s        *Server
	conn     quic.Connection
	nat      *udpNAT
	log      *slog.Logger
	authed   chan struct{}
	authOnce sync.Once
}

// handleStream reads the stream-kind preamble and dispatches.
func (cs *connState) handleStream(str quic.Stream) {
	var kind [1]byte
	if _, err := io.ReadFull(str, kind[:]); err != nil {
		str.Close()
		return
	}
	switch kind[0] {
	case protocol.KindControl:
		cs.handleControl(str)
	case protocol.KindProxy:
		cs.handleProxy(str)
	default:
		str.Close()
	}
}

// handleControl authenticates the connection, then echoes heartbeats.
func (cs *connState) handleControl(str quic.Stream) {
	defer str.Close()
	peer := cs.conn.RemoteAddr().String()
	tlsState := cs.conn.ConnectionState().TLS
	exporter, err := tlsState.ExportKeyingMaterial(tunnel.ExporterLabel, nil, 32)
	if err != nil {
		cs.log.Warn("exporter unavailable", "peer", peer, "err", err)
		return
	}
	if err := tunnel.ServerAuth(str, cs.s.opt.PSK, exporter); err != nil {
		cs.log.Warn("auth rejected", "peer", peer, "err", err)
		cs.conn.CloseWithError(1, "auth failed")
		return
	}
	cs.log.Info("client authenticated", "peer", peer, "0rtt", cs.conn.ConnectionState().Used0RTT)
	cs.authOnce.Do(func() { close(cs.authed) })
	if m := cs.s.opt.Metrics; m != nil {
		m.Connections.Inc()
		defer m.Connections.Dec()
		if cs.conn.ConnectionState().Used0RTT {
			m.ZeroRTT.Inc()
		}
	}
	heartbeatEcho(str)
}

// heartbeatEcho replies to control-stream pings so the client can measure RTT
// and detect a dead tunnel.
func heartbeatEcho(s io.ReadWriter) {
	buf := make([]byte, 1)
	for {
		if _, err := io.ReadFull(s, buf); err != nil {
			return
		}
		if buf[0] == protocol.CtrlPing {
			if _, err := s.Write([]byte{protocol.CtrlPong}); err != nil {
				return
			}
		}
	}
}

// handleProxy waits for authentication, then relays one TCP connection.
func (cs *connState) handleProxy(str quic.Stream) {
	defer str.Close()
	select {
	case <-cs.authed:
	case <-cs.conn.Context().Done():
		return
	case <-time.After(10 * time.Second):
		return // unauthenticated proxy stream: drop
	}

	req, err := protocol.ReadStreamRequest(str)
	if err != nil {
		return
	}
	if req.Cmd != protocol.CmdTCPConnect {
		protocol.WriteReply(str, protocol.StatusGeneralErr, 0)
		return
	}
	if !cs.s.opt.ACL.Allowed(req.Addr) {
		cs.log.Debug("blocked by ACL", "target", req.Addr.String())
		protocol.WriteReply(str, protocol.StatusNotAllowed, 0)
		return
	}

	target := req.Addr.String()
	dialCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var d net.Dialer
	remote, err := d.DialContext(dialCtx, "tcp", target)
	if err != nil {
		cs.log.Debug("dial failed", "target", target, "err", err)
		if m := cs.s.opt.Metrics; m != nil {
			m.DialErrors.Inc()
		}
		protocol.WriteReply(str, dialStatus(err), 0)
		return
	}
	defer remote.Close()

	useComp := cs.s.opt.Compression && req.Flags&protocol.FlagCompress != 0
	var negFlags byte
	if useComp {
		negFlags |= protocol.FlagCompress
	}
	if err := protocol.WriteReply(str, protocol.StatusOK, negFlags); err != nil {
		return
	}
	if m := cs.s.opt.Metrics; m != nil {
		m.StreamsTotal.Inc()
		m.ActiveStreams.Inc()
		defer m.ActiveStreams.Dec()
	}
	cs.pipe(str, remote, useComp)
}

// pipe bridges the QUIC stream and the remote TCP connection, compressing the
// egress direction and decompressing the ingress direction when negotiated.
func (cs *connState) pipe(str quic.Stream, remote net.Conn, useComp bool) {
	done := make(chan struct{}, 2)
	go func() { // client -> remote
		var n int64
		if useComp {
			n, _ = compress.Decopy(remote, str)
		} else {
			n, _ = io.Copy(remote, str)
		}
		if tc, ok := remote.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		if m := cs.s.opt.Metrics; m != nil {
			m.AddUp(n)
		}
		done <- struct{}{}
	}()
	go func() { // remote -> client
		var n int64
		if useComp {
			n, _ = compress.Copy(str, remote)
		} else {
			n, _ = io.Copy(str, remote)
		}
		str.Close()
		if m := cs.s.opt.Metrics; m != nil {
			m.AddDown(n)
		}
		done <- struct{}{}
	}()
	<-done
}

func dialStatus(err error) byte {
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return protocol.StatusHostUnreach
	case errors.As(err, &ne) && ne.Timeout():
		return protocol.StatusHostUnreach
	default:
		return protocol.StatusConnRefused
	}
}
