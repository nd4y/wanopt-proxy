// Package server provides authenticated TCP and UDP egress over HTTP/3 and QUIC.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"wanopt/internal/acl"
	"wanopt/internal/admission"
	"wanopt/internal/compress"
	"wanopt/internal/metrics"
	"wanopt/internal/protocol"
	"wanopt/internal/tunnel"
)

type Options struct {
	CongestionControl                      string
	MaxActiveStreams, MaxCompressedStreams int
	PSK                                    []byte
	PreviousPSK                            []byte
	PreviousPSKExpires                     time.Time
	Cert                                   tls.Certificate
	ALPN                                   string
	IdleTimeout                            time.Duration
	HandshakeTimeout                       time.Duration
	RequestTimeout                         time.Duration
	MaxConnections                         int
	MaxStreamsPerConnection                int
	ACL                                    *acl.List
	Resolver                               *acl.Resolver
	UDP                                    UDPOptions
	// Allow0RTT is ignored: application traffic always follows a full TLS handshake.
	Allow0RTT           bool
	Compression         bool
	Metrics             *metrics.Metrics
	Decoy               http.Handler
	MaxStreamRecvWindow uint64
	MaxConnRecvWindow   uint64
	Log                 *slog.Logger
}

type Server struct {
	opt            Options
	tlsConf        *tls.Config
	h3             *http3.Server
	log            *slog.Logger
	mu             sync.Mutex
	states         map[*quic.Conn]*connState
	slots          chan struct{}
	active, codecs *admission.Budget
	credentials    *tunnel.ServerCredentials
}
type connContextKey struct{}

func New(opt Options) *Server {
	if opt.IdleTimeout <= 0 {
		opt.IdleTimeout = 60 * time.Second
	}
	if opt.HandshakeTimeout <= 0 {
		opt.HandshakeTimeout = 10 * time.Second
	}
	if opt.RequestTimeout <= 0 {
		opt.RequestTimeout = 15 * time.Second
	}
	if opt.MaxConnections <= 0 {
		opt.MaxConnections = 256
	}
	if opt.MaxStreamsPerConnection <= 0 {
		opt.MaxStreamsPerConnection = 128
	}
	if opt.MaxActiveStreams <= 0 {
		opt.MaxActiveStreams = 128
	}
	if opt.MaxCompressedStreams <= 0 {
		opt.MaxCompressedStreams = min(16, opt.MaxActiveStreams)
	}
	if opt.ALPN == "" {
		opt.ALPN = tunnel.DefaultALPN
	}
	if opt.Log == nil {
		opt.Log = slog.Default()
	}
	if opt.Resolver == nil {
		opt.Resolver = acl.NewResolver(opt.ACL, 5*time.Second, 32)
	}
	if opt.Decoy == nil {
		opt.Decoy = http.NotFoundHandler()
	}
	s := &Server{opt: opt, tlsConf: tunnel.ServerTLSConfig(opt.Cert, opt.ALPN), log: opt.Log, states: make(map[*quic.Conn]*connState), slots: make(chan struct{}, opt.MaxConnections)}
	s.credentials = tunnel.NewServerCredentials(opt.PSK, opt.PreviousPSK, opt.PreviousPSKExpires, opt.Cert)
	s.tlsConf = s.credentials.TLSConfig(opt.ALPN)
	opt.Metrics.Controller(opt.CongestionControl)
	s.active = admission.New(opt.MaxActiveStreams, opt.Metrics.BudgetChange(false))
	s.codecs = admission.New(opt.MaxCompressedStreams, opt.Metrics.BudgetChange(true))
	s.h3 = &http3.Server{Handler: http.HandlerFunc(s.serveHTTP), EnableDatagrams: false, MaxHeaderBytes: 16 << 10, IdleTimeout: opt.IdleTimeout, Logger: opt.Log,
		ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
			s.mu.Lock()
			cs := s.states[c]
			s.mu.Unlock()
			return context.WithValue(ctx, connContextKey{}, cs)
		},
	}
	return s
}

func (s *Server) quicConfig() *quic.Config {
	return tunnel.NewQUICConfig(tunnel.QUICOptions{CongestionControl: s.opt.CongestionControl, EnableDatagrams: true, IdleTimeout: s.opt.IdleTimeout, HandshakeTimeout: s.opt.HandshakeTimeout,
		MaxStreamRecvWindow: s.opt.MaxStreamRecvWindow, MaxConnRecvWindow: s.opt.MaxConnRecvWindow, MaxIncomingStreams: int64(s.opt.MaxStreamsPerConnection + 1)})
}

// ListenAndServe closes accepted connections and waits for workers on cancellation.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	packet, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	return s.ServePacketConn(ctx, packet)
}

// ServePacketConn owns the UDP socket and transport. Explicit transport closure
// releases the socket immediately after workers join, including QUIC draining IDs.
func (s *Server) ServePacketConn(ctx context.Context, packet net.PacketConn) error {
	defer packet.Close()
	transport := &quic.Transport{Conn: packet}
	defer transport.Close()
	ln, err := transport.Listen(s.tlsConf, s.quicConfig())
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln)
}

// Serve owns the listener and accepted connections, and joins their workers.
// The caller still owns the QUIC transport and its UDP socket. Use ServePacketConn
// when the server should also close those resources after the workers finish.
func (s *Server) Serve(ctx context.Context, ln *quic.Listener) error {
	serveCtx, cancel := context.WithCancel(ctx)
	listenerClosed := make(chan struct{})
	stop := context.AfterFunc(serveCtx, func() {
		defer close(listenerClosed)
		_ = ln.Close()
	})
	var wg sync.WaitGroup
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.revokeUnauthorized()
			case <-serveCtx.Done():
				return
			}
		}
	}()
	defer func() {
		// Cancel before taking the connection snapshot: an accepted worker may
		// not yet be registered in states when Accept fails independently of ctx.
		cancel()
		_ = ln.Close()
		s.closeConnections()
		wg.Wait()
		<-watcherDone
		if !stop() {
			<-listenerClosed
		}
	}()
	s.log.Info("server listening", "addr", ln.Addr())
	for {
		conn, err := ln.Accept(serveCtx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		select {
		case s.slots <- struct{}{}:
			wg.Add(1)
			go func() { defer wg.Done(); defer func() { <-s.slots }(); s.handleConn(serveCtx, conn) }()
		default:
			s.opt.Metrics.Rejected("connection")
			conn.CloseWithError(1, "connection capacity reached")
		}
	}
}

func (s *Server) closeConnections() {
	s.mu.Lock()
	connections := make([]*quic.Conn, 0, len(s.states))
	for conn := range s.states {
		connections = append(connections, conn)
	}
	s.mu.Unlock()
	for _, conn := range connections {
		conn.CloseWithError(0, "server shutting down")
	}
}
func (s *Server) handleConn(ctx context.Context, conn *quic.Conn) {
	stop := context.AfterFunc(ctx, func() { conn.CloseWithError(0, "server shutting down") })
	defer stop()
	cs := &connState{s: s, conn: conn, authed: make(chan struct{}), log: s.log, streams: make(chan struct{}, s.opt.MaxStreamsPerConnection)}
	// The deadline starts at accept, not when the peer eventually opens control.
	// Transport keepalives and ordinary cover requests cannot renew it.
	cs.authTimer = time.AfterFunc(s.opt.HandshakeTimeout, func() {
		select {
		case <-cs.authed:
			return
		default:
			s.opt.Metrics.Failure("auth", context.DeadlineExceeded)
			conn.CloseWithError(1, "authentication timeout")
		}
	})
	defer cs.authTimer.Stop()
	cs.nat = newUDPNAT(conn.Context(), conn, s.opt.Resolver, cs.authed, s.opt.UDP, s.opt.Metrics, s.log)
	s.mu.Lock()
	s.states[conn] = cs
	s.mu.Unlock()
	dgDone := make(chan struct{})
	go func() { defer close(dgDone); s.serveDatagrams(conn.Context(), conn, cs.nat) }()
	defer func() {
		conn.CloseWithError(0, "")
		cs.nat.close()
		<-dgDone
		s.mu.Lock()
		delete(s.states, conn)
		s.mu.Unlock()
	}()
	_ = s.h3.ServeQUICConn(conn)
}

type connState struct {
	s              *Server
	conn           *quic.Conn
	nat            *udpNAT
	log            *slog.Logger
	authed         chan struct{}
	controlStarted atomic.Bool
	streams        chan struct{}
	authKey        atomic.Pointer[[32]byte]
	authTimer      *time.Timer
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect || (r.Host != tunnel.ControlAuthority && r.Host != tunnel.ProxyAuthority) {
		s.opt.Decoy.ServeHTTP(w, r)
		return
	}
	if r.Header.Get(tunnel.VersionHeader) != strconv.Itoa(int(protocol.Version)) {
		http.Error(w, "unsupported protocol", http.StatusBadRequest)
		return
	}
	cs, _ := r.Context().Value(connContextKey{}).(*connState)
	if cs == nil {
		http.Error(w, "connection unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.Host == tunnel.ControlAuthority {
		if !cs.controlStarted.CompareAndSwap(false, true) {
			http.Error(w, "control stream already exists", http.StatusConflict)
			return
		}
	} else {
		select {
		case <-cs.authed:
		default:
			http.Error(w, "authentication required", http.StatusForbidden)
			return
		}
		if id := cs.authKey.Load(); id == nil || !s.credentials.Accepts(*id) {
			http.Error(w, "credentials revoked", http.StatusForbidden)
			return
		}
		lease, ok := s.active.TryAcquire()
		if !ok {
			s.opt.Metrics.Rejected("stream")
			http.Error(w, "global stream capacity reached", http.StatusServiceUnavailable)
			return
		}
		defer lease.Release()
		select {
		case cs.streams <- struct{}{}:
			defer func() { <-cs.streams }()
		default:
			s.opt.Metrics.Rejected("stream")
			http.Error(w, "stream capacity reached", http.StatusServiceUnavailable)
			return
		}
	}
	hs, ok := w.(http3.HTTPStreamer)
	if !ok {
		http.Error(w, "HTTP/3 required", http.StatusHTTPVersionNotSupported)
		return
	}
	w.WriteHeader(http.StatusOK)
	str := hs.HTTPStream()
	defer str.CancelRead(0)
	defer str.Close()
	if r.Host == tunnel.ControlAuthority {
		cs.handleControl(str)
	} else {
		cs.handleProxy(str)
	}
}

func (cs *connState) handleControl(str tunnel.Stream) {
	authStart := time.Now()
	ctx, cancel := context.WithTimeout(cs.conn.Context(), cs.s.opt.HandshakeTimeout)
	unbind := tunnel.BindContext(ctx, str)
	tlsState := cs.conn.ConnectionState().TLS
	exporter, err := tlsState.ExportKeyingMaterial(tunnel.ExporterLabel, nil, 32)
	if err == nil {
		err = cs.s.credentials.Authenticate(str, exporter, func(id [32]byte) error {
			cs.authKey.Store(&id)
			if !cs.s.credentials.Accepts(id) {
				return errors.New("tunnel: key revoked during authentication")
			}
			close(cs.authed)
			cs.authTimer.Stop()
			return nil
		})
	}
	cs.s.opt.Metrics.Observe("auth", time.Since(authStart))
	unbind()
	cancel()
	if err != nil {
		cs.s.opt.Metrics.Failure("auth", err)
		cs.conn.CloseWithError(1, "authentication failed")
		return
	}
	_ = str.SetDeadline(time.Time{})
	if m := cs.s.opt.Metrics; m != nil {
		defer m.TrackConnection(cs.conn)()
	}
	cs.log.Info("client authenticated", "peer", cs.conn.RemoteAddr())
	// Losing the authenticated control stream invalidates the entire tunnel.
	defer cs.conn.CloseWithError(0, "control stream closed")
	var b [1]byte
	for {
		_ = str.SetReadDeadline(time.Now().Add(cs.s.opt.IdleTimeout))
		if _, err := io.ReadFull(str, b[:]); err != nil {
			return
		}
		if b[0] != protocol.CtrlPing {
			return
		}
		_ = str.SetWriteDeadline(time.Now().Add(cs.s.opt.RequestTimeout))
		if _, err := str.Write([]byte{protocol.CtrlPong}); err != nil {
			return
		}
	}
}

func (cs *connState) handleProxy(str tunnel.Stream) {
	ctx, cancel := context.WithTimeout(cs.conn.Context(), cs.s.opt.RequestTimeout)
	unbind := tunnel.BindContext(ctx, str)
	// Stop timeout callbacks before handing this stream to the long-lived relay.
	finished := false
	defer func() {
		if !finished {
			unbind()
			cancel()
		}
	}()
	req, err := protocol.ReadStreamRequest(str)
	if err != nil {
		return
	}
	if req.Cmd != protocol.CmdTCPConnect {
		_ = protocol.WriteReply(str, protocol.StatusGeneralErr, 0)
		return
	}
	remote, err := cs.s.opt.Resolver.DialContext(ctx, "tcp", req.Addr)
	if err != nil {
		cs.s.opt.Metrics.Failure("dial", err)
		status := dialStatus(err)
		if errors.Is(err, acl.ErrDenied) {
			status = protocol.StatusNotAllowed
		} else if m := cs.s.opt.Metrics; m != nil {
			m.DialErrors.Inc()
		}
		_ = protocol.WriteReply(str, status, 0)
		return
	}
	defer remote.Close()
	useComp := cs.s.opt.Compression && req.Flags&protocol.FlagCompress != 0
	if useComp {
		lease, ok := cs.s.codecs.TryAcquire()
		if ok {
			defer lease.Release()
		} else {
			useComp = false
			cs.s.opt.Metrics.CodecFallback()
		}
	}
	var flags byte
	if useComp {
		flags = protocol.FlagCompress
	}
	if err := protocol.WriteReply(str, protocol.StatusOK, flags); err != nil {
		return
	}
	unbind()
	if ctx.Err() != nil {
		cancel()
		finished = true
		return
	}
	cancel()
	finished = true
	_ = str.SetDeadline(time.Time{})
	if m := cs.s.opt.Metrics; m != nil {
		m.StreamsTotal.Inc()
		m.ActiveStreams.Inc()
		defer m.ActiveStreams.Dec()
	}
	cs.pipe(str, remote, useComp)
}

// pipe preserves normal half-closes and joins both directions. An actual copy
// error or tunnel cancellation aborts both halves so no blocked worker survives.
func (cs *connState) pipe(str tunnel.Stream, remote net.Conn, useComp bool) {
	results := make(chan error, 2)
	stop := context.AfterFunc(cs.conn.Context(), func() { tunnel.Abort(str); remote.Close() })
	defer stop()
	m := cs.s.opt.Metrics
	go func() {
		var err error
		if useComp {
			_, err = compress.Decopy(m.Writer(remote, "up"), str)
		} else {
			_, err = io.Copy(m.Writer(remote, "up"), str)
		}
		if err == nil {
			if cw, ok := remote.(interface{ CloseWrite() error }); ok {
				err = cw.CloseWrite()
			}
		}
		results <- err
	}()
	go func() {
		var err error
		if useComp {
			_, err = compress.CopyObserved(str, remote, func(n int) { m.AddDown(int64(n)) }, m.Compression)
		} else {
			_, err = io.Copy(m.Writer(str, "down"), remote)
		}
		if err == nil {
			err = str.Close()
		}
		results <- err
	}()
	for range 2 {
		if err := <-results; err != nil {
			m.Failure("relay", err)
			tunnel.Abort(str)
			remote.Close()
		}
	}
}
func dialStatus(err error) byte {
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return protocol.StatusHostUnreach
	}
	return protocol.StatusConnRefused
}
