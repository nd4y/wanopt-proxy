// Package server implements the egress side of the tunnel: it accepts QUIC
// connections, authenticates them, enforces an access-control policy, and
// relays TCP streams and UDP datagrams out to their real destinations.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/quic-go/quic-go"

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
	MaxStreamRecvWindow uint64
	MaxConnRecvWindow   uint64
	Log                 *slog.Logger
}

// Server relays authenticated tunnel traffic to the internet.
type Server struct {
	opt     Options
	tlsConf *tls.Config
	log     *slog.Logger
}

// New builds a Server from Options.
func New(opt Options) *Server {
	if opt.IdleTimeout <= 0 {
		opt.IdleTimeout = 60 * time.Second
	}
	if opt.ALPN == "" {
		opt.ALPN = tunnel.DefaultALPN
	}
	return &Server{
		opt:     opt,
		tlsConf: tunnel.ServerTLSConfig(opt.Cert, opt.ALPN),
		log:     opt.Log,
	}
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

// listen returns an accept function abstracting over the early/normal listener.
func (s *Server) listen(addr string, conf *quic.Config) (func(context.Context) (quic.Connection, error), func(), error) {
	if s.opt.Allow0RTT {
		ln, err := quic.ListenAddrEarly(addr, s.tlsConf, conf)
		if err != nil {
			return nil, nil, err
		}
		return func(ctx context.Context) (quic.Connection, error) {
			c, err := ln.Accept(ctx)
			return c, err // EarlyConnection satisfies Connection
		}, func() { ln.Close() }, nil
	}
	ln, err := quic.ListenAddr(addr, s.tlsConf, conf)
	if err != nil {
		return nil, nil, err
	}
	return ln.Accept, func() { ln.Close() }, nil
}

func (s *Server) handleConn(ctx context.Context, conn quic.Connection) {
	peer := conn.RemoteAddr().String()
	defer conn.CloseWithError(0, "")

	ctrl, err := conn.AcceptStream(ctx)
	if err != nil {
		return
	}
	tlsState := conn.ConnectionState().TLS
	exporter, err := tlsState.ExportKeyingMaterial(tunnel.ExporterLabel, nil, 32)
	if err != nil {
		s.log.Warn("exporter unavailable", "peer", peer, "err", err)
		return
	}
	if err := tunnel.ServerAuth(ctrl, s.opt.PSK, exporter); err != nil {
		s.log.Warn("auth rejected", "peer", peer, "err", err)
		conn.CloseWithError(1, "auth failed")
		return
	}
	s.log.Info("client authenticated", "peer", peer, "0rtt", conn.ConnectionState().Used0RTT)
	if s.opt.Metrics != nil {
		s.opt.Metrics.Connections.Inc()
		defer s.opt.Metrics.Connections.Dec()
		if conn.ConnectionState().Used0RTT {
			s.opt.Metrics.ZeroRTT.Inc()
		}
	}

	nat := newUDPNAT(conn, s.opt.ACL, s.log)
	defer nat.close()
	go s.serveDatagrams(ctx, conn, nat)
	go heartbeatEcho(ctrl)

	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go s.handleStream(stream)
	}
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

func (s *Server) handleStream(stream quic.Stream) {
	defer stream.Close()
	req, err := protocol.ReadStreamRequest(stream)
	if err != nil {
		return
	}
	if req.Cmd != protocol.CmdTCPConnect {
		protocol.WriteReply(stream, protocol.StatusGeneralErr, 0)
		return
	}
	if !s.opt.ACL.Allowed(req.Addr) {
		s.log.Debug("blocked by ACL", "target", req.Addr.String())
		protocol.WriteReply(stream, protocol.StatusNotAllowed, 0)
		return
	}

	target := req.Addr.String()
	dialCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var d net.Dialer
	remote, err := d.DialContext(dialCtx, "tcp", target)
	if err != nil {
		s.log.Debug("dial failed", "target", target, "err", err)
		if s.opt.Metrics != nil {
			s.opt.Metrics.DialErrors.Inc()
		}
		protocol.WriteReply(stream, dialStatus(err), 0)
		return
	}
	defer remote.Close()

	useComp := s.opt.Compression && req.Flags&protocol.FlagCompress != 0
	var negFlags byte
	if useComp {
		negFlags |= protocol.FlagCompress
	}
	if err := protocol.WriteReply(stream, protocol.StatusOK, negFlags); err != nil {
		return
	}
	if s.opt.Metrics != nil {
		s.opt.Metrics.StreamsTotal.Inc()
		s.opt.Metrics.ActiveStreams.Inc()
		defer s.opt.Metrics.ActiveStreams.Dec()
	}

	s.pipe(stream, remote, useComp)
}

// pipe bridges the QUIC stream and the remote TCP connection. When compression
// is negotiated, the egress (remote->client) direction is compressed and the
// ingress (client->remote) direction is decompressed.
func (s *Server) pipe(stream quic.Stream, remote net.Conn, useComp bool) {
	done := make(chan struct{}, 2)
	// client -> remote
	go func() {
		var n int64
		if useComp {
			n, _ = compress.Decopy(remote, stream)
		} else {
			n, _ = io.Copy(remote, stream)
		}
		if tc, ok := remote.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		if s.opt.Metrics != nil {
			s.opt.Metrics.AddUp(n)
		}
		done <- struct{}{}
	}()
	// remote -> client
	go func() {
		var n int64
		if useComp {
			n, _ = compress.Copy(stream, remote)
		} else {
			n, _ = io.Copy(stream, remote)
		}
		stream.Close()
		if s.opt.Metrics != nil {
			s.opt.Metrics.AddDown(n)
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
