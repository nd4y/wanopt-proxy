// Package server implements the egress side of the tunnel: it accepts QUIC
// connections, authenticates them, and relays TCP streams and UDP datagrams out
// to their real destinations.
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

	"wanopt/internal/protocol"
	"wanopt/internal/tunnel"
)

// Server relays authenticated tunnel traffic to the internet.
type Server struct {
	psk         []byte
	tlsConf     *tls.Config
	idleTimeout time.Duration
	log         *slog.Logger
}

// New builds a Server. psk is the raw shared secret; cert is the server's TLS
// certificate.
func New(psk []byte, cert tls.Certificate, idleTimeout time.Duration, log *slog.Logger) *Server {
	if idleTimeout <= 0 {
		idleTimeout = 60 * time.Second
	}
	return &Server{
		psk:         psk,
		tlsConf:     tunnel.ServerTLSConfig(cert),
		idleTimeout: idleTimeout,
		log:         log,
	}
}

// ListenAndServe binds the QUIC listener and serves until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := quic.ListenAddr(addr, s.tlsConf, &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  s.idleTimeout,
		KeepAlivePeriod: s.idleTimeout / 2,
	})
	if err != nil {
		return err
	}
	defer ln.Close()
	s.log.Info("server listening", "addr", addr)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept(ctx)
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

func (s *Server) handleConn(ctx context.Context, conn quic.Connection) {
	peer := conn.RemoteAddr().String()
	defer conn.CloseWithError(0, "")

	// The first stream the client opens is the control stream; authenticate on it.
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
	if err := tunnel.ServerAuth(ctrl, s.psk, exporter); err != nil {
		s.log.Warn("auth rejected", "peer", peer, "err", err)
		conn.CloseWithError(1, "auth failed")
		return
	}
	s.log.Info("client authenticated", "peer", peer)

	// UDP relay state lives for the life of the connection.
	nat := newUDPNAT(conn, s.log)
	defer nat.close()
	go s.serveDatagrams(ctx, conn, nat)
	go drainControl(ctrl) // keep the control stream open; ignore its payload

	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go s.handleStream(stream, peer)
	}
}

// drainControl reads and discards control-stream bytes so the stream's flow
// control stays healthy; it returns when the client closes the stream.
func drainControl(s io.Reader) {
	io.Copy(io.Discard, s)
}

func (s *Server) handleStream(stream quic.Stream, peer string) {
	defer stream.Close()
	req, err := protocol.ReadStreamRequest(stream)
	if err != nil {
		return
	}
	if req.Cmd != protocol.CmdTCPConnect {
		protocol.WriteReply(stream, protocol.StatusGeneralErr)
		return
	}

	target := req.Addr.String()
	dialCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var d net.Dialer
	remote, err := d.DialContext(dialCtx, "tcp", target)
	if err != nil {
		s.log.Debug("dial failed", "target", target, "err", err)
		protocol.WriteReply(stream, dialStatus(err))
		return
	}
	defer remote.Close()
	if err := protocol.WriteReply(stream, protocol.StatusOK); err != nil {
		return
	}

	pipe(stream, remote)
}

// pipe copies bidirectionally between the QUIC stream and the remote TCP conn,
// finishing when either direction closes.
func pipe(stream quic.Stream, remote net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(remote, stream)
		if tc, ok := remote.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		io.Copy(stream, remote)
		stream.Close()
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
