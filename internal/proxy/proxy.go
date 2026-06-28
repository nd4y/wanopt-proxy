// Package proxy implements the local-facing SOCKS5 and HTTP proxy servers that
// hand traffic to the tunnel client.
package proxy

import (
	"io"
	"log/slog"
	"net"

	"github.com/quic-go/quic-go"

	"wanopt/internal/client"
)

// Proxy serves local SOCKS5/HTTP listeners backed by a tunnel client.
type Proxy struct {
	c   *client.Client
	log *slog.Logger
}

// New builds a Proxy around an established tunnel client.
func New(c *client.Client, log *slog.Logger) *Proxy {
	return &Proxy{c: c, log: log}
}

// relay copies bidirectionally between a local TCP conn and a tunnel stream.
func relay(local net.Conn, stream quic.Stream) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(stream, local)
		stream.Close()
		done <- struct{}{}
	}()
	go func() {
		io.Copy(local, stream)
		if tc, ok := local.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
}
