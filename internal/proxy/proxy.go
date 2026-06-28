// Package proxy implements the local-facing SOCKS5 and HTTP proxy servers that
// hand traffic to the tunnel client.
package proxy

import (
	"io"
	"log/slog"

	"wanopt/internal/client"
	"wanopt/internal/compress"
	"wanopt/internal/metrics"
)

// Proxy serves local SOCKS5/HTTP listeners backed by a tunnel client.
type Proxy struct {
	c   *client.Client
	m   *metrics.Metrics
	log *slog.Logger
}

// New builds a Proxy around an established tunnel client.
func New(c *client.Client, log *slog.Logger) *Proxy {
	return &Proxy{c: c, m: c.Metrics(), log: log}
}

// closeWriter is implemented by net.TCPConn (CloseWrite) and used to half-close.
type closeWriter interface{ CloseWrite() error }

// relay bridges a local endpoint and a tunnel stream, applying adaptive
// compression in whichever direction was negotiated and counting payload bytes.
//
// localR/localW are the local side (a single net.Conn for SOCKS, or a buffered
// reader + conn for HTTP CONNECT). The client is the *sender* on the app->tunnel
// direction and the *receiver* on the tunnel->app direction.
func (p *Proxy) relay(localR io.Reader, localW io.Writer, ts *client.Stream) {
	if p.m != nil {
		p.m.StreamsTotal.Inc()
		p.m.ActiveStreams.Inc()
		defer p.m.ActiveStreams.Dec()
	}
	done := make(chan struct{}, 2)
	// app -> tunnel
	go func() {
		var n int64
		if ts.Compressed {
			n, _ = compress.Copy(ts, localR)
		} else {
			n, _ = io.Copy(ts, localR)
		}
		ts.Close()
		if p.m != nil {
			p.m.AddUp(n)
		}
		done <- struct{}{}
	}()
	// tunnel -> app
	go func() {
		var n int64
		if ts.Compressed {
			n, _ = compress.Decopy(localW, ts)
		} else {
			n, _ = io.Copy(localW, ts)
		}
		if cw, ok := localW.(closeWriter); ok {
			cw.CloseWrite()
		}
		if p.m != nil {
			p.m.AddDown(n)
		}
		done <- struct{}{}
	}()
	<-done
}
