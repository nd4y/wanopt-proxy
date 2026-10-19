// Package proxy implements bounded local SOCKS5 and HTTP proxy listeners.
package proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"wanopt/internal/client"
	"wanopt/internal/compress"
	"wanopt/internal/metrics"
	"wanopt/internal/protocol"
)

type Options struct {
	MaxConnections            int
	HandshakeTimeout          time.Duration
	IdleTimeout               time.Duration
	HTTPResponseHeaderTimeout time.Duration
	MaxHeaderBytes            int
}

func (o Options) defaults() Options {
	if o.MaxConnections <= 0 {
		o.MaxConnections = 256
	}
	if o.HandshakeTimeout <= 0 {
		o.HandshakeTimeout = 10 * time.Second
	}
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = 5 * time.Minute
	}
	if o.HTTPResponseHeaderTimeout <= 0 {
		o.HTTPResponseHeaderTimeout = 2 * time.Minute
	}
	if o.MaxHeaderBytes <= 0 {
		o.MaxHeaderBytes = 64 << 10
	}
	return o
}

// Proxy shares admission limits between both listeners.
type Proxy struct {
	c             *client.Client
	m             *metrics.Metrics
	log           *slog.Logger
	opt           Options
	slots         chan struct{}
	mu            sync.Mutex
	conns         map[*trackedConn]struct{}
	dialStream    func(context.Context, protocol.Address, bool) (net.Conn, bool, error)
	newUDPSession func() (udpSession, error)
}

func New(c *client.Client, log *slog.Logger) *Proxy { return NewWithOptions(c, log, Options{}) }

func NewWithOptions(c *client.Client, log *slog.Logger, opt Options) *Proxy {
	opt = opt.defaults()
	if log == nil {
		log = slog.Default()
	}
	p := &Proxy{c: c, log: log, opt: opt, slots: make(chan struct{}, opt.MaxConnections), conns: make(map[*trackedConn]struct{})}
	if c != nil {
		p.m = c.Metrics()
		p.newUDPSession = func() (udpSession, error) { return c.NewUDPSession() }
		p.dialStream = func(ctx context.Context, a protocol.Address, compression bool) (net.Conn, bool, error) {
			s, err := c.OpenTCP(ctx, a, compression)
			if err != nil {
				return nil, false, err
			}
			return s, s.Compressed, nil
		}
	}
	return p
}

func (p *Proxy) compressionEnabled() bool { return p.c != nil && p.c.CompressionEnabled() }

type trackedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
func (c *trackedConn) CloseWrite() error { return closeWrite(c.Conn) }

func (p *Proxy) track(c net.Conn) *trackedConn {
	select {
	case p.slots <- struct{}{}:
	default:
		c.Close()
		return nil
	}
	t := &trackedConn{Conn: c}
	t.release = func() { p.mu.Lock(); delete(p.conns, t); p.mu.Unlock(); <-p.slots }
	p.mu.Lock()
	p.conns[t] = struct{}{}
	p.mu.Unlock()
	return t
}
func (p *Proxy) closeConnections() {
	p.mu.Lock()
	list := make([]*trackedConn, 0, len(p.conns))
	for c := range p.conns {
		list = append(list, c)
	}
	p.mu.Unlock()
	for _, c := range list {
		c.Close()
	}
}

type limitedListener struct {
	net.Listener
	p *Proxy
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if t := l.p.track(c); t != nil {
			return t, nil
		}
	}
}

type closeWriter interface{ CloseWrite() error }

func closeWrite(c net.Conn) error {
	if cw, ok := c.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return errors.New("proxy: connection does not support half-close")
}

// Any successful traffic refreshes both directions, so a long one-way transfer
// does not time out merely because the reverse direction is quiet.
type idleConn struct {
	net.Conn
	timeout time.Duration
}

func (c *idleConn) touch() {
	if c.timeout > 0 {
		c.Conn.SetDeadline(time.Now().Add(c.timeout))
	}
}
func (c *idleConn) Read(b []byte) (int, error) {
	c.touch()
	n, e := c.Conn.Read(b)
	if n > 0 {
		c.touch()
	}
	return n, e
}
func (c *idleConn) Write(b []byte) (int, error) {
	c.touch()
	n, e := c.Conn.Write(b)
	if n > 0 {
		c.touch()
	}
	return n, e
}
func (c *idleConn) CloseWrite() error { return closeWrite(c.Conn) }

type countingWriter struct {
	w   io.Writer
	add func(int64)
}

func (w countingWriter) Write(b []byte) (int, error) {
	n, e := w.w.Write(b)
	if n > 0 {
		w.add(int64(n))
	}
	return n, e
}
func (p *Proxy) countWriter(w io.Writer, up bool) io.Writer {
	if p.m == nil {
		return w
	}
	add := p.m.AddDown
	if up {
		add = p.m.AddUp
	}
	return countingWriter{w: w, add: add}
}

// relay preserves TCP half-closes. Only errors or cancellation abort both
// directions; normal EOF waits for the other direction's trailing response.
func (p *Proxy) relay(ctx context.Context, localR io.Reader, local, remote net.Conn, compressed bool) {
	if p.m != nil {
		p.m.StreamsTotal.Inc()
		p.m.ActiveStreams.Inc()
		defer p.m.ActiveStreams.Dec()
	}
	abort := func() { local.Close(); remote.Close() }
	stop := context.AfterFunc(ctx, abort)
	defer stop()
	defer abort()
	done := make(chan error, 2)
	go func() {
		var err error
		if compressed {
			var onPayload func(int)
			if p.m != nil {
				onPayload = func(n int) { p.m.AddUp(int64(n)) }
			}
			_, err = compress.CopyObserved(remote, localR, onPayload, p.m.Compression)
		} else {
			_, err = io.Copy(p.countWriter(remote, true), localR)
		}
		if err == nil {
			err = closeWrite(remote)
		}
		done <- err
	}()
	go func() {
		var err error
		if compressed {
			_, err = compress.Decopy(p.countWriter(local, false), remote)
		} else {
			_, err = io.Copy(p.countWriter(local, false), remote)
		}
		if err == nil {
			err = closeWrite(local)
		}
		done <- err
	}()
	for range 2 {
		if err := <-done; err != nil {
			abort()
		}
	}
}
