package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"wanopt/internal/client"
	"wanopt/internal/protocol"
)

func (p *Proxy) ServeHTTP(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	p.log.Info("HTTP proxy listening", "addr", ln.Addr())
	return p.serveHTTP(ctx, ln)
}

func (p *Proxy) serveHTTP(parent context.Context, ln net.Listener) error {
	ctx, cancel := context.WithCancel(parent)
	tr, closeTransport := p.httpTransport(ctx)
	handler := p.httpHandler(tr)
	var workers sync.WaitGroup
	var gate sync.Mutex
	stopping := false
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gate.Lock()
			if stopping {
				gate.Unlock()
				return
			}
			workers.Add(1)
			gate.Unlock()
			defer workers.Done()
			handler.ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: p.opt.HandshakeTimeout, IdleTimeout: p.opt.IdleTimeout, MaxHeaderBytes: p.opt.MaxHeaderBytes,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	stop := context.AfterFunc(ctx, func() { srv.Close(); p.closeConnections() })
	defer func() {
		gate.Lock()
		stopping = true
		gate.Unlock()
		cancel()
		srv.Close()
		p.closeConnections()
		closeTransport()
		workers.Wait()
		stop()
	}()
	err := srv.Serve(&limitedListener{Listener: ln, p: p})
	if errors.Is(err, http.ErrServerClosed) || ctx.Err() != nil {
		return nil
	}
	return err
}

// The transport owns a bounded pool of idle and active outgoing streams. Closing
// a listener cancels pending dials and closes the entire pool before returning.
func (p *Proxy) httpTransport(serverCtx context.Context) (*http.Transport, func()) {
	var mu sync.Mutex
	var dials sync.WaitGroup
	conns := make(map[*trackedConn]struct{})
	closing := false
	idle := p.opt.MaxConnections
	if p.c != nil {
		idle = min(idle, p.c.HTTPIdleCapacity())
	}
	tr := &http.Transport{DisableKeepAlives: idle == 0,
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			mu.Lock()
			if closing {
				mu.Unlock()
				return nil, net.ErrClosed
			}
			dials.Add(1)
			mu.Unlock()
			defer dials.Done()
			ctx, cancel := context.WithCancel(ctx)
			stop := context.AfterFunc(serverCtx, cancel)
			defer cancel()
			defer stop()
			a, err := protocol.ParseAddress(addr)
			if err != nil || a.Port == 0 {
				return nil, errors.New("proxy: invalid HTTP target")
			}
			s, compressed, err := p.dialStream(ctx, a, p.compressionEnabled())
			if err != nil {
				p.countDialErr(err)
				return nil, err
			}
			if compressed {
				s = newCompressedHTTPConn(s, p.m.Compression)
			}
			c := net.Conn(&idleConn{Conn: s, timeout: p.opt.IdleTimeout})
			if p.m != nil {
				p.m.StreamsTotal.Inc()
				p.m.ActiveStreams.Inc()
				c = &meteredConn{Conn: c, p: p}
			}
			tracked := &trackedConn{Conn: c}
			tracked.release = func() { mu.Lock(); delete(conns, tracked); mu.Unlock() }
			mu.Lock()
			if closing {
				mu.Unlock()
				tracked.Close()
				return nil, net.ErrClosed
			}
			conns[tracked] = struct{}{}
			mu.Unlock()
			return tracked, nil
		},
		MaxIdleConns: max(1, idle), MaxIdleConnsPerHost: max(1, min(16, idle)), MaxConnsPerHost: p.opt.MaxConnections,
		IdleConnTimeout: p.opt.IdleTimeout, ResponseHeaderTimeout: p.opt.HTTPResponseHeaderTimeout,
		ExpectContinueTimeout: time.Second, MaxResponseHeaderBytes: int64(p.opt.MaxHeaderBytes), DisableCompression: true, ForceAttemptHTTP2: false,
	}
	closeAll := func() {
		mu.Lock()
		closing = true
		list := make([]*trackedConn, 0, len(conns))
		for c := range conns {
			list = append(list, c)
		}
		mu.Unlock()
		for _, c := range list {
			c.Close()
		}
		tr.CloseIdleConnections()
		dials.Wait()
	}
	return tr, closeAll
}

type meteredConn struct {
	net.Conn
	p    *Proxy
	once sync.Once
}

func (c *meteredConn) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	if n > 0 {
		c.p.m.AddDown(int64(n))
	}
	return n, e
}
func (c *meteredConn) Write(b []byte) (int, error) {
	n, e := c.Conn.Write(b)
	if n > 0 {
		c.p.m.AddUp(int64(n))
	}
	return n, e
}
func (c *meteredConn) Close() error {
	e := c.Conn.Close()
	c.once.Do(func() { c.p.m.ActiveStreams.Dec() })
	return e
}
func (c *meteredConn) CloseWrite() error { return closeWrite(c.Conn) }

func (p *Proxy) httpHandler(tr *http.Transport) http.Handler {
	forward := &httputil.ReverseProxy{
		Rewrite:   func(pr *httputil.ProxyRequest) { pr.Out.Host = pr.Out.URL.Host; pr.Out.Close = false },
		Transport: tr,
		ModifyResponse: func(resp *http.Response) error {
			if body, ok := resp.Request.Body.(*progressBody); ok && !body.finished() {
				// A response to an incomplete upload cannot reuse this connection.
				resp.Header.Set("Connection", "close")
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			rejectHTTP(w, r, "upstream unavailable", capacityHTTPStatus(err))
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		// Apply cancellation and progress bounds before every validation/error
		// path, not just successfully forwarded requests.
		rc.EnableFullDuplex()
		w = &progressResponseWriter{ResponseWriter: w, controller: rc, timeout: p.opt.IdleTimeout}
		if r.Body != nil && r.Body != http.NoBody {
			body := &progressBody{ReadCloser: r.Body, controller: rc, timeout: p.opt.IdleTimeout}
			r.Body = body
			defer body.Close()
		}
		if r.Method == http.MethodConnect {
			p.httpConnect(w, r)
			return
		}
		if r.URL.Scheme != "http" || r.URL.Host == "" || r.URL.User != nil {
			rejectHTTP(w, r, "absolute http URL required", http.StatusBadRequest)
			return
		}
		a, err := protocol.ParseAddress(ensurePort(r.URL.Host, "80"))
		if err != nil || a.Port == 0 {
			rejectHTTP(w, r, "invalid target", http.StatusBadRequest)
			return
		}
		forward.ServeHTTP(w, r)
	})
}

func rejectHTTP(w http.ResponseWriter, r *http.Request, message string, status int) {
	if r.Body != nil && r.Body != http.NoBody {
		w.Header().Set("Connection", "close")
	}
	http.Error(w, message, status)
}

type progressBody struct {
	io.ReadCloser
	controller *http.ResponseController
	timeout    time.Duration
	mu         sync.Mutex
	closed     bool
	eof        bool
}

func (b *progressBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return 0, http.ErrBodyReadAfterClose
	}
	b.controller.SetReadDeadline(time.Now().Add(b.timeout))
	b.mu.Unlock()
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		b.mu.Lock()
		b.eof = true
		if !b.closed {
			b.controller.SetReadDeadline(time.Time{})
		}
		b.mu.Unlock()
	}
	return n, err
}
func (b *progressBody) finished() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.eof }
func (b *progressBody) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	// http.Transport can close a request body while its read is still blocked.
	// Expire only reads; the completed response can still be flushed to the client.
	if !b.eof {
		b.controller.SetReadDeadline(time.Now())
	}
	b.mu.Unlock()
	return b.ReadCloser.Close()
}

type progressResponseWriter struct {
	http.ResponseWriter
	controller *http.ResponseController
	timeout    time.Duration
}

func (w *progressResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *progressResponseWriter) Write(p []byte) (int, error) {
	w.controller.SetWriteDeadline(time.Now().Add(w.timeout))
	return w.ResponseWriter.Write(p)
}

func (p *Proxy) httpConnect(w http.ResponseWriter, r *http.Request) {
	a, err := protocol.ParseAddress(ensurePort(r.Host, "443"))
	if err != nil || a.Port == 0 || (r.Body != nil && r.Body != http.NoBody) {
		rejectHTTP(w, r, "invalid CONNECT target", http.StatusBadRequest)
		return
	}
	remote, compressed, err := p.dialStream(r.Context(), a, p.compressionEnabled())
	if err != nil {
		p.countDialErr(err)
		rejectHTTP(w, r, "upstream unavailable", capacityHTTPStatus(err))
		return
	}
	defer remote.Close()
	conn, rw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(p.opt.HandshakeTimeout))
	if _, err = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err = rw.Flush(); err != nil {
		return
	}
	conn.SetDeadline(time.Time{})
	local := &idleConn{Conn: conn, timeout: p.opt.IdleTimeout}
	peer := &idleConn{Conn: remote, timeout: p.opt.IdleTimeout}
	// Preserve CONNECT bytes that arrived in the same packet as the headers.
	var reader io.Reader = local
	if rw.Reader.Buffered() > 0 {
		reader = io.MultiReader(io.LimitReader(rw.Reader, int64(rw.Reader.Buffered())), local)
	}
	p.relay(r.Context(), reader, local, peer, compressed)
}

func ensurePort(hostport, defaultPort string) string {
	if _, _, err := net.SplitHostPort(hostport); err == nil {
		return hostport
	}
	if strings.HasPrefix(hostport, "[") && strings.HasSuffix(hostport, "]") {
		host := strings.TrimSuffix(strings.TrimPrefix(hostport, "["), "]")
		if net.ParseIP(host) != nil {
			return net.JoinHostPort(host, defaultPort)
		}
	}
	if net.ParseIP(hostport) != nil {
		return net.JoinHostPort(hostport, defaultPort)
	}
	if !strings.Contains(hostport, ":") {
		return net.JoinHostPort(hostport, defaultPort)
	}
	return hostport
}

func capacityHTTPStatus(err error) int {
	if errors.Is(err, client.ErrCapacity) {
		return http.StatusServiceUnavailable
	}
	return http.StatusBadGateway
}
