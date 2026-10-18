// Package client maintains one authenticated HTTP/3 tunnel with bounded queues.
package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"wanopt/internal/admission"
	"wanopt/internal/metrics"
	"wanopt/internal/protocol"
	"wanopt/internal/tunnel"
)

const (
	initialBackoff    = 500 * time.Millisecond
	maxBackoff        = 30 * time.Second
	heartbeatInterval = 10 * time.Second
	heartbeatTimeout  = 15 * time.Second
)

var (
	ErrCapacity = errors.New("tunnel request capacity reached")
	ErrClosed   = errors.New("tunnel client is closed")
)

type Options struct {
	CongestionControl                      string
	MaxActiveStreams, MaxCompressedStreams int
	DisableSessionResumption               bool
	Server                                 string
	PSK                                    []byte
	Pin                                    string
	NextPin                                string
	NextPinExpires                         time.Time
	ALPN                                   string
	IdleTimeout                            time.Duration
	HandshakeTimeout                       time.Duration
	RequestTimeout                         time.Duration
	MaxPendingRequests                     int
	MaxUDPSessions                         int
	// Enable0RTT is a deprecated compatibility field. TLS session resumption is
	// always enabled, but no authentication or application data uses 0-RTT.
	Enable0RTT          bool
	Compression         bool
	Metrics             *metrics.Metrics
	MaxStreamRecvWindow uint64
	MaxConnRecvWindow   uint64
	Log                 *slog.Logger
}

type liveConn struct {
	conn *quic.Conn
	h3   *http3.ClientConn
}
type Client struct {
	opt            Options
	tlsConf        *tls.Config
	quicConf       *quic.Config
	mu             sync.Mutex
	live           *liveConn
	ready          chan struct{}
	stopped        bool
	running        atomic.Bool
	pending        chan struct{}
	active, codecs *admission.Budget
	sessionSeq     atomic.Uint64
	udpMu          sync.Mutex
	udpRoutes      map[uint64]*UDPSession
}

func New(opt Options) *Client {
	if opt.IdleTimeout <= 0 {
		opt.IdleTimeout = 60 * time.Second
	}
	if opt.HandshakeTimeout <= 0 {
		opt.HandshakeTimeout = 10 * time.Second
	}
	if opt.RequestTimeout <= 0 {
		opt.RequestTimeout = 15 * time.Second
	}
	if opt.MaxPendingRequests <= 0 {
		opt.MaxPendingRequests = 256
	}
	if opt.MaxUDPSessions <= 0 {
		opt.MaxUDPSessions = 128
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
	opt.Metrics.Controller(opt.CongestionControl)
	var sessionCache tls.ClientSessionCache
	if !opt.DisableSessionResumption {
		sessionCache = tls.NewLRUClientSessionCache(32)
	}
	return &Client{active: admission.New(opt.MaxActiveStreams, opt.Metrics.BudgetChange(false)), codecs: admission.New(opt.MaxCompressedStreams, opt.Metrics.BudgetChange(true)), opt: opt, tlsConf: tunnel.ClientTLSConfigWithRotation(opt.Pin, opt.NextPin, opt.NextPinExpires, opt.ALPN, sessionCache),
		quicConf: tunnel.NewQUICConfig(tunnel.QUICOptions{CongestionControl: opt.CongestionControl, EnableDatagrams: true, IdleTimeout: opt.IdleTimeout, HandshakeTimeout: opt.HandshakeTimeout,
			MaxStreamRecvWindow: opt.MaxStreamRecvWindow, MaxConnRecvWindow: opt.MaxConnRecvWindow, MaxIncomingStreams: -1, TokenStore: quic.NewLRUTokenStore(8, 8)}),
		ready: make(chan struct{}), pending: make(chan struct{}, opt.MaxPendingRequests), udpRoutes: make(map[uint64]*UDPSession)}
}
func (c *Client) Metrics() *metrics.Metrics { return c.opt.Metrics }
func (c *Client) CompressionEnabled() bool  { return c.opt.Compression }

// Run is called once. It joins the datagram dispatcher before reconnecting and
// wakes pending operations when it stops. Existing TCP streams fail on reconnect.
func (c *Client) Run(ctx context.Context) {
	if !c.running.CompareAndSwap(false, true) {
		return
	}
	defer func() {
		c.mu.Lock()
		c.stopped = true
		c.live = nil
		close(c.ready)
		c.ready = make(chan struct{})
		c.mu.Unlock()
		c.udpMu.Lock()
		for _, s := range c.udpRoutes {
			s.stop()
		}
		clear(c.udpRoutes)
		c.udpMu.Unlock()
	}()
	backoff := initialBackoff
	for ctx.Err() == nil {
		live, ctrl, err := c.dialAuth(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.opt.Metrics.Failure("connect", err)
			c.opt.Log.Warn("tunnel connect failed", "err", err)
		} else {
			backoff = initialBackoff
			c.setConn(live)
			finishMetrics := c.opt.Metrics.TrackConnection(live.conn)
			dgDone := make(chan struct{})
			go func() { defer close(dgDone); c.dispatchDatagrams(live.conn) }()
			c.runHeartbeat(ctx, live.conn, ctrl)
			c.clearConn(live)
			live.conn.CloseWithError(0, "")
			<-dgDone
			finishMetrics()
			if ctx.Err() != nil {
				return
			}
		}
		c.opt.MetricsReconnect()
		jitter := time.Duration(rand.Int64N(int64(backoff/2) + 1))
		timer := time.NewTimer(backoff/2 + jitter)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

func (o Options) MetricsReconnect() {
	if o.Metrics != nil {
		o.Metrics.Reconnects.Inc()
	}
}

func (c *Client) dialAuth(ctx context.Context) (*liveConn, *http3.RequestStream, error) {
	ctx, cancel := context.WithTimeout(ctx, c.opt.HandshakeTimeout)
	defer cancel()
	conn, err := quic.DialAddr(ctx, c.opt.Server, c.tlsConf, c.quicConf)
	if err != nil {
		return nil, nil, fmt.Errorf("dial tunnel: %w", err)
	}
	succeeded := false
	defer func() {
		if !succeeded {
			conn.CloseWithError(1, "authentication failed")
		}
	}()
	live := &liveConn{conn: conn, h3: (&http3.Transport{EnableDatagrams: false, DisableCompression: true, MaxResponseHeaderBytes: 16 << 10}).NewClientConn(conn)}
	ctrl, err := openTunnelStream(ctx, live, tunnel.ControlAuthority)
	if err != nil {
		return nil, nil, err
	}
	unbind := tunnel.BindContext(ctx, ctrl)
	defer unbind()
	tlsState := conn.ConnectionState().TLS
	exporter, err := tlsState.ExportKeyingMaterial(tunnel.ExporterLabel, nil, 32)
	if err == nil {
		err = tunnel.ClientAuth(ctrl, c.opt.PSK, exporter)
	}
	if err != nil {
		return nil, nil, err
	}
	unbind()
	if err = ctx.Err(); err != nil {
		return nil, nil, err
	}
	_ = ctrl.SetDeadline(time.Time{})
	succeeded = true
	c.opt.Log.Info("tunnel established", "server", c.opt.Server, "resumed", tlsState.DidResume)
	return live, ctrl, nil
}

func openTunnelStream(ctx context.Context, live *liveConn, authority string) (*http3.RequestStream, error) {
	str, err := live.h3.OpenRequestStream(ctx)
	if err != nil {
		return nil, err
	}
	unbind := tunnel.BindContext(ctx, str)
	defer unbind()
	ok := false
	defer func() {
		if !ok {
			tunnel.Abort(str)
		}
	}()
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Host: authority}, Host: authority,
		Header: http.Header{tunnel.VersionHeader: []string{strconv.Itoa(int(protocol.Version))}}}
	if err = str.SendRequestHeader(req); err != nil {
		return nil, err
	}
	resp, err := str.ReadResponse()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tunnel CONNECT status %d", resp.StatusCode)
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	ok = true
	return str, nil
}

func (c *Client) runHeartbeat(ctx context.Context, conn *quic.Conn, ctrl *http3.RequestStream) {
	stop := context.AfterFunc(ctx, func() { conn.CloseWithError(0, "") })
	defer stop()
	interval := min(heartbeatInterval, c.opt.IdleTimeout/3)
	timeout := min(heartbeatTimeout, c.opt.IdleTimeout/2)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var b [1]byte
	for {
		select {
		case <-ctx.Done():
			return
		case <-conn.Context().Done():
			return
		case <-ticker.C:
		}
		_ = ctrl.SetDeadline(time.Now().Add(timeout))
		if _, err := ctrl.Write([]byte{protocol.CtrlPing}); err != nil {
			return
		}
		if _, err := io.ReadFull(ctrl, b[:]); err != nil || b[0] != protocol.CtrlPong {
			return
		}
	}
}

func (c *Client) setConn(live *liveConn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.live = live
	close(c.ready)
	c.ready = make(chan struct{})
}
func (c *Client) clearConn(live *liveConn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.live == live {
		c.live = nil
	}
}
func (c *Client) getConn(ctx context.Context) (*liveConn, error) {
	for {
		c.mu.Lock()
		live, ready, stopped := c.live, c.ready, c.stopped
		c.mu.Unlock()
		if stopped {
			return nil, ErrClosed
		}
		if live != nil {
			select {
			case <-live.conn.Context().Done():
			default:
				return live, nil
			}
		}
		select {
		case <-ready:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// Stream implements net.Conn. CloseWrite sends FIN while keeping replies readable.
// Close releases both directions; it must not be substituted for a normal half-close.
type Stream struct {
	*http3.RequestStream
	Compressed    bool
	local, remote net.Addr
	closeOnce     sync.Once
	writeClosed   atomic.Bool
	release       func()
	stopRelease   func() bool
}

var _ net.Conn = (*Stream)(nil)

func (s *Stream) LocalAddr() net.Addr  { return s.local }
func (s *Stream) RemoteAddr() net.Addr { return s.remote }
func (s *Stream) CloseWrite() error {
	if s.writeClosed.CompareAndSwap(false, true) {
		return s.RequestStream.Close()
	}
	return nil
}
func (s *Stream) Close() error {
	s.closeOnce.Do(func() {
		if s.stopRelease != nil {
			s.stopRelease()
		}
		if s.release != nil {
			s.release()
		}
		s.CancelRead(0)
		if !s.writeClosed.Load() {
			s.CancelWrite(0)
		}
	})
	return nil
}

func (c *Client) OpenTCP(ctx context.Context, target protocol.Address, wantCompress bool) (_ *Stream, resultErr error) {
	start := time.Now()
	defer func() { c.opt.Metrics.Failure("open", resultErr); c.opt.Metrics.Observe("open", time.Since(start)) }()
	lease, admitted := c.active.TryAcquire()
	if !admitted {
		c.opt.Metrics.Rejected("stream")
		return nil, ErrCapacity
	}
	handedOff := false
	var codec *admission.Lease
	defer func() {
		if !handedOff {
			lease.Release()
			codec.Release()
		}
	}()
	select {
	case c.pending <- struct{}{}:
		defer func() { <-c.pending }()
	default:
		c.opt.Metrics.Rejected("pending")
		return nil, ErrCapacity
	}
	ctx, cancel := context.WithTimeout(ctx, c.opt.RequestTimeout)
	defer cancel()
	live, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	str, err := openTunnelStream(ctx, live, tunnel.ProxyAuthority)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			tunnel.Abort(str)
		}
	}()
	unbind := tunnel.BindContext(ctx, str)
	defer unbind()
	req := protocol.StreamRequest{Cmd: protocol.CmdTCPConnect, Addr: target}
	if wantCompress && c.opt.Compression {
		var acquired bool
		codec, acquired = c.codecs.TryAcquire()
		if acquired {
			req.Flags = protocol.FlagCompress
		} else {
			c.opt.Metrics.CodecFallback()
		}
		// flags are set only when a codec lease exists.
	}
	if _, err = req.WriteTo(str); err != nil {
		return nil, err
	}
	status, flags, err := protocol.ReadReply(str)
	if err != nil {
		return nil, err
	}
	if status != protocol.StatusOK {
		return nil, &DialError{Status: status}
	}
	unbind()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	_ = str.SetDeadline(time.Time{})
	if flags & ^byte(protocol.FlagCompress) != 0 || (flags&protocol.FlagCompress != 0 && req.Flags&protocol.FlagCompress == 0) {
		return nil, errors.New("tunnel: unrequested stream flags")
	}
	if flags&protocol.FlagCompress == 0 {
		codec.Release()
		codec = nil
	}
	var once sync.Once
	release := func() { once.Do(func() { codec.Release(); lease.Release() }) }
	result := &Stream{RequestStream: str, Compressed: flags&protocol.FlagCompress != 0, local: live.conn.LocalAddr(), remote: live.conn.RemoteAddr(), release: release}
	result.stopRelease = context.AfterFunc(live.conn.Context(), release)
	handedOff = true
	ok = true
	return result, nil
}

type DialError struct{ Status byte }

func (e *DialError) Error() string { return fmt.Sprintf("server dial failed (status %d)", e.Status) }

type UDPSession struct {
	c    *Client
	id   uint64
	recv chan protocol.Datagram
	done chan struct{}
	once sync.Once
}

func (c *Client) NewUDPSession() (*UDPSession, error) {
	c.udpMu.Lock()
	defer c.udpMu.Unlock()
	c.mu.Lock()
	stopped := c.stopped
	c.mu.Unlock()
	if stopped {
		return nil, ErrClosed
	}
	if len(c.udpRoutes) >= c.opt.MaxUDPSessions {
		return nil, ErrCapacity
	}
	s := &UDPSession{c: c, id: c.sessionSeq.Add(1), recv: make(chan protocol.Datagram, 32), done: make(chan struct{})}
	c.udpRoutes[s.id] = s
	return s, nil
}
func (s *UDPSession) Send(ctx context.Context, target protocol.Address, payload []byte) error {
	if err := target.Validate(); err != nil {
		s.c.opt.Metrics.UDPDrop("invalid")
		return err
	}
	if target.Port == 0 {
		s.c.opt.Metrics.UDPDrop("invalid")
		return errors.New("UDP destination port must be nonzero")
	}
	select {
	case <-s.done:
		s.c.opt.Metrics.UDPDrop("closed")
		return ErrClosed
	default:
	}
	if len(payload) > protocol.MaxUDPPayload {
		s.c.opt.Metrics.UDPDrop("size")
		return errors.New("UDP payload exceeds supported size")
	}
	ctx, cancel := context.WithTimeout(ctx, s.c.opt.RequestTimeout)
	defer cancel()
	live, err := s.c.getConn(ctx)
	if err != nil {
		s.c.opt.Metrics.UDPDrop("send")
		return err
	}
	data := protocol.EncodeDatagram(s.id, target, payload)
	if len(data) > protocol.MaxUDPDatagramSize {
		s.c.opt.Metrics.UDPDrop("size")
		return errors.New("UDP envelope exceeds supported size")
	}
	if err = live.conn.SendDatagram(data); err != nil {
		s.c.opt.Metrics.UDPDrop("send")
		return err
	}
	s.c.opt.Metrics.UDPDatagram("up", len(payload))
	return nil
}
func (s *UDPSession) Recv() <-chan protocol.Datagram { return s.recv }
func (s *UDPSession) Done() <-chan struct{}          { return s.done }
func (s *UDPSession) stop()                          { s.once.Do(func() { close(s.done) }) }
func (s *UDPSession) Close() {
	s.c.udpMu.Lock()
	delete(s.c.udpRoutes, s.id)
	s.stop()
	s.c.udpMu.Unlock()
}
func (c *Client) dispatchDatagrams(conn *quic.Conn) {
	for {
		data, err := conn.ReceiveDatagram(conn.Context())
		if err != nil {
			return
		}
		dg, err := protocol.DecodeDatagram(data)
		if err != nil {
			c.opt.Metrics.UDPDrop("invalid")
			continue
		}
		c.udpMu.Lock()
		s := c.udpRoutes[dg.SessionID]
		c.udpMu.Unlock()
		if s == nil {
			c.opt.Metrics.UDPDrop("closed")
			continue
		}
		select {
		case <-s.done:
			continue
		default:
		}
		select {
		case s.recv <- dg:
			c.opt.Metrics.UDPDatagram("down", len(dg.Payload))
		default:
			c.opt.Metrics.UDPDrop("queue")
		}
	}
}
