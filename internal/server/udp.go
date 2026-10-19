package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"wanopt/internal/acl"
	"wanopt/internal/metrics"
	"wanopt/internal/protocol"
)

// UDPOptions bounds work and memory per authenticated tunnel connection.
type UDPOptions struct {
	MaxFlows          int
	QueueSize         int
	Workers           int
	NewFlowsPerSecond int
	MaxPayload        int
	IdleTimeout       time.Duration
}

func (o UDPOptions) defaults() UDPOptions {
	if o.MaxFlows <= 0 {
		o.MaxFlows = 256
	}
	if o.QueueSize <= 0 {
		o.QueueSize = 128
	}
	if o.Workers <= 0 {
		o.Workers = 4
	}
	if o.Workers > o.MaxFlows {
		o.Workers = o.MaxFlows
	}
	if o.NewFlowsPerSecond <= 0 {
		o.NewFlowsPerSecond = 32
	}
	if o.MaxPayload <= 0 || o.MaxPayload > protocol.MaxUDPPayload {
		o.MaxPayload = protocol.MaxUDPPayload
	}
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = 60 * time.Second
	}
	return o
}

// datagramConn permits deterministic cancellation/limit tests without QUIC internals.
type datagramConn interface{ SendDatagram([]byte) error }
type udpNAT struct {
	conn      datagramConn
	resolver  *acl.Resolver
	auth      <-chan struct{}
	opt       UDPOptions
	metrics   *metrics.Metrics
	log       *slog.Logger
	ctx       context.Context
	cancel    context.CancelFunc
	queue     chan protocol.Datagram
	packets   chan udpPacket
	mu        sync.Mutex
	flows     map[string]*udpFlow
	pending   map[string]bool
	closed    bool
	tokens    float64
	tokenTime time.Time
	wg        sync.WaitGroup
	closeOnce sync.Once
}
type udpPacket struct {
	flow    *udpFlow
	payload []byte
}
type udpFlow struct {
	sock      *net.UDPConn
	sessionID uint64
	target    protocol.Address
	lastSeen  time.Time // guarded by NAT mutex
}

func newUDPNAT(ctx context.Context, conn *quic.Conn, resolver *acl.Resolver, auth <-chan struct{}, opt UDPOptions, m *metrics.Metrics, log *slog.Logger) *udpNAT {
	return makeUDPNAT(ctx, conn, resolver, auth, opt, m, log)
}
func makeUDPNAT(ctx context.Context, conn datagramConn, resolver *acl.Resolver, auth <-chan struct{}, opt UDPOptions, m *metrics.Metrics, log *slog.Logger) *udpNAT {
	opt = opt.defaults()
	ctx, cancel := context.WithCancel(ctx)
	if resolver == nil {
		resolver = acl.NewResolver(nil, 5*time.Second, 32)
	}
	n := &udpNAT{conn: conn, resolver: resolver, auth: auth, opt: opt, metrics: m, log: log, ctx: ctx, cancel: cancel, queue: make(chan protocol.Datagram, opt.QueueSize), packets: make(chan udpPacket, opt.QueueSize), flows: make(map[string]*udpFlow), pending: make(map[string]bool), tokens: float64(opt.NewFlowsPerSecond), tokenTime: time.Now()}
	n.wg.Add(opt.Workers + 1)
	go n.packetWorker()
	for i := 0; i < opt.Workers; i++ {
		go n.worker()
	}
	return n
}
func flowKey(sessionID uint64, target string) string { return fmt.Sprintf("%d|%s", sessionID, target) }
func (n *udpNAT) drop(reason string) {
	if n.metrics != nil {
		n.metrics.UDPDrop(reason)
	}
}
func (n *udpNAT) authenticated() bool {
	select {
	case <-n.auth:
		return true
	default:
		return false
	}
}

// forward is deliberately nonblocking: DNS or an unresponsive destination must
// never stall the connection-wide DATAGRAM receive loop. Queues own their bytes.
func (n *udpNAT) forward(dg protocol.Datagram) {
	if !n.authenticated() {
		n.drop("auth")
		return
	}
	if len(dg.Payload) > n.opt.MaxPayload {
		n.drop("size")
		return
	}
	if n.ctx.Err() != nil {
		n.drop("closed")
		return
	}
	dg.Payload = append([]byte(nil), dg.Payload...)
	n.mu.Lock()
	f := n.flows[flowKey(dg.SessionID, dg.Addr.String())]
	n.mu.Unlock()
	if f != nil {
		select {
		case n.packets <- udpPacket{flow: f, payload: dg.Payload}:
		default:
			n.drop("queue")
		}
		return
	}
	select {
	case n.queue <- dg:
	default:
		n.drop("queue")
	}
}

// Existing flows have a separate queue so slow DNS admissions never block them.
func (n *udpNAT) packetWorker() {
	defer n.wg.Done()
	for {
		select {
		case <-n.ctx.Done():
			return
		case packet := <-n.packets:
			if n.ctx.Err() == nil {
				n.write(packet.flow, packet.payload)
			}
		}
	}
}
func (n *udpNAT) worker() {
	defer n.wg.Done()
	for {
		select {
		case <-n.ctx.Done():
			return
		case dg := <-n.queue:
			if n.ctx.Err() == nil && n.authenticated() {
				n.send(dg)
			}
		}
	}
}
func (n *udpNAT) send(dg protocol.Datagram) {
	key := flowKey(dg.SessionID, dg.Addr.String())
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return
	}
	f := n.flows[key]
	if f != nil {
		f.lastSeen = time.Now()
		n.mu.Unlock()
		n.write(f, dg.Payload)
		return
	}
	if n.pending[key] {
		n.mu.Unlock()
		n.drop("queue")
		return
	}
	if len(n.flows)+len(n.pending) >= n.opt.MaxFlows {
		n.mu.Unlock()
		n.drop("limit")
		return
	}
	now := time.Now()
	n.tokens += now.Sub(n.tokenTime).Seconds() * float64(n.opt.NewFlowsPerSecond)
	if n.tokens > float64(n.opt.NewFlowsPerSecond) {
		n.tokens = float64(n.opt.NewFlowsPerSecond)
	}
	n.tokenTime = now
	if n.tokens < 1 {
		n.mu.Unlock()
		n.drop("rate")
		return
	}
	n.tokens--
	n.pending[key] = true
	n.mu.Unlock()
	// All DNS and network operations happen outside the flow table mutex.
	ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
	remote, err := n.resolver.DialContext(ctx, "udp", dg.Addr)
	cancel()
	n.mu.Lock()
	delete(n.pending, key)
	if err != nil || n.closed {
		n.mu.Unlock()
		if remote != nil {
			remote.Close()
		}
		if err != nil {
			if errors.Is(err, acl.ErrDenied) {
				n.drop("acl")
			} else if errors.Is(err, acl.ErrBusy) {
				n.drop("limit")
			} else {
				n.drop("dns")
			}
		}
		return
	}
	sock, ok := remote.(*net.UDPConn)
	if !ok {
		n.mu.Unlock()
		remote.Close()
		n.drop("send")
		return
	}
	f = &udpFlow{sock: sock, sessionID: dg.SessionID, target: dg.Addr, lastSeen: time.Now()}
	n.flows[key] = f
	if n.metrics != nil {
		n.metrics.UDPFlow(1)
	}
	n.wg.Add(1)
	n.mu.Unlock()
	go n.pumpReplies(key, f)
	n.write(f, dg.Payload)
}
func (n *udpNAT) write(f *udpFlow, payload []byte) {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return
	}
	f.lastSeen = time.Now()
	n.mu.Unlock()
	f.sock.SetWriteDeadline(time.Now().Add(2 * time.Second))
	sent, err := f.sock.Write(payload)
	if err != nil {
		n.drop("send")
		return
	}
	if n.metrics != nil {
		n.metrics.UDPDatagram("up", sent)
	}
}
func (n *udpNAT) pumpReplies(key string, f *udpFlow) {
	defer n.wg.Done()
	defer func() {
		f.sock.Close()
		n.mu.Lock()
		defer n.mu.Unlock()
		if n.flows[key] == f {
			delete(n.flows, key)
			if n.metrics != nil {
				n.metrics.UDPFlow(-1)
			}
		}
	}()
	// One extra byte detects datagrams larger than the supported payload limit.
	buf := make([]byte, n.opt.MaxPayload+1)
	for {
		n.mu.Lock()
		deadline := f.lastSeen.Add(n.opt.IdleTimeout)
		closed := n.closed
		n.mu.Unlock()
		if closed || n.ctx.Err() != nil {
			return
		}
		f.sock.SetReadDeadline(deadline)
		nr, err := f.sock.Read(buf)
		// Windows reports a truncated UDP read as WSAEMSGSIZE with nr equal
		// to the buffer length. Classify oversize first so it does not retire
		// an otherwise healthy flow; Linux returns the same bytes without error.
		if nr > n.opt.MaxPayload {
			n.drop("size")
			continue
		}
		if err != nil {
			if errors.Is(err, net.ErrClosed) || n.ctx.Err() != nil {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				n.mu.Lock()
				expired := time.Since(f.lastSeen) >= n.opt.IdleTimeout
				n.mu.Unlock()
				if !expired {
					continue
				}
			}
			// ICMP failures and other permanent errors retire the flow; never spin.
			return
		}

		n.mu.Lock()
		f.lastSeen = time.Now()
		n.mu.Unlock()
		out := protocol.EncodeDatagram(f.sessionID, f.target, buf[:nr])
		if len(out) > protocol.MaxUDPDatagramSize {
			n.drop("size")
			continue
		}
		if err := n.conn.SendDatagram(out); err != nil {
			n.drop("send")
			continue
		}
		if n.metrics != nil {
			n.metrics.UDPDatagram("down", nr)
		}
	}
}
func (n *udpNAT) close() {
	n.closeOnce.Do(func() {
		n.cancel()
		n.mu.Lock()
		n.closed = true
		for _, f := range n.flows {
			f.sock.Close()
		}
		n.mu.Unlock()
		n.wg.Wait()
	})
}

// Drain pre-auth traffic immediately; it must never be queued for replay after
// authentication. Only authenticated datagrams reach the bounded work queue.
func (s *Server) serveDatagrams(ctx context.Context, conn *quic.Conn, nat *udpNAT) {
	for {
		data, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		if !nat.authenticated() {
			nat.drop("auth")
			continue
		}
		if len(data) > protocol.MaxUDPDatagramSize {
			nat.drop("size")
			continue
		}
		dg, err := protocol.DecodeDatagram(data)
		if err != nil {
			nat.drop("invalid")
			continue
		}
		nat.forward(dg)
	}
}
