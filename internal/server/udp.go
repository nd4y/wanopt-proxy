package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"wanopt/internal/protocol"
)

// udpIdleTimeout reclaims sockets for flows that have gone quiet.
const udpIdleTimeout = 60 * time.Second

// udpNAT maps (sessionID, target) pairs to outbound UDP sockets, much like a
// home router's NAT table, and forwards replies back over QUIC datagrams.
type udpNAT struct {
	conn quic.Connection
	log  *slog.Logger

	mu    sync.Mutex
	flows map[string]*udpFlow
}

type udpFlow struct {
	sock      *net.UDPConn
	sessionID uint64
	target    protocol.Address
	lastSeen  time.Time
}

func newUDPNAT(conn quic.Connection, log *slog.Logger) *udpNAT {
	return &udpNAT{conn: conn, log: log, flows: make(map[string]*udpFlow)}
}

func flowKey(sessionID uint64, target string) string {
	return fmt.Sprintf("%d|%s", sessionID, target)
}

// forward sends a client datagram's payload to its target, creating the
// outbound socket (and its reply pump) on first use.
func (n *udpNAT) forward(dg protocol.Datagram) {
	key := flowKey(dg.SessionID, dg.Addr.String())

	n.mu.Lock()
	f := n.flows[key]
	if f == nil {
		raddr, err := net.ResolveUDPAddr("udp", dg.Addr.String())
		if err != nil {
			n.mu.Unlock()
			return
		}
		sock, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			n.mu.Unlock()
			return
		}
		f = &udpFlow{sock: sock, sessionID: dg.SessionID, target: dg.Addr}
		n.flows[key] = f
		go n.pumpReplies(key, f)
	}
	f.lastSeen = time.Now()
	n.mu.Unlock()

	f.sock.Write(dg.Payload)
}

// pumpReplies reads datagrams from the outbound socket and ships them back to
// the client, tagged with the original session ID and source target.
func (n *udpNAT) pumpReplies(key string, f *udpFlow) {
	buf := make([]byte, 64*1024)
	for {
		f.sock.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		nr, err := f.sock.Read(buf)
		if err != nil {
			n.mu.Lock()
			if cur, ok := n.flows[key]; ok && cur == f && time.Since(f.lastSeen) >= udpIdleTimeout {
				delete(n.flows, key)
				f.sock.Close()
				n.mu.Unlock()
				return
			}
			n.mu.Unlock()
			// transient read error or still-active flow: keep going
			if nr == 0 {
				continue
			}
		}
		out := protocol.EncodeDatagram(f.sessionID, f.target, buf[:nr])
		if err := n.conn.SendDatagram(out); err != nil {
			n.log.Debug("send datagram failed", "err", err)
		}
	}
}

func (n *udpNAT) close() {
	n.mu.Lock()
	defer n.mu.Unlock()
	for k, f := range n.flows {
		f.sock.Close()
		delete(n.flows, k)
	}
}

// serveDatagrams reads incoming QUIC datagrams and forwards them via the NAT.
func (s *Server) serveDatagrams(ctx context.Context, conn quic.Connection, nat *udpNAT) {
	for {
		data, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		dg, err := protocol.DecodeDatagram(data)
		if err != nil {
			continue
		}
		nat.forward(dg)
	}
}
