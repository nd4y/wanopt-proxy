package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"time"

	"wanopt/internal/protocol"
)

type udpSession interface {
	Send(context.Context, protocol.Address, []byte) error
	Recv() <-chan protocol.Datagram
	Close()
}

var errUDPPayloadTooLarge = errors.New("socks: UDP payload exceeds supported datagram size")

// UDP ASSOCIATE is owned by its TCP control connection. The peer IP is fixed;
// an unspecified source port is pinned on the first valid datagram, never moved.
func (p *Proxy) socksUDPAssociate(parent context.Context, ctrl net.Conn, requested protocol.Address) {
	ctrl.SetDeadline(time.Now().Add(p.opt.HandshakeTimeout))
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	peerHost, _, err := net.SplitHostPort(ctrl.RemoteAddr().String())
	if err != nil {
		return
	}
	peerIP := net.ParseIP(peerHost)
	peerZone := ""
	if i := bytes.LastIndexByte([]byte(peerHost), '%'); i >= 0 {
		peerIP = net.ParseIP(peerHost[:i])
		peerZone = peerHost[i+1:]
	}
	if peerIP == nil {
		return
	}
	if !p.validUDPSource(ctx, requested, peerIP) {
		writeSOCKSReply(ctrl, repNotAllowed, net.IPv4zero, 0)
		return
	}
	session, err := p.newUDPSession()
	if err != nil {
		writeSOCKSReply(ctrl, repGeneralFailure, net.IPv4zero, 0)
		return
	}
	defer session.Close()
	host, _, err := net.SplitHostPort(ctrl.LocalAddr().String())
	if err != nil {
		return
	}
	laddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, "0"))
	if err != nil {
		return
	}
	network := "udp6"
	if laddr.IP.To4() != nil {
		network = "udp4"
	}
	sock, err := net.ListenUDP(network, laddr)
	if err != nil {
		writeSOCKSReply(ctrl, repGeneralFailure, net.IPv4zero, 0)
		return
	}
	defer sock.Close()
	bound := sock.LocalAddr().(*net.UDPAddr)
	ctrl.SetWriteDeadline(time.Now().Add(p.opt.HandshakeTimeout))
	if err = writeSOCKSReply(ctrl, repSuccess, bound.IP, uint16(bound.Port)); err != nil {
		return
	}
	ctrl.SetDeadline(time.Time{})
	stop := context.AfterFunc(ctx, func() { sock.Close(); ctrl.Close() })
	defer stop()
	var source atomic.Pointer[net.UDPAddr]
	var done = make(chan struct{}, 3)
	touch := func() { sock.SetReadDeadline(time.Now().Add(p.opt.IdleTimeout)) }
	touch()
	go func() {
		defer func() { done <- struct{}{} }()
		// Full UDP receive buffer lets us detect oversize payloads without truncation.
		buf := make([]byte, 65535)
		for {
			n, from, err := sock.ReadFromUDP(buf)
			if err != nil {
				return
			}
			to := source.Load()
			if !from.IP.Equal(peerIP) || (peerZone != "" && from.Zone != peerZone) || (requested.Port != 0 && from.Port != int(requested.Port)) || (to != nil && (to.Port != from.Port || to.Zone != from.Zone)) {
				p.udpDrop("source")
				continue
			}
			target, payload, err := parseSOCKSUDP(buf[:n])
			if err != nil {
				if errors.Is(err, errUDPPayloadTooLarge) {
					p.udpDrop("size")
				} else {
					p.udpDrop("invalid")
				}
				continue
			}
			if to == nil {
				source.Store(from)
			}
			sendCtx, sendCancel := context.WithTimeout(ctx, p.opt.HandshakeTimeout)
			err = session.Send(sendCtx, target, payload)
			sendCancel()
			if err != nil {
				// The tunnel client records failed sends exactly once.
				continue
			}
			touch()
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			select {
			case <-ctx.Done():
				return
			case dg, ok := <-session.Recv():
				if !ok {
					return
				}
				to := source.Load()
				if to == nil {
					p.udpDrop("source")
					continue
				}
				if len(dg.Payload) > protocol.MaxUDPPayload {
					p.udpDrop("size")
					continue
				}
				sock.SetWriteDeadline(time.Now().Add(p.opt.HandshakeTimeout))
				if _, err := sock.WriteToUDP(buildSOCKSUDP(dg.Addr, dg.Payload), to); err != nil {
					p.udpDrop("send")
					continue
				}
				touch()
			}
		}
	}()
	go func() { defer func() { done <- struct{}{} }(); io.Copy(io.Discard, ctrl) }()
	remaining := 3
	select {
	case <-ctx.Done():
	case <-done:
		remaining--
	}
	cancel()
	sock.Close()
	ctrl.Close()
	for range remaining {
		<-done
	}
}

func (p *Proxy) validUDPSource(ctx context.Context, a protocol.Address, peer net.IP) bool {
	if a.Atyp != protocol.AtypDomain {
		return a.IP.IsUnspecified() || a.IP.Equal(peer)
	}
	lookupCtx, cancel := context.WithTimeout(ctx, p.opt.HandshakeTimeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(lookupCtx, a.Host)
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if ip.IP.Equal(peer) {
			return true
		}
	}
	return false
}
func (p *Proxy) udpDrop(reason string) {
	if p.m != nil {
		p.m.UDPDrop(reason)
	}
}

func parseSOCKSUDP(b []byte) (protocol.Address, []byte, error) {
	if len(b) < 4 {
		return protocol.Address{}, nil, io.ErrUnexpectedEOF
	}
	if b[0] != 0 || b[1] != 0 || b[2] != 0 {
		return protocol.Address{}, nil, errors.New("socks: unsupported UDP reserved/fragment fields")
	}
	r := bytes.NewReader(b[3:])
	addr, err := protocol.ReadAddress(r)
	if err != nil {
		return protocol.Address{}, nil, err
	}
	if addr.Port == 0 || (addr.Atyp == protocol.AtypDomain && addr.Host == "") {
		return protocol.Address{}, nil, errors.New("socks: invalid UDP destination")
	}
	if r.Len() > protocol.MaxUDPPayload {
		return protocol.Address{}, nil, errUDPPayloadTooLarge
	}
	return addr, b[len(b)-r.Len():], nil
}
func buildSOCKSUDP(src protocol.Address, payload []byte) []byte {
	return append(src.Encode([]byte{0, 0, 0}), payload...)
}
