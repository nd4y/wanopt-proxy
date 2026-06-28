package proxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync/atomic"
	"time"

	"wanopt/internal/protocol"
)

// socksUDPAssociate handles a UDP ASSOCIATE request. It opens a local UDP relay
// socket, tells the client where to send datagrams, and bridges them to the
// tunnel. The association lives until the controlling TCP connection closes.
func (p *Proxy) socksUDPAssociate(ctx context.Context, ctrl net.Conn) {
	// Bind the relay socket on the same IP the control connection arrived on so
	// the client application can reach it.
	host, _, _ := net.SplitHostPort(ctrl.LocalAddr().String())
	laddr := &net.UDPAddr{IP: net.ParseIP(host), Port: 0}
	uconn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		writeSOCKSReply(ctrl, repGeneralFailure, net.IPv4zero, 0)
		return
	}
	defer uconn.Close()

	bound := uconn.LocalAddr().(*net.UDPAddr)
	if err := writeSOCKSReply(ctrl, repSuccess, bound.IP, uint16(bound.Port)); err != nil {
		return
	}

	session := p.c.NewUDPSession()
	defer session.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var clientAddr atomic.Pointer[net.UDPAddr] // last address the app sent from

	// App -> tunnel.
	go func() {
		buf := make([]byte, 64*1024)
		for {
			uconn.SetReadDeadline(time.Now().Add(idleUDPTimeout))
			n, from, err := uconn.ReadFromUDP(buf)
			if err != nil {
				cancel()
				return
			}
			clientAddr.Store(from)
			target, payload, err := parseSOCKSUDP(buf[:n])
			if err != nil {
				continue
			}
			session.Send(ctx, target, payload)
		}
	}()

	// Tunnel -> app.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case dg := <-session.Recv():
				to := clientAddr.Load()
				if to == nil {
					continue
				}
				uconn.WriteToUDP(buildSOCKSUDP(dg.Addr, dg.Payload), to)
			}
		}
	}()

	// Block until the control connection closes, then tear everything down.
	io.Copy(io.Discard, ctrl)
	cancel()
}

// parseSOCKSUDP decodes a SOCKS5 UDP request: RSV(2) FRAG(1) ATYP ADDR PORT DATA.
func parseSOCKSUDP(b []byte) (protocol.Address, []byte, error) {
	if len(b) < 4 {
		return protocol.Address{}, nil, io.ErrUnexpectedEOF
	}
	// b[0:2] reserved, b[2] fragment (we only support whole datagrams: FRAG==0).
	r := bytes.NewReader(b[3:])
	addr, err := protocol.ReadAddress(r)
	if err != nil {
		return protocol.Address{}, nil, err
	}
	payload := make([]byte, r.Len())
	io.ReadFull(r, payload)
	return addr, payload, nil
}

// buildSOCKSUDP wraps a payload in a SOCKS5 UDP reply header tagged with src.
func buildSOCKSUDP(src protocol.Address, payload []byte) []byte {
	out := []byte{0x00, 0x00, 0x00} // RSV, FRAG
	out = src.Encode(out)
	return append(out, payload...)
}
