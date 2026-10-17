package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"wanopt/internal/client"
	"wanopt/internal/protocol"
)

const (
	socksVersion           = 0x05
	methodNoAuth           = 0x00
	methodNotAcceptable    = 0xff
	cmdConnect             = 0x01
	cmdUDPAssociate        = 0x03
	repSuccess             = 0x00
	repGeneralFailure      = 0x01
	repNotAllowed          = 0x02
	repHostUnreach         = 0x04
	repCmdNotSupport       = 0x07
	repAddressNotSupported = 0x08
)

func (p *Proxy) ServeSOCKS(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	p.log.Info("SOCKS5 proxy listening", "addr", ln.Addr())
	return p.serveSOCKS(ctx, ln)
}
func (p *Proxy) serveSOCKS(parent context.Context, ln net.Listener) error {
	ctx, cancel := context.WithCancel(parent)
	var workers sync.WaitGroup
	stop := context.AfterFunc(ctx, func() { ln.Close(); p.closeConnections() })
	defer func() { cancel(); ln.Close(); p.closeConnections(); workers.Wait(); stop() }()
	for {
		raw, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		conn := p.track(raw)
		if conn == nil {
			continue
		}
		if ctx.Err() != nil {
			conn.Close()
			return nil
		}
		workers.Add(1)
		go func() { defer workers.Done(); p.handleSOCKS(ctx, conn) }()
	}
}
func (p *Proxy) handleSOCKS(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	conn.SetDeadline(time.Now().Add(p.opt.HandshakeTimeout))
	if err := socksHandshake(conn); err != nil {
		return
	}
	_, cmd, addr, err := readSOCKSRequest(conn)
	if err != nil {
		writeSOCKSReply(conn, repAddressNotSupported, net.IPv4zero, 0)
		return
	}
	// Tunnel establishment is separately bounded by the client's request timeout.
	conn.SetDeadline(time.Time{})
	switch cmd {
	case cmdConnect:
		if addr.Port == 0 {
			writeSOCKSReply(conn, repAddressNotSupported, net.IPv4zero, 0)
			return
		}
		p.socksConnect(ctx, conn, addr)
	case cmdUDPAssociate:
		p.socksUDPAssociate(ctx, conn, addr)
	default:
		writeSOCKSReply(conn, repCmdNotSupport, net.IPv4zero, 0)
	}
}

func socksHandshake(conn net.Conn) error {
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != socksVersion {
		return errors.New("socks: bad version")
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	accepted := false
	for _, m := range methods {
		if m == methodNoAuth {
			accepted = true
		}
	}
	method := byte(methodNotAcceptable)
	if accepted {
		method = methodNoAuth
	}
	if _, err := conn.Write([]byte{socksVersion, method}); err != nil {
		return err
	}
	if !accepted {
		return errors.New("socks: no acceptable authentication method")
	}
	return nil
}

func readSOCKSRequest(conn net.Conn) (ver, cmd byte, addr protocol.Address, err error) {
	var hdr [3]byte
	if _, err = io.ReadFull(conn, hdr[:]); err != nil {
		return
	}
	ver, cmd = hdr[0], hdr[1]
	if ver != socksVersion || hdr[2] != 0 {
		err = errors.New("socks: invalid request header")
		return
	}
	addr, err = protocol.ReadAddress(conn)
	if err == nil && addr.Atyp == protocol.AtypDomain && addr.Host == "" {
		err = errors.New("socks: empty domain")
	}
	return
}

func (p *Proxy) socksConnect(ctx context.Context, conn net.Conn, addr protocol.Address) {
	remote, compressed, err := p.dialStream(ctx, addr, p.compressionEnabled())
	if err != nil {
		p.countDialErr(err)
		conn.SetWriteDeadline(time.Now().Add(p.opt.HandshakeTimeout))
		writeSOCKSReply(conn, dialErrToRep(err), net.IPv4zero, 0)
		return
	}
	defer remote.Close()
	conn.SetWriteDeadline(time.Now().Add(p.opt.HandshakeTimeout))
	if err = writeSOCKSReply(conn, repSuccess, net.IPv4zero, 0); err != nil {
		return
	}
	conn.SetDeadline(time.Time{})
	local := &idleConn{Conn: conn, timeout: p.opt.IdleTimeout}
	peer := &idleConn{Conn: remote, timeout: p.opt.IdleTimeout}
	p.relay(ctx, local, local, peer, compressed)
}

func (p *Proxy) countDialErr(err error) {
	if p.m == nil {
		return
	}
	var de *client.DialError
	if errors.As(err, &de) && de.Status == protocol.StatusNotAllowed {
		return
	}
	p.m.DialErrors.Inc()
}

func writeSOCKSReply(conn net.Conn, rep byte, ip net.IP, port uint16) error {
	var buf []byte
	if v4 := ip.To4(); v4 != nil {
		buf = append([]byte{socksVersion, rep, 0, protocol.AtypIPv4}, v4...)
	} else if v6 := ip.To16(); v6 != nil {
		buf = append([]byte{socksVersion, rep, 0, protocol.AtypIPv6}, v6...)
	} else {
		buf = []byte{socksVersion, rep, 0, protocol.AtypIPv4, 0, 0, 0, 0}
	}
	buf = binary.BigEndian.AppendUint16(buf, port)
	_, err := conn.Write(buf)
	return err
}

func dialErrToRep(err error) byte {
	var de *client.DialError
	if errors.As(err, &de) {
		switch de.Status {
		case protocol.StatusHostUnreach:
			return repHostUnreach
		case protocol.StatusNotAllowed:
			return repNotAllowed
		}
	}
	return repGeneralFailure
}
