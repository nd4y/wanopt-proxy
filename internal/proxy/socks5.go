package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"wanopt/internal/client"
	"wanopt/internal/protocol"
)

// SOCKS5 constants.
const (
	socksVersion = 0x05

	methodNoAuth = 0x00

	cmdConnect      = 0x01
	cmdUDPAssociate = 0x03

	repSuccess        = 0x00
	repGeneralFailure = 0x01
	repNotAllowed     = 0x02
	repHostUnreach    = 0x04
	repCmdNotSupport  = 0x07
)

// ServeSOCKS runs the SOCKS5 listener until ctx is cancelled.
func (p *Proxy) ServeSOCKS(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	p.log.Info("SOCKS5 proxy listening", "addr", addr)
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		go p.handleSOCKS(ctx, conn)
	}
}

func (p *Proxy) handleSOCKS(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	if err := socksHandshake(conn); err != nil {
		return
	}
	ver, cmd, addr, err := readSOCKSRequest(conn)
	if err != nil || ver != socksVersion {
		return
	}
	switch cmd {
	case cmdConnect:
		p.socksConnect(ctx, conn, addr)
	case cmdUDPAssociate:
		p.socksUDPAssociate(ctx, conn)
	default:
		writeSOCKSReply(conn, repCmdNotSupport, net.IPv4zero, 0)
	}
}

// socksHandshake performs the method-negotiation step (no auth).
func socksHandshake(conn net.Conn) error {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return err
	}
	if hdr[0] != socksVersion {
		return errors.New("socks: bad version")
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	_, err := conn.Write([]byte{socksVersion, methodNoAuth})
	return err
}

// readSOCKSRequest parses VER CMD RSV ATYP DST.ADDR DST.PORT.
func readSOCKSRequest(conn net.Conn) (ver, cmd byte, addr protocol.Address, err error) {
	hdr := make([]byte, 3)
	if _, err = io.ReadFull(conn, hdr); err != nil {
		return
	}
	ver, cmd = hdr[0], hdr[1]
	addr, err = protocol.ReadAddress(conn)
	return
}

func (p *Proxy) socksConnect(ctx context.Context, conn net.Conn, addr protocol.Address) {
	stream, err := p.c.OpenTCP(ctx, addr, p.c.CompressionEnabled())
	if err != nil {
		p.countDialErr(err)
		writeSOCKSReply(conn, dialErrToRep(err), net.IPv4zero, 0)
		return
	}
	defer stream.Close()
	if err := writeSOCKSReply(conn, repSuccess, net.IPv4zero, 0); err != nil {
		return
	}
	p.relay(conn, conn, stream)
}

// countDialErr records dial failures (other than ACL denials) in metrics.
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

// writeSOCKSReply writes VER REP RSV ATYP BND.ADDR BND.PORT (IPv4 bind addr).
func writeSOCKSReply(conn net.Conn, rep byte, ip net.IP, port uint16) error {
	v4 := ip.To4()
	if v4 == nil {
		v4 = net.IPv4zero.To4()
	}
	buf := []byte{socksVersion, rep, 0x00, protocol.AtypIPv4}
	buf = append(buf, v4...)
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
		default:
			return repGeneralFailure
		}
	}
	return repGeneralFailure
}

// idleUDPTimeout bounds how long a UDP association stays open with no traffic.
const idleUDPTimeout = 5 * time.Minute
