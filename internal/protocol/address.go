// Package protocol defines the on-the-wire framing used inside the QUIC tunnel:
// a SOCKS5-like address codec, the per-stream TCP request header, and the UDP
// datagram envelope used for QUIC DATAGRAM relaying.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// Address types, mirroring SOCKS5 so we can pass addresses through untouched.
const (
	AtypIPv4   byte = 0x01
	AtypDomain byte = 0x03
	AtypIPv6   byte = 0x04
)

var errBadAddress = errors.New("protocol: malformed address")

// Address is a target endpoint. Exactly one of IP/Host is meaningful depending
// on Atyp; we keep the original form to avoid needless DNS resolution on the
// client and to let the server resolve names closer to the destination.
type Address struct {
	Atyp byte
	Host string // domain name when Atyp == AtypDomain
	IP   net.IP // for IPv4/IPv6
	Port uint16
}

// String renders host:port, suitable for net.Dial.
func (a Address) String() string {
	if a.Atyp == AtypDomain {
		return net.JoinHostPort(a.Host, strconv.Itoa(int(a.Port)))
	}
	return net.JoinHostPort(a.IP.String(), strconv.Itoa(int(a.Port)))
}

// ParseAddress builds an Address from a host:port string, choosing the most
// compact representation.
func ParseAddress(hostport string) (Address, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return Address{}, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return Address{}, fmt.Errorf("protocol: bad port: %w", err)
	}
	a := Address{Port: uint16(port)}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			a.Atyp, a.IP = AtypIPv4, v4
		} else {
			a.Atyp, a.IP = AtypIPv6, ip.To16()
		}
		return a, nil
	}
	if len(host) > 255 {
		return Address{}, errors.New("protocol: domain name too long")
	}
	a.Atyp, a.Host = AtypDomain, host
	return a, nil
}

// Encode appends the wire form of the address to b and returns the result.
func (a Address) Encode(b []byte) []byte {
	switch a.Atyp {
	case AtypIPv4:
		b = append(b, AtypIPv4)
		b = append(b, a.IP.To4()...)
	case AtypIPv6:
		b = append(b, AtypIPv6)
		b = append(b, a.IP.To16()...)
	case AtypDomain:
		b = append(b, AtypDomain, byte(len(a.Host)))
		b = append(b, a.Host...)
	}
	b = binary.BigEndian.AppendUint16(b, a.Port)
	return b
}

// ReadAddress decodes an address from a stream reader.
func ReadAddress(r io.Reader) (Address, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return Address{}, err
	}
	var a Address
	a.Atyp = atyp[0]
	switch atyp[0] {
	case AtypIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(r, buf); err != nil {
			return Address{}, err
		}
		a.IP = net.IP(buf)
	case AtypIPv6:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(r, buf); err != nil {
			return Address{}, err
		}
		a.IP = net.IP(buf)
	case AtypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return Address{}, err
		}
		buf := make([]byte, l[0])
		if _, err := io.ReadFull(r, buf); err != nil {
			return Address{}, err
		}
		a.Host = string(buf)
	default:
		return Address{}, errBadAddress
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return Address{}, err
	}
	a.Port = binary.BigEndian.Uint16(port[:])
	return a, nil
}

// decodeAddress parses an address from the front of buf, returning the address
// and the number of bytes consumed. Used for datagram parsing.
func decodeAddress(buf []byte) (Address, int, error) {
	if len(buf) < 1 {
		return Address{}, 0, errBadAddress
	}
	a := Address{Atyp: buf[0]}
	off := 1
	switch buf[0] {
	case AtypIPv4:
		if len(buf) < off+4+2 {
			return Address{}, 0, errBadAddress
		}
		a.IP = net.IP(append([]byte(nil), buf[off:off+4]...))
		off += 4
	case AtypIPv6:
		if len(buf) < off+16+2 {
			return Address{}, 0, errBadAddress
		}
		a.IP = net.IP(append([]byte(nil), buf[off:off+16]...))
		off += 16
	case AtypDomain:
		if len(buf) < off+1 {
			return Address{}, 0, errBadAddress
		}
		dl := int(buf[off])
		off++
		if len(buf) < off+dl+2 {
			return Address{}, 0, errBadAddress
		}
		a.Host = string(buf[off : off+dl])
		off += dl
	default:
		return Address{}, 0, errBadAddress
	}
	a.Port = binary.BigEndian.Uint16(buf[off : off+2])
	off += 2
	return a, off, nil
}
