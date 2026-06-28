package protocol

import (
	"encoding/binary"
	"errors"
	"io"
)

// Protocol version byte, bumped on incompatible framing changes.
const Version byte = 0x01

// Stream commands (first byte of the command after Version on a proxy stream).
const (
	CmdTCPConnect byte = 0x01
)

// Reply status codes the server returns on a TCP stream after the dial attempt.
const (
	StatusOK            byte = 0x00
	StatusGeneralErr    byte = 0x01
	StatusConnRefused   byte = 0x02
	StatusHostUnreach   byte = 0x03
	StatusNotAllowed    byte = 0x04
)

// StreamRequest is the header a client writes at the start of every proxy
// stream, identifying the destination the server should dial.
type StreamRequest struct {
	Cmd  byte
	Addr Address
}

// WriteTo encodes the request (version, cmd, address) to w in a single write.
func (rq StreamRequest) WriteTo(w io.Writer) (int64, error) {
	buf := make([]byte, 0, 2+1+len(rq.Addr.Host)+18)
	buf = append(buf, Version, rq.Cmd)
	buf = rq.Addr.Encode(buf)
	n, err := w.Write(buf)
	return int64(n), err
}

// ReadStreamRequest decodes a StreamRequest from r.
func ReadStreamRequest(r io.Reader) (StreamRequest, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return StreamRequest{}, err
	}
	if hdr[0] != Version {
		return StreamRequest{}, errors.New("protocol: unsupported version")
	}
	addr, err := ReadAddress(r)
	if err != nil {
		return StreamRequest{}, err
	}
	return StreamRequest{Cmd: hdr[1], Addr: addr}, nil
}

// WriteReply writes the one-byte dial status to w.
func WriteReply(w io.Writer, status byte) error {
	_, err := w.Write([]byte{status})
	return err
}

// ReadReply reads the one-byte dial status from r.
func ReadReply(r io.Reader) (byte, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}

// --- UDP datagram envelope (carried over QUIC DATAGRAM) ---
//
// Layout: [version:1][sessionID:uvarint][address][payload...]
// The address is the *target* for client->server datagrams, and the *source*
// for server->client datagrams, letting one association reach many peers.

// EncodeDatagram builds a UDP relay datagram.
func EncodeDatagram(sessionID uint64, addr Address, payload []byte) []byte {
	buf := make([]byte, 0, 1+binary.MaxVarintLen64+1+len(addr.Host)+18+len(payload))
	buf = append(buf, Version)
	buf = binary.AppendUvarint(buf, sessionID)
	buf = addr.Encode(buf)
	buf = append(buf, payload...)
	return buf
}

// Datagram is a decoded UDP relay datagram. Payload aliases the input buffer.
type Datagram struct {
	SessionID uint64
	Addr      Address
	Payload   []byte
}

// DecodeDatagram parses a UDP relay datagram.
func DecodeDatagram(buf []byte) (Datagram, error) {
	if len(buf) < 2 || buf[0] != Version {
		return Datagram{}, errors.New("protocol: bad datagram header")
	}
	sid, n := binary.Uvarint(buf[1:])
	if n <= 0 {
		return Datagram{}, errors.New("protocol: bad datagram session id")
	}
	off := 1 + n
	addr, used, err := decodeAddress(buf[off:])
	if err != nil {
		return Datagram{}, err
	}
	off += used
	return Datagram{SessionID: sid, Addr: addr, Payload: buf[off:]}, nil
}
