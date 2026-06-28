package tunnel

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"io"
)

// Mutual PSK authentication, bound to the TLS session.
//
// Both peers derive the same 32-byte keying material from the TLS exporter
// (RFC 5705 / RFC 8446 §7.5). Each side proves knowledge of the PSK by sending
// HMAC-SHA256(PSK, label || exporter). Because the exporter is unique per TLS
// session and unpredictable, the proof cannot be replayed and authenticates
// *both* ends (the server's reply proves it also holds the PSK). Combined with
// SPKI pinning this gives confidentiality, PFS, and mutual authentication
// without any PKI.

// ExporterLabel is the RFC 8446 exporter label for our auth keying material.
const ExporterLabel = "EXPORTER-wanopt-auth"

const proofLen = sha256.Size

func proof(psk, exporter []byte, who string) []byte {
	m := hmac.New(sha256.New, psk)
	m.Write([]byte(who))
	m.Write(exporter)
	return m.Sum(nil)
}

// ClientAuth runs the client side of the handshake over the control stream:
// send the client proof, then verify the server's proof.
func ClientAuth(rw io.ReadWriter, psk, exporter []byte) error {
	if _, err := rw.Write(proof(psk, exporter, "client")); err != nil {
		return err
	}
	got := make([]byte, proofLen)
	if _, err := io.ReadFull(rw, got); err != nil {
		return err
	}
	if !hmac.Equal(got, proof(psk, exporter, "server")) {
		return errors.New("tunnel: server authentication failed (bad PSK?)")
	}
	return nil
}

// ServerAuth runs the server side: verify the client proof, then send ours.
func ServerAuth(rw io.ReadWriter, psk, exporter []byte) error {
	got := make([]byte, proofLen)
	if _, err := io.ReadFull(rw, got); err != nil {
		return err
	}
	if !hmac.Equal(got, proof(psk, exporter, "client")) {
		return errors.New("tunnel: client authentication failed (bad PSK?)")
	}
	if _, err := rw.Write(proof(psk, exporter, "server")); err != nil {
		return err
	}
	return nil
}
