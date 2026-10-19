package tunnel

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"sync/atomic"
	"time"
)

type credentialSnapshot struct {
	primary, previous []byte
	expires           time.Time
	cert              tls.Certificate
}

// ServerCredentials publishes complete immutable snapshots. Callers must not mutate certificates.
type ServerCredentials struct {
	current atomic.Pointer[credentialSnapshot]
}

func NewServerCredentials(primary, previous []byte, expires time.Time, cert tls.Certificate) *ServerCredentials {
	c := &ServerCredentials{}
	c.store(primary, previous, expires, cert)
	return c
}
func (c *ServerCredentials) store(primary, previous []byte, expires time.Time, cert tls.Certificate) {
	c.current.Store(&credentialSnapshot{append([]byte(nil), primary...), append([]byte(nil), previous...), expires, cert})
}
func (c *ServerCredentials) Update(primary, previous []byte, expires time.Time, cert tls.Certificate) error {
	if len(primary) < 16 || len(primary) > 256 || len(cert.Certificate) == 0 || cert.PrivateKey == nil {
		return errors.New("tunnel: invalid replacement credentials")
	}
	if len(previous) > 0 && (len(previous) < 16 || len(previous) > 256 || hmac.Equal(primary, previous) || expires.IsZero() || expires.After(time.Now().Add(7*24*time.Hour))) {
		return errors.New("tunnel: invalid previous key overlap")
	}
	if len(previous) == 0 && !expires.IsZero() {
		return errors.New("tunnel: expiry without previous key")
	}
	c.store(primary, previous, expires, cert)
	return nil
}
func (c *ServerCredentials) TLSConfig(alpn string) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{alpn}, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &c.current.Load().cert, nil }}
}
func (c *ServerCredentials) Accepts(id [32]byte) bool {
	s := c.current.Load()
	a := sha256.Sum256(s.primary)
	b := sha256.Sum256(s.previous)
	primary := hmac.Equal(id[:], a[:])
	previous := hmac.Equal(id[:], b[:]) && len(s.previous) > 0 && time.Now().Before(s.expires)
	return primary || previous
}

// Authenticate retains protocol v2 proofs, selecting the matching active key.
func (c *ServerCredentials) Authenticate(rw io.ReadWriter, exporter []byte, ready func([32]byte) error) error {
	s := c.current.Load()
	var got [proofLen]byte
	if _, err := io.ReadFull(rw, got[:]); err != nil {
		return err
	}
	primaryOK := hmac.Equal(got[:], proof(s.primary, exporter, "client"))
	previousOK := hmac.Equal(got[:], proof(s.previous, exporter, "client")) && len(s.previous) > 0 && time.Now().Before(s.expires)
	var key []byte
	if primaryOK && len(s.primary) > 0 {
		key = s.primary
	} else if previousOK {
		key = s.previous
	} else {
		return errors.New("tunnel: client authentication failed")
	}
	if ready != nil {
		if err := ready(sha256.Sum256(key)); err != nil {
			return err
		}
	}
	return writeProof(rw, proof(key, exporter, "server"))
}
