package server

import (
	"crypto/tls"
	"github.com/quic-go/quic-go"
	"time"
)

// ReloadCredentials atomically changes future TLS/auth handshakes and revokes sessions using removed keys.
func (s *Server) ReloadCredentials(primary, previous []byte, expires time.Time, cert tls.Certificate) error {
	if err := s.credentials.Update(primary, previous, expires, cert); err != nil {
		return err
	}
	s.revokeUnauthorized()
	return nil
}
func (s *Server) revokeUnauthorized() {
	s.mu.Lock()
	var closeList []*quic.Conn
	for conn, cs := range s.states {
		if id := cs.authKey.Load(); id != nil && !s.credentials.Accepts(*id) {
			closeList = append(closeList, conn)
		}
	}
	s.mu.Unlock()
	for _, conn := range closeList {
		conn.CloseWithError(1, "credentials revoked")
	}
}
