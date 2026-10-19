package tunnel

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestCredentialOverlapExpiryAndRejectedReload(t *testing.T) {
	a := bytes.Repeat([]byte{1}, 32)
	b := bytes.Repeat([]byte{2}, 32)
	cert, _, _ := GenerateSelfSigned()
	c := NewServerCredentials(a, b, time.Now().Add(time.Hour), cert)
	exporter := []byte("session")
	for _, key := range [][]byte{a, b} {
		buf := bytes.NewBuffer(proof(key, exporter, "client"))
		ready := false
		if err := c.Authenticate(buf, exporter, func(id [32]byte) error {
			ready = true
			if !c.Accepts(id) {
				return errors.New("not accepted")
			}
			return nil
		}); err != nil || !ready || !bytes.Equal(buf.Bytes(), proof(key, exporter, "server")) {
			t.Fatal("overlap handshake", err)
		}
	}
	if err := c.Update(a, b, time.Now().Add(-time.Second), cert); err != nil {
		t.Fatal(err)
	}
	if c.Accepts(sha256.Sum256(b)) {
		t.Fatal("expired key accepted")
	}
	if err := c.Authenticate(bytes.NewBuffer(proof(b, exporter, "client")), exporter, nil); err == nil {
		t.Fatal("expired proof accepted")
	}
	if err := c.Update(b, a, time.Now().Add(30*24*time.Hour), cert); err == nil {
		t.Fatal("unbounded overlap accepted")
	}
	if !c.Accepts(sha256.Sum256(a)) {
		t.Fatal("failed reload changed live key")
	}
}
func TestCredentialSnapshotsConcurrent(t *testing.T) {
	a := bytes.Repeat([]byte{1}, 32)
	b := bytes.Repeat([]byte{2}, 32)
	cert, _, _ := GenerateSelfSigned()
	c := NewServerCredentials(a, b, time.Now().Add(time.Hour), cert)
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 100 {
				if !c.Accepts(sha256.Sum256(a)) || !c.Accepts(sha256.Sum256(b)) {
					t.Error("partial credential snapshot")
				}
				cfg := c.TLSConfig("h3")
				if _, err := cfg.GetCertificate(nil); err != nil {
					t.Error(err)
				}
			}
		})
	}
	for range 100 {
		if err := c.Update(b, a, time.Now().Add(time.Hour), cert); err != nil {
			t.Fatal(err)
		}
		if err := c.Update(a, b, time.Now().Add(time.Hour), cert); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}
func TestNextPinExpiryAndResumption(t *testing.T) {
	a, pin, _ := GenerateSelfSigned()
	b, next, _ := GenerateSelfSigned()
	cfg := ClientTLSConfigWithRotation(pin, next, time.Now().Add(time.Hour), "h3", nil)
	state := tls.ConnectionState{DidResume: true, PeerCertificates: []*x509.Certificate{b.Leaf}}
	if err := cfg.VerifyConnection(state); err != nil {
		t.Fatal(err)
	}
	cfg = ClientTLSConfigWithRotation(pin, next, time.Now().Add(-time.Second), "h3", nil)
	if cfg.VerifyConnection(state) == nil {
		t.Fatal("expired next pin accepted on resumption")
	}
	state.PeerCertificates[0] = a.Leaf
	if err := cfg.VerifyConnection(state); err != nil {
		t.Fatal("primary pin changed", err)
	}
}
