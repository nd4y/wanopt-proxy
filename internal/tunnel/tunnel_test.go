package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"github.com/quic-go/quic-go"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

type shortWriter struct{}

func (shortWriter) Write(b []byte) (int, error) { return len(b) - 1, nil }
func TestProofBindingAndShortWrites(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	if bytes.Equal(proof(key, []byte("first session"), "client"), proof(key, []byte("second session"), "client")) {
		t.Fatal("proof not bound to TLS session")
	}
	if bytes.Equal(proof(key, []byte("session"), "client"), proof(key, []byte("session"), "server")) {
		t.Fatal("client and server proof labels collide")
	}
	if err := writeProof(shortWriter{}, key); err != io.ErrShortWrite {
		t.Fatalf("short proof accepted: %v", err)
	}
}

func TestPinVerificationRunsOnResumedState(t *testing.T) {
	trusted, pin, err := GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	config := ClientTLSConfig(pin, "h3", tls.NewLRUClientSessionCache(1))
	state := tls.ConnectionState{DidResume: true, PeerCertificates: []*x509.Certificate{trusted.Leaf}}
	if err = config.VerifyConnection(state); err != nil {
		t.Fatal(err)
	}
	state.PeerCertificates[0] = other.Leaf
	if err = config.VerifyConnection(state); err == nil {
		t.Fatal("resumed session bypassed pin verification")
	}
}

type canceledStream struct {
	reads, writes atomic.Int32
	done          chan struct{}
}

func (s *canceledStream) Read([]byte) (int, error)         { return 0, io.EOF }
func (s *canceledStream) Write(b []byte) (int, error)      { return len(b), nil }
func (s *canceledStream) Close() error                     { return nil }
func (s *canceledStream) CancelRead(quic.StreamErrorCode)  { s.reads.Add(1) }
func (s *canceledStream) CancelWrite(quic.StreamErrorCode) { s.writes.Add(1); close(s.done) }
func (s *canceledStream) SetDeadline(time.Time) error      { return nil }
func (s *canceledStream) SetReadDeadline(time.Time) error  { return nil }
func (s *canceledStream) SetWriteDeadline(time.Time) error { return nil }
func TestContextBindingCancellationAndIdempotentStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &canceledStream{done: make(chan struct{})}
	stop := BindContext(ctx, s)
	cancel()
	select {
	case <-s.done:
	case <-time.After(time.Second):
		t.Fatal("stream not canceled")
	}
	stop()
	stop()
	if s.reads.Load() != 1 || s.writes.Load() != 1 {
		t.Fatal("stream halves not canceled exactly once")
	}
}

type authReadWriter struct {
	io.Reader
	write func([]byte) (int, error)
}

func (rw authReadWriter) Write(b []byte) (int, error) { return rw.write(b) }

func TestServerPublishesReadinessBeforeAuthenticationReply(t *testing.T) {
	psk := bytes.Repeat([]byte{7}, 32)
	exporter := []byte("test TLS exporter")
	valid := proof(psk, exporter, "client")
	invalid := append([]byte(nil), valid...)
	invalid[0] ^= 0xff
	for _, tc := range []struct {
		name  string
		input []byte
		valid bool
	}{
		{"valid", valid, true},
		{"invalid", invalid, false},
		{"incomplete", valid[:len(valid)-1], false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authenticated := false
			callbacks, writes := 0, 0
			rw := authReadWriter{Reader: bytes.NewReader(tc.input), write: func(reply []byte) (int, error) {
				writes++
				if !authenticated {
					t.Error("server proof became observable before readiness")
				}
				if !bytes.Equal(reply, proof(psk, exporter, "server")) {
					t.Error("incorrect server proof")
				}
				return len(reply), nil
			}}
			err := ServerAuth(rw, psk, exporter, func() { callbacks++; authenticated = true })
			if tc.valid {
				if err != nil || !authenticated || callbacks != 1 || writes != 1 {
					t.Fatalf("successful auth: err=%v gate=%v callbacks=%d writes=%d", err, authenticated, callbacks, writes)
				}
			} else if err == nil || authenticated || callbacks != 0 || writes != 0 {
				t.Fatalf("rejected proof opened readiness or wrote reply: err=%v gate=%v callbacks=%d writes=%d", err, authenticated, callbacks, writes)
			}
		})
	}
}
