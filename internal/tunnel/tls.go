// Package tunnel sets up the QUIC/TLS transport between client and server.
//
// PFS is inherent: QUIC mandates TLS 1.3, which always uses ephemeral ECDHE.
// We deliberately avoid a PKI. Instead the server presents a self-signed
// certificate and the client pins its SPKI (subject public key info) hash.
// Mutual application-level authentication is layered on top via a PSK proof
// bound to the TLS exporter (see auth.go), which also authenticates the server.
package tunnel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// DefaultALPN is used when none is configured. It is set to "h3" so the
// handshake is indistinguishable from HTTP/3 on the wire (lightweight DPI
// camouflage). Client and server must agree on the value.
const DefaultALPN = "h3"

// SPKIPin returns the base64-encoded SHA-256 of a certificate's
// SubjectPublicKeyInfo — the value clients pin. This is stable across cert
// re-issuance as long as the key pair is reused.
func SPKIPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// GenerateSelfSigned creates a fresh ECDSA P-256 self-signed certificate valid
// for ~10 years and returns the tls.Certificate plus its SPKI pin so an
// operator can copy the pin into the client config.
func GenerateSelfSigned() (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "wanopt"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	return cert, SPKIPin(leaf), nil
}

// LoadOrCreateCert loads a PEM cert+key pair from disk, or returns a freshly
// generated one when both paths are empty. The SPKI pin is always returned.
func LoadOrCreateCert(certPEM, keyPEM []byte) (tls.Certificate, string, error) {
	if len(certPEM) == 0 && len(keyPEM) == 0 {
		return GenerateSelfSigned()
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	if cert.Leaf == nil {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return tls.Certificate{}, "", err
		}
		cert.Leaf = leaf
	}
	return cert, SPKIPin(cert.Leaf), nil
}

// EncodeCertPEM serializes a generated certificate and its private key to PEM,
// so operators can persist a stable pin across restarts.
func EncodeCertPEM(cert tls.Certificate) (certPEM, keyPEM []byte, err error) {
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	key, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("tunnel: unexpected private key type")
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	return certPEM, keyPEM, nil
}

// ServerTLSConfig builds the server-side tls.Config for the given ALPN.
func ServerTLSConfig(cert tls.Certificate, alpn string) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{alpn},
	}
}

// ClientTLSConfig builds the client-side tls.Config that skips the default PKI
// verification and instead enforces the pinned SPKI hash. When sessionCache is
// non-nil, TLS session resumption (and thus 0-RTT) becomes possible.
func ClientTLSConfig(pin, alpn string, sessionCache tls.ClientSessionCache) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, // we verify via pinning below, not the system CA pool
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{alpn},
		ClientSessionCache: sessionCache,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("tunnel: server presented no certificate")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			if got := SPKIPin(cert); got != pin {
				return fmt.Errorf("tunnel: server pin mismatch (got %s)", got)
			}
			return nil
		},
	}
}
