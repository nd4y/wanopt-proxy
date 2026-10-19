package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func configFile(t *testing.T, s string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(s), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func testPSK() string { return "psk: " + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n" }
func testClient() string {
	return testPSK() + "server: example.com:443\npin: " + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"
}
func TestServerRejectsInvalidConfigurations(t *testing.T) {
	cases := []string{"", "cert_file: cert.pem\n", "allow_ephemeral_cert: true\nunknown: true\n", "allow_ephemeral_cert: true\nmax_connections: -1\n", "allow_ephemeral_cert: true\nudp:\n  max_payload: 851\n", "allow_ephemeral_cert: true\nacl:\n  deny_ports: [65536]\n", "allow_ephemeral_cert: true\nmax_stream_recv_window_mb: -1\n", "allow_ephemeral_cert: true\nmax_stream_recv_window_mb: 25\n", "allow_ephemeral_cert: true\n---\nlisten: ':443'\n", "allow_ephemeral_cert: true\ndecoy:\n  mode: invalid\n"}
	for _, s := range cases {
		if _, err := LoadServer(configFile(t, testPSK()+s)); err == nil {
			t.Fatalf("accepted %q", s)
		}
	}
}
func TestDefaultsAndPersistentPaths(t *testing.T) {
	path := configFile(t, testPSK()+"cert_file: cert.pem\nkey_file: key.pem\n")
	c, err := LoadServer(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Compression || c.Decoy.Mode != "off" || c.MaxConnections != 256 || c.UDP.MaxPayload != 850 {
		t.Fatalf("unsafe defaults %+v", c)
	}
	if c.KeyFile != filepath.Join(filepath.Dir(path), "key.pem") {
		t.Fatal(c.KeyFile)
	}
}
func TestClientValidation(t *testing.T) {
	for _, s := range []string{"max_connections: -1\n", "http_listen: ':8080'\n", "pin_typo: x\n", "alpn: other\n", "proxy_idle_timeout_sec: -1\n", "max_conn_recv_window_mb: 1\n"} {
		if _, err := LoadClient(configFile(t, testClient()+s)); err == nil {
			t.Fatalf("accepted %q", s)
		}
	}
	if _, err := LoadClient(configFile(t, strings.Replace(testClient(), "pin: ", "pin: invalid", 1))); err == nil {
		t.Fatal("accepted invalid pin")
	}
	c, err := LoadClient(configFile(t, testClient()))
	if err != nil {
		t.Fatal(err)
	}
	if c.Compression || c.SOCKSListen != "127.0.0.1:1080" || c.MaxPendingRequests != 256 {
		t.Fatalf("defaults %+v", c)
	}
	if _, err := LoadClient(configFile(t, testClient()+"http_listen: ':8080'\nallow_remote_proxy: true\n")); err != nil {
		t.Fatal(err)
	}
}

func TestConfigurationSizeBound(t *testing.T) {
	path := configFile(t, "#"+strings.Repeat("x", 1<<20))
	if _, err := LoadServer(path); err == nil || !strings.Contains(err.Error(), "exceeds 1 MiB") {
		t.Fatalf("oversized config: %v", err)
	}
}
