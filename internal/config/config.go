// Package config loads YAML configuration for the server and client.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ACL is a destination allow/deny policy. Empty allow lists mean "any".
type ACL struct {
	Allow      []string `yaml:"allow"`       // host patterns: domain suffix or IP/CIDR
	Deny       []string `yaml:"deny"`        // host patterns (deny wins)
	AllowPorts []int    `yaml:"allow_ports"` // empty = any port
	DenyPorts  []int    `yaml:"deny_ports"`
}

// Server holds server-side settings.
type Server struct {
	// Listen is the UDP address the QUIC listener binds to, e.g. ":4242"
	// (use ":443" together with alpn "h3" for HTTP/3 camouflage).
	Listen string `yaml:"listen"`
	// PSK is the shared secret, base64-encoded. Must match the client.
	PSK string `yaml:"psk"`
	// ALPN advertised in the TLS handshake; must match the client. Default "h3".
	ALPN string `yaml:"alpn"`
	// CertFile/KeyFile point to a PEM cert+key. When empty, an ephemeral
	// self-signed certificate is generated at startup and its pin is logged.
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	// IdleTimeout for QUIC connections, in seconds (0 = default).
	IdleTimeoutSec int `yaml:"idle_timeout_sec"`
	// ACL restricts which destinations the server will dial.
	ACL ACL `yaml:"acl"`
	// Allow0RTT enables 0-RTT connection resumption.
	Allow0RTT bool `yaml:"allow_0rtt"`
	// Compression enables adaptive stream compression (negotiated per stream).
	Compression bool `yaml:"compression"`
	// MetricsListen exposes Prometheus /metrics, e.g. "127.0.0.1:9101" (empty = off).
	MetricsListen string `yaml:"metrics_listen"`
	// Receive-window caps in MiB (0 = built-in default).
	MaxStreamRecvWindowMB int `yaml:"max_stream_recv_window_mb"`
	MaxConnRecvWindowMB   int `yaml:"max_conn_recv_window_mb"`
}

// Client holds client-side settings.
type Client struct {
	// Server is the QUIC server address, host:port.
	Server string `yaml:"server"`
	// PSK is the shared secret, base64-encoded. Must match the server.
	PSK string `yaml:"psk"`
	// Pin is the server's base64 SPKI hash (printed by the server at startup).
	Pin string `yaml:"pin"`
	// ALPN advertised in the TLS handshake; must match the server. Default "h3".
	ALPN string `yaml:"alpn"`
	// SOCKSListen / HTTPListen are the local proxy addresses. Empty disables.
	SOCKSListen string `yaml:"socks_listen"`
	HTTPListen  string `yaml:"http_listen"`
	// IdleTimeoutSec for the QUIC connection (0 = default).
	IdleTimeoutSec int `yaml:"idle_timeout_sec"`
	// Enable0RTT uses 0-RTT resumption for faster reconnects (server must allow).
	Enable0RTT bool `yaml:"enable_0rtt"`
	// Compression requests adaptive stream compression (server must also enable).
	Compression bool `yaml:"compression"`
	// MetricsListen exposes Prometheus /metrics, e.g. "127.0.0.1:9102" (empty = off).
	MetricsListen string `yaml:"metrics_listen"`
	// Receive-window caps in MiB (0 = built-in default).
	MaxStreamRecvWindowMB int `yaml:"max_stream_recv_window_mb"`
	MaxConnRecvWindowMB   int `yaml:"max_conn_recv_window_mb"`
}

// ALPNOrDefault returns the configured ALPN or the default "h3".
func (c *Server) ALPNOrDefault() string { return alpnOr(c.ALPN) }

// ALPNOrDefault returns the configured ALPN or the default "h3".
func (c *Client) ALPNOrDefault() string { return alpnOr(c.ALPN) }

func alpnOr(a string) string {
	if a == "" {
		return "h3"
	}
	return a
}

// DecodePSK returns the raw PSK bytes.
func DecodePSK(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("config: psk is required")
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("config: psk must be base64: %w", err)
	}
	if len(b) < 16 {
		return nil, errors.New("config: psk must be at least 16 bytes")
	}
	return b, nil
}

// LoadServer reads and validates a server config file.
func LoadServer(path string) (*Server, error) {
	var c Server
	if err := load(path, &c); err != nil {
		return nil, err
	}
	if c.Listen == "" {
		c.Listen = ":4242"
	}
	if _, err := DecodePSK(c.PSK); err != nil {
		return nil, err
	}
	return &c, nil
}

// LoadClient reads and validates a client config file.
func LoadClient(path string) (*Client, error) {
	var c Client
	if err := load(path, &c); err != nil {
		return nil, err
	}
	if c.Server == "" {
		return nil, errors.New("config: server address is required")
	}
	if c.Pin == "" {
		return nil, errors.New("config: server pin is required")
	}
	if c.SOCKSListen == "" && c.HTTPListen == "" {
		c.SOCKSListen = "127.0.0.1:1080"
	}
	if _, err := DecodePSK(c.PSK); err != nil {
		return nil, err
	}
	return &c, nil
}

func load(path string, dst any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, dst)
}
