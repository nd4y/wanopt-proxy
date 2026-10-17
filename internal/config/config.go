// Package config loads YAML configuration for the server and client.
package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"

	"gopkg.in/yaml.v3"
)

// ACL is a destination allow/deny policy. Empty allow lists mean "any".
type ACL struct {
	Allow      []string `yaml:"allow"`       // host patterns: domain suffix or IP/CIDR
	Deny       []string `yaml:"deny"`        // host patterns (deny wins)
	AllowPorts []int    `yaml:"allow_ports"` // empty = any port
	DenyPorts  []int    `yaml:"deny_ports"`
}

// Decoy configures the cover website served to non-tunnel HTTP/3 requests.
type Decoy struct {
	// Mode: "builtin" (embedded file-cloud site), "proxy" (reverse-proxy to
	// Upstream), "dir" (serve Dir), or "off" (return 404). Default: off.
	Mode     string `yaml:"mode"`
	Upstream string `yaml:"upstream"`  // mode=proxy
	Dir      string `yaml:"dir"`       // mode=dir
	SiteName string `yaml:"site_name"` // mode=builtin branding
}

// Server holds server-side settings.
type Server struct {
	HandshakeTimeoutSec     int `yaml:"handshake_timeout_sec"`
	RequestTimeoutSec       int `yaml:"request_timeout_sec"`
	MaxConnections          int `yaml:"max_connections"`
	MaxStreamsPerConnection int `yaml:"max_streams_per_connection"`
	DNSTimeoutSec           int `yaml:"dns_timeout_sec"`
	DNSConcurrency          int `yaml:"dns_concurrency"`
	UDP                     UDP `yaml:"udp"`
	// Ephemeral certificates are only for explicit local experiments.
	AllowEphemeralCert bool `yaml:"allow_ephemeral_cert"`
	// Listen is the UDP address the QUIC listener binds to, e.g. ":4242"
	// ALPN h3 is required by protocol v2.
	Listen string `yaml:"listen"`
	// PSK is the shared secret, base64-encoded. Must match the client.
	PSK string `yaml:"psk"`
	// ALPN advertised in the TLS handshake; must match the client. Default "h3".
	ALPN string `yaml:"alpn"`
	// CertFile/KeyFile point to a persistent PEM cert+key, relative to the config.
	// Empty paths require explicit AllowEphemeralCert for local experiments.
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	// IdleTimeout for QUIC connections, in seconds (0 = default).
	IdleTimeoutSec int `yaml:"idle_timeout_sec"`
	// ACL restricts which destinations the server will dial.
	ACL ACL `yaml:"acl"`
	// Decoy is the optional site shown to ordinary HTTP/3 requests.
	Decoy Decoy `yaml:"decoy"`
	// Allow0RTT is a deprecated, ignored compatibility field. Early data is disabled.
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
	HandshakeTimeoutSec          int  `yaml:"handshake_timeout_sec"`
	RequestTimeoutSec            int  `yaml:"request_timeout_sec"`
	MaxPendingRequests           int  `yaml:"max_pending_requests"`
	MaxUDPSessions               int  `yaml:"max_udp_sessions"`
	MaxConnections               int  `yaml:"max_connections"`
	ProxyIdleTimeoutSec          int  `yaml:"proxy_idle_timeout_sec"`
	HTTPResponseHeaderTimeoutSec int  `yaml:"http_response_header_timeout_sec"`
	MaxHeaderBytes               int  `yaml:"max_header_bytes"`
	AllowRemoteProxy             bool `yaml:"allow_remote_proxy"`
	// DisableSessionResumption turns off the TLS session cache. No 0-RTT data is sent.
	DisableSessionResumption bool `yaml:"disable_session_resumption"`
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
	// Enable0RTT is a deprecated, ignored compatibility field. Use DisableSessionResumption.
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

// UDP limits resource use independently of transport stream limits.
type UDP struct {
	MaxFlows          int `yaml:"max_flows"`
	QueueSize         int `yaml:"queue_size"`
	Workers           int `yaml:"workers"`
	NewFlowsPerSecond int `yaml:"new_flows_per_second"`
	MaxPayload        int `yaml:"max_payload"`
	IdleTimeoutSec    int `yaml:"idle_timeout_sec"`
}

func LoadServer(path string) (*Server, error) {
	var c Server
	if err := load(path, &c); err != nil {
		return nil, err
	}
	if c.Listen == "" {
		c.Listen = ":4242"
	}
	if err := validateEndpoint(c.Listen, false); err != nil {
		return nil, err
	}
	if _, err := DecodePSK(c.PSK); err != nil {
		return nil, err
	}
	if err := validateCommon(c.ALPN, c.MetricsListen, &c.IdleTimeoutSec, &c.HandshakeTimeoutSec, &c.RequestTimeoutSec, c.MaxStreamRecvWindowMB, c.MaxConnRecvWindowMB); err != nil {
		return nil, err
	}
	if (c.CertFile == "") != (c.KeyFile == "") {
		return nil, errors.New("config: cert_file and key_file must be provided together")
	}
	if c.CertFile == "" && !c.AllowEphemeralCert {
		return nil, errors.New("config: persistent cert_file/key_file required; allow_ephemeral_cert is for local experiments")
	}
	for _, p := range []*string{&c.CertFile, &c.KeyFile, &c.Decoy.Dir} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(filepath.Dir(path), *p)
		}
	}
	if c.Decoy.Mode == "" {
		c.Decoy.Mode = "off"
	}
	switch c.Decoy.Mode {
	case "off", "builtin":
	case "dir":
		if c.Decoy.Dir == "" {
			return nil, errors.New("config: decoy dir is required")
		}
	case "proxy":
		u, err := url.Parse(c.Decoy.Upstream)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
			return nil, errors.New("config: invalid decoy upstream")
		}
	default:
		return nil, errors.New("config: unknown decoy mode")
	}
	for _, list := range [][]int{c.ACL.AllowPorts, c.ACL.DenyPorts} {
		for _, p := range list {
			if p < 1 || p > 65535 {
				return nil, errors.New("config: ACL port outside 1..65535")
			}
		}
	}
	checks := []struct {
		p             *int
		name          string
		def, min, max int
	}{
		{&c.MaxConnections, "max_connections", 256, 1, 65536}, {&c.MaxStreamsPerConnection, "max_streams_per_connection", 128, 2, 4096},
		{&c.DNSTimeoutSec, "dns_timeout_sec", 5, 1, 60}, {&c.DNSConcurrency, "dns_concurrency", 32, 1, 256},
		{&c.UDP.MaxFlows, "udp.max_flows", 256, 1, 65536}, {&c.UDP.QueueSize, "udp.queue_size", 128, 1, 4096},
		{&c.UDP.Workers, "udp.workers", 4, 1, 64}, {&c.UDP.NewFlowsPerSecond, "udp.new_flows_per_second", 32, 1, 4096},
		{&c.UDP.MaxPayload, "udp.max_payload", 850, 1, 850}, {&c.UDP.IdleTimeoutSec, "udp.idle_timeout_sec", 60, 1, 3600},
	}
	for _, v := range checks {
		if err := bounded(v.p, v.name, v.def, v.min, v.max); err != nil {
			return nil, err
		}
	}
	return &c, nil
}
func LoadClient(path string) (*Client, error) {
	var c Client
	if err := load(path, &c); err != nil {
		return nil, err
	}
	if err := validateEndpoint(c.Server, true); err != nil {
		return nil, fmt.Errorf("config: server: %w", err)
	}
	pin, err := base64.StdEncoding.DecodeString(c.Pin)
	if err != nil || len(pin) != 32 {
		return nil, errors.New("config: pin must be a base64 SHA256 hash")
	}
	if _, err := DecodePSK(c.PSK); err != nil {
		return nil, err
	}
	if err := validateCommon(c.ALPN, c.MetricsListen, &c.IdleTimeoutSec, &c.HandshakeTimeoutSec, &c.RequestTimeoutSec, c.MaxStreamRecvWindowMB, c.MaxConnRecvWindowMB); err != nil {
		return nil, err
	}
	if c.SOCKSListen == "" && c.HTTPListen == "" {
		c.SOCKSListen = "127.0.0.1:1080"
	}
	for _, addr := range []string{c.SOCKSListen, c.HTTPListen} {
		if addr == "" {
			continue
		}
		if err := validateEndpoint(addr, false); err != nil {
			return nil, err
		}
		host, _, _ := net.SplitHostPort(addr)
		ip := net.ParseIP(host)
		if !c.AllowRemoteProxy && (ip == nil || !ip.IsLoopback()) {
			return nil, errors.New("config: proxy listeners must use a loopback IP; allow_remote_proxy explicitly enables unauthenticated remote access")
		}
	}
	if c.SOCKSListen != "" && c.SOCKSListen == c.HTTPListen {
		return nil, errors.New("config: proxy listeners overlap")
	}
	checks := []struct {
		p             *int
		name          string
		def, min, max int
	}{
		{&c.MaxConnections, "max_connections", 256, 1, 65536}, {&c.MaxPendingRequests, "max_pending_requests", 256, 1, 65536},
		{&c.MaxUDPSessions, "max_udp_sessions", 128, 1, 65536}, {&c.ProxyIdleTimeoutSec, "proxy_idle_timeout_sec", 300, 1, 86400},
		{&c.HTTPResponseHeaderTimeoutSec, "http_response_header_timeout_sec", 120, 1, 3600}, {&c.MaxHeaderBytes, "max_header_bytes", 65536, 1024, 1048576},
	}
	for _, v := range checks {
		if err := bounded(v.p, v.name, v.def, v.min, v.max); err != nil {
			return nil, err
		}
	}
	return &c, nil
}
func bounded(p *int, name string, def, min, max int) error {
	if *p == 0 {
		*p = def
	}
	if *p < min || *p > max {
		return fmt.Errorf("config: %s must be %d..%d (0 selects default)", name, min, max)
	}
	return nil
}
func validateCommon(alpn, metrics string, idle, handshake, request *int, stream, conn int) error {
	if alpn != "" && alpn != "h3" {
		return errors.New("config: protocol v2 requires ALPN h3")
	}
	if metrics != "" {
		if err := validateEndpoint(metrics, false); err != nil {
			return err
		}
	}
	for _, v := range []struct {
		p             *int
		name          string
		def, min, max int
	}{{idle, "idle_timeout_sec", 60, 5, 3600}, {handshake, "handshake_timeout_sec", 10, 1, 120}, {request, "request_timeout_sec", 15, 1, 300}} {
		if err := bounded(v.p, v.name, v.def, v.min, v.max); err != nil {
			return err
		}
	}
	if stream < 0 || stream > 256 || conn < 0 || conn > 1024 {
		return errors.New("config: receive windows must be nonnegative and within 256/1024 MiB")
	}
	if stream == 0 {
		stream = 16
	}
	if conn == 0 {
		conn = 24
	}
	if conn < stream {
		return errors.New("config: connection receive window must cover stream window")
	}
	return nil
}
func validateEndpoint(addr string, hostRequired bool) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("config: invalid endpoint %q", addr)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || (hostRequired && host == "") {
		return fmt.Errorf("config: invalid endpoint %q", addr)
	}
	return nil
}
func load(path string, dst any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return err
	}
	if len(data) > 1<<20 {
		return errors.New("config: file exceeds 1 MiB")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("config: exactly one YAML document required")
	}
	return nil
}
