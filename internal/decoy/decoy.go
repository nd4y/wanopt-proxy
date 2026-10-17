// Package decoy serves an optional HTTP/3 site. It provides no guarantee against traffic analysis or active probing.
package decoy

import (
	"embed"
	"errors"
	"html/template"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

//go:embed assets/index.html assets/404.html
var assets embed.FS

// Config selects the decoy behaviour.
type Config struct {
	Enabled  bool
	Mode     string // "builtin" | "proxy" | "dir"
	Upstream string // mode=proxy
	Dir      string // mode=dir
	SiteName string // mode=builtin branding
}

// Handler builds the http.Handler that fronts the server.
func Handler(cfg Config) (http.Handler, error) {
	if !cfg.Enabled {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "404 page not found", http.StatusNotFound)
		}), nil
	}
	switch cfg.Mode {
	case "proxy":
		u, err := url.Parse(cfg.Upstream)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
			return nil, errors.New("decoy: invalid upstream URL")
		}
		transport := &http.Transport{
			DialContext:         (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
			IdleConnTimeout: 30 * time.Second, MaxIdleConns: 16, MaxIdleConnsPerHost: 16, MaxConnsPerHost: 16,
			MaxResponseHeaderBytes: 64 << 10,
		}
		return &httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) { r.SetURL(u); r.Out.Host = u.Host }, Transport: transport}, nil
	case "dir":
		return http.FileServer(http.Dir(cfg.Dir)), nil
	default:
		return builtin(cfg.SiteName)
	}
}

type builtinSite struct {
	index    *template.Template
	notFound *template.Template
	data     map[string]string
}

func builtin(siteName string) (http.Handler, error) {
	if siteName == "" {
		siteName = "CloudVault"
	}
	index, err := template.ParseFS(assets, "assets/index.html")
	if err != nil {
		return nil, err
	}
	notFound, err := template.ParseFS(assets, "assets/404.html")
	if err != nil {
		return nil, err
	}
	return &builtinSite{
		index:    index,
		notFound: notFound,
		data:     map[string]string{"SiteName": siteName, "Initial": string([]rune(siteName)[:1])},
	}, nil
}

func (s *builtinSite) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Headers a typical self-hosted deployment behind nginx would emit.
	// This is an optional site, not a network fingerprint guarantee.
	// Do not advertise a hard-coded port when the listener is configurable.

	switch {
	case r.URL.Path == "/" || r.URL.Path == "/login":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		s.index.Execute(w, s.data)
	case r.URL.Path == "/api/auth/login" && r.Method == http.MethodPost:
		// A failed login is the most natural response to an unauthenticated POST.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_credentials","message":"Invalid username or password"}`))
	case r.URL.Path == "/status" || r.URL.Path == "/healthz":
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok","version":"3.2.1","maintenance":false}`))
	case r.URL.Path == "/favicon.ico":
		w.WriteHeader(http.StatusNoContent)
	case strings.HasPrefix(r.URL.Path, "/api/"):
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized"}`))
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		s.notFound.Execute(w, s.data)
	}
}
