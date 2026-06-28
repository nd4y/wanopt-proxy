// Package decoy serves a believable "cover" website for any plain HTTP/3 request
// that reaches the tunnel server. To a browser, scanner, or active prober the
// endpoint looks exactly like a self-hosted file-sync cloud, so the presence of
// the tunnel cannot be inferred from ordinary HTTP behaviour.
//
// Three modes are supported: a built-in file-cloud login site, a reverse proxy
// to a real upstream site, or a static directory.
package decoy

import (
	"embed"
	"html/template"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
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
		if err != nil {
			return nil, err
		}
		return httputil.NewSingleHostReverseProxy(u), nil
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
	w.Header().Set("Server", "nginx")
	w.Header().Set("Alt-Svc", `h3=":443"; ma=2592000`)

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
