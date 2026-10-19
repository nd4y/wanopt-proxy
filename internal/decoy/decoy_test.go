package decoy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProxyRewritesHostAndPreservesResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "public.example" || r.URL.Path != "/base/file" || r.URL.RawQuery != "a=1" {
			t.Errorf("unexpected upstream request host=%s url=%s", r.Host, r.URL)
		}
		w.Header().Set("X-Origin", "yes")
		w.WriteHeader(http.StatusAccepted)
		io.WriteString(w, "upstream response")
	}))
	defer upstream.Close()
	handler, err := Handler(Config{Enabled: true, Mode: "proxy", Upstream: upstream.URL + "/base"})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://public.example/file?a=1", nil))
	if response.Code != http.StatusAccepted || response.Body.String() != "upstream response" || response.Header().Get("X-Origin") != "yes" {
		t.Fatalf("response=%+v", response.Result())
	}
}

func TestInvalidUpstreamRejected(t *testing.T) {
	for _, address := range []string{"", "file:///etc/passwd", "https://user:pass@example.com", "http:///missing-host"} {
		if _, err := Handler(Config{Enabled: true, Mode: "proxy", Upstream: address}); err == nil {
			t.Fatalf("accepted invalid upstream %q", address)
		}
	}
}

func TestBuiltinEscapesBrandAndDoesNotAdvertiseWrongPort(t *testing.T) {
	handler, err := Handler(Config{Enabled: true, Mode: "builtin", SiteName: "<script>test</script>"})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://example.com:4242/", nil))
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "<script>test</script>") {
		t.Fatal("unsafe site branding")
	}
	if response.Header().Get("Alt-Svc") != "" {
		t.Fatal("advertised an unconfigured port")
	}
}
