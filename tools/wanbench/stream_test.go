package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestContinuousStreamIntegrityBothDirections(t *testing.T) {
	f, _ := fixtures([]int{32768})
	srv := httptest.NewServer(originHandler(f))
	defer srv.Close()
	for _, direction := range []string{"GET", "POST"} {
		o := options{base: srv.URL, kind: "random", direction: direction, n: 32768, repeats: 1, concurrency: 1, warm: true, streaming: true, duration: 50 * time.Millisecond, timeout: 6 * time.Second}
		result, err := run(context.Background(), o)
		if err != nil || result["integrity"] != true || result["bytes"].(int64) <= 32768 || result["requests"].(int64) != 1 {
			t.Fatal(direction, result, err)
		}
	}
}
func TestStreamingRejectsEarlyUploadSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ping" {
			io.WriteString(w, "ok")
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"bytes": 0, "sha256": ""})
	}))
	defer srv.Close()
	o := options{base: srv.URL, kind: "random", direction: "POST", n: 32768, repeats: 1, concurrency: 1, streaming: true, duration: 50 * time.Millisecond, timeout: 6 * time.Second}
	if _, err := run(context.Background(), o); err == nil {
		t.Fatal("early success accepted")
	}
}
