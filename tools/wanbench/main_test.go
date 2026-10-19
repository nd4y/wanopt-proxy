package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBenchmarkPrebuiltFixturesAndDirections(t *testing.T) {
	f, err := fixtures([]int{32768})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(originHandler(f))
	defer srv.Close()
	for _, direction := range []string{"GET", "POST"} {
		o := options{base: srv.URL, kind: "random", direction: direction, n: 32768, repeats: 2, concurrency: 2, warm: true, timeout: time.Second}
		result, err := run(context.Background(), o)
		if err != nil || result["integrity"] != true || result["requests"].(int64) != 4 || result["connection_reused"] != true {
			t.Fatal(result, err)
		}
	}
	resp, err := http.Get(srv.URL + "/transfer?kind=random&bytes=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatal("origin generated an unprepared fixture")
	}
}
func TestBenchmarkDetectsCorruptPayloadAndAbortRecovers(t *testing.T) {
	b := bytes.Repeat([]byte{3}, 32768)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ping" {
			io.WriteString(w, "ok")
			return
		}
		w.Header().Set("X-SHA256", "invalid")
		w.Write(b)
	}))
	defer srv.Close()
	o := options{base: srv.URL, kind: "random", direction: "GET", n: 32768, repeats: 1, concurrency: 1, timeout: time.Second}
	if _, err := run(context.Background(), o); err == nil {
		t.Fatal("corruption not detected")
	}
	f, _ := fixtures([]int{32768})
	valid := httptest.NewServer(originHandler(f))
	defer valid.Close()
	o.base = valid.URL
	o.abortAfter = 100
	if result, err := run(context.Background(), o); err != nil || result["integrity"] != true {
		t.Fatal(result, err)
	}
}
func TestFixtureMemoryBound(t *testing.T) {
	if _, err := fixtures([]int{8 << 20, 1}); err == nil {
		t.Fatal("fixture budget exceeded")
	}
	if _, err := fixtures([]int{-1}); err == nil {
		t.Fatal("negative fixture accepted")
	}
}
