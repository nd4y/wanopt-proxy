package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

func data(kind string, n int) []byte {
	b := make([]byte, n)
	r := rand.New(rand.NewSource(42))
	r.Read(b)
	if kind == "text" || kind == "gzip" {
		var out bytes.Buffer
		for out.Len() < n {
			fmt.Fprintf(&out, "{\"timestamp\":\"2026-10-18T00:%02d:%02dZ\",\"level\":\"info\",\"service\":\"api-%d\",\"request_id\":\"%016x\",\"method\":\"GET\",\"path\":\"/v1/items/%d\",\"status\":200,\"duration_ms\":%d,\"bytes\":%d}\n", r.Intn(60), r.Intn(60), r.Intn(8), r.Uint64(), r.Intn(100000), r.Intn(1000), r.Intn(65536))
		}
		b = out.Bytes()[:n]
	}
	if kind == "gzip" {
		var out bytes.Buffer
		w, _ := gzip.NewWriterLevel(&out, gzip.BestSpeed)
		w.Write(b)
		w.Close()
		return out.Bytes()
	}
	return b
}
func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func main() {
	serve := flag.Bool("serve", false, "")
	listen := flag.String("listen", "127.0.0.1:25243", "HTTP benchmark origin listen address")
	warm := flag.Bool("warm", false, "")
	hold := flag.Bool("hold", false, "")
	base := flag.String("url", "http://127.0.0.1:25243", "")
	proxy := flag.String("proxy", "", "")
	kind := flag.String("kind", "random", "")
	n := flag.Int("bytes", 4<<20, "")
	dir := flag.String("direction", "GET", "")
	label := flag.String("label", "", "")
	flag.Parse()
	if *hold {
		time.Sleep(time.Hour)
		return
	}
	if *serve {
		http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
		http.HandleFunc("/transfer", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" {
				h := sha256.New()
				n, e := io.Copy(h, io.LimitReader(r.Body, 32<<20))
				if e != nil {
					http.Error(w, e.Error(), 400)
					return
				}
				json.NewEncoder(w).Encode(map[string]any{"bytes": n, "sha256": hex.EncodeToString(h.Sum(nil))})
				return
			}
			n, _ := strconv.Atoi(r.URL.Query().Get("bytes"))
			if n < 1 || n > 16<<20 {
				http.Error(w, "size", 400)
				return
			}
			b := data(r.URL.Query().Get("kind"), n)
			w.Header().Set("X-SHA256", hash(b))
			w.Header().Set("Content-Length", strconv.Itoa(len(b)))
			w.Write(b)
		})
		s := http.Server{Addr: *listen, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 120 * time.Second, WriteTimeout: 120 * time.Second}
		panic(s.ListenAndServe())
	}
	b := data(*kind, *n)
	expected := hash(b)
	tr := &http.Transport{DisableCompression: true}
	if *proxy != "" {
		u, _ := url.Parse(*proxy)
		tr.Proxy = http.ProxyURL(u)
	}
	c := &http.Client{Transport: tr, Timeout: 120 * time.Second}
	r, e := c.Get(*base + "/ping")
	if e != nil {
		panic(e)
	}
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
	iterations := 1
	if *warm {
		iterations = 2
	}
	for iteration := 0; iteration < iterations; iteration++ {
		var body io.Reader
		if *dir == "POST" {
			body = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(*dir, *base+"/transfer?kind="+*kind+"&bytes="+strconv.Itoa(*n), body)
		start := time.Now()
		r, e = c.Do(req)
		if e != nil {
			panic(e)
		}
		defer r.Body.Close()
		var count int64
		var got string
		if *dir == "GET" {
			h := sha256.New()
			count, e = io.Copy(h, r.Body)
			got = hex.EncodeToString(h.Sum(nil))
			if r.Header.Get("X-SHA256") != expected {
				panic("server dataset mismatch")
			}
		} else {
			var o struct {
				Bytes int64  `json:"bytes"`
				Hash  string `json:"sha256"`
			}
			e = json.NewDecoder(r.Body).Decode(&o)
			count = o.Bytes
			got = o.Hash
		}
		sec := time.Since(start).Seconds()
		ok := e == nil && r.StatusCode == 200 && got == expected && count == int64(len(b))
		if iteration == iterations-1 {
			json.NewEncoder(os.Stdout).Encode(map[string]any{"warmed": *warm, "label": *label, "kind": *kind, "direction": *dir, "bytes": count, "logical_bytes": *n, "seconds": sec, "mbps": float64(count) * 8 / sec / 1e6, "integrity": ok})
		}
		r.Body.Close()
		if !ok {
			os.Exit(1)
		}
	}
}
