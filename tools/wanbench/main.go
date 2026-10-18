// wanbench measures checksummed application traffic with bounded prebuilt fixtures.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"runtime"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"sync"
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

type fixture struct {
	body []byte
	hash string
}

func fixtures(sizes []int) (map[string]fixture, error) {
	sum := 0
	for _, n := range sizes {
		if n < 1 || n > 8<<20 {
			return nil, errors.New("fixture size outside 1..8MiB")
		}
		sum += n
		if sum > 8<<20 {
			return nil, errors.New("sum of fixture sizes exceeds 8MiB")
		}
	}
	out := make(map[string]fixture)
	for _, n := range sizes {
		for _, kind := range []string{"text", "random", "gzip"} {
			b := data(kind, n)
			out[kind+":"+strconv.Itoa(n)] = fixture{b, hash(b)}
		}
	}
	return out, nil
}
func originHandler(f map[string]fixture) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/stream", streamHandler(f))
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })
	mux.HandleFunc("/transfer", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			h := sha256.New()
			n, err := io.Copy(h, io.LimitReader(r.Body, 32<<20+1))
			if err != nil || n > 32<<20 {
				http.Error(w, "body exceeds limit or read failed", http.StatusBadRequest)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"bytes": n, "sha256": hex.EncodeToString(h.Sum(nil))})
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method", 405)
			return
		}
		value, ok := f[r.URL.Query().Get("kind")+":"+r.URL.Query().Get("bytes")]
		if !ok {
			http.Error(w, "fixture not prebuilt", 400)
			return
		}
		w.Header().Set("X-SHA256", value.hash)
		w.Header().Set("Content-Length", strconv.Itoa(len(value.body)))
		w.Write(value.body)
	})
	return mux
}

type options struct {
	streaming                              bool
	base, proxy, kind, direction, label    string
	n, repeats, concurrency, abortAfter    int
	warm                                   bool
	duration, timeout, slowRead, slowWrite time.Duration
}
type worker struct {
	lastBytes       int64
	client          *http.Client
	transport       *http.Transport
	opt             options
	body            []byte
	expected        string
	requests, bytes int64
	samples         []float64
	reused, closed  bool
	rng             *rand.Rand
}
type delayedReader struct {
	ctx   context.Context
	r     io.Reader
	delay time.Duration
}

func (r delayedReader) Read(b []byte) (int, error) {
	if len(b) > 8192 {
		b = b[:8192]
	}
	if r.delay > 0 {
		timer := time.NewTimer(r.delay)
		select {
		case <-timer.C:
		case <-r.ctx.Done():
			timer.Stop()
			return 0, r.ctx.Err()
		}
	}
	return r.r.Read(b)
}

var errAborted = errors.New("intentional abort")

func (w *worker) transfer(ctx context.Context, abort int) (float64, error) {
	if w.opt.streaming {
		if abort > 0 {
			return 0, errors.New("abort probe requires finite mode")
		}
		return w.streamTransfer(ctx)
	}
	var body io.Reader
	if w.opt.direction == "POST" {
		body = bytes.NewReader(w.body)
		if w.opt.slowWrite > 0 {
			body = delayedReader{ctx, body, w.opt.slowWrite}
		}
	}
	req, err := http.NewRequestWithContext(ctx, w.opt.direction, w.opt.base+"/transfer?kind="+w.opt.kind+"&bytes="+strconv.Itoa(w.opt.n), body)
	if err != nil {
		return 0, err
	}
	if body != nil {
		req.ContentLength = int64(len(w.body))
	}
	reused := false
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { reused = i.Reused }}))
	start := time.Now()
	resp, err := w.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	w.reused = w.reused && reused
	w.closed = w.closed || resp.Close
	if abort > 0 {
		if w.opt.direction != "GET" {
			return 0, errors.New("abort mode requires GET")
		}
		_, err := io.CopyN(io.Discard, resp.Body, int64(abort))
		if err != nil {
			return 0, err
		}
		return time.Since(start).Seconds(), errAborted
	}
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}
	var count int64
	var got string
	if w.opt.direction == "GET" {
		h := sha256.New()
		var reader io.Reader = resp.Body
		if w.opt.slowRead > 0 {
			reader = delayedReader{ctx, reader, w.opt.slowRead}
		}
		count, err = io.Copy(h, reader)
		got = hex.EncodeToString(h.Sum(nil))
		if resp.Header.Get("X-SHA256") != w.expected {
			return 0, errors.New("origin fixture mismatch")
		}
	} else {
		var out struct {
			Bytes int64  `json:"bytes"`
			Hash  string `json:"sha256"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 1024)).Decode(&out)
		if err == nil {
			_, err = io.Copy(io.Discard, resp.Body)
		}
		count, got = out.Bytes, out.Hash
	}
	if err != nil {
		return 0, err
	}
	if count != int64(len(w.body)) || got != w.expected {
		return 0, errors.New("checksum or length mismatch")
	}
	w.lastBytes = count
	return time.Since(start).Seconds(), nil
}
func newWorker(ctx context.Context, o options, b []byte, index int) (*worker, error) {
	tr := &http.Transport{DisableCompression: true, MaxIdleConnsPerHost: 1}
	if o.proxy != "" {
		u, err := url.Parse(o.proxy)
		if err != nil || u.Host == "" {
			return nil, errors.New("invalid proxy URL")
		}
		tr.Proxy = http.ProxyURL(u)
	}
	w := &worker{client: &http.Client{Transport: tr, Timeout: o.timeout}, transport: tr, opt: o, body: b, expected: hash(b), reused: true, rng: rand.New(rand.NewSource(int64(42 + index)))}
	req, err := http.NewRequestWithContext(ctx, "GET", o.base+"/ping", nil)
	if err != nil {
		return nil, err
	}
	resp, err := w.client.Do(req)
	if err != nil {
		tr.CloseIdleConnections()
		return nil, err
	}
	_, readErr := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if readErr != nil || resp.StatusCode != 200 {
		tr.CloseIdleConnections()
		return nil, errors.New("ping failed")
	}
	return w, nil
}
func (w *worker) sample(v float64) {
	w.requests++
	w.bytes += w.lastBytes
	if len(w.samples) < 4096 {
		w.samples = append(w.samples, v)
	} else if i := w.rng.Int63n(w.requests); i < 4096 {
		w.samples[i] = v
	}
}
func quantile(v []float64, q float64) float64 {
	if len(v) == 0 {
		return 0
	}
	return v[int(float64(len(v)-1)*q)]
}
func run(ctx context.Context, o options) (map[string]any, error) {
	if o.n < 1 || o.n > 8<<20 || o.concurrency < 1 || o.concurrency > 16 || o.repeats < 1 || o.duration < 0 || o.duration > 24*time.Hour || o.timeout <= 0 || o.slowRead < 0 || o.slowRead > 100*time.Millisecond || o.slowWrite < 0 || o.slowWrite > 100*time.Millisecond {
		return nil, errors.New("invalid benchmark limits")
	}
	if o.kind != "text" && o.kind != "random" && o.kind != "gzip" {
		return nil, errors.New("invalid kind")
	}
	if o.direction != "GET" && o.direction != "POST" {
		return nil, errors.New("direction must be GET or POST")
	}
	if o.abortAfter < 0 || o.abortAfter >= o.n {
		return nil, errors.New("abort-after must be smaller than payload")
	}
	if o.streaming && (o.duration <= 0 || o.duration > 2*time.Minute || o.timeout < o.duration+5*time.Second || o.abortAfter > 0) {
		return nil, errors.New("stream mode needs duration<=2m, timeout>=duration+5s, and no abort probe")
	}
	b := data(o.kind, o.n)
	setupStart := time.Now()
	var workers []*worker
	defer func() {
		for _, w := range workers {
			w.transport.CloseIdleConnections()
		}
	}()
	for i := 0; i < o.concurrency; i++ {
		w, err := newWorker(ctx, o, b, i)
		if err != nil {
			return nil, err
		}
		workers = append(workers, w)
	}
	setup := time.Since(setupStart).Seconds()
	warmStart := time.Now()
	first := 0.0
	for _, w := range workers {
		if o.abortAfter > 0 {
			abortCtx, cancel := context.WithCancel(ctx)
			_, err := w.transfer(abortCtx, o.abortAfter)
			cancel()
			if !errors.Is(err, errAborted) {
				return nil, fmt.Errorf("abort probe: %w", err)
			}
		}
		if o.warm {
			mode := w.opt.streaming
			w.opt.streaming = false
			v, err := w.transfer(ctx, 0)
			w.opt.streaming = mode
			if err != nil {
				return nil, err
			}
			if first == 0 {
				first = v
			}
		}
	}
	warmTime := time.Since(warmStart).Seconds()
	before := runtime.NumGoroutine()
	start := time.Now()
	deadline := start.Add(o.duration)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, len(workers))
	var wg sync.WaitGroup
	for _, w := range workers {
		wg.Go(func() {
			for i := 0; i < o.repeats || o.duration > 0; i++ {
				if o.duration > 0 && i > 0 && !time.Now().Before(deadline) {
					break
				}
				v, err := w.transfer(ctx, 0)
				if err != nil {
					errs <- err
					cancel()
					return
				}
				w.sample(v)
			}
		})
	}
	wg.Wait()
	seconds := time.Since(start).Seconds()
	close(errs)
	var failure error
	for err := range errs {
		if failure == nil {
			failure = err
		}
	}
	var count, transferred int64
	var samples []float64
	reused, closed := true, false
	for _, w := range workers {
		count += w.requests
		transferred += w.bytes
		samples = append(samples, w.samples...)
		reused = reused && w.reused
		closed = closed || w.closed
		w.transport.CloseIdleConnections()
	}
	sort.Float64s(samples)
	result := map[string]any{"streaming": o.streaming, "label": o.label, "kind": o.kind, "direction": o.direction, "logical_bytes": o.n, "bytes": transferred, "requests": count, "seconds": seconds, "mbps": float64(transferred) * 8 / seconds / 1e6, "integrity": failure == nil, "warmed": o.warm, "connection_reused": reused, "response_close": closed, "setup_seconds": setup, "warmup_seconds": warmTime, "first_warm_transfer_seconds": first, "request_seconds_p50": quantile(samples, .5), "request_seconds_p95": quantile(samples, .95), "request_seconds_p99": quantile(samples, .99), "latency_samples": len(samples), "concurrency": o.concurrency, "goroutines_before": before, "goroutines_after": runtime.NumGoroutine(), "abort_probe": o.abortAfter > 0}
	if failure != nil {
		result["error"] = failure.Error()
	}
	return result, failure
}
func main() {
	serve := flag.Bool("serve", false, "serve prebuilt fixtures")
	listen := flag.String("listen", "127.0.0.1:25243", "origin listen address")
	sizes := flag.String("fixture-sizes", "", "comma-separated prebuilt byte sizes; sum <=8MiB")
	hold := flag.Bool("hold", false, "sleep for a test process")
	var o options
	flag.StringVar(&o.base, "url", "http://127.0.0.1:25243", "origin URL")
	flag.StringVar(&o.proxy, "proxy", "", "HTTP proxy URL")
	flag.StringVar(&o.kind, "kind", "random", "text, random, gzip")
	flag.StringVar(&o.direction, "direction", "GET", "GET or POST")
	flag.StringVar(&o.label, "label", "", "measurement label")
	flag.IntVar(&o.n, "bytes", 4<<20, "logical fixture bytes, maximum8MiB")
	flag.BoolVar(&o.streaming, "stream", false, "one continuous upload/download for duration with end-to-end checksum")
	flag.BoolVar(&o.warm, "warm", false, "one full untimed warm transfer per worker")
	flag.IntVar(&o.repeats, "repeats", 1, "requests per worker when duration is zero")
	flag.IntVar(&o.concurrency, "concurrency", 1, "independent connections, maximum16")
	flag.DurationVar(&o.duration, "duration", 0, "steady measurement duration, maximum24h")
	flag.DurationVar(&o.timeout, "request-timeout", 30*time.Second, "per request deadline")
	flag.DurationVar(&o.slowRead, "slow-read-delay", 0, "delay per8KiB read")
	flag.DurationVar(&o.slowWrite, "slow-write-delay", 0, "delay per8KiB body read")
	flag.IntVar(&o.abortAfter, "abort-after", 0, "cancel an untimed GET after this many bytes")
	cpu := flag.String("cpuprofile", "", "optional CPU profile path")
	mem := flag.String("memprofile", "", "optional heap profile path")
	flag.Parse()
	if *hold {
		time.Sleep(time.Hour)
		return
	}
	if *serve {
		ns := []int{o.n}
		if *sizes != "" {
			ns = nil
			for _, x := range strings.Split(*sizes, ",") {
				n, err := strconv.Atoi(x)
				if err != nil {
					panic(err)
				}
				ns = append(ns, n)
			}
		}
		f, err := fixtures(ns)
		if err != nil {
			panic(err)
		}
		srv := &http.Server{Addr: *listen, Handler: originHandler(f), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 120 * time.Second, WriteTimeout: 120 * time.Second, IdleTimeout: 60 * time.Second}
		if err := srv.ListenAndServe(); err != nil {
			panic(err)
		}
		return
	}
	var cpuFile *os.File
	if *cpu != "" {
		var err error
		cpuFile, err = os.OpenFile(*cpu, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			panic(err)
		}
		if err = pprof.StartCPUProfile(cpuFile); err != nil {
			panic(err)
		}
	}
	result, err := run(context.Background(), o)
	if cpuFile != nil {
		pprof.StopCPUProfile()
		cpuFile.Close()
	}
	if *mem != "" {
		f, e := os.OpenFile(*mem, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			panic(e)
		}
		runtime.GC()
		pprof.WriteHeapProfile(f)
		f.Close()
	}
	if result != nil {
		json.NewEncoder(os.Stdout).Encode(result)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
