package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	hashpkg "hash"
	"io"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"sync"
	"time"
)

const streamLimit int64 = 16 << 30

func streamHandler(fixtures map[string]fixture) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			h := sha256.New()
			n, err := io.Copy(h, io.LimitReader(r.Body, streamLimit+1))
			if err != nil || n > streamLimit {
				http.Error(w, "stream read failed or limit exceeded", 400)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"bytes": n, "sha256": hex.EncodeToString(h.Sum(nil))})
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method", 405)
			return
		}
		d, err := time.ParseDuration(r.URL.Query().Get("duration"))
		f, ok := fixtures[r.URL.Query().Get("kind")+":"+r.URL.Query().Get("bytes")]
		if err != nil || d <= 0 || d > 2*time.Minute || !ok {
			http.Error(w, "invalid streaming fixture or duration", 400)
			return
		}
		w.Header().Add("Trailer", "X-Transfer-SHA256")
		w.Header().Add("Trailer", "X-Transfer-Bytes")
		h := sha256.New()
		until := time.Now().Add(d)
		var total int64
		for time.Now().Before(until) && total < streamLimit {
			b := f.body
			if int64(len(b)) > streamLimit-total {
				b = b[:int(streamLimit-total)]
			}
			n, err := w.Write(b)
			if n > 0 {
				h.Write(b[:n])
				total += int64(n)
			}
			if err != nil || n == 0 {
				return
			}
		}
		w.Header().Set("X-Transfer-SHA256", hex.EncodeToString(h.Sum(nil)))
		w.Header().Set("X-Transfer-Bytes", strconv.FormatInt(total, 10))
	}
}

// timedFixture emits a prebuilt block repeatedly and verifies that the sender
// actually reached EOF. A premature HTTP response cannot count as success.
type timedFixture struct {
	mu       sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
	block    []byte
	duration time.Duration
	until    time.Time
	offset   int
	total    int64
	h        hashpkg.Hash
	finished bool
}

func newTimedFixture(ctx context.Context, block []byte, d time.Duration) *timedFixture {
	ctx, cancel := context.WithCancel(ctx)
	return &timedFixture{ctx: ctx, cancel: cancel, block: block, duration: d, h: sha256.New()}
}
func (r *timedFixture) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.until.IsZero() {
		r.until = time.Now().Add(r.duration)
	}
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if !time.Now().Before(r.until) || r.total >= streamLimit {
		r.finished = true
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	n := copy(p, r.block[r.offset:])
	if int64(n) > streamLimit-r.total {
		n = int(streamLimit - r.total)
	}
	r.h.Write(p[:n])
	r.total += int64(n)
	r.offset = (r.offset + n) % len(r.block)
	return n, nil
}
func (r *timedFixture) Close() error { r.cancel(); return nil }
func (r *timedFixture) snapshot() (int64, string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.total, hex.EncodeToString(r.h.Sum(nil)), r.finished
}
func (w *worker) streamTransfer(ctx context.Context) (float64, error) {
	var body io.Reader
	var generated *timedFixture
	if w.opt.direction == "POST" {
		generated = newTimedFixture(ctx, w.body, w.opt.duration)
		defer generated.Close()
		body = generated
		if w.opt.slowWrite > 0 {
			body = delayedReader{ctx, body, w.opt.slowWrite}
		}
	}
	req, err := http.NewRequestWithContext(ctx, w.opt.direction, w.opt.base+"/stream?kind="+w.opt.kind+"&bytes="+strconv.Itoa(w.opt.n)+"&duration="+w.opt.duration.String(), body)
	if err != nil {
		return 0, err
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
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("stream HTTP status %d", resp.StatusCode)
	}
	var count int64
	if w.opt.direction == "GET" {
		h := sha256.New()
		var reader io.Reader = resp.Body
		if w.opt.slowRead > 0 {
			reader = delayedReader{ctx, reader, w.opt.slowRead}
		}
		count, err = io.Copy(h, reader)
		if err != nil {
			return 0, err
		}
		expected, parseErr := strconv.ParseInt(resp.Trailer.Get("X-Transfer-Bytes"), 10, 64)
		if parseErr != nil || count != expected || hex.EncodeToString(h.Sum(nil)) != resp.Trailer.Get("X-Transfer-SHA256") {
			return 0, errors.New("stream trailer length/checksum mismatch")
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
		if err != nil {
			return 0, err
		}
		n, digest, finished := generated.snapshot()
		if !finished || out.Bytes != n || out.Hash != digest {
			return 0, errors.New("stream upload incomplete or checksum mismatch")
		}
		count = n
	}
	if count <= 0 {
		return 0, errors.New("empty stream")
	}
	w.lastBytes = count
	return time.Since(start).Seconds(), nil
}
