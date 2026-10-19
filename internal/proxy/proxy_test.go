package proxy

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"wanopt/internal/compress"
	"wanopt/internal/protocol"
)

type memoryConn struct {
	r *bytes.Reader
	w bytes.Buffer
}

func (c *memoryConn) Read(b []byte) (int, error)       { return c.r.Read(b) }
func (c *memoryConn) Write(b []byte) (int, error)      { return c.w.Write(b) }
func (c *memoryConn) Close() error                     { return nil }
func (c *memoryConn) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (c *memoryConn) RemoteAddr() net.Addr             { return c.LocalAddr() }
func (c *memoryConn) SetDeadline(time.Time) error      { return nil }
func (c *memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memoryConn) SetWriteDeadline(time.Time) error { return nil }

func TestSOCKSMethodsAndReservedFields(t *testing.T) {
	for _, tc := range []struct {
		name   string
		input  []byte
		method byte
		valid  bool
	}{
		{"noauth", []byte{5, 1, 0}, 0, true},
		{"among_methods", []byte{5, 2, 2, 0}, 0, true},
		{"unsupported", []byte{5, 1, 2}, 255, false},
		{"empty", []byte{5, 0}, 255, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &memoryConn{r: bytes.NewReader(tc.input)}
			err := socksHandshake(c)
			if (err == nil) != tc.valid || !bytes.Equal(c.w.Bytes(), []byte{5, tc.method}) {
				t.Fatalf("err=%v reply=%x", err, c.w.Bytes())
			}
		})
	}
	for _, hdr := range [][]byte{{5, 1, 1}, {4, 1, 0}} {
		c := &memoryConn{r: bytes.NewReader(hdr)}
		if _, _, _, err := readSOCKSRequest(c); err == nil {
			t.Fatalf("accepted header %x", hdr)
		}
	}
}

func TestSOCKSIPv6Reply(t *testing.T) {
	c := &memoryConn{}
	ip := net.ParseIP("::1")
	if err := writeSOCKSReply(c, repSuccess, ip, 12345); err != nil {
		t.Fatal(err)
	}
	b := c.w.Bytes()
	if b[3] != protocol.AtypIPv6 {
		t.Fatalf("reply %x", b)
	}
	a, err := protocol.ReadAddress(bytes.NewReader(b[3:]))
	if err != nil || !a.IP.Equal(ip) || a.Port != 12345 {
		t.Fatalf("%v %v", a, err)
	}
}

func TestSOCKSUDPValidation(t *testing.T) {
	a := protocol.Address{Atyp: protocol.AtypIPv4, IP: net.IPv4(192, 0, 2, 1), Port: 53}
	valid := buildSOCKSUDP(a, []byte("dns"))
	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
		valid  bool
	}{
		{"valid", func(b []byte) []byte { return b }, true},
		{"reserved0", func(b []byte) []byte { b[0] = 1; return b }, false},
		{"reserved1", func(b []byte) []byte { b[1] = 1; return b }, false},
		{"fragment", func(b []byte) []byte { b[2] = 1; return b }, false},
		{"truncated", func(b []byte) []byte { return b[:5] }, false},
		{"oversize", func(b []byte) []byte { return append(b, make([]byte, protocol.MaxUDPPayload)...) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := tc.mutate(append([]byte(nil), valid...))
			_, payload, err := parseSOCKSUDP(b)
			if (err == nil) != tc.valid {
				t.Fatalf("err=%v", err)
			}
			if tc.valid && !bytes.Equal(payload, []byte("dns")) {
				t.Fatalf("payload=%q", payload)
			}
		})
	}
}

func TestEnsurePortIPv6(t *testing.T) {
	for in, want := range map[string]string{"[::1]": "[::1]:443", "::1": "[::1]:443", "[::1]:8443": "[::1]:8443", "example.com": "example.com:443", "example.com:80": "example.com:80"} {
		if got := ensurePort(in, "443"); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	first, err := net.DialTCP("tcp4", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	second, err := ln.AcceptTCP()
	if err != nil {
		first.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { first.Close(); second.Close() })
	first.SetDeadline(time.Now().Add(5 * time.Second))
	second.SetDeadline(time.Now().Add(5 * time.Second))
	return first, second
}

func TestRelayPreservesHalfClose(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		name := "raw"
		if compressed {
			name = "compressed"
		}
		t.Run(name, func(t *testing.T) {
			app, local := tcpPair(t)
			remote, origin := tcpPair(t)
			p := New(nil, nil)
			done := make(chan struct{})
			go func() { p.relay(context.Background(), local, local, remote, compressed); close(done) }()
			payload := bytes.Repeat([]byte("large trailing response"), 32768)
			serverErr := make(chan error, 1)
			go func() {
				var req bytes.Buffer
				var err error
				if compressed {
					_, err = compress.Decopy(&req, origin)
				} else {
					_, err = io.Copy(&req, origin)
				}
				if err == nil && !bytes.Equal(req.Bytes(), []byte("request")) {
					err = io.ErrUnexpectedEOF
				}
				if err == nil {
					if compressed {
						_, err = compress.Copy(origin, bytes.NewReader(payload))
					} else {
						_, err = origin.Write(payload)
					}
				}
				origin.CloseWrite()
				serverErr <- err
			}()
			app.Write([]byte("request"))
			app.CloseWrite()
			got, err := io.ReadAll(app)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("truncated response: got %d want %d", len(got), len(payload))
			}
			if err = <-serverErr; err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("relay leaked")
			}
		})
	}
}

func TestRelayCancellationClosesBothSides(t *testing.T) {
	_, local := tcpPair(t)
	remote, _ := tcpPair(t)
	p := New(nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.relay(ctx, local, local, remote, false); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("relay did not stop")
	}
}

func TestSharedAdmissionLimit(t *testing.T) {
	p := NewWithOptions(nil, nil, Options{MaxConnections: 1})
	a, b := net.Pipe()
	defer b.Close()
	c, d := net.Pipe()
	defer d.Close()
	first := p.track(a)
	if first == nil {
		t.Fatal("first rejected")
	}
	if p.track(c) != nil {
		t.Fatal("over-capacity connection accepted")
	}
	p.closeConnections()
	if len(p.slots) != 0 {
		t.Fatal("capacity leaked")
	}
}

func startHTTPProxy(t *testing.T, p *Proxy) *url.URL {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if p.dialStream == nil {
		p.dialStream = func(ctx context.Context, a protocol.Address, _ bool) (net.Conn, bool, error) {
			c, e := (&net.Dialer{}).DialContext(ctx, "tcp", a.String())
			return c, false, e
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.serveHTTP(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("HTTP server did not stop")
		}
	})
	u, _ := url.Parse("http://" + ln.Addr().String())
	return u
}

func TestHTTPKeepAliveAndConnectionHeaders(t *testing.T) {
	var mu sync.Mutex
	var origins []string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Remove") != "" || r.Header.Get("Proxy-Authorization") != "" {
			t.Errorf("hop headers forwarded: %v", r.Header)
		}
		mu.Lock()
		origins = append(origins, r.RemoteAddr)
		mu.Unlock()
		w.Header().Set("Connection", "X-Remove-Response")
		w.Header().Set("X-Remove-Response", "secret")
		io.WriteString(w, "response")
	}))
	defer origin.Close()
	p := New(nil, nil)
	u := startHTTPProxy(t, p)
	tr := &http.Transport{Proxy: http.ProxyURL(u)}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	for range 2 {
		req, _ := http.NewRequest("GET", origin.URL, nil)
		req.Header.Set("Connection", "X-Remove")
		req.Header.Set("X-Remove", "secret")
		req.Header.Set("Proxy-Authorization", "secret")
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || string(b) != "response" {
			t.Fatalf("body=%q err=%v", b, err)
		}
		if resp.Header.Get("X-Remove-Response") != "" {
			t.Fatal("response hop header forwarded")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(origins) != 2 || origins[0] != origins[1] {
		t.Fatalf("origin connection not reused: %v", origins)
	}
}

func TestHTTPExpectContinueAndEarlyResponse(t *testing.T) {
	for _, early := range []bool{false, true} {
		name := "continue"
		if early {
			name = "early_response"
		}
		t.Run(name, func(t *testing.T) {
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if early {
					w.Header().Set("Connection", "close")
					w.WriteHeader(http.StatusExpectationFailed)
					return
				}
				// Exercise multiple informational responses deterministically.
				w.WriteHeader(http.StatusContinue)
				w.WriteHeader(http.StatusEarlyHints)
				b, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("origin read: %v", err)
					return
				}
				w.Write(b)
			}))
			defer origin.Close()
			p := New(nil, nil)
			u := startHTTPProxy(t, p)
			c, err := net.Dial("tcp", u.Host)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(3 * time.Second))
			io.WriteString(c, "POST "+origin.URL+"/ HTTP/1.1\r\nHost: "+strings.TrimPrefix(origin.URL, "http://")+"\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n")
			br := bufio.NewReader(c)
			resp, err := http.ReadResponse(br, &http.Request{Method: "POST"})
			if err != nil {
				t.Fatal(err)
			}
			if early {
				if resp.StatusCode != http.StatusExpectationFailed {
					t.Fatalf("status=%d", resp.StatusCode)
				}
				resp.Body.Close()
				return
			}
			if resp.StatusCode != 100 {
				t.Fatalf("expected 100 before body, got %d", resp.StatusCode)
			}
			io.WriteString(c, "data")
			// The proxy can emit its own 100 Continue and forward upstream 1xx.
			// Read all informational responses before checking the final body.
			sawEarlyHints := false
			for informational := 0; ; informational++ {
				if informational == 10 {
					t.Fatal("too many informational responses before final response")
				}
				resp, err = http.ReadResponse(br, &http.Request{Method: "POST"})
				if err != nil {
					t.Fatal(err)
				}
				if resp.StatusCode < 100 || resp.StatusCode >= 200 || resp.StatusCode == http.StatusSwitchingProtocols {
					break
				}
				if resp.StatusCode == http.StatusEarlyHints {
					sawEarlyHints = true
				}
				resp.Body.Close()
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("expected final 200, got %d", resp.StatusCode)
			}
			if !sawEarlyHints {
				t.Fatal("upstream 103 Early Hints was not forwarded")
			}
			b, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || string(b) != "data" {
				t.Fatalf("body=%q err=%v", b, err)
			}
		})
	}
}

func TestHTTPConnectBufferedBytesAndHalfClose(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	originErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			originErr <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		b, err := io.ReadAll(c)
		if err == nil {
			_, err = c.Write(append([]byte("echo:"), b...))
		}
		originErr <- err
	}()
	p := New(nil, nil)
	u := startHTTPProxy(t, p)
	c, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	io.WriteString(c, "CONNECT "+ln.Addr().String()+" HTTP/1.1\r\nHost: "+ln.Addr().String()+"\r\n\r\nbuffered-request")
	br := bufio.NewReader(c)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "200") {
		t.Fatalf("%q %v", status, err)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	c.(*net.TCPConn).CloseWrite()
	b, err := io.ReadAll(br)
	if err != nil || string(b) != "echo:buffered-request" {
		t.Fatalf("response=%q err=%v", b, err)
	}
	if err = <-originErr; err != nil {
		t.Fatal(err)
	}
}

func TestHTTPBoundsHeadersAndPartialHeaderTime(t *testing.T) {
	p := NewWithOptions(nil, nil, Options{MaxHeaderBytes: 1024, HandshakeTimeout: 150 * time.Millisecond})
	u := startHTTPProxy(t, p)
	for _, request := range []string{"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nX-Large: " + strings.Repeat("x", 16<<10) + "\r\n\r\n", "GET http://example.com/ HTTP/1.1\r\nHost:"} {
		c, err := net.Dial("tcp", u.Host)
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(2 * time.Second))
		io.WriteString(c, request)
		_, err = io.ReadAll(c)
		c.Close()
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatal("header limit did not terminate connection")
		}
	}
}

func TestHTTPEarlyResponseDuringChunkedUpload(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		http.NewResponseController(w).EnableFullDuplex()
		http.Error(w, "rejected", http.StatusRequestEntityTooLarge)
	}))
	defer origin.Close()
	p := NewWithOptions(nil, nil, Options{IdleTimeout: 2 * time.Second})
	u := startHTTPProxy(t, p)
	c, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	io.WriteString(c, "POST "+origin.URL+"/ HTTP/1.1\r\nHost: "+strings.TrimPrefix(origin.URL, "http://")+"\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ndata\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "POST"})
	if err != nil {
		t.Fatalf("early response blocked on unfinished request: %v", err)
	}
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestHTTPBodyProgressAndPostKeepAlive(t *testing.T) {
	var mu sync.Mutex
	var peers []string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		if string(b) != "upload" {
			t.Errorf("body=%q", b)
		}
		mu.Lock()
		peers = append(peers, r.RemoteAddr)
		mu.Unlock()
		for range 8 {
			io.WriteString(w, "part")
			w.(http.Flusher).Flush()
			time.Sleep(50 * time.Millisecond)
		}
	}))
	defer origin.Close()
	p := NewWithOptions(nil, nil, Options{IdleTimeout: 300 * time.Millisecond})
	u := startHTTPProxy(t, p)
	tr := &http.Transport{Proxy: http.ProxyURL(u)}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	for range 2 {
		resp, err := hc.Post(origin.URL, "text/plain", strings.NewReader("upload"))
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || string(b) != strings.Repeat("part", 8) {
			t.Fatalf("progressing body truncated: %q %v", b, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(peers) != 2 || peers[0] != peers[1] {
		t.Fatalf("successful POST did not reuse origin connection: %v", peers)
	}
}

func TestHTTPUpgrade(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
		rw.Flush()
		b := make([]byte, 4)
		if _, err = io.ReadFull(rw, b); err != nil {
			t.Error(err)
			return
		}
		rw.Write(b)
		rw.Flush()
	}))
	defer origin.Close()
	p := New(nil, nil)
	u := startHTTPProxy(t, p)
	c, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	io.WriteString(c, "GET "+origin.URL+"/ HTTP/1.1\r\nHost: "+strings.TrimPrefix(origin.URL, "http://")+"\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 101 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	io.WriteString(c, "ping")
	b := make([]byte, 4)
	if _, err = io.ReadFull(br, b); err != nil || string(b) != "ping" {
		t.Fatalf("echo=%q err=%v", b, err)
	}
}

func TestHTTPRejectionDoesNotDrainIncompleteBody(t *testing.T) {
	for _, tc := range []struct {
		name, request string
		status        int
	}{
		{"origin_form", "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ndata\r\n", 400},
		{"zero_port", "POST http://localhost:0/ HTTP/1.1\r\nHost: localhost\r\nContent-Length: 9\r\n\r\ndata", 400},
		{"connect_body", "CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\nContent-Length: 9\r\n\r\ndata", 400},
		{"connect_chunked", "CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ndata\r\n", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := NewWithOptions(nil, nil, Options{MaxConnections: 1, IdleTimeout: 3 * time.Second})
			p.dialStream = func(context.Context, protocol.Address, bool) (net.Conn, bool, error) {
				t.Error("invalid request reached upstream dial")
				return nil, false, io.ErrUnexpectedEOF
			}
			u := startHTTPProxy(t, p)
			c, err := net.Dial("tcp", u.Host)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(time.Second))
			io.WriteString(c, tc.request)
			resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "POST"})
			if err != nil {
				t.Fatalf("error response blocked on incomplete body: %v", err)
			}
			if resp.StatusCode != tc.status || !resp.Close {
				t.Fatalf("status=%d close=%v", resp.StatusCode, resp.Close)
			}
			if _, err = io.ReadAll(resp.Body); err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			c.Close()
			deadline := time.Now().Add(1500 * time.Millisecond)
			for len(p.slots) != 0 && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if len(p.slots) != 0 {
				t.Fatal("invalid request retained admission slot")
			}
		})
	}
}
