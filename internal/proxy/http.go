package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"

	"wanopt/internal/protocol"
)

// hopByHop headers must not be forwarded to the origin server.
var hopByHop = []string{
	"Proxy-Connection", "Connection", "Keep-Alive",
	"Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer",
	"Transfer-Encoding", "Upgrade",
}

// ServeHTTP runs the HTTP proxy listener until ctx is cancelled. It supports
// CONNECT (used for HTTPS and any TCP) and absolute-URI forwarding for plain
// HTTP requests.
func (p *Proxy) ServeHTTP(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	p.log.Info("HTTP proxy listening", "addr", addr)
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		go p.handleHTTP(ctx, conn)
	}
}

func (p *Proxy) handleHTTP(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method == http.MethodConnect {
		p.httpConnect(ctx, conn, br, req.Host)
		return
	}
	p.httpForward(ctx, conn, br, req)
}

// httpConnect tunnels a raw TCP stream after a CONNECT request.
func (p *Proxy) httpConnect(ctx context.Context, conn net.Conn, br *bufio.Reader, hostport string) {
	addr, err := protocol.ParseAddress(ensurePort(hostport, "443"))
	if err != nil {
		io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}
	stream, err := p.c.OpenTCP(ctx, addr)
	if err != nil {
		io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer stream.Close()
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	// br may hold bytes the client already sent; read the local side through it.
	done := make(chan struct{}, 2)
	go func() { io.Copy(stream, br); stream.Close(); done <- struct{}{} }()
	go func() { io.Copy(conn, stream); done <- struct{}{} }()
	<-done
}

// httpForward forwards a plain (absolute-URI) HTTP request to the origin server
// through the tunnel, then relays the response. Single request per connection.
func (p *Proxy) httpForward(ctx context.Context, conn net.Conn, br *bufio.Reader, req *http.Request) {
	if req.URL.Host == "" {
		io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}
	addr, err := protocol.ParseAddress(ensurePort(req.URL.Host, "80"))
	if err != nil {
		io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}
	stream, err := p.c.OpenTCP(ctx, addr)
	if err != nil {
		io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer stream.Close()

	// Rewrite to origin form and strip hop-by-hop headers.
	req.RequestURI = ""
	req.URL.Scheme = ""
	req.URL.Host = ""
	for _, h := range hopByHop {
		req.Header.Del(h)
	}
	req.Close = true
	if err := req.Write(stream); err != nil {
		return
	}
	io.Copy(conn, stream)
}

// ensurePort appends :defPort when hostport carries no port.
func ensurePort(hostport, defPort string) string {
	if _, _, err := net.SplitHostPort(hostport); err != nil {
		if strings.HasPrefix(err.Error(), "address") && strings.Contains(err.Error(), "missing port") {
			return net.JoinHostPort(hostport, defPort)
		}
	}
	return hostport
}
