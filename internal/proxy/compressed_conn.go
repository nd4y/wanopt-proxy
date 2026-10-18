package proxy

import (
	"io"
	"net"
	"sync"
	"sync/atomic"

	"wanopt/internal/compress"
)

// compressedHTTPConn exposes the negotiated framed tunnel as a plain net.Conn
// for http.Transport. The pipes provide backpressure without unbounded queues.
// HTTP connection close aborts both codecs and waits for their workers to exit.
// CONNECT and SOCKS keep using relay, which separately preserves half-closes.
type compressedHTTPConn struct {
	net.Conn
	wire      net.Conn
	bridge    net.Conn
	once      sync.Once
	remaining atomic.Int32
	readEOF   atomic.Bool
	done      chan struct{}
}

func newCompressedHTTPConn(wire net.Conn) net.Conn {
	app, bridge := net.Pipe()
	c := &compressedHTTPConn{Conn: app, wire: wire, bridge: bridge, done: make(chan struct{})}
	c.remaining.Store(2)
	finish := func() {
		c.abort()
		if c.remaining.Add(-1) == 0 {
			close(c.done)
		}
	}
	go func() { defer finish(); compress.Copy(wire, bridge) }()
	go func() {
		defer finish()
		if _, err := compress.Decopy(bridge, wire); err == nil {
			c.readEOF.Store(true)
		}
	}()
	return c
}
func (c *compressedHTTPConn) abort() {
	c.once.Do(func() { c.Conn.Close(); c.bridge.Close(); c.wire.Close() })
}
func (c *compressedHTTPConn) Close() error         { c.abort(); <-c.done; return nil }
func (c *compressedHTTPConn) LocalAddr() net.Addr  { return c.wire.LocalAddr() }
func (c *compressedHTTPConn) RemoteAddr() net.Addr { return c.wire.RemoteAddr() }

func (c *compressedHTTPConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	// A clean framed-stream EOF must remain EOF for close-delimited HTTP bodies.
	// Local cancellation and malformed frames remain errors, never successful EOF.
	if err == io.ErrClosedPipe && c.readEOF.Load() {
		err = io.EOF
	}
	return n, err
}
