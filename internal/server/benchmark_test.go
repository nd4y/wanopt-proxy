package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"wanopt/internal/client"
	"wanopt/internal/compress"
	"wanopt/internal/protocol"
	"wanopt/internal/tunnel"
)

type benchmarkStream interface {
	net.Conn
	CloseWrite() error
}
type benchmarkDial func() (benchmarkStream, error)

// BenchmarkRelay compares new logical application connections, while QUIC reuses
// an authenticated tunnel. Setup and one full warmup exchange are not timed.
// Reported bytes include upload + verified echo download (512 KiB per operation).
// This measures the relay core, excluding local SOCKS/HTTP parsing and metrics.
// For netem, shape packets with BOTH src and dst 127.0.0.1/32. Proxy egress uses
// an origin on 127.0.0.2, so it does not receive a second artificial WAN delay.
func BenchmarkRelay(b *testing.B) {
	const payloadSize = 256 << 10
	random := make([]byte, payloadSize)
	_, _ = rand.New(rand.NewSource(42)).Read(random)
	compressible := bytes.Repeat([]byte("wanopt benchmark payload\n"), payloadSize/25+1)[:payloadSize]
	for _, data := range []struct {
		name    string
		payload []byte
	}{{"random", random}, {"compressible", compressible}} {
		b.Run(data.name, func(b *testing.B) {
			for _, mode := range []string{"direct_tcp", "tcp_relay", "quic_raw", "quic_compressed"} {
				b.Run(mode, func(b *testing.B) {
					dial, compressed := benchmarkSetup(b, mode)
					exchange := func() {
						c, err := dial()
						if err != nil {
							b.Fatal(err)
						}
						c.SetDeadline(time.Now().Add(30 * time.Second))
						var sent int64
						if compressed {
							sent, err = compress.Copy(c, bytes.NewReader(data.payload))
						} else {
							sent, err = io.Copy(c, bytes.NewReader(data.payload))
						}
						if err != nil || sent != int64(len(data.payload)) {
							c.Close()
							b.Fatalf("upload bytes=%d err=%v", sent, err)
						}
						if err = c.CloseWrite(); err != nil {
							c.Close()
							b.Fatal(err)
						}
						var out bytes.Buffer
						var received int64
						if compressed {
							received, err = compress.Decopy(&out, c)
						} else {
							received, err = io.Copy(&out, c)
						}
						c.Close()
						if err != nil || received != int64(len(data.payload)) || !bytes.Equal(out.Bytes(), data.payload) {
							b.Fatalf("echo corruption bytes=%d expected=%d err=%v", received, len(data.payload), err)
						}
					}
					exchange()
					b.ReportAllocs()
					b.SetBytes(2 * int64(len(data.payload)))
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						exchange()
					}
					b.StopTimer()
				})
			}
		})
	}
}

func benchmarkSetup(b *testing.B, mode string) (benchmarkDial, bool) {
	b.Helper()
	originIP := "127.0.0.2"
	if mode == "direct_tcp" {
		originIP = "127.0.0.1"
	}
	target := benchmarkTCPListener(b, originIP, func(c *net.TCPConn) {
		data, err := io.ReadAll(io.LimitReader(c, 1<<20))
		if err == nil {
			_, _ = io.Copy(c, bytes.NewReader(data))
		}
	})
	dialTCP := func(addr string) benchmarkDial {
		return func() (benchmarkStream, error) {
			c, e := net.DialTimeout("tcp4", addr, 30*time.Second)
			if e != nil {
				return nil, e
			}
			return c.(*net.TCPConn), nil
		}
	}
	if mode == "direct_tcp" {
		return dialTCP(target), false
	}
	if mode == "tcp_relay" {
		relay := benchmarkTCPListener(b, "127.0.0.1", func(local *net.TCPConn) {
			remote, err := net.DialTimeout("tcp4", target, 30*time.Second)
			if err != nil {
				return
			}
			defer remote.Close()
			remote.SetDeadline(time.Now().Add(30 * time.Second))
			done := make(chan error, 2)
			go func() {
				_, err := io.Copy(remote, local)
				if err == nil {
					err = remote.(*net.TCPConn).CloseWrite()
				}
				done <- err
			}()
			go func() {
				_, err := io.Copy(local, remote)
				if err == nil {
					err = local.CloseWrite()
				}
				done <- err
			}()
			for range 2 {
				if err := <-done; err != nil {
					local.Close()
					remote.Close()
				}
			}
		})
		return dialTCP(relay), false
	}
	cert, pin, err := tunnel.GenerateSelfSigned()
	if err != nil {
		b.Fatal(err)
	}
	psk := bytes.Repeat([]byte{9}, 32)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	compressed := mode == "quic_compressed"
	srv := New(Options{PSK: psk, Cert: cert, Compression: compressed, Log: log, HandshakeTimeout: 30 * time.Second, RequestTimeout: 30 * time.Second})
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	go func() { serverDone <- srv.ServePacketConn(ctx, packet) }()
	c := client.New(client.Options{Server: packet.LocalAddr().String(), PSK: psk, Pin: pin, Compression: compressed, Log: log, HandshakeTimeout: 30 * time.Second, RequestTimeout: 30 * time.Second})
	clientDone := make(chan struct{})
	go func() { defer close(clientDone); c.Run(ctx) }()
	b.Cleanup(func() {
		cancel()
		select {
		case <-clientDone:
		case <-time.After(5 * time.Second):
			b.Error("benchmark client cleanup timed out")
		}
		select {
		case e := <-serverDone:
			if e != nil && !errors.Is(e, context.Canceled) {
				b.Error(e)
			}
		case <-time.After(5 * time.Second):
			b.Error("benchmark server cleanup timed out")
		}
	})
	addr, err := protocol.ParseAddress(target)
	if err != nil {
		b.Fatal(err)
	}
	return func() (benchmarkStream, error) {
		s, err := c.OpenTCP(ctx, addr, compressed)
		if err != nil {
			return nil, err
		}
		if s.Compressed != compressed {
			s.Close()
			return nil, errors.New("unexpected compression negotiation")
		}
		return s, nil
	}, compressed
}

func benchmarkTCPListener(b *testing.B, host string, handler func(*net.TCPConn)) string {
	b.Helper()
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP(host)})
	if err != nil {
		b.Fatal(err)
	}
	var mu sync.Mutex
	active := make(map[*net.TCPConn]struct{})
	var workers sync.WaitGroup
	accepting := make(chan struct{})
	go func() {
		defer close(accepting)
		for {
			c, err := ln.AcceptTCP()
			if err != nil {
				return
			}
			mu.Lock()
			active[c] = struct{}{}
			mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer c.Close()
				defer func() { mu.Lock(); delete(active, c); mu.Unlock() }()
				c.SetDeadline(time.Now().Add(30 * time.Second))
				handler(c)
			}()
		}
	}()
	b.Cleanup(func() {
		ln.Close()
		<-accepting
		mu.Lock()
		for c := range active {
			c.Close()
		}
		mu.Unlock()
		done := make(chan struct{})
		go func() { workers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			b.Error("benchmark TCP cleanup timed out")
		}
	})
	return ln.Addr().String()
}
