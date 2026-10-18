package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
	"wanopt/internal/client"
)

func secondClient(t *testing.T, f *testTunnel, opt client.Options) *client.Client {
	t.Helper()
	opt.Server = f.addr
	opt.Pin = f.pin
	if opt.PSK == nil {
		opt.PSK = bytes.Repeat([]byte{7}, 32)
	}
	opt.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	opt.RequestTimeout = time.Second
	c := client.New(opt)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); c.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("client leaked")
		}
	})
	return c
}
func eventuallyAdmission(t *testing.T, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatal("admission did not recover")
		}
		time.Sleep(time.Millisecond)
	}
}
func TestGlobalAdmissionAcrossConnectionsAndCodecFallback(t *testing.T) {
	f := startTunnel(t, Options{Compression: true, MaxActiveStreams: 2, MaxCompressedStreams: 1})
	other := secondClient(t, f, client.Options{Compression: true})
	target := tcpOrigin(t, func(c net.Conn) { io.Copy(io.Discard, c) })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a, err := f.client.OpenTCP(ctx, target, true)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if !a.Compressed {
		t.Fatal("first codec not granted")
	}
	b, err := other.OpenTCP(ctx, target, true)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if b.Compressed {
		t.Fatal("global codec quota exceeded")
	}
	if c, err := other.OpenTCP(ctx, target, false); err == nil {
		c.Close()
		t.Fatal("global stream quota exceeded across clients")
	}
	a.Close()
	eventuallyAdmission(t, func() bool { return f.server.active.InUse() == 1 })
	c, err := other.OpenTCP(ctx, target, true)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !c.Compressed {
		t.Fatal("codec lease leaked after close")
	}
}
func TestClientActiveAndCodecLeaseLifetime(t *testing.T) {
	f := startTunnel(t, Options{Compression: true})
	c := secondClient(t, f, client.Options{Compression: true, MaxActiveStreams: 2, MaxCompressedStreams: 1})
	target := tcpOrigin(t, func(c net.Conn) { io.Copy(io.Discard, c) })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a, err := c.OpenTCP(ctx, target, true)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	a.CloseWrite()
	b, err := c.OpenTCP(ctx, target, true)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if b.Compressed {
		t.Fatal("half-close released codec before response side closed")
	}
	if d, err := c.OpenTCP(ctx, target, false); err == nil {
		d.Close()
		t.Fatal("client active budget exceeded")
	}
	a.Close()
	a.Close()
	d, err := c.OpenTCP(ctx, target, true)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if !d.Compressed {
		t.Fatal("client codec lease leaked")
	}
}
