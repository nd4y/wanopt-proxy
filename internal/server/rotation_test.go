package server

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
	"wanopt/internal/client"
)

func TestLiveCredentialRotationRetainsGraceAndRevokesOld(t *testing.T) {
	f := startTunnel(t, Options{})
	target := tcpOrigin(t, func(c net.Conn) { io.Copy(c, c) })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	old, err := f.client.OpenTCP(ctx, target, false)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	key := bytes.Repeat([]byte{8}, 32)
	previous := bytes.Repeat([]byte{7}, 32)
	if err := f.server.ReloadCredentials(key, previous, time.Now().Add(time.Hour), f.cert); err != nil {
		t.Fatal(err)
	}
	exchange := func(c net.Conn) {
		t.Helper()
		c.SetDeadline(time.Now().Add(time.Second))
		if _, err := c.Write([]byte("ok")); err != nil {
			t.Fatal(err)
		}
		var b [2]byte
		if _, err := io.ReadFull(c, b[:]); err != nil || string(b[:]) != "ok" {
			t.Fatal("live exchange failed", err)
		}
	}
	exchange(old)
	fresh := secondClient(t, f, client.Options{PSK: key})
	newStream, err := fresh.OpenTCP(ctx, target, false)
	if err != nil {
		t.Fatal(err)
	}
	defer newStream.Close()
	exchange(newStream)
	if err := f.server.ReloadCredentials(key, nil, time.Time{}, f.cert); err != nil {
		t.Fatal(err)
	}
	old.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := old.Read(b[:]); err == nil {
		t.Fatal("revoked session remained open")
	}
	exchange(newStream)
}
func TestPreviousKeyExpiryClosesExistingSessions(t *testing.T) {
	f := startTunnel(t, Options{})
	target := tcpOrigin(t, func(c net.Conn) { io.Copy(io.Discard, c) })
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	old, err := f.client.OpenTCP(ctx, target, false)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	if err := f.server.ReloadCredentials(bytes.Repeat([]byte{9}, 32), bytes.Repeat([]byte{7}, 32), time.Now().Add(50*time.Millisecond), f.cert); err != nil {
		t.Fatal(err)
	}
	old.SetReadDeadline(time.Now().Add(2 * time.Second))
	var b [1]byte
	if _, err := old.Read(b[:]); err == nil {
		t.Fatal("expired session survived")
	}
}
