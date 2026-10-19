package acl

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"wanopt/internal/protocol"
)

type lookupFunc func(context.Context, string, string) ([]netip.Addr, error)

func (f lookupFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}
func domain(host string) protocol.Address {
	return protocol.Address{Atyp: protocol.AtypDomain, Host: host, Port: 443}
}
func TestNumericDomainCannotBypassCIDRDeny(t *testing.T) {
	l, err := New(nil, []string{"127.0.0.0/8", "::1/128"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := NewResolver(l, time.Second, 1)
	for _, host := range []string{"127.0.0.1", "127.0.0.1.", "::1", "::ffff:127.0.0.1"} {
		t.Run(host, func(t *testing.T) {
			if l.Allowed(domain(host)) {
				t.Fatal("numeric wire-domain bypass")
			}
			if _, err := r.Resolve(context.Background(), domain(host)); !errors.Is(err, ErrDenied) {
				t.Fatalf("got %v", err)
			}
		})
	}
}
func TestResolvedIPDeniesOverrideDomainAllow(t *testing.T) {
	l, _ := New([]string{"example.test"}, []string{"127.0.0.0/8"}, nil, nil)
	r := NewResolver(l, time.Second, 1)
	r.lookup = lookupFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("192.0.2.1")}, nil
	})
	got, err := r.Resolve(context.Background(), domain("Sub.Example.Test."))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got[0].IP.Equal(net.ParseIP("192.0.2.1")) {
		t.Fatalf("unapproved endpoint retained: %#v", got)
	}
	l, _ = New([]string{"192.0.2.0/24"}, nil, nil, nil)
	r.policy = l
	if got, err = r.Resolve(context.Background(), domain("arbitrary.test")); err != nil || len(got) != 1 {
		t.Fatalf("CIDR allow must apply to resolved addresses: %v %v", got, err)
	}
}
func TestDomainDenialDoesNotResolve(t *testing.T) {
	l, _ := New([]string{"example.test"}, []string{"blocked.example.test"}, nil, nil)
	r := NewResolver(l, time.Second, 1)
	r.lookup = lookupFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		t.Fatal("denied domain resolved")
		return nil, nil
	})
	if _, err := r.Resolve(context.Background(), domain("blocked.example.test")); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
}
func TestDialUsesExactlyOneApprovedResolution(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var calls atomic.Int32
	l, _ := New([]string{"service.test"}, nil, nil, nil)
	r := NewResolver(l, time.Second, 1)
	r.lookup = lookupFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		if calls.Add(1) > 1 {
			return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	})
	addr := domain("service.test")
	addr.Port = uint16(listener.Addr().(*net.TCPAddr).Port)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := r.DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if calls.Load() != 1 {
		t.Fatalf("resolved %d times", calls.Load())
	}
}
func TestDNSConcurrencyAndTimeout(t *testing.T) {
	r := NewResolver(nil, 40*time.Millisecond, 1)
	started := make(chan struct{})
	r.lookup = lookupFunc(func(ctx context.Context, _ string, _ string) ([]netip.Addr, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	done := make(chan error, 1)
	go func() { _, e := r.Resolve(context.Background(), domain("slow.test")); done <- e }()
	<-started
	if _, e := r.Resolve(context.Background(), domain("other.test")); !errors.Is(e, ErrBusy) {
		t.Fatalf("unbounded DNS: %v", e)
	}
	select {
	case e := <-done:
		if !errors.Is(e, context.DeadlineExceeded) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("DNS timeout failed")
	}
}
func TestInvalidPolicyPortsAndNamesFailClosed(t *testing.T) {
	for _, port := range []int{-1, 0, 65536} {
		if _, e := New(nil, nil, []int{port}, nil); e == nil {
			t.Fatalf("accepted invalid port %d", port)
		}
	}
	for _, host := range []string{"", "name with spaces", "host/path", "a..test"} {
		if _, e := New([]string{host}, nil, nil, nil); e == nil && host != "" {
			t.Fatalf("accepted invalid name %q", host)
		}
	}
}
