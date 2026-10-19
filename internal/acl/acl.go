// Package acl applies destination policies to names and their resolved addresses.
// Domain allow rules never override an IP deny rule. Call Resolver.DialContext,
// rather than resolving again after Allowed, when enforcing network boundaries.
package acl

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"wanopt/internal/protocol"
)

var (
	ErrDenied  = errors.New("acl: destination denied")
	ErrBusy    = errors.New("acl: DNS concurrency limit reached")
	ErrAddress = errors.New("acl: invalid destination")
)

type List struct {
	allowHosts []rule
	denyHosts  []rule
	allowPorts map[uint16]bool
	denyPorts  map[uint16]bool
}
type rule struct {
	cidr   *net.IPNet
	domain string
}

func New(allowHosts, denyHosts []string, allowPorts, denyPorts []int) (*List, error) {
	l := &List{allowPorts: map[uint16]bool{}, denyPorts: map[uint16]bool{}}
	var err error
	if l.allowHosts, err = parseRules(allowHosts); err != nil {
		return nil, err
	}
	if l.denyHosts, err = parseRules(denyHosts); err != nil {
		return nil, err
	}
	for _, spec := range []struct {
		ports []int
		dst   map[uint16]bool
	}{{allowPorts, l.allowPorts}, {denyPorts, l.denyPorts}} {
		for _, p := range spec.ports {
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("acl: port %d outside 1..65535", p)
			}
			spec.dst[uint16(p)] = true
		}
	}
	return l, nil
}
func parseRules(specs []string) ([]rule, error) {
	out := make([]rule, 0, len(specs))
	for _, s := range specs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if strings.Contains(s, "/") {
			_, n, e := net.ParseCIDR(s)
			if e != nil {
				return nil, e
			}
			out = append(out, rule{cidr: n})
			continue
		}
		if ip := net.ParseIP(s); ip != nil {
			bits := 128
			if v4 := ip.To4(); v4 != nil {
				ip = v4
				bits = 32
			}
			out = append(out, rule{cidr: &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}})
			continue
		}
		s = canonicalName(strings.TrimPrefix(s, "*."))
		if !validName(s) {
			return nil, fmt.Errorf("acl: invalid host pattern %q", s)
		}
		out = append(out, rule{domain: s})
	}
	return out, nil
}
func canonicalName(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".")) }
func validName(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}
func normalized(addr protocol.Address) (protocol.Address, error) {
	if addr.Port == 0 {
		return protocol.Address{}, ErrAddress
	}
	if addr.Atyp == protocol.AtypDomain {
		addr.Host = canonicalName(addr.Host)
		if ip := net.ParseIP(addr.Host); ip != nil {
			addr.IP = ip
			addr.Host = ""
		} else {
			if !validName(addr.Host) {
				return protocol.Address{}, ErrAddress
			}
			return addr, nil
		}
	} else if addr.Atyp != protocol.AtypIPv4 && addr.Atyp != protocol.AtypIPv6 {
		return protocol.Address{}, ErrAddress
	}
	if v4 := addr.IP.To4(); v4 != nil {
		addr.Atyp = protocol.AtypIPv4
		addr.IP = v4
	} else if v6 := addr.IP.To16(); v6 != nil {
		addr.Atyp = protocol.AtypIPv6
		addr.IP = v6
	} else {
		return protocol.Address{}, ErrAddress
	}
	return addr, nil
}
func (l *List) portsAllowed(port uint16) bool {
	return l == nil || !l.denyPorts[port] && (len(l.allowPorts) == 0 || l.allowPorts[port])
}
func matchAny(rules []rule, addr protocol.Address) bool {
	for _, r := range rules {
		if r.cidr != nil && addr.Atyp != protocol.AtypDomain && r.cidr.Contains(addr.IP) {
			return true
		}
		if r.domain != "" && addr.Atyp == protocol.AtypDomain && (addr.Host == r.domain || strings.HasSuffix(addr.Host, "."+r.domain)) {
			return true
		}
	}
	return false
}

// Allowed checks literal addresses and domain rules without DNS. Use Resolve or
// DialContext to enforce IP policies for names and connect to checked addresses.
func (l *List) Allowed(addr protocol.Address) bool {
	a, err := normalized(addr)
	if err != nil || !l.portsAllowed(a.Port) {
		return false
	}
	return l == nil || !matchAny(l.denyHosts, a) && (len(l.allowHosts) == 0 || matchAny(l.allowHosts, a))
}
func (l *List) resolvedAllowed(original, ip protocol.Address) bool {
	if !l.portsAllowed(original.Port) {
		return false
	}
	if l == nil {
		return true
	}
	if matchAny(l.denyHosts, original) || matchAny(l.denyHosts, ip) {
		return false
	}
	return len(l.allowHosts) == 0 || matchAny(l.allowHosts, original) || matchAny(l.allowHosts, ip)
}

type ipLookup interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// Resolver bounds DNS work globally across a server, applies name and IP policy,
// and dials numeric results without a second resolution (including rebinding).
type Resolver struct {
	policy  *List
	lookup  ipLookup
	slots   chan struct{}
	timeout time.Duration
}

func NewResolver(policy *List, timeout time.Duration, concurrency int) *Resolver {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if concurrency <= 0 {
		concurrency = 32
	}
	return &Resolver{policy: policy, lookup: net.DefaultResolver, slots: make(chan struct{}, concurrency), timeout: timeout}
}
func (r *Resolver) Resolve(ctx context.Context, addr protocol.Address) ([]protocol.Address, error) {
	a, err := normalized(addr)
	if err != nil {
		return nil, err
	}
	if !r.policy.portsAllowed(a.Port) {
		return nil, ErrDenied
	}
	if a.Atyp != protocol.AtypDomain {
		if !r.policy.Allowed(a) {
			return nil, ErrDenied
		}
		return []protocol.Address{a}, nil
	}
	if r.policy != nil && matchAny(r.policy.denyHosts, a) {
		return nil, ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r.slots <- struct{}{}:
		defer func() { <-r.slots }()
	default:
		return nil, ErrBusy
	}
	ips, err := r.lookup.LookupNetIP(ctx, "ip", a.Host)
	if err != nil {
		return nil, err
	}
	out := make([]protocol.Address, 0, len(ips))
	seen := make(map[netip.Addr]bool, len(ips))
	for _, ip := range ips {
		ip = ip.Unmap()
		if !ip.IsValid() || seen[ip] {
			continue
		}
		seen[ip] = true
		candidate := protocol.Address{IP: net.IP(ip.AsSlice()), Port: a.Port, Atyp: protocol.AtypIPv6}
		if ip.Is4() {
			candidate.Atyp = protocol.AtypIPv4
		}
		if r.policy.resolvedAllowed(a, candidate) {
			out = append(out, candidate)
		}
	}
	if len(out) == 0 {
		return nil, ErrDenied
	}
	return out, nil
}

// DialContext connects only to the numeric endpoints approved by Resolve.
// TCP races the two address families with a bounded 250 ms fallback delay.
func (r *Resolver) DialContext(ctx context.Context, network string, addr protocol.Address) (net.Conn, error) {
	addresses, err := r.Resolve(ctx, addr)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if !strings.HasPrefix(network, "tcp") || len(addresses) == 1 {
		return dialAddresses(ctx, network, addresses)
	}
	primary := []protocol.Address{}
	fallback := []protocol.Address{}
	for _, a := range addresses {
		if a.Atyp == addresses[0].Atyp {
			primary = append(primary, a)
		} else {
			fallback = append(fallback, a)
		}
	}
	if len(fallback) == 0 {
		return dialAddresses(ctx, network, primary)
	}
	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result)
	run := func(addrs []protocol.Address) {
		conn, err := dialAddresses(ctx, network, addrs)
		select {
		case results <- result{conn, err}:
		case <-ctx.Done():
			if conn != nil {
				conn.Close()
			}
		}
	}
	go run(primary)
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	started := false
	var firstErr error
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			if !started {
				started = true
				go run(fallback)
			}
		case got := <-results:
			if got.err == nil {
				return got.conn, nil
			}
			if firstErr != nil {
				return nil, errors.Join(firstErr, got.err)
			}
			firstErr = got.err
			if !started {
				started = true
				go run(fallback)
			}
		}
	}
}
func dialAddresses(ctx context.Context, network string, addresses []protocol.Address) (net.Conn, error) {
	var last error
	for i, a := range addresses {
		timeout := 10 * time.Second
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline) / time.Duration(len(addresses)-i)
			if remaining < timeout {
				timeout = remaining
			}
		}
		if timeout <= 0 {
			return nil, context.DeadlineExceeded
		}
		d := net.Dialer{Timeout: timeout}
		conn, err := d.DialContext(ctx, network, a.String())
		if err == nil {
			return conn, nil
		}
		last = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, last
}
