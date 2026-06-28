// Package acl implements a destination allow/deny policy for the server's
// egress. Rules match on host (domain suffix or IP/CIDR); ports are matched
// separately. Deny always wins; a non-empty allow list switches the host (or
// port) dimension into whitelist mode.
package acl

import (
	"net"
	"strings"

	"wanopt/internal/protocol"
)

// List is a compiled access-control policy. The zero value allows everything.
type List struct {
	allowHosts []rule
	denyHosts  []rule
	allowPorts map[uint16]bool
	denyPorts  map[uint16]bool
}

type rule struct {
	cidr   *net.IPNet // set for IP/CIDR rules
	domain string     // set (lowercased) for domain rules
}

// New compiles allow/deny host patterns and port lists into a List.
func New(allowHosts, denyHosts []string, allowPorts, denyPorts []int) (*List, error) {
	l := &List{allowPorts: map[uint16]bool{}, denyPorts: map[uint16]bool{}}
	var err error
	if l.allowHosts, err = parseRules(allowHosts); err != nil {
		return nil, err
	}
	if l.denyHosts, err = parseRules(denyHosts); err != nil {
		return nil, err
	}
	for _, p := range allowPorts {
		l.allowPorts[uint16(p)] = true
	}
	for _, p := range denyPorts {
		l.denyPorts[uint16(p)] = true
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
			_, ipnet, err := net.ParseCIDR(s)
			if err != nil {
				return nil, err
			}
			out = append(out, rule{cidr: ipnet})
			continue
		}
		if ip := net.ParseIP(s); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			out = append(out, rule{cidr: &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}})
			continue
		}
		out = append(out, rule{domain: strings.ToLower(strings.TrimPrefix(s, "*."))})
	}
	return out, nil
}

// Allowed reports whether the destination passes the policy.
func (l *List) Allowed(addr protocol.Address) bool {
	if l == nil {
		return true
	}
	// Port dimension.
	if l.denyPorts[addr.Port] {
		return false
	}
	if len(l.allowPorts) > 0 && !l.allowPorts[addr.Port] {
		return false
	}
	// Host dimension.
	if matchAny(l.denyHosts, addr) {
		return false
	}
	if len(l.allowHosts) > 0 && !matchAny(l.allowHosts, addr) {
		return false
	}
	return true
}

func matchAny(rules []rule, addr protocol.Address) bool {
	host := strings.ToLower(strings.TrimSuffix(addr.Host, "."))
	for _, r := range rules {
		switch {
		case r.cidr != nil:
			if addr.Atyp != protocol.AtypDomain && r.cidr.Contains(addr.IP) {
				return true
			}
		case r.domain != "":
			if addr.Atyp == protocol.AtypDomain &&
				(host == r.domain || strings.HasSuffix(host, "."+r.domain)) {
				return true
			}
		}
	}
	return false
}
