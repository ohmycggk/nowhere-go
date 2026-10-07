package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strings"
)

// dialMode selects between the legacy single-source policy and the Nowhere 2.2
// dual-stack per-family policy.
type dialMode uint8

const (
	dialLegacy dialMode = iota
	dialDualStack
)

// dialPolicy mirrors upstream common::dial::DialPolicy. A zero value is the
// "auto" policy: no source binding and no family restriction.
type dialPolicy struct {
	mode   dialMode
	legacy net.IP // dialLegacy: single source IP and single-family restriction (nil = auto)
	v4     net.IP // dialDualStack: IPv4 source (nil = auto)
	v6     net.IP // dialDualStack: IPv6 source (nil = auto)
}

// configured reports whether any source address is pinned. When it is not, the
// familyDialer defers to a plain net.Dialer and preserves default behavior.
func (p dialPolicy) configured() bool {
	if p.mode == dialLegacy {
		return p.legacy != nil
	}
	return p.v4 != nil || p.v6 != nil
}

// accepts reports whether target's address family is permitted by the policy.
// Only the legacy single-source mode restricts the family.
func (p dialPolicy) accepts(target net.IP) bool {
	if p.mode == dialLegacy && p.legacy != nil {
		return isIPv4(p.legacy) == isIPv4(target)
	}
	return true
}

// sourceFor returns the outbound source IP for a target of the given family, or
// nil to let the kernel choose. The legacy policy errors when the target family
// conflicts with its single pinned source.
func (p dialPolicy) sourceFor(target net.IP) (net.IP, error) {
	if !p.accepts(target) {
		return nil, errDialFamilyConflict
	}
	switch p.mode {
	case dialDualStack:
		if isIPv4(target) {
			return p.v4, nil
		}
		return p.v6, nil
	default:
		return p.legacy, nil
	}
}

func isIPv4(ip net.IP) bool { return ip.To4() != nil }

var (
	errDialFamilyConflict = errors.New("target address family conflicts with dial")
	errDialNoAddr         = errors.New("no target address matches the configured address family")
)

// parseDialPolicy validates the dial/dial4/dial6 query parameters exactly as
// upstream DialPolicy::from_query does. Presence matters even for empty values.
func parseDialPolicy(query url.Values) (dialPolicy, error) {
	_, hasDial := query["dial"]
	_, hasDial4 := query["dial4"]
	_, hasDial6 := query["dial6"]
	if hasDial && (hasDial4 || hasDial6) {
		return dialPolicy{}, errors.New("dial and dial4/dial6 are mutually exclusive")
	}
	if hasDial4 || hasDial6 {
		var p dialPolicy
		p.mode = dialDualStack
		if v := query.Get("dial4"); v != "" && v != "auto" {
			addr, err := netip.ParseAddr(v)
			if err != nil || !addr.Is4() {
				return dialPolicy{}, errors.New("dial4 must be auto or an IPv4 literal")
			}
			p.v4 = net.IP(addr.AsSlice())
		}
		if v := query.Get("dial6"); v != "" && v != "auto" {
			addr, err := netip.ParseAddr(v)
			if err != nil || addr.Is4() {
				return dialPolicy{}, errors.New("dial6 must be auto or an IPv6 literal")
			}
			if addr.Is4In6() {
				return dialPolicy{}, errors.New("dial6 must not be an IPv4-mapped IPv6 address")
			}
			p.v6 = net.IP(addr.AsSlice())
		}
		return p, nil
	}
	var p dialPolicy
	p.mode = dialLegacy
	if v := query.Get("dial"); v != "" && v != "auto" {
		ip := net.ParseIP(v)
		if ip == nil {
			return dialPolicy{}, errors.New("dial must be auto or an IP literal")
		}
		p.legacy = ip
	}
	return p, nil
}

// familyDialer binds outbound connections to a source address chosen by the
// resolved target's address family. It satisfies server.Dialer and the
// tcptls.TCPDialer interface, so it plugs into every existing dial path without
// a library change.
type familyDialer struct {
	policy dialPolicy
}

func (d familyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if !d.policy.configured() {
		var nd net.Dialer
		return nd.DialContext(ctx, network, address)
	}
	switch {
	case strings.HasPrefix(network, "tcp"):
		return d.dialTCP(ctx, address)
	case strings.HasPrefix(network, "udp"):
		return d.dialUDP(ctx, address)
	default:
		var nd net.Dialer
		return nd.DialContext(ctx, network, address)
	}
}

func (d familyDialer) dialTCP(ctx context.Context, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ip, err := d.selectAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	src, err := d.policy.sourceFor(ip)
	if err != nil {
		return nil, err
	}
	nd := &net.Dialer{}
	network := "tcp"
	if src != nil {
		nd.LocalAddr = &net.TCPAddr{IP: src}
		if isIPv4(src) {
			network = "tcp4"
		} else {
			network = "tcp6"
		}
	}
	return nd.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
}

func (d familyDialer) dialUDP(ctx context.Context, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ip, err := d.selectAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	src, err := d.policy.sourceFor(ip)
	if err != nil {
		return nil, err
	}
	nd := &net.Dialer{}
	network := "udp"
	if src != nil {
		nd.LocalAddr = &net.UDPAddr{IP: src}
		if isIPv4(src) {
			network = "udp4"
		} else {
			network = "udp6"
		}
	}
	return nd.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
}

// listenPacket binds a UDP socket for the QUIC carrier. When a family source is
// configured it binds to the source matching the endpoint's resolved family;
// otherwise it listens on the wildcard, matching the unconfigured behavior.
func (d familyDialer) listenPacket(addr string) (net.PacketConn, error) {
	if !d.policy.configured() {
		return net.ListenPacket("udp", "")
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return net.ListenPacket("udp", "")
	}
	ip, err := d.selectAddr(context.Background(), host)
	if err != nil {
		// Resolution failure here is not fatal for binding; the eventual QUIC
		// dial resolves and reports the real error.
		return net.ListenPacket("udp", "")
	}
	src, err := d.policy.sourceFor(ip)
	if err != nil || src == nil {
		return net.ListenPacket("udp", "")
	}
	network := "udp6"
	if isIPv4(src) {
		network = "udp4"
	}
	return net.ListenPacket(network, net.JoinHostPort(src.String(), "0"))
}

// selectAddr resolves host and returns the first address accepted by the policy.
// An IP literal is returned directly without touching the resolver.
func (d familyDialer) selectAddr(ctx context.Context, host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if !d.policy.accepts(ip) {
			return nil, errDialFamilyConflict
		}
		return ip, nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		if d.policy.accepts(a.IP) {
			return a.IP, nil
		}
	}
	return nil, errDialNoAddr
}
