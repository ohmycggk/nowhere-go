package main

import (
	"errors"
	"net"
	"net/url"
	"testing"
)

func mustValues(t *testing.T, raw string) url.Values {
	t.Helper()
	u, err := url.Parse("http://x/?" + raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}

func TestParseDialPolicy(t *testing.T) {
	cases := []struct {
		name    string
		query   string
		wantErr string
		check   func(t *testing.T, p dialPolicy)
	}{
		{name: "unset is legacy auto", query: "", check: func(t *testing.T, p dialPolicy) {
			if p.mode != dialLegacy || p.legacy != nil || p.configured() {
				t.Fatalf("got %+v", p)
			}
		}},
		{name: "dial=auto", query: "dial=auto", check: func(t *testing.T, p dialPolicy) {
			if p.mode != dialLegacy || p.legacy != nil {
				t.Fatalf("got %+v", p)
			}
		}},
		{name: "dial v4", query: "dial=1.2.3.4", check: func(t *testing.T, p dialPolicy) {
			if p.mode != dialLegacy || p.legacy.String() != "1.2.3.4" {
				t.Fatalf("got %+v", p)
			}
		}},
		{name: "dial v6", query: "dial=2001:db8::1", check: func(t *testing.T, p dialPolicy) {
			if p.mode != dialLegacy || p.legacy.String() != "2001:db8::1" {
				t.Fatalf("got %+v", p)
			}
		}},
		{name: "dial invalid", query: "dial=notanip", wantErr: "dial must be auto or an IP literal"},
		{name: "dial4 literal", query: "dial4=10.0.0.1", check: func(t *testing.T, p dialPolicy) {
			if p.mode != dialDualStack || p.v4.String() != "10.0.0.1" || p.v6 != nil {
				t.Fatalf("got %+v", p)
			}
		}},
		{name: "dial4 auto", query: "dial4=auto", check: func(t *testing.T, p dialPolicy) {
			if p.mode != dialDualStack || p.v4 != nil || p.v6 != nil || p.configured() {
				t.Fatalf("got %+v", p)
			}
		}},
		{name: "dial6 literal", query: "dial6=2001:db8::5", check: func(t *testing.T, p dialPolicy) {
			if p.mode != dialDualStack || p.v6.String() != "2001:db8::5" {
				t.Fatalf("got %+v", p)
			}
		}},
		{name: "dial6 rejects v4 literal", query: "dial6=1.2.3.4", wantErr: "dial6 must be auto or an IPv6 literal"},
		{name: "dial6 rejects v4-mapped", query: "dial6=::ffff:1.2.3.4", wantErr: "dial6 must not be an IPv4-mapped IPv6 address"},
		{name: "dial4 rejects v6 literal", query: "dial4=::1", wantErr: "dial4 must be auto or an IPv4 literal"},
		{name: "dial and dial4 exclusive", query: "dial=1.2.3.4&dial4=10.0.0.1", wantErr: "dial and dial4/dial6 are mutually exclusive"},
		{name: "dial and dial6 exclusive", query: "dial=1.2.3.4&dial6=2001:db8::1", wantErr: "dial and dial4/dial6 are mutually exclusive"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseDialPolicy(mustValues(t, tc.query))
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.check != nil {
				tc.check(t, got)
			}
		})
	}
}

func TestDialPolicySourceFor(t *testing.T) {
	legacyV4 := dialPolicy{mode: dialLegacy, legacy: net.ParseIP("10.0.0.1")}
	if src, err := legacyV4.sourceFor(net.ParseIP("1.1.1.1")); err != nil || src.String() != "10.0.0.1" {
		t.Fatalf("legacy v4->v4: %v %v", src, err)
	}
	if _, err := legacyV4.sourceFor(net.ParseIP("2001:db8::1")); !errors.Is(err, errDialFamilyConflict) {
		t.Fatalf("legacy v4->v6 want conflict, got %v", err)
	}

	dual := dialPolicy{mode: dialDualStack, v4: net.ParseIP("10.0.0.1"), v6: net.ParseIP("2001:db8::1")}
	if src, _ := dual.sourceFor(net.ParseIP("8.8.8.8")); src.String() != "10.0.0.1" {
		t.Fatalf("dual v4 target: %v", src)
	}
	if src, _ := dual.sourceFor(net.ParseIP("2001:db8::9")); src.String() != "2001:db8::1" {
		t.Fatalf("dual v6 target: %v", src)
	}

	dualV4Only := dialPolicy{mode: dialDualStack, v4: net.ParseIP("10.0.0.1")}
	if src, _ := dualV4Only.sourceFor(net.ParseIP("2001:db8::9")); src != nil {
		t.Fatalf("dual v4-only on v6 target should be nil, got %v", src)
	}
}

func TestFamilyDialerConfiguredDelegates(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = c.Close()
	}()

	// Auto policy delegates to a plain dial.
	conn, err := (familyDialer{}).DialContext(t.Context(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	// A configured v4 source still reaches a v4 loopback target.
	fd := familyDialer{policy: dialPolicy{mode: dialLegacy, legacy: net.ParseIP("127.0.0.1")}}
	conn, err = fd.DialContext(t.Context(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if got := conn.LocalAddr().(*net.TCPAddr).IP.String(); got != "127.0.0.1" {
		t.Fatalf("local addr = %s", got)
	}
	_ = conn.Close()

	// A v6 source conflicts with the v4 loopback target.
	fdV6 := familyDialer{policy: dialPolicy{mode: dialLegacy, legacy: net.ParseIP("::1")}}
	if _, err := fdV6.DialContext(t.Context(), "tcp", ln.Addr().String()); !errors.Is(err, errDialFamilyConflict) {
		t.Fatalf("v6 source to v4 target: want conflict, got %v", err)
	}
}
