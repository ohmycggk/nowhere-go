package main

import (
	"net/url"
	"strings"
	"testing"
)

func TestValidateListenerKey(t *testing.T) {
	const rule = "shared key must be 32\u201364 lowercase hexadecimal characters; use nowhere generate-key"
	ok := []string{
		strings.Repeat("a", 32),
		strings.Repeat("0", 33), // odd length accepted
		strings.Repeat("f", 64),
		strings.Repeat("0123456789abcdef", 4), // 64 chars
	}
	for _, k := range ok {
		if err := validateListenerKey(k); err != nil {
			t.Fatalf("valid key %q rejected: %v", k, err)
		}
	}
	bad := []string{
		strings.Repeat("a", 31),                                 // too short
		strings.Repeat("a", 65),                                 // too long
		strings.Repeat("A", 32),                                 // uppercase
		"g" + strings.Repeat("a", 31),                           // non-hex
		" " + strings.Repeat("a", 32),                           // leading whitespace
		strings.Repeat("a", 32) + " ",                           // trailing whitespace
		strings.Repeat("a", 16) + " " + strings.Repeat("a", 15), // embedded whitespace
		"%25" + strings.Repeat("a", 30),                         // double-percent-encoding leaves a '%'
	}
	for _, k := range bad {
		err := validateListenerKey(k)
		if err == nil {
			t.Fatalf("invalid key %q accepted", k)
		}
		if err.Error() != rule {
			t.Fatalf("key %q error = %q, want %q", k, err.Error(), rule)
		}
	}
}

func TestPortalListenerKeyRuleMessage(t *testing.T) {
	_, err := parseCommandURL("portal://secret@:2000")
	if err == nil {
		t.Fatal("short portal key accepted")
	}
	want := "Portal listener: shared key must be 32\u201364 lowercase hexadecimal characters; use nowhere generate-key"
	if err.Error() != want {
		t.Fatalf("got %q want %q", err.Error(), want)
	}
}

func TestParseLogLevelRejectsEvent(t *testing.T) {
	_, err := parseLogLevel("event")
	if err == nil {
		t.Fatal("log=event accepted")
	}
	want := `log must be none, debug, info, warn, or error; found "event"`
	if err.Error() != want {
		t.Fatalf("got %q want %q", err.Error(), want)
	}
	for _, lvl := range []string{"none", "debug", "info", "warn", "error"} {
		if _, err := parseLogLevel(lvl); err != nil {
			t.Fatalf("level %q rejected: %v", lvl, err)
		}
	}
}

func TestEndpointSanitizedMessages(t *testing.T) {
	u, err := url.Parse("vector://x@[::1]/tcp4:2000")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseServiceEndpoint(u, false, "Vector endpoint"); err == nil || !strings.Contains(err.Error(), "address family does not match host") {
		t.Fatalf("family mismatch = %v", err)
	} else if strings.Contains(err.Error(), "::1") {
		t.Fatalf("family error echoes host: %v", err)
	}

	u, err = url.Parse("vector://x@host/sctp:2000")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseServiceEndpoint(u, false, "Vector endpoint"); err == nil ||
		err.Error() != "Vector endpoint: unknown carrier; expected tcp, tcp4, tcp6, udp, udp4, or udp6" {
		t.Fatalf("unknown carrier = %v", err)
	}
}

func TestFingerprintShareLinkRejections(t *testing.T) {
	if err := runFingerprint("portal://" + testListenerKey + "@relay.example:2000"); err == nil ||
		err.Error() != "fingerprint requires a nowhere:// share link" {
		t.Fatalf("non-nowhere scheme = %v", err)
	}
	if err := runFingerprint("nowhere://" + testListenerKey + "@relay.example/udp:2000"); err == nil ||
		err.Error() != "fingerprint requires a TCP carrier in the Nowhere share link" {
		t.Fatalf("no tcp carrier = %v", err)
	}
	if err := runFingerprint("nowhere://" + testListenerKey + "@relay.example/tcp4:2000"); err == nil ||
		err.Error() != "Nowhere share-link carrier paths support only tcp and udp" {
		t.Fatalf("r4 suffix = %v", err)
	}
}

func TestParseProbeTarget(t *testing.T) {
	if _, err := parseProbeTarget("example.com"); err == nil {
		t.Fatal("bare host accepted")
	}
	if _, err := parseProbeTarget("example.com:0"); err == nil {
		t.Fatal("port 0 accepted")
	}
	target, err := parseProbeTarget("example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if target.Type != 0x03 || target.Port != 443 {
		t.Fatalf("target %+v", target)
	}
}
