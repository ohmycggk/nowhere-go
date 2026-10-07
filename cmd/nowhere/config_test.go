package main

import "testing"

const (
	testListenerKey = "0123456789abcdef0123456789abcdef" // 32 lowercase hex
	testNextKey     = "fedcba9876543210fedcba9876543210" // 32 lowercase hex
)

func TestParsePortalCompact(t *testing.T) {
	cfg, err := parseCommandURL("portal://" + testListenerKey + "@:2000")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.kind != kindPortal || cfg.key != testListenerKey {
		t.Fatalf("%+v", cfg)
	}
	if cfg.endpoint.host != "*" || cfg.endpoint.tcp == nil || cfg.endpoint.tcp.port != 2000 {
		t.Fatalf("endpoint %+v", cfg.endpoint)
	}
	if !cfg.endpoint.hasUDP() {
		t.Fatal("compact form should enable UDP")
	}
}

func TestParseVectorRequiresSocks(t *testing.T) {
	if _, err := parseCommandURL("vector://secret@127.0.0.1:2000"); err == nil {
		t.Fatal("expected socks required")
	}
	cfg, err := parseCommandURL("vector://secret@127.0.0.1:2000?socks=:1080")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.socks != ":1080" && cfg.socks != "[::]:1080" && cfg.socks != "0.0.0.0:1080" {
		if cfg.socks == "" {
			t.Fatal("empty socks")
		}
	}
}

func TestParseExplicitCarriers(t *testing.T) {
	cfg, err := parseCommandURL("portal://" + testListenerKey + "@*/tcp:2006/udp:2017")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.endpoint.tcp.port != 2006 || cfg.endpoint.udp.port != 2017 {
		t.Fatalf("%+v", cfg.endpoint)
	}
}

func TestParseRejectsMixCarrier(t *testing.T) {
	if _, err := parseCommandURL("vector://secret@127.0.0.1:2000?up=mix&socks=:1080"); err == nil {
		t.Fatal("expected up=mix to fail")
	}
	if _, err := parseCommandURL("vector://secret@127.0.0.1:2000?down=mix&socks=:1080"); err == nil {
		t.Fatal("expected down=mix to fail")
	}
	cfg, err := parseCommandURL("vector://secret@127.0.0.1:2000?up=tcp&down=udp&socks=:1080")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.up != "tcp" || cfg.down != "udp" {
		t.Fatalf("up=%q down=%q", cfg.up, cfg.down)
	}
}

func TestParseRejectsPassword(t *testing.T) {
	if _, err := parseCommandURL("portal://secret:pass@127.0.0.1:2000"); err == nil {
		t.Fatal("password accepted")
	}
}

func TestParseNextHop(t *testing.T) {
	cfg, err := parseCommandURL("portal://" + testListenerKey + "@:2000?next=" + testNextKey + "@origin.example:2000")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.next == nil || cfg.next.key != testNextKey || cfg.next.endpoint.host != "origin.example" {
		t.Fatalf("next %+v", cfg.next)
	}
}
