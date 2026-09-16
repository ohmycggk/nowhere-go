package main

import "testing"

func TestParsePortalCompact(t *testing.T) {
	cfg, err := parseCommandURL("portal://secret@:2000")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.kind != kindPortal || cfg.key != "secret" {
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
	cfg, err := parseCommandURL("portal://k@*/tcp:2006/udp:2017")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.endpoint.tcp.port != 2006 || cfg.endpoint.udp.port != 2017 {
		t.Fatalf("%+v", cfg.endpoint)
	}
}

func TestParseRejectsPassword(t *testing.T) {
	if _, err := parseCommandURL("portal://secret:pass@127.0.0.1:2000"); err == nil {
		t.Fatal("password accepted")
	}
}

func TestParseNextHop(t *testing.T) {
	cfg, err := parseCommandURL("portal://a@:2000?next=b@origin.example:2000")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.next == nil || cfg.next.key != "b" || cfg.next.endpoint.host != "origin.example" {
		t.Fatalf("next %+v", cfg.next)
	}
}
