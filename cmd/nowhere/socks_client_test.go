package main

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestSocksDialerTCPConnect(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		c, err := echo.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()

	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	go serveTestSOCKSConnect(proxy)

	d := &socksDialer{addr: proxy.Addr().String()}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("got %q", buf)
	}
}

func TestParsePortalSOCKSOutbound(t *testing.T) {
	cfg, err := parseCommandURL("portal://secret@127.0.0.1:2000?socks=user:pass@127.0.0.1:1080")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.socks != "127.0.0.1:1080" || cfg.socksUser != "user" || cfg.socksPass != "pass" {
		t.Fatalf("%+v", cfg)
	}
	if _, err := parseCommandURL("portal://secret@127.0.0.1:2000?socks=127.0.0.1:1080&next=k@h:1"); err == nil {
		t.Fatal("socks+next should fail")
	}
}

func serveTestSOCKSConnect(ln net.Listener) {
	c, err := ln.Accept()
	if err != nil {
		return
	}
	defer c.Close()
	if err := socksHandshake(c, "", ""); err != nil {
		return
	}
	cmd, target, err := socksReadRequest(c)
	if err != nil || cmd != socksCmdConnect {
		return
	}
	remote, err := net.Dial("tcp", targetAddr(target))
	if err != nil {
		_ = socksReply(c, 0x05, c.LocalAddr())
		return
	}
	defer remote.Close()
	if err := socksReply(c, 0x00, c.LocalAddr()); err != nil {
		return
	}
	relay(c, remote)
}
