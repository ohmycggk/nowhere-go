package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ohmycggk/nowhere-go/egress"
	"github.com/ohmycggk/nowhere-go/morph"
	"github.com/ohmycggk/nowhere-go/nw2/server"
	"github.com/ohmycggk/nowhere-go/nw2/wire"
	"github.com/ohmycggk/nowhere-go/portal"
	"github.com/ohmycggk/nowhere-go/qio"
	"github.com/ohmycggk/nowhere-go/runtime"
	"github.com/ohmycggk/nowhere-go/vector"
	nw3wire "github.com/ohmycggk/nowhere-go/wire"
)

func testProfile() runtime.Profile {
	return runtime.Profile{Name: "throughput", Stream: 64 << 10, Connection: 64 << 10, Send: 64 << 10}
}

func TestURLEdition(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef"
	nw3, err := urlEdition("portal://" + key + "@127.0.0.1:2000")
	if err != nil || nw3 != "nw3" {
		t.Fatalf("default %s %v", nw3, err)
	}
	nw2, err := urlEdition("vector://secret@127.0.0.1:2000?socks=:1080")
	if err != nil || nw2 != "nw2" {
		t.Fatalf("nw2 %s %v", nw2, err)
	}
	if _, err := urlEdition("portal://" + key + "@127.0.0.1:2000?in=:1080&socks=:1080"); err == nil {
		t.Fatal("mixed options accepted")
	}
	if _, err := urlEdition("vector://" + key + "@127.0.0.1:2000?up=tcp&cipher=aes&socks=:1080"); err == nil {
		t.Fatal("nw2 and cipher mixed options accepted")
	}
	cfg, err := parseNW3("portal://"+key+"@127.0.0.1:2000", true)
	if err != nil || !cfg.morph || cfg.cipher != morph.CipherChaCha || cfg.endpoint.udp == nil {
		t.Fatalf("default nw3 portal %+v %v", cfg, err)
	}
	if len(mustServerALPN(t, cfg)) != 1 || mustServerALPN(t, cfg)[0] != nw3wire.ALPN {
		t.Fatal("nw3 portal would advertise more than nw3")
	}
}

func TestParseNW3CipherLiteralFirstDuplicateAndDisabledValidation(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef"
	parse := func(query string) (nw3Config, error) {
		return parseNW3("vector://"+key+"@127.0.0.1:2000?in=127.0.0.1:1080&"+query, true)
	}
	aesCfg, err := parse("%63ipher=chacha&cipher=%61es&cipher=%ZZ")
	if err != nil {
		t.Fatalf("literal cipher query failed: %v", err)
	}
	if !aesCfg.morph || aesCfg.cipher != morph.CipherAES {
		t.Fatalf("got morph=%v cipher=%v, want true/aes", aesCfg.morph, aesCfg.cipher)
	}
	disabledCfg, err := parse("morph=0&cipher=aes")
	if err != nil {
		t.Fatalf("morph=0&cipher=aes failed: %v", err)
	}
	if disabledCfg.morph {
		t.Fatal("morph=0 unexpectedly enabled morph")
	}
	for _, query := range []string{
		"morph=0&cipher=AES",
		"cipher",
		"cipher=&cipher=aes",
		"cipher=%FF",
		"cipher=%ZZ",
	} {
		if _, err := parse(query); err == nil {
			t.Fatalf("query %q unexpectedly accepted", query)
		}
	}
	// Role-specific unknown options with invalid values or percent-encoding are ignored.
	if _, err := parseNW3("portal://"+key+"@127.0.0.1:2000?in=%ZZ&pin=wrong&cipher=aes", true); err != nil {
		t.Fatalf("portal rejected unknown options: %v", err)
	}
	if _, err := parseNW3("vector://"+key+"@127.0.0.1:2000?in=127.0.0.1:1080&out=%ZZ&dial=bad&cipher=aes", true); err != nil {
		t.Fatalf("vector rejected unknown options: %v", err)
	}
	if _, err := parseNW3("egress://"+key+"@127.0.0.1:2000?in=%ZZ&out=%ZZ&cipher=aes", true); err != nil {
		t.Fatalf("egress rejected unknown options: %v", err)
	}
}

func TestMorphQUICAndEgressAESAndMismatch(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef"
	cert := testLeaf(t)
	aesKeys, err := morph.DeriveWithCipher([]byte(key), morph.CipherAES)
	if err != nil {
		t.Fatal(err)
	}
	chachaKeys := morph.Derive([]byte(key))

	// QUIC Portal with AES-128-CTR + QUIC Egress with AES-128-CTR.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	packet, err := morph.WrapPacketConn(pc, aesKeys, false)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := listenNW3QUIC(packet, &tls.Config{Certificates: []tls.Certificate{cert}}, 0, testProfile(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv, err := portal.New(portal.Config{
		SharedKey:        key,
		Morph:            true,
		MorphCipher:      morph.CipherAES,
		TLS:              &tls.Config{Certificates: []tls.Certificate{cert}},
		Egress:           true,
		DatagramOverhead: nw3DatagramOverhead(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.ServeQUIC(ctx, ln) }()

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) }(c)
		}
	}()

	dialWithKeys := func(keys morph.Keys) func(context.Context) (qio.Conn, error) {
		return func(ctx context.Context) (qio.Conn, error) {
			raw, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				return nil, err
			}
			wrapped, err := morph.WrapPacketConn(raw, keys, true)
			if err != nil {
				_ = raw.Close()
				return nil, err
			}
			conn, err := dialNW3QUIC(ctx, wrapped, pc.LocalAddr().String(), &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         "nowhere",
				NextProtos:         []string{nw3wire.ALPN},
			}, 0, testProfile(), true)
			if err != nil {
				_ = wrapped.Close()
				return nil, err
			}
			return conn, nil
		}
	}

	egCtx, egCancel := context.WithCancel(context.Background())
	defer egCancel()
	go func() {
		_ = egress.Run(egCtx, egress.Config{
			SharedKey:        key,
			Morph:            true,
			MorphCipher:      morph.CipherAES,
			DialQUIC:         dialWithKeys(aesKeys),
			Upstream:         portal.Direct{},
			DatagramOverhead: nw3DatagramOverhead(true),
		})
	}()

	aesClient, err := vector.New(vector.Config{
		SharedKey:        key,
		Morph:            true,
		MorphCipher:      morph.CipherAES,
		DialQUIC:         dialWithKeys(aesKeys),
		DatagramOverhead: nw3DatagramOverhead(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer aesClient.Close()

	host, port, _ := net.SplitHostPort(echoLn.Addr().String())
	target, err := nw3wire.NewIPTarget(netip.MustParseAddr(host), parsePort(port))
	if err != nil {
		t.Fatal(err)
	}
	var conn net.Conn
	deadline := time.Now().Add(5 * time.Second)
	for {
		flowCtx, cancelFlow := context.WithTimeout(context.Background(), 2*time.Second)
		conn, err = aesClient.OpenTCP(flowCtx, target)
		cancelFlow()
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("aes quic egress flow: %v", err)
	}
	if _, err := conn.Write([]byte("aes!")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "aes!" {
		t.Fatalf("got %q, want aes!", buf)
	}
	_ = conn.Close()

	// ChaCha20 client cannot handshake with an AES QUIC Portal.
	wrongClient, err := vector.New(vector.Config{
		SharedKey:        key,
		Morph:            true,
		MorphCipher:      morph.CipherChaCha,
		DialQUIC:         dialWithKeys(chachaKeys),
		DatagramOverhead: nw3DatagramOverhead(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer wrongClient.Close()
	badCtx, cancelBad := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancelBad()
	if badConn, err := wrongClient.OpenTCP(badCtx, target); err == nil {
		_ = badConn.Close()
		t.Fatal("chacha client unexpectedly connected to aes quic portal")
	}
}

func TestFingerprintAESCipher(t *testing.T) {
	t.Setenv(runtime.EnvHandshakeTimeout, "300ms")
	key := "0123456789abcdef0123456789abcdef"
	cert := testLeaf(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv, err := portal.New(portal.Config{
		SharedKey:   key,
		Morph:       true,
		MorphCipher: morph.CipherAES,
		TLS:         &tls.Config{Certificates: []tls.Certificate{cert}},
		Upstream:    portal.Direct{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	want := wire.LeafCertificateSHA256Hex(cert.Certificate[0])
	got, err := fetchCertificateFingerprint(ln.Addr().String(), key, "127.0.0.1", "nowhere", true, true, morph.CipherAES)
	if err != nil {
		t.Fatalf("fingerprint with aes: %v", err)
	}
	if got != want {
		t.Fatalf("fingerprint = %s, want %s", got, want)
	}
	if _, err := fetchCertificateFingerprint(ln.Addr().String(), key, "127.0.0.1", "nowhere", true, true, morph.CipherChaCha); err == nil {
		t.Fatal("fingerprint with mismatched chacha cipher unexpectedly succeeded")
	}
}

func TestServeNW3UDPCleansUpOnControlClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srvConnCh := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		srvConnCh <- c
	}()
	cliConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cliConn.Close()
	srvConn := <-srvConnCh
	defer srvConn.Close()

	done := make(chan error, 1)
	go func() {
		done <- serveNW3UDP(context.Background(), nil, srvConn, wire.Target{
			Type: wire.TargetTypeIPv4,
			Addr: netip.MustParseAddr("0.0.0.0"),
		}, newLogger(logNone))
	}()
	// Read SOCKS5 UDP ASSOCIATE success reply (10 bytes for IPv4).
	reply := make([]byte, 10)
	_ = cliConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(cliConn, reply); err != nil {
		t.Fatalf("read socks reply: %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("socks reply status = %#x, want 0", reply[1])
	}
	// Closing the TCP control connection must unblock serveNW3UDP immediately
	// without waiting for another UDP datagram.
	_ = cliConn.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serveNW3UDP returned error after control close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("serveNW3UDP hung after control connection closed")
	}
}

func TestMorphUDPDropsUnsupportedVersion(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef"
	cert := testLeaf(t)
	for _, morphing := range []bool{false, true} {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		packet := pc
		if morphing {
			packet, err = morph.WrapPacketConn(pc, morph.Derive([]byte(key)), false)
			if err != nil {
				t.Fatal(err)
			}
		}
		ln, err := listenNW3QUIC(packet, &tls.Config{Certificates: []tls.Certificate{cert}}, 0, testProfile(), false)
		if err != nil {
			t.Fatal(err)
		}
		srv, err := portal.New(portal.Config{
			SharedKey: key,
			TLS:       &tls.Config{Certificates: []tls.Certificate{cert}},
			Upstream:  portal.Direct{},
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		go func() { _ = srv.ServeQUIC(ctx, ln) }()

		probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		body := make([]byte, 1200)
		body[0] = 0xc0
		body[1], body[2], body[3], body[4] = 0x0a, 0x1a, 0x2a, 0x3a
		body[5] = 8
		target := pc.LocalAddr().(*net.UDPAddr)
		if morphing {
			client, err := morph.WrapPacketConn(probe, morph.Derive([]byte(key)), true)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.WriteTo(body, target); err != nil {
				t.Fatal(err)
			}
		} else if _, err := probe.WriteTo(body, target); err != nil {
			t.Fatal(err)
		}
		if morphing {
			// One more copy, so a single delayed reply cannot be mistaken for a drop.
			client, err := morph.WrapPacketConn(probe, morph.Derive([]byte(key)), true)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.WriteTo(body, target); err != nil {
				t.Fatal(err)
			}
		}
		wait := 200 * time.Millisecond
		if morphing {
			wait = 500 * time.Millisecond
		}
		_ = probe.SetReadDeadline(time.Now().Add(wait))
		buf := make([]byte, 1500)
		n, err := probe.Read(buf)
		if morphing {
			if err == nil {
				t.Fatalf("morph udp answered unsupported version with %d bytes", n)
			}
		} else if err != nil || n < 7 || buf[0]&0x80 == 0 || !bytes.Equal(buf[1:5], []byte{0, 0, 0, 0}) {
			t.Fatalf("plain udp version negotiation: n=%d err=%v head=%x", n, err, buf[:min(n, 7)])
		}
		cancel()
		_ = ln.Close()
		_ = probe.Close()
		_ = pc.Close()
	}
}

func TestMorphQUICStillHandshakes(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef"
	cert := testLeaf(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	packet, err := morph.WrapPacketConn(pc, morph.Derive([]byte(key)), false)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := listenNW3QUIC(packet, &tls.Config{Certificates: []tls.Certificate{cert}}, 0, testProfile(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv, err := portal.New(portal.Config{
		SharedKey: key,
		Morph:     true,
		TLS:       &tls.Config{Certificates: []tls.Certificate{cert}},
		Upstream:  portal.Direct{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.ServeQUIC(ctx, ln) }()

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		c, err := echoLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()

	client, err := vector.New(vector.Config{
		SharedKey: key,
		Morph:     true,
		DialQUIC: func(ctx context.Context) (qio.Conn, error) {
			raw, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				return nil, err
			}
			wrapped, err := morph.WrapPacketConn(raw, morph.Derive([]byte(key)), true)
			if err != nil {
				return nil, err
			}
			return dialNW3QUIC(ctx, wrapped, pc.LocalAddr().String(), &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         "nowhere",
				NextProtos:         []string{nw3wire.ALPN},
			}, 0, testProfile(), false)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	flowCtx, cancelFlow := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFlow()
	host, port, _ := net.SplitHostPort(echoLn.Addr().String())
	target, err := nw3wire.NewIPTarget(netip.MustParseAddr(host), parsePort(port))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := client.OpenTCP(flowCtx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("morph")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "morph" {
		t.Fatalf("got %q", buf)
	}
}

func TestNW3QUICFlows(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef"
	cert := testLeaf(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	ln, err := listenNW3QUIC(pc, &tls.Config{Certificates: []tls.Certificate{cert}}, 0, testProfile(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv, err := portal.New(portal.Config{
		SharedKey: key,
		TLS:       &tls.Config{Certificates: []tls.Certificate{cert}},
		Upstream:  portal.Direct{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.ServeQUIC(ctx, ln) }()

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) }(c)
		}
	}()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = udp.WriteTo(append([]byte(nil), buf[:n]...), addr)
		}
	}()

	client, err := vector.New(vector.Config{
		SharedKey: key,
		DialQUIC: func(ctx context.Context) (qio.Conn, error) {
			packet, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				return nil, err
			}
			return dialNW3QUIC(ctx, packet, pc.LocalAddr().String(), &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         "nowhere",
				NextProtos:         []string{nw3wire.ALPN},
			}, 0, testProfile(), false)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	host, port, _ := net.SplitHostPort(echoLn.Addr().String())
	target, err := nw3wire.NewIPTarget(netip.MustParseAddr(host), parsePort(port))
	if err != nil {
		t.Fatal(err)
	}
	flowCtx, cancelFlow := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancelFlow()
	conn, err := client.OpenTCP(flowCtx, target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("quic")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "quic" {
		t.Fatalf("tcp %q", buf)
	}
	_ = conn.Close()

	_, udpPort, _ := net.SplitHostPort(udp.LocalAddr().String())
	uTarget, err := nw3wire.NewIPTarget(netip.MustParseAddr("127.0.0.1"), parsePort(udpPort))
	if err != nil {
		t.Fatal(err)
	}
	uc, err := client.OpenUDP(flowCtx, uTarget)
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	if _, err := uc.Write([]byte("udp!")); err != nil {
		t.Fatal(err)
	}
	_ = uc.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := uc.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "udp!" {
		t.Fatalf("udp %q", buf[:n])
	}
}

func TestEgressBusy(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef"
	cert := testLeaf(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	ln, err := listenNW3QUIC(pc, &tls.Config{Certificates: []tls.Certificate{cert}}, 0, testProfile(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv, err := portal.New(portal.Config{
		SharedKey: key,
		TLS:       &tls.Config{Certificates: []tls.Certificate{cert}},
		Egress:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.ServeQUIC(ctx, ln) }()

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) }(c)
		}
	}()
	dial := func(ctx context.Context) (qio.Conn, error) {
		packet, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		return dialNW3QUIC(ctx, packet, pc.LocalAddr().String(), &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "nowhere",
			NextProtos:         []string{nw3wire.ALPN},
		}, 0, testProfile(), false)
	}
	egCtx, egCancel := context.WithCancel(context.Background())
	defer egCancel()
	go func() {
		_ = egress.Run(egCtx, egress.Config{SharedKey: key, DialQUIC: dial, Upstream: portal.Direct{}})
	}()

	client, err := vector.New(vector.Config{SharedKey: key, DialQUIC: dial})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	host, port, _ := net.SplitHostPort(echoLn.Addr().String())
	target, err := nw3wire.NewIPTarget(netip.MustParseAddr(host), parsePort(port))
	if err != nil {
		t.Fatal(err)
	}
	var conn net.Conn
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err = client.OpenTCP(context.Background(), target)
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("exit")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	// A second QUIC Egress joins the FIFO instead of being rejected. QUIC has
	// no pending cap; BUSY is the TLS registration limit.
	second, err := vector.New(vector.Config{SharedKey: key, DialQUIC: dial})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	again, err := second.OpenTCP(context.Background(), target)
	if err != nil {
		t.Fatalf("second egress flow: %v", err)
	}
	_ = again.Close()
}

func TestCrossALPNRejected(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef"
	cert := testLeaf(t)
	nw3Ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer nw3Ln.Close()
	nw3Srv, err := portal.New(portal.Config{
		SharedKey: key,
		TLS:       &tls.Config{Certificates: []tls.Certificate{cert}},
		Upstream:  portal.Direct{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = nw3Srv.Serve(ctx, nw3Ln) }()
	if err := handshakeALPN(nw3Ln.Addr().String(), "nw2"); err == nil {
		t.Fatal("nw2 client completed a handshake with an nw3 portal")
	}

	creds, err := wire.NewCredentials(key)
	if err != nil {
		t.Fatal(err)
	}
	nw2Cfg, err := server.NewConfig(server.ConfigOptions{
		Credentials: creds,
		Networks:    []server.Network{server.NetworkTCP},
	})
	if err != nil {
		t.Fatal(err)
	}
	nw2Srv, err := server.NewServer(server.ServerOptions{
		Config:   nw2Cfg,
		TLS:      &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{wire.DefaultALPN}},
		Upstream: server.NewDialUpstream(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	nw2Ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer nw2Ln.Close()
	go func() { _ = nw2Srv.Serve(ctx, nw2Ln) }()
	client, err := vector.New(vector.Config{
		SharedKey:  key,
		PortalAddr: nw2Ln.Addr().String(),
		TLS:        &tls.Config{InsecureSkipVerify: true, ServerName: "nowhere"},
		DialTCP: func(ctx context.Context, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	target, err := nw3wire.NewIPTarget(netip.MustParseAddr("127.0.0.1"), 9)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.OpenTCP(context.Background(), target); err == nil {
		t.Fatal("nw3 client completed a handshake with an nw2 portal")
	}
}

func handshakeALPN(addr, alpn string) error {
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer raw.Close()
	client := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{alpn},
		ServerName:         "nowhere",
	})
	return client.Handshake()
}

func mustServerALPN(t *testing.T, cfg nw3Config) []string {
	t.Helper()
	tlsCfg, err := loadServerTLSALPN(cfg.certPath, cfg.keyPath, cfg.tlsMode, nw3wire.ALPN)
	if err != nil {
		t.Fatal(err)
	}
	return tlsCfg.NextProtos
}

func testLeaf(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "nowhere"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"nowhere"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func parsePort(s string) uint16 {
	var n int
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return uint16(n)
}
