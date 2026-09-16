package main

import (
	"context"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/ohmycggk/nowhere-go/bundle"
	"github.com/ohmycggk/nowhere-go/wire"
)

func runVector(ctx context.Context, cfg appConfig, log *logger) error {
	client, err := newBundle(cfg.key, cfg.endpoint, cfg.up, cfg.down, cfg.mux, cfg.sni, cfg.pin, cfg.morph, log)
	if err != nil {
		return err
	}
	defer client.Close()

	ln, _, err := listenSOCKS(cfg.socks, log)
	if err != nil {
		return err
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				errCh <- err
				return
			}
			go serveSOCKSClient(ctx, client, conn, cfg.socksUser, cfg.socksPass, log)
		}
	}()
	return waitDone(ctx, errCh)
}

func listenSOCKS(addr string, log *logger) (net.Listener, []string, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, nil, err
	}
	port, _ := strconv.Atoi(portStr)
	family := familyAny
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			family = familyV4
		} else {
			family = familyV6
		}
	}
	if host == "" {
		host = "*"
	}
	return listenAll("tcp", listenHosts(host, family), port, log)
}

func serveSOCKSClient(ctx context.Context, client *bundle.CarrierBundle, conn net.Conn, user, pass string, log *logger) {
	defer conn.Close()
	if err := socksHandshake(conn, user, pass); err != nil {
		log.debug("socks handshake: %v", err)
		return
	}
	cmd, target, err := socksReadRequest(conn)
	if err != nil {
		log.debug("socks request: %v", err)
		return
	}
	switch cmd {
	case socksCmdConnect:
		remote, err := client.OpenTCP(ctx, target)
		if err != nil {
			_ = socksReply(conn, 0x05, conn.LocalAddr())
			log.debug("open tcp %v: %v", targetAddr(target), err)
			return
		}
		defer remote.Close()
		if err := socksReply(conn, 0x00, conn.LocalAddr()); err != nil {
			return
		}
		relay(conn, remote)
	case socksCmdUDP:
		if err := serveUDPAssociate(ctx, client, conn, log); err != nil {
			log.debug("udp associate: %v", err)
		}
	default:
		_ = socksReply(conn, 0x07, conn.LocalAddr())
	}
}

func serveUDPAssociate(ctx context.Context, client *bundle.CarrierBundle, control net.Conn, log *logger) error {
	udp, err := net.ListenPacket("udp", bindUDPFor(control))
	if err != nil {
		_ = socksReply(control, 0x01, nil)
		return err
	}
	defer udp.Close()
	if err := socksReply(control, 0x00, udp.LocalAddr()); err != nil {
		return err
	}

	type destKey struct {
		host string
		port uint16
	}
	var mu sync.Mutex
	flows := map[destKey]net.PacketConn{}
	defer func() {
		mu.Lock()
		for _, pc := range flows {
			_ = pc.Close()
		}
		mu.Unlock()
	}()

	done := make(chan struct{})
	go func() {
		buf := make([]byte, 1)
		_, _ = control.Read(buf)
		close(done)
	}()

	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
			return nil
		default:
		}
		_ = udp.SetReadDeadline(time.Now().Add(time.Second))
		n, src, err := udp.ReadFrom(buf)
		if err != nil {
			select {
			case <-done:
				return nil
			default:
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return err
			}
		}
		target, payload, err := decodeSocksUDP(buf[:n])
		if err != nil {
			continue
		}
		key := destKey{host: targetHost(target), port: target.Port}
		mu.Lock()
		pc := flows[key]
		mu.Unlock()
		if pc == nil {
			pc, err = client.OpenUDPAsync(ctx, target)
			if err != nil {
				log.debug("open udp %v: %v", targetAddr(target), err)
				continue
			}
			mu.Lock()
			flows[key] = pc
			mu.Unlock()
			go relayUDPDown(udp, pc, src, target)
		}
		_, _ = pc.WriteTo(payload, nil)
		_ = src
	}
}

func relayUDPDown(socks net.PacketConn, flow net.PacketConn, client net.Addr, target wire.Target) {
	buf := make([]byte, 65535)
	for {
		n, _, err := flow.ReadFrom(buf)
		if err != nil {
			return
		}
		pkt, err := encodeSocksUDP(target, buf[:n])
		if err != nil {
			continue
		}
		_, _ = socks.WriteTo(pkt, client)
	}
}

func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(a, b); done <- struct{}{} }()
	go func() { _, _ = io.Copy(b, a); done <- struct{}{} }()
	<-done
	_ = a.Close()
	_ = b.Close()
	<-done
}

func bindUDPFor(control net.Conn) string {
	host, _, err := net.SplitHostPort(control.LocalAddr().String())
	if err != nil {
		return ":0"
	}
	return net.JoinHostPort(host, "0")
}

func targetAddr(t wire.Target) string {
	return net.JoinHostPort(targetHost(t), strconv.Itoa(int(t.Port)))
}

func targetHost(t wire.Target) string {
	if t.Type == wire.TargetTypeDomain {
		return t.Host
	}
	return t.Addr.String()
}

