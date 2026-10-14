package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"

	"github.com/ohmycggk/nowhere-go/egress"
	"github.com/ohmycggk/nowhere-go/flowio"
	"github.com/ohmycggk/nowhere-go/morph"
	"github.com/ohmycggk/nowhere-go/nw2/wire"
	"github.com/ohmycggk/nowhere-go/portal"
	"github.com/ohmycggk/nowhere-go/qio"
	"github.com/ohmycggk/nowhere-go/vector"
	nw3wire "github.com/ohmycggk/nowhere-go/wire"
)

func runNW3(ctx context.Context, cfg nw3Config, log *logger) error {
	switch cfg.kind {
	case nw3Portal:
		return runNW3Portal(ctx, cfg, log)
	case nw3Vector:
		return runNW3Vector(ctx, cfg, log)
	case nw3Egress:
		return runNW3Egress(ctx, cfg, log)
	default:
		return fmt.Errorf("unknown command")
	}
}

func runNW3Portal(ctx context.Context, cfg nw3Config, log *logger) error {
	tlsCfg, err := loadServerTLSALPN(cfg.certPath, cfg.keyPath, cfg.tlsMode, nw3wire.ALPN)
	if err != nil {
		return err
	}
	if fp, err := serverCertFingerprintHex(tlsCfg); err == nil {
		log.info("TLS certificate SHA-256 fingerprint: %s", fp)
	}
	var upstream portal.Upstream
	if cfg.exit != nw3ExitEgress {
		fd := familyDialer{policy: cfg.dial}
		if cfg.exit == nw3ExitSocks {
			log.info("portal outbound socks %s", cfg.socks)
			upstream = socksUpstream{socksDialer{
				addr: cfg.socks, user: cfg.socksUser, pass: cfg.socksPass, fd: fd,
			}}
		} else {
			upstream = directUpstream{fd}
		}
	}
	srv, err := portal.New(portal.Config{
		SharedKey:    cfg.key,
		Morph:        cfg.morph,
		TLS:          tlsCfg,
		Upstream:     upstream,
		Egress:       cfg.exit == nw3ExitEgress,
		UploadMbps:   cfg.rate,
		DownloadMbps: cfg.etar,
	})
	if err != nil {
		return err
	}
	errCh := make(chan error, 2)
	if cfg.endpoint.hasTCP() {
		ln, _, err := listenAll("tcp", listenHosts(cfg.endpoint.host, cfg.endpoint.tcp.family), cfg.endpoint.tcp.port, log)
		if err != nil {
			return err
		}
		go func() { errCh <- srv.Serve(ctx, ln) }()
	}
	if cfg.endpoint.hasUDP() {
		qln, err := listenNW3UDP(cfg, tlsCfg, false, log)
		if err != nil {
			return err
		}
		go func() { errCh <- srv.ServeQUIC(ctx, qln) }()
	}
	return waitDone(ctx, errCh)
}

func runNW3Vector(ctx context.Context, cfg nw3Config, log *logger) error {
	client, err := newNW3Vector(ctx, cfg)
	if err != nil {
		return err
	}
	defer client.Close()
	ln, _, err := listenSOCKS(cfg.inAddr, log)
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
			go serveNW3SOCKS(ctx, client, conn, cfg.inUser, cfg.inPass, log)
		}
	}()
	return waitDone(ctx, errCh)
}

func runNW3Egress(ctx context.Context, cfg nw3Config, log *logger) error {
	fd := familyDialer{policy: cfg.dial}
	tlsCfg, err := clientTLSConfigALPN(cfg.sni, cfg.pin, cfg.endpoint.host, nw3wire.ALPN)
	if err != nil {
		return err
	}
	return egress.Run(ctx, egress.Config{
		SharedKey: cfg.key,
		DialQUIC: func(ctx context.Context) (qio.Conn, error) {
			return dialNW3Carrier(ctx, cfg, tlsCfg, true)
		},
		Upstream:     directUpstream{fd},
		UploadMbps:   cfg.rate,
		DownloadMbps: cfg.etar,
	})
}

func newNW3Vector(ctx context.Context, cfg nw3Config) (*vector.Client, error) {
	tlsCfg, err := clientTLSConfigALPN(cfg.sni, cfg.pin, cfg.endpoint.host, nw3wire.ALPN)
	if err != nil {
		return nil, err
	}
	vc := vector.Config{
		SharedKey:    cfg.key,
		Morph:        cfg.morph,
		UploadMbps:   cfg.rate,
		DownloadMbps: cfg.etar,
	}
	if cfg.endpoint.hasUDP() && !cfg.endpoint.hasTCP() {
		vc.DialQUIC = func(dialCtx context.Context) (qio.Conn, error) {
			return dialNW3Carrier(dialCtx, cfg, tlsCfg, true)
		}
	} else {
		vc.PortalAddr = cfg.endpoint.tcpAddr()
		vc.TLS = tlsCfg
		vc.DialTCP = func(dialCtx context.Context, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
		}
	}
	client, err := vector.New(vc)
	if err != nil {
		return nil, err
	}
	_ = ctx
	return client, nil
}

func dialNW3Carrier(ctx context.Context, cfg nw3Config, tlsCfg *tls.Config, client bool) (qio.Conn, error) {
	pc, err := net.ListenPacket("udp", "")
	if err != nil {
		return nil, err
	}
	if cfg.morph {
		pc = morph.WrapPacketConn(pc, morph.Derive([]byte(cfg.key)), client)
	}
	conn, err := dialNW3QUIC(ctx, pc, cfg.endpoint.udpAddr(), tlsCfg)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	return conn, nil
}

func listenNW3UDP(cfg nw3Config, tlsCfg *tls.Config, client bool, log *logger) (qio.Listener, error) {
	pcs, _, err := listenUDPPacket(cfg.endpoint.host, cfg.endpoint.udp.port, cfg.endpoint.udp.family, log)
	if err != nil {
		return nil, err
	}
	var listeners []qio.Listener
	for _, pc := range pcs {
		if cfg.morph {
			pc = morph.WrapPacketConn(pc, morph.Derive([]byte(cfg.key)), client)
		}
		ln, err := listenNW3QUIC(pc, tlsCfg)
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, ln)
	}
	if len(listeners) == 1 {
		return listeners[0], nil
	}
	return &multiNW3{listeners: listeners, ch: make(chan qioAccept)}, nil
}

type qioAccept struct {
	c   qio.Conn
	err error
}

type multiNW3 struct {
	listeners []qio.Listener
	ch        chan qioAccept
	once      sync.Once
}

func (m *multiNW3) Accept(ctx context.Context) (qio.Conn, error) {
	m.once.Do(func() {
		for _, ln := range m.listeners {
			go func(ln qio.Listener) {
				for {
					c, err := ln.Accept(context.Background())
					m.ch <- qioAccept{c, err}
					if err != nil {
						return
					}
				}
			}(ln)
		}
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-m.ch:
		return res.c, res.err
	}
}

func (m *multiNW3) Close() error {
	var err error
	for _, ln := range m.listeners {
		if e := ln.Close(); e != nil {
			err = e
		}
	}
	return err
}

type directUpstream struct{ d familyDialer }

func (u directUpstream) DialTCP(ctx context.Context, target nw3wire.Target) (net.Conn, error) {
	return u.d.DialContext(ctx, "tcp", target.HostPort())
}

func (u directUpstream) DialUDP(ctx context.Context, target nw3wire.Target) (net.Conn, error) {
	return u.d.DialContext(ctx, "udp", target.HostPort())
}

type socksUpstream struct{ socksDialer }

func (s socksUpstream) DialTCP(ctx context.Context, target nw3wire.Target) (net.Conn, error) {
	return s.DialContext(ctx, "tcp", target.HostPort())
}

func (s socksUpstream) DialUDP(ctx context.Context, target nw3wire.Target) (net.Conn, error) {
	return s.DialContext(ctx, "udp", target.HostPort())
}

func serveNW3SOCKS(ctx context.Context, client *vector.Client, conn net.Conn, user, pass string, log *logger) {
	defer conn.Close()
	var cmd byte
	var target wire.Target
	if err := setupWithShutdown(ctx, func() error {
		if err := socksHandshake(conn, user, pass); err != nil {
			return err
		}
		var err error
		cmd, target, err = socksReadRequest(conn)
		return err
	}); err != nil {
		return
	}
	switch cmd {
	case socksCmdConnect:
		nt, err := toNW3Target(target)
		if err != nil {
			_ = socksReply(conn, 0x04, conn.LocalAddr())
			return
		}
		remote, err := client.OpenTCP(ctx, nt)
		if err != nil {
			_ = socksReply(conn, 0x05, conn.LocalAddr())
			log.debug("open tcp %s: %v", nt.HostPort(), err)
			return
		}
		defer remote.Close()
		if err := socksReply(conn, 0x00, conn.LocalAddr()); err != nil {
			return
		}
		flowio.Relay(conn, remote, nil, nil)
	case socksCmdUDP:
		if err := serveNW3UDP(ctx, client, conn, target, log); err != nil {
			log.debug("udp associate: %v", err)
		}
	default:
		_ = socksReply(conn, 0x07, conn.LocalAddr())
	}
}

func serveNW3UDP(ctx context.Context, client *vector.Client, control net.Conn, requested wire.Target, log *logger) error {
	peerHost, _, err := net.SplitHostPort(control.RemoteAddr().String())
	if err != nil {
		_ = socksReply(control, 0x01, nil)
		return err
	}
	peerIP := net.ParseIP(peerHost)
	peerAddr, peerOK := netip.AddrFromSlice(peerIP)
	// A UDP ASSOCIATE request address is a source constraint, not a dial
	// target: the unspecified address means "any source", a matching IP with a
	// nonzero port pins the client source port. Domains are not constraints.
	var wantPort uint16
	if requested.Type == wire.TargetTypeDomain {
		_ = socksReply(control, 0x02, nil)
		return fmt.Errorf("domain udp source constraint unsupported")
	}
	if !peerOK || (!requested.Addr.Unmap().IsUnspecified() && requested.Addr.Unmap() != peerAddr.Unmap()) {
		_ = socksReply(control, 0x02, nil)
		return fmt.Errorf("udp source ip differs from control peer")
	}
	wantPort = requested.Port
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
	flows := map[destKey]net.Conn{}
	// expected pins the accepted client source: the request port when given,
	// otherwise the first datagram source. nil means nothing pinned yet.
	var expected *net.UDPAddr
	if wantPort != 0 {
		expected = &net.UDPAddr{IP: peerIP, Port: int(wantPort)}
	}
	defer func() {
		mu.Lock()
		for _, c := range flows {
			_ = c.Close()
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
		n, src, err := udp.ReadFrom(buf)
		if err != nil {
			return err
		}
		from, ok := src.(*net.UDPAddr)
		if !ok || !from.IP.Equal(peerIP) {
			continue
		}
		mu.Lock()
		if expected == nil {
			expected = from
		}
		accept := expected.Port == from.Port && expected.IP.Equal(from.IP)
		mu.Unlock()
		if !accept {
			continue
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
			nt, err := toNW3Target(target)
			if err != nil {
				continue
			}
			pc, err = client.OpenUDP(ctx, nt)
			if err != nil {
				log.debug("open udp %s: %v", nt.HostPort(), err)
				continue
			}
			mu.Lock()
			flows[key] = pc
			mu.Unlock()
			go func(pc net.Conn, src net.Addr, target wire.Target) {
				rbuf := make([]byte, 65535)
				for {
					n, err := pc.Read(rbuf)
					if err != nil {
						return
					}
					_ = n
					pkt, err := encodeSocksUDP(target, rbuf[:n])
					if err != nil {
						continue
					}
					_, _ = udp.WriteTo(pkt, src)
				}
			}(pc, src, target)
		}
		_, _ = pc.Write(payload)
	}
}

func toNW3Target(t wire.Target) (nw3wire.Target, error) {
	if t.Type == wire.TargetTypeDomain {
		return nw3wire.NewDomainTarget(t.Host, t.Port)
	}
	return nw3wire.NewIPTarget(t.Addr, t.Port)
}

// loadServerTLSALPN builds a portal certificate with a single ALPN.
func loadServerTLSALPN(certPath, keyPath string, mode int, alpn string) (*tls.Config, error) {
	cfg, err := loadServerTLS(appConfig{tlsMode: mode, certPath: certPath, keyPath: keyPath})
	if err != nil {
		return nil, err
	}
	cfg.NextProtos = []string{alpn}
	return cfg, nil
}

func clientTLSConfigALPN(sni, pin, host, alpn string) (*tls.Config, error) {
	cfg, err := clientTLSConfig(sni, pin, host)
	if err != nil {
		return nil, err
	}
	cfg.NextProtos = []string{alpn}
	return cfg, nil
}

// Keep io import used when relay paths type-check in editors that drop it.
var _ = io.EOF
