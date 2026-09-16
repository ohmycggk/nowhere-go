package main

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/ohmycggk/nowhere-go/bundle"
	"github.com/ohmycggk/nowhere-go/carrier/morph"
	"github.com/ohmycggk/nowhere-go/carrier/tcptls"
	"github.com/ohmycggk/nowhere-go/server"
	"github.com/ohmycggk/nowhere-go/wire"
)

func runPortal(ctx context.Context, cfg appConfig, log *logger) error {
	creds, err := wire.NewCredentials(cfg.key)
	if err != nil {
		return err
	}
	tlsCfg, err := loadServerTLS(cfg)
	if err != nil {
		return err
	}
	networks := make([]server.Network, 0, 2)
	if cfg.endpoint.hasTCP() {
		networks = append(networks, server.NetworkTCP)
	}
	if cfg.endpoint.hasUDP() {
		networks = append(networks, server.NetworkUDP)
	}
	var morphKey []byte
	if cfg.morph {
		morphKey = []byte(cfg.key)
	}
	srvCfg, err := server.NewConfig(server.ConfigOptions{
		Credentials:    creds,
		Networks:       networks,
		MorphSharedKey: morphKey,
	})
	if err != nil {
		return err
	}

	upstream, closer, err := portalUpstream(cfg, log)
	if err != nil {
		return err
	}
	if closer != nil {
		defer closer()
	}

	var quicLn server.QuicListener
	if cfg.endpoint.hasUDP() {
		pcs, _, err := listenUDPPacket(cfg.endpoint.host, cfg.endpoint.udp.port, cfg.endpoint.udp.family, log)
		if err != nil {
			return err
		}
		var listeners []*serverListener
		for _, pc := range pcs {
			if cfg.morph {
				pc = morph.WrapPacketConn(pc, morph.Derive([]byte(cfg.key)).UDP)
			}
			ln, err := listenQUIC(pc, tlsCfg)
			if err != nil {
				return err
			}
			listeners = append(listeners, ln)
		}
		quicLn = newMultiQuicListener(listeners)
	}

	srv, err := server.NewServer(server.ServerOptions{
		Config:       srvCfg,
		TLS:          tlsCfg,
		Upstream:     upstream,
		Observer:     log,
		QUICListener: quicLn,
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
		go func() { errCh <- srv.ServeQUIC(ctx) }()
	}
	err = waitDone(ctx, errCh)
	_ = srv.Shutdown(context.Background())
	return err
}

func portalUpstream(cfg appConfig, log *logger) (server.Upstream, func(), error) {
	if cfg.next == nil {
		d := net.Dialer{}
		if ip := net.ParseIP(cfg.dial); ip != nil {
			d.LocalAddr = &net.TCPAddr{IP: ip}
		}
		if cfg.socks != "" {
			log.info("portal outbound socks %s", cfg.socks)
			return server.NewDialUpstream(&socksDialer{
				addr: cfg.socks, user: cfg.socksUser, pass: cfg.socksPass, d: d,
			}), nil, nil
		}
		return server.NewDialUpstream(&d), nil, nil
	}
	client, err := newBundle(cfg.next.key, cfg.next.endpoint, cfg.up, cfg.down, cfg.mux, cfg.sni, cfg.pin, cfg.morph, log)
	if err != nil {
		return nil, nil, err
	}
	up, err := server.NewPortalUpstream(client)
	if err != nil {
		_ = client.Close()
		return nil, nil, err
	}
	return up, func() { _ = client.Close() }, nil
}

func newBundle(key string, endpoint serviceEndpoint, up, down string, mux bundle.MuxMode, sni, pin string, enableMorph bool, log *logger) (*bundle.CarrierBundle, error) {
	creds, err := wire.NewCredentials(key)
	if err != nil {
		return nil, err
	}
	tlsCfg, err := clientTLSConfig(sni, pin)
	if err != nil {
		return nil, err
	}
	upC, downC, mixUp, mixDown := routeCarriers(up, down)
	usesTCP := endpoint.hasTCP() && (up != "udp" || down != "udp" || mixUp || mixDown)
	usesQUIC := endpoint.hasUDP() && (up != "tcp" || down != "tcp" || mixUp || mixDown)
	if mixUp || mixDown {
		usesTCP, usesQUIC = endpoint.hasTCP(), endpoint.hasUDP()
	}

	opts := bundle.BundleOptions{
		Credentials: creds,
		Up:          upC,
		Down:        downC,
		MixUp:       mixUp,
		MixDown:     mixDown,
		Mux:         mux,
		Observer:    log,
	}
	var morphKey []byte
	if enableMorph {
		morphKey = []byte(key)
	}
	if usesTCP {
		tcpAddr := endpoint.tcpAddr()
		if tcpAddr == "" {
			return nil, fmt.Errorf("TCP carrier required")
		}
		tcp, err := tcptls.NewConfig(tcptls.TCPOptions{
			Address:        tcpAddr,
			Dialer:         netDialer{},
			TLSDialer:      stdTLSDialer{cfg: tlsCfg},
			Observer:       log,
			MorphSharedKey: morphKey,
		})
		if err != nil {
			return nil, err
		}
		opts.TCP = tcp
	}
	if usesQUIC {
		udpAddr := endpoint.udpAddr()
		if udpAddr == "" {
			return nil, fmt.Errorf("UDP carrier required")
		}
		var pc net.PacketConn
		pc, err = net.ListenPacket("udp", "")
		if err != nil {
			return nil, err
		}
		if enableMorph {
			pc = morph.WrapPacketConn(pc, morph.Derive([]byte(key)).UDP)
		}
		opts.QUIC = newClientBackend(udpAddr, tlsCfg, pc)
		opts.PoolSize = 0
	}
	if mux == bundle.MuxEnabled {
		opts.PoolSize = 0
	}
	if usesTCP && !usesQUIC && mux == bundle.MuxDisabled {
		opts.PoolSize = tcptls.DefaultPoolSize
	}
	return bundle.NewCarrierBundle(opts)
}

func copyConn(dst, src net.Conn) {
	_, _ = io.Copy(dst, src)
	_ = dst.Close()
}
