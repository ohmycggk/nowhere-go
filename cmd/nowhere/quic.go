package main

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/ohmycggk/nowhere-go/qio"
	"github.com/ohmycggk/nowhere-go/wire"
	"github.com/quic-go/quic-go"
)

func nw3QuicConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  120 * time.Second,
		Allow0RTT:       false,
	}
}

func nw3ServerTLS(base *tls.Config) *tls.Config {
	cfg := base.Clone()
	cfg.MinVersion = tls.VersionTLS13
	cfg.MaxVersion = tls.VersionTLS13
	cfg.NextProtos = []string{wire.ALPN}
	cfg.SessionTicketsDisabled = true
	return cfg
}

type nw3Listener struct{ ln *quic.Listener }

func listenNW3QUIC(pc net.PacketConn, tlsCfg *tls.Config) (*nw3Listener, error) {
	ln, err := quic.Listen(pc, nw3ServerTLS(tlsCfg), nw3QuicConfig())
	if err != nil {
		return nil, err
	}
	return &nw3Listener{ln: ln}, nil
}

func (l *nw3Listener) Accept(ctx context.Context) (qio.Conn, error) {
	c, err := l.ln.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return &nw3Conn{c: c}, nil
}

func (l *nw3Listener) Close() error { return l.ln.Close() }

func dialNW3QUIC(ctx context.Context, pc net.PacketConn, addr string, tlsCfg *tls.Config) (qio.Conn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	cfg := tlsCfg.Clone()
	cfg.MinVersion = tls.VersionTLS13
	cfg.MaxVersion = tls.VersionTLS13
	cfg.NextProtos = []string{wire.ALPN}
	cfg.ClientSessionCache = nil
	c, err := quic.Dial(ctx, pc, udpAddr, cfg, nw3QuicConfig())
	if err != nil {
		return nil, err
	}
	return &nw3Conn{c: c}, nil
}

type nw3Conn struct{ c *quic.Conn }

func (c *nw3Conn) TLSVersion() uint16 { return c.c.ConnectionState().TLS.Version }
func (c *nw3Conn) ALPN() string       { return c.c.ConnectionState().TLS.NegotiatedProtocol }
func (c *nw3Conn) Exporter() ([]byte, error) {
	st := c.c.ConnectionState().TLS
	return (&st).ExportKeyingMaterial(wire.ExporterLabel, []byte{}, wire.ExporterLen)
}
func (c *nw3Conn) AcceptStream(ctx context.Context) (qio.Stream, error) {
	st, err := c.c.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return &nw3Stream{Stream: st}, nil
}
func (c *nw3Conn) OpenStream(ctx context.Context) (qio.Stream, error) {
	st, err := c.c.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &nw3Stream{Stream: st}, nil
}
func (c *nw3Conn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return c.c.ReceiveDatagram(ctx)
}
func (c *nw3Conn) SendDatagram(b []byte) error { return c.c.SendDatagram(b) }
func (c *nw3Conn) MaxDatagramSize() int        { return 1200 }
func (c *nw3Conn) CloseWithError(code uint64, message string) error {
	return c.c.CloseWithError(quic.ApplicationErrorCode(code), message)
}
func (c *nw3Conn) Context() context.Context { return c.c.Context() }
func (c *nw3Conn) RemoteAddr() net.Addr     { return c.c.RemoteAddr() }

type nw3Stream struct{ *quic.Stream }

func (s *nw3Stream) ID() uint64        { return uint64(s.Stream.StreamID()) }
func (s *nw3Stream) CloseWrite() error { return s.Stream.Close() }
func (s *nw3Stream) Close() error      { s.CancelRead(0); return s.Stream.Close() }
func (s *nw3Stream) SetDeadline(t time.Time) error {
	return s.Stream.SetDeadline(t)
}
func (s *nw3Stream) SetReadDeadline(t time.Time) error  { return s.Stream.SetReadDeadline(t) }
func (s *nw3Stream) SetWriteDeadline(t time.Time) error { return s.Stream.SetWriteDeadline(t) }
