package main

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"

	nquic "github.com/ohmycggk/nowhere-go/carrier/quic"
	"github.com/ohmycggk/nowhere-go/server"
	"github.com/ohmycggk/nowhere-go/wire"
	"github.com/quic-go/quic-go"
)

func quicConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  120 * time.Second,
	}
}

type clientBackend struct {
	addr    string
	tls     *tls.Config
	packet  net.PacketConn
	mu      sync.Mutex
	session *clientSession
}

func newClientBackend(addr string, tlsCfg *tls.Config, packet net.PacketConn) *clientBackend {
	return &clientBackend{addr: addr, tls: tlsCfg, packet: packet}
}

func (b *clientBackend) AcquireSession(ctx context.Context) (nquic.Session, error) {
	b.mu.Lock()
	if b.session != nil && !b.session.closed() {
		s := b.session
		b.mu.Unlock()
		return s, nil
	}
	b.mu.Unlock()

	udpAddr, err := net.ResolveUDPAddr("udp", b.addr)
	if err != nil {
		return nil, err
	}
	pc := b.packet
	if pc == nil {
		pc, err = net.ListenPacket("udp", "")
		if err != nil {
			return nil, err
		}
	}
	conn, err := quic.Dial(ctx, pc, udpAddr, b.tls.Clone(), quicConfig())
	if err != nil {
		if b.packet == nil {
			_ = pc.Close()
		}
		return nil, err
	}
	s := &clientSession{conn: conn, pc: pc, owned: b.packet == nil}
	b.mu.Lock()
	b.session = s
	b.mu.Unlock()
	return s, nil
}

func (b *clientBackend) InvalidateSession(session nquic.Session) {
	s, ok := session.(*clientSession)
	if !ok || s == nil {
		return
	}
	b.mu.Lock()
	if b.session == s {
		b.session = nil
	}
	b.mu.Unlock()
	s.Close()
}

func (b *clientBackend) Close() error {
	b.mu.Lock()
	s := b.session
	b.session = nil
	b.mu.Unlock()
	if s != nil {
		s.Close()
	}
	return nil
}

type clientSession struct {
	conn  quic.Connection
	pc    net.PacketConn
	owned bool
}

func (s *clientSession) closed() bool {
	return s == nil || s.conn == nil || s.conn.Context().Err() != nil
}

func (s *clientSession) TLSHandshakeInfo() (wire.TLSHandshakeInfo, error) {
	state := s.conn.ConnectionState()
	material, err := state.TLS.ExportKeyingMaterial(wire.TLSExporterLabel, wire.EmptyTLSExporterContext(), wire.TLSExporterLen)
	if err != nil {
		return wire.TLSHandshakeInfo{}, err
	}
	var exporter wire.TLSExporter
	copy(exporter[:], material)
	return wire.TLSHandshakeInfo{
		TLSVersion:     state.TLS.Version,
		NegotiatedALPN: state.TLS.NegotiatedProtocol,
		Exporter:       exporter,
	}, nil
}

func (s *clientSession) PrepareStream(ctx context.Context) (nquic.PreparedStream, error) {
	stream, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &preparedStream{stream: stream}, nil
}

func (s *clientSession) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return s.conn.ReceiveDatagram(ctx)
}

func (s *clientSession) CurrentMaxDatagramSize() int { return 1200 }

func (s *clientSession) SendDatagram(_ context.Context, payload []byte) error {
	return s.conn.SendDatagram(payload)
}

func (s *clientSession) LocalAddr() net.Addr { return s.conn.LocalAddr() }

func (s *clientSession) Close() {
	_ = s.conn.CloseWithError(0, "")
	if s.owned && s.pc != nil {
		_ = s.pc.Close()
	}
}

type preparedStream struct {
	stream quic.Stream
	once   sync.Once
}

func (p *preparedStream) Commit(ctx context.Context, setup []byte, finishWrite bool) (net.Conn, error) {
	if _, err := p.stream.Write(setup); err != nil {
		_ = p.stream.Close()
		return nil, err
	}
	if finishWrite {
		_ = p.stream.Close()
	}
	return &streamConn{Stream: p.stream, local: nil, remote: nil}, nil
}

func (p *preparedStream) Close() error {
	var err error
	p.once.Do(func() { err = p.stream.Close() })
	return err
}

type streamConn struct {
	quic.Stream
	local, remote net.Addr
}

func (s *streamConn) LocalAddr() net.Addr {
	if s.local != nil {
		return s.local
	}
	return dummyAddr{}
}
func (s *streamConn) RemoteAddr() net.Addr {
	if s.remote != nil {
		return s.remote
	}
	return dummyAddr{}
}

type dummyAddr struct{}

func (dummyAddr) Network() string { return "quic" }
func (dummyAddr) String() string  { return "quic" }

type serverListener struct {
	ln *quic.Listener
}

func listenQUIC(packet net.PacketConn, tlsCfg *tls.Config) (*serverListener, error) {
	ln, err := quic.Listen(packet, tlsCfg, quicConfig())
	if err != nil {
		return nil, err
	}
	return &serverListener{ln: ln}, nil
}

func (l *serverListener) Accept(ctx context.Context) (server.QuicConn, error) {
	c, err := l.ln.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return &serverConn{c: c}, nil
}

func (l *serverListener) Close() error { return l.ln.Close() }

type serverConn struct {
	c quic.Connection
}

func (s *serverConn) TLSHandshakeInfo() (wire.TLSHandshakeInfo, error) {
	state := s.c.ConnectionState()
	material, err := state.TLS.ExportKeyingMaterial(wire.TLSExporterLabel, wire.EmptyTLSExporterContext(), wire.TLSExporterLen)
	if err != nil {
		return wire.TLSHandshakeInfo{}, err
	}
	var exporter wire.TLSExporter
	copy(exporter[:], material)
	return wire.TLSHandshakeInfo{
		TLSVersion:     state.TLS.Version,
		NegotiatedALPN: state.TLS.NegotiatedProtocol,
		Exporter:       exporter,
	}, nil
}

type wrappedStream struct{ quic.Stream }

func (s wrappedStream) CancelRead(code uint64) {
	s.Stream.CancelRead(quic.StreamErrorCode(code))
}
func (s wrappedStream) CancelWrite(code uint64) {
	s.Stream.CancelWrite(quic.StreamErrorCode(code))
}

func (s *serverConn) AcceptStream(ctx context.Context) (server.QuicStream, error) {
	st, err := s.c.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return wrappedStream{st}, nil
}

func (s *serverConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return s.c.ReceiveDatagram(ctx)
}

func (s *serverConn) SendDatagram(_ context.Context, b []byte) error {
	return s.c.SendDatagram(b)
}

func (s *serverConn) CloseWithError(code uint64, message string) error {
	return s.c.CloseWithError(quic.ApplicationErrorCode(code), message)
}

func (s *serverConn) Close() error { return s.c.CloseWithError(0, "") }

func (s *serverConn) Context() context.Context { return s.c.Context() }

func (s *serverConn) LocalAddr() net.Addr { return s.c.LocalAddr() }

func (s *serverConn) RemoteAddr() net.Addr { return s.c.RemoteAddr() }

type multiQuicListener struct {
	listeners []*serverListener
	ch        chan acceptRes
	once      sync.Once
}

type acceptRes struct {
	c   server.QuicConn
	err error
}

func newMultiQuicListener(listeners []*serverListener) server.QuicListener {
	if len(listeners) == 1 {
		return listeners[0]
	}
	m := &multiQuicListener{listeners: listeners, ch: make(chan acceptRes)}
	for _, ln := range listeners {
		go func(ln *serverListener) {
			for {
				c, err := ln.Accept(context.Background())
				m.ch <- acceptRes{c, err}
				if err != nil {
					return
				}
			}
		}(ln)
	}
	return m
}

func (m *multiQuicListener) Accept(ctx context.Context) (server.QuicConn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-m.ch:
		return res.c, res.err
	}
}

func (m *multiQuicListener) Close() error {
	var err error
	m.once.Do(func() {
		for _, ln := range m.listeners {
			if e := ln.Close(); e != nil && err == nil {
				err = e
			}
		}
	})
	return err
}

var (
	_ nquic.Backend        = (*clientBackend)(nil)
	_ nquic.Session        = (*clientSession)(nil)
	_ nquic.PreparedStream = (*preparedStream)(nil)
	_ server.QuicListener  = (*serverListener)(nil)
	_ server.QuicConn      = (*serverConn)(nil)
)
