// Package portal is the Nowhere 3 server. A listener accepts only ALPN nw3.
package portal

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ohmycggk/nowhere-go/dgram"
	"github.com/ohmycggk/nowhere-go/flowio"
	"github.com/ohmycggk/nowhere-go/morph"
	"github.com/ohmycggk/nowhere-go/qio"
	"github.com/ohmycggk/nowhere-go/runtime"
	"github.com/ohmycggk/nowhere-go/wire"
)

const (
	maxUnauth    = 256
	maxPerSource = 32
	maxFlows     = 4096
)

// Config is a Portal. Egress mode ignores Upstream and bridges to the registered exit.
type Config struct {
	SharedKey    string
	Morph        bool
	TLS          *tls.Config
	Upstream     Upstream
	Egress       bool
	UploadMbps   int
	DownloadMbps int
	// DatagramOverhead is subtracted from the QUIC datagram size before
	// encoding. Morph UDP uses 12 for the unmasked nonce.
	DatagramOverhead int
}

// Server accepts Vector and, when Egress is set, a FIFO of Egress registrations.
type Server struct {
	creds    *wire.Credentials
	keys     *morph.Keys
	tls      *tls.Config
	up       Upstream
	egress   bool
	upload   *flowio.Limiter
	download *flowio.Limiter
	rt       runtime.Settings

	admit    admit
	flows    gate
	reg      *registry
	overhead int
}

// New checks the shared key and exit mode.
func New(cfg Config) (*Server, error) {
	if err := wire.ValidateServiceKey(cfg.SharedKey); err != nil {
		return nil, err
	}
	if cfg.TLS == nil {
		return nil, errors.New("nw3: missing portal TLS config")
	}
	if !cfg.Egress && cfg.Upstream == nil {
		return nil, errors.New("nw3: missing portal upstream")
	}
	creds, err := wire.NewCredentials(cfg.SharedKey)
	if err != nil {
		return nil, err
	}
	rt, err := runtime.Load(cfg.SharedKey, false)
	if err != nil {
		return nil, err
	}
	tlsCfg := cfg.TLS.Clone()
	tlsCfg.MinVersion = tls.VersionTLS13
	tlsCfg.MaxVersion = tls.VersionTLS13
	tlsCfg.NextProtos = []string{wire.ALPN}
	tlsCfg.SessionTicketsDisabled = true
	s := &Server{
		creds:    creds,
		tls:      tlsCfg,
		up:       cfg.Upstream,
		egress:   cfg.Egress,
		upload:   flowio.NewMbps(cfg.UploadMbps),
		download: flowio.NewMbps(cfg.DownloadMbps),
		rt:       rt,
		admit:    admit{per: map[string]int{}},
		reg:      newRegistry(rt.PortalTLSIdleMax),
		overhead: cfg.DatagramOverhead,
	}
	if cfg.Morph {
		keys := morph.Derive([]byte(cfg.SharedKey))
		s.keys = &keys
	}
	return s, nil
}

// Serve accepts TLS connections. The listener is closed when ctx ends.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go s.serveTCP(ctx, conn)
	}
}

// ServeQUIC accepts QUIC connections that already negotiated ALPN nw3 inside the host stack.
// The host TLS config must offer only nw3; mismatched ALPNs are closed here as well.
func (s *Server) ServeQUIC(ctx context.Context, ln qio.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go s.serveQUIC(ctx, conn)
	}
}

func (s *Server) serveTCP(ctx context.Context, raw net.Conn) {
	acceptedAt := time.Now()
	deadline := acceptedAt.Add(s.rt.HandshakeTimeout)
	morphing := s.keys != nil
	if morphing {
		// Abortive close stays on until Vector authentication succeeds.
		if err := setZeroLinger(raw); err != nil {
			_ = raw.Close()
			return
		}
	}
	if !s.admit.take(raw.RemoteAddr()) {
		if !morphing {
			_ = raw.Close()
			return
		}
		// A Morph TCP connection waits for a slot until the handshake deadline
		// instead of being dropped. The wait does not read the socket.
		if !s.admit.wait(ctx, raw.RemoteAddr(), deadline) {
			_ = raw.Close()
			return
		}
	}
	held := true
	defer func() {
		if held {
			s.admit.release(raw.RemoteAddr())
		}
	}()
	if morphing {
		raw = morph.WrapTCPServer(raw, *s.keys)
	}
	tlsConn := tls.Server(raw, s.tls)
	_ = tlsConn.SetDeadline(deadline)
	if err := tlsConn.Handshake(); err != nil {
		// A rejected prelude or ClientHello is not drained: the Morph reader
		// stops returning socket bytes once admission fails. The slot is released
		// before the hold, because the connection will not authenticate. The
		// socket itself stays open until the deadline captured at accept.
		// crypto/tls does not preserve the admission error, so every Morph
		// failure before a TLS response takes this path.
		if morphing {
			s.admit.release(raw.RemoteAddr())
			held = false
			parkUntil(deadline)
		}
		_ = tlsConn.Close()
		return
	}
	state := tlsConn.ConnectionState()
	exp, err := exportState(state)
	if err != nil || state.NegotiatedProtocol != wire.ALPN || state.Version != tls.VersionTLS13 {
		_ = tlsConn.Close()
		return
	}
	br := bufio.NewReader(tlsConn)
	role, err := wire.ReadAuthFrame(br, s.creds, wire.AuthTLS, exp)
	s.admit.release(raw.RemoteAddr())
	held = false
	if err != nil || (role != wire.RoleVector && role != wire.RoleEgress) {
		_ = tlsConn.Close()
		return
	}
	if morphing {
		if err := morph.ReleaseAuthenticated(raw, deadline); err != nil {
			_ = tlsConn.Close()
			return
		}
	}
	if role == wire.RoleEgress && s.egress {
		// Standby lasts 120s. The handshake deadline must not expire it.
		_ = tlsConn.SetDeadline(time.Time{})
		s.serveEgressTLS(ctx, tlsConn, br)
		return
	}
	if role != wire.RoleVector {
		_ = tlsConn.Close()
		return
	}
	_ = tlsConn.SetDeadline(time.Now().Add(s.rt.FlowSetupTimeout))
	kind, target, ok, err := wire.ReadFlowRequest(br)
	rw := &pipe{Reader: br, write: tlsConn, closer: tlsConn}
	if err != nil || !ok {
		if ok || err != nil {
			_ = wire.WriteSetupResult(tlsConn, wire.SetupInvalidRequest)
		}
		_ = tlsConn.Close()
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})
	s.serveFlow(ctx, kind, target, rw, nil, 0, true)
}

func (s *Server) serveQUIC(ctx context.Context, conn qio.Conn) {
	defer conn.CloseWithError(0, "")
	if conn.ALPN() != wire.ALPN || conn.TLSVersion() != tls.VersionTLS13 {
		return
	}
	if !s.admit.take(conn.RemoteAddr()) {
		return
	}
	dropCtx, cancelDrop := context.WithCancel(ctx)
	dropDone := make(chan struct{})
	go func() {
		defer close(dropDone)
		for {
			if _, err := conn.ReceiveDatagram(dropCtx); err != nil {
				return
			}
		}
	}()
	authCtx, cancelAuth := context.WithTimeout(ctx, s.rt.HandshakeTimeout)
	st, err := conn.AcceptStream(authCtx)
	cancelAuth()
	if err != nil || st.ID() != 0 {
		cancelDrop()
		<-dropDone
		s.admit.release(conn.RemoteAddr())
		return
	}
	exp, err := exportConn(conn)
	if err != nil {
		cancelDrop()
		<-dropDone
		s.admit.release(conn.RemoteAddr())
		return
	}
	_ = st.SetDeadline(time.Now().Add(s.rt.HandshakeTimeout))
	br := bufio.NewReader(st)
	role, err := wire.ReadAuthFrame(br, s.creds, wire.AuthQUIC, exp)
	s.admit.release(conn.RemoteAddr())
	cancelDrop()
	<-dropDone
	if err != nil {
		return
	}
	if release, ok := conn.(qio.PreAuth); ok {
		release.ReleasePreAuth()
	}
	_ = st.SetDeadline(time.Time{})
	router := dgram.NewRouter(conn, s.rt.QUICUDPQueue)
	router.SetOverhead(s.overhead)
	go router.Run(ctx)
	switch role {
	case wire.RoleVector:
		s.serveVectorConn(ctx, conn, router, st, br)
	case wire.RoleEgress:
		s.serveEgressConn(ctx, conn, router, st, br)
	default:
	}
}

func (s *Server) serveVectorConn(ctx context.Context, conn qio.Conn, router *dgram.Router, first qio.Stream, br *bufio.Reader) {
	go s.readAndServe(ctx, router, first, br, true)
	for {
		if !s.flows.try() {
			// The application flow cap is full. Stop accepting until one
			// finishes, so a peer cannot hold a goroutine per stream on QUIC
			// credit alone. The wait is bounded by the flow setup timeout.
			if !s.flows.wait(ctx, s.rt.FlowSetupTimeout) {
				return
			}
		}
		st, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		if st.ID()&2 != 0 || st.ID()&1 != 0 {
			_ = conn.CloseWithError(0, "direction")
			return
		}
		go s.readAndServe(ctx, router, st, bufio.NewReader(st), true)
	}
}

func (s *Server) readAndServe(ctx context.Context, router *dgram.Router, st qio.Stream, br *bufio.Reader, client bool) {
	_ = st.SetReadDeadline(time.Now().Add(s.rt.FlowSetupTimeout))
	kind, target, ok, err := wire.ReadFlowRequest(br)
	_ = st.SetReadDeadline(time.Time{})
	if err != nil || !ok {
		if err != nil {
			_ = wire.WriteSetupResult(st, wire.SetupInvalidRequest)
		}
		_ = st.CloseWrite()
		return
	}
	rw := &pipe{Reader: br, write: st, closer: st}
	s.serveFlow(ctx, kind, target, rw, router, st.ID(), client)
}

func (s *Server) serveFlow(ctx context.Context, kind wire.FlowKind, target wire.Target, client *pipe, router *dgram.Router, streamID uint64, clientInitiated bool) {
	if !s.flows.acquire() {
		_ = wire.WriteSetupResult(client, wire.SetupFlowLimit)
		_ = client.Close()
		return
	}
	defer s.flows.release()
	// A UDP flow over QUIC needs DATAGRAM support on the Vector connection.
	// Reject it before any target dial or READY; Core forbids a fallback.
	if kind == wire.FlowUDP && router != nil && router.MaxDatagramSize() <= 0 {
		_ = wire.WriteSetupResult(client, wire.SetupInternalError)
		_ = client.Close()
		return
	}
	setupCtx, cancel := context.WithTimeout(ctx, s.rt.FlowSetupTimeout)
	defer cancel()
	if s.egress {
		s.serveViaEgress(setupCtx, kind, target, client, router, streamID)
		return
	}
	var peer net.Conn
	var err error
	if kind == wire.FlowTCP {
		peer, err = s.up.DialTCP(setupCtx, target)
	} else {
		peer, err = s.up.DialUDP(setupCtx, target)
	}
	if err != nil {
		_ = wire.WriteSetupResult(client, wire.SetupDialFailed)
		_ = client.Close()
		return
	}
	defer peer.Close()
	var id uint32
	if kind == wire.FlowUDP && router != nil {
		id, err = wire.UDPFlowID(streamID, !clientInitiated)
		if err != nil {
			_ = wire.WriteSetupResult(client, wire.SetupFlowLimit)
			_ = client.Close()
			return
		}
	}
	if err := wire.WriteSetupResult(client, wire.SetupReady); err != nil {
		return
	}
	if kind == wire.FlowTCP {
		flowio.Relay(client, peer, s.upload, s.download)
		return
	}
	if router == nil {
		relayUoT(client, peer, s.upload, s.download, s.rt.UDPIdleTimeout)
		return
	}
	relayQUICUDP(router, id, client, peer, s.upload, s.download, s.rt.UDPIdleTimeout)
}

func (s *Server) serveViaEgress(ctx context.Context, kind wire.FlowKind, target wire.Target, client *pipe, router *dgram.Router, streamID uint64) {
	deadline, _ := ctx.Deadline()
	if deadline.IsZero() {
		deadline = time.Now().Add(s.rt.FlowSetupTimeout)
	}
	slot, tlsSlot, ok := s.reg.claim(ctx, deadline)
	if !ok {
		_ = wire.WriteSetupResult(client, wire.SetupDialFailed)
		_ = client.Close()
		return
	}
	if tlsSlot && slot.tlsConn == nil {
		_ = wire.WriteSetupResult(client, wire.SetupInternalError)
		_ = client.Close()
		return
	}
	var st qio.Stream
	var err error
	if tlsSlot {
		st = &tlsStream{Conn: slot.tlsConn, reader: slot.reader}
		err = wire.WriteFlowRequest(slot.tlsConn, kind, target)
		if err == nil {
			// The standby read deadline is how the Egress learns it was
			// claimed. Cancelling it here would leave that read parked.
			slot.close()
		}
	} else {
		st, err = slot.conn.OpenStream(ctx)
		if err == nil {
			err = wire.WriteFlowRequest(st, kind, target)
		}
	}
	if err != nil || st == nil {
		if st != nil {
			_ = st.Close()
		}
		_ = wire.WriteSetupResult(client, wire.SetupDialFailed)
		_ = client.Close()
		return
	}
	defer st.Close()
	_ = st.SetReadDeadline(time.Now().Add(timeLeft(ctx, s.rt.FlowSetupTimeout)))
	res, err := wire.ReadSetupResult(st)
	_ = st.SetReadDeadline(time.Time{})
	if err != nil {
		res = wire.SetupDialFailed
	}
	if res != wire.SetupReady {
		_ = wire.WriteSetupResult(client, res)
		_ = client.Close()
		return
	}
	// A UDP flow forwarded to a QUIC Egress needs DATAGRAM support on that
	// connection too. Fail before READY rather than after the target dial.
	if kind == wire.FlowUDP && slot.router != nil && slot.router.MaxDatagramSize() <= 0 {
		_ = wire.WriteSetupResult(client, wire.SetupInternalError)
		_ = client.Close()
		return
	}
	if err := wire.WriteSetupResult(client, wire.SetupReady); err != nil {
		return
	}
	peer := &pipe{Reader: st, write: st, closer: st}
	if kind == wire.FlowTCP {
		flowio.Relay(client, peer, s.upload, s.download)
		return
	}
	switch {
	case router == nil && slot.router == nil:
		relayUoTPair(client, peer, s.upload, s.download)
	case router == nil:
		eid, err := wire.UDPFlowID(st.ID(), true)
		if err != nil {
			return
		}
		bridgeUoT(client, slot.router, eid, peer, s.upload, s.download, true)
	case slot.router == nil:
		vid, err := wire.UDPFlowID(streamID, false)
		if err != nil {
			return
		}
		bridgeUoT(peer, router, vid, client, s.upload, s.download, false)
	default:
		vid, err := wire.UDPFlowID(streamID, false)
		if err != nil {
			return
		}
		eid, err := wire.UDPFlowID(st.ID(), true)
		if err != nil {
			return
		}
		bridgeUDP(router, vid, client, slot.router, eid, peer)
	}
}

// serveEgressTLS registers one TLS connection. It carries a single flow and
// leaves the FIFO when claimed. BUSY does not enter the FIFO.
func (s *Server) serveEgressTLS(ctx context.Context, conn net.Conn, br *bufio.Reader) {
	if !s.egress || !s.reg.reservePending() {
		_ = wire.WriteRegistrationResult(conn, wire.RegistrationBusy)
		select {
		case <-ctx.Done():
		case <-time.After(s.rt.HandshakeTimeout):
		}
		_ = conn.Close()
		return
	}
	slot := &egressSlot{
		tls:     true,
		tlsConn: conn,
		reader:  br,
		expires: time.Now().Add(runtime.TLSStandbyTTL),
		dead:    make(chan struct{}),
	}
	if err := wire.WriteRegistrationResult(conn, wire.RegistrationAccepted); err != nil {
		s.reg.releasePending()
		_ = conn.Close()
		return
	}
	s.reg.push(slot)
	// Standby has nothing to read. Closing the socket unblocks a claim that
	// loses the race with expiry.
	select {
	case <-ctx.Done():
	case <-slot.dead:
	}
	if s.reg.take(slot, true) {
		slot.close()
		_ = conn.Close()
	}
}

func (s *Server) serveEgressConn(ctx context.Context, conn qio.Conn, router *dgram.Router, st qio.Stream, br *bufio.Reader) {
	if !s.egress {
		return
	}
	_ = st.SetReadDeadline(time.Now().Add(s.rt.HandshakeTimeout))
	var extra [1]byte
	if n, err := br.Read(extra[:]); n > 0 || (err != nil && !errors.Is(err, io.EOF)) {
		return
	}
	if err := wire.WriteRegistrationResult(st, wire.RegistrationAccepted); err != nil {
		return
	}
	if err := st.CloseWrite(); err != nil {
		return
	}
	slot := &egressSlot{conn: conn, router: router, dead: make(chan struct{})}
	s.reg.push(slot)
	defer func() {
		s.reg.take(slot, false)
		slot.close()
	}()
	for {
		stray, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		// AcceptStream delivers peer-opened streams. A client bidirectional
		// stream is a role-direction violation. Unidirectional streams carry
		// no NW3 messages and are discarded.
		if stray.ID()&2 == 0 && stray.ID()&1 == 0 {
			_ = stray.Close()
			_ = conn.CloseWithError(0, "direction")
			return
		}
		_ = stray.Close()
	}
}

// tlsStream is the single TLS Egress connection after registration. Reads use
// the buffered handshake reader so a pipelined byte is not lost.
type tlsStream struct {
	net.Conn
	reader io.Reader
}

func (s *tlsStream) Read(p []byte) (int, error) {
	if s.reader != nil {
		return s.reader.Read(p)
	}
	return s.Conn.Read(p)
}

func (s *tlsStream) ID() uint64 { return 1 }

func (s *tlsStream) CloseWrite() error {
	if cw, ok := s.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

type pipe struct {
	io.Reader
	write  io.Writer
	closer io.Closer
}

func (p *pipe) Read(b []byte) (int, error)  { return p.Reader.Read(b) }
func (p *pipe) Write(b []byte) (int, error) { return p.write.Write(b) }
func (p *pipe) Close() error {
	if p.closer != nil {
		return p.closer.Close()
	}
	return nil
}

func (p *pipe) CloseWrite() error {
	if cw, ok := p.write.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	if cw, ok := p.closer.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return p.Close()
}

func relayUoT(client *pipe, udp net.Conn, up, down *flowio.Limiter, idle time.Duration) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			pkt, err := wire.ReadUoT(client)
			if err != nil {
				break
			}
			_ = up.WaitN(context.Background(), len(pkt))
			if _, err := udp.Write(pkt); err != nil {
				break
			}
		}
		_ = udp.Close()
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			_ = udp.SetReadDeadline(time.Now().Add(idle))
			n, err := udp.Read(buf)
			if err != nil {
				break
			}
			_ = down.WaitN(context.Background(), n)
			if err := wire.WriteUoT(client, buf[:n]); err != nil {
				break
			}
		}
		_ = client.CloseWrite()
	}()
	wg.Wait()
}

func relayQUICUDP(router *dgram.Router, id uint32, client *pipe, udp net.Conn, up, down *flowio.Limiter, idle time.Duration) {
	flow := router.Register(id)
	defer router.CloseFlow(id)
	done := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(done) }) }
	go func() {
		var b [1]byte
		_, _ = client.Read(b[:])
		finish()
	}()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			_ = udp.SetReadDeadline(time.Now().Add(idle))
			n, err := udp.Read(buf)
			if err != nil {
				finish()
				return
			}
			_ = down.WaitN(context.Background(), n)
			if err := router.Send(id, buf[:n]); err != nil {
				finish()
				return
			}
		}
	}()
	for {
		select {
		case <-done:
			wg.Wait()
			// The reliable control stream owns the route. CLOSE above is only
			// a hint; FIN is what lets the peer drop it.
			_ = client.CloseWrite()
			return
		case pkt, ok := <-flow.C:
			if !ok {
				wg.Wait()
				_ = client.CloseWrite()
				return
			}
			_ = up.WaitN(context.Background(), len(pkt))
			if _, err := udp.Write(pkt); err != nil {
				finish()
				wg.Wait()
				_ = client.CloseWrite()
				return
			}
		}
	}
}

// relayUoTPair copies length-prefixed datagrams between two TLS UDP flows.
func relayUoTPair(left, right *pipe, up, down *flowio.Limiter) {
	var wg sync.WaitGroup
	wg.Add(2)
	copy := func(dst, src *pipe, lim *flowio.Limiter) {
		defer wg.Done()
		for {
			pkt, err := wire.ReadUoT(src)
			if err != nil {
				break
			}
			_ = lim.WaitN(context.Background(), len(pkt))
			if err := wire.WriteUoT(dst, pkt); err != nil {
				break
			}
		}
		_ = dst.CloseWrite()
	}
	go copy(right, left, up)
	go copy(left, right, down)
	wg.Wait()
}

// bridgeUoT joins one TLS UDP flow to one QUIC datagram flow. toQUIC is true
// when the first pipe is the TLS side.
func bridgeUoT(tls *pipe, router *dgram.Router, id uint32, quic *pipe, up, down *flowio.Limiter, toQUIC bool) {
	if router == nil {
		return
	}
	flow := router.Register(id)
	defer router.CloseFlow(id)
	done := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(done) }) }
	go func() {
		var b [1]byte
		_, _ = quic.Read(b[:])
		finish()
	}()
	go func() {
		for {
			pkt, err := wire.ReadUoT(tls)
			if err != nil {
				finish()
				return
			}
			lim := up
			if !toQUIC {
				lim = down
			}
			_ = lim.WaitN(context.Background(), len(pkt))
			if err := router.Send(id, pkt); err != nil {
				finish()
				return
			}
		}
	}()
	for {
		select {
		case <-done:
			_ = tls.CloseWrite()
			_ = quic.CloseWrite()
			return
		case pkt, ok := <-flow.C:
			if !ok {
				_ = tls.CloseWrite()
				_ = quic.CloseWrite()
				return
			}
			lim := down
			if !toQUIC {
				lim = up
			}
			_ = lim.WaitN(context.Background(), len(pkt))
			if err := wire.WriteUoT(tls, pkt); err != nil {
				finish()
				_ = tls.CloseWrite()
				_ = quic.CloseWrite()
				return
			}
		}
	}
}

func bridgeUDP(from *dgram.Router, fromID uint32, fromCtl *pipe, to *dgram.Router, toID uint32, toCtl *pipe) {
	left := from.Register(fromID)
	right := to.Register(toID)
	defer from.CloseFlow(fromID)
	defer to.CloseFlow(toID)
	done := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(done) }) }
	go func() {
		var b [1]byte
		_, _ = fromCtl.Read(b[:])
		finish()
	}()
	go func() {
		var b [1]byte
		_, _ = toCtl.Read(b[:])
		finish()
	}()
	for {
		select {
		case <-done:
			_ = fromCtl.CloseWrite()
			_ = toCtl.CloseWrite()
			return
		case pkt, ok := <-left.C:
			if !ok || to.Send(toID, pkt) != nil {
				finish()
			}
		case pkt, ok := <-right.C:
			if !ok || from.Send(fromID, pkt) != nil {
				finish()
			}
		}
	}
}

func exportState(state tls.ConnectionState) (wire.Exporter, error) {
	var out wire.Exporter
	b, err := state.ExportKeyingMaterial(wire.ExporterLabel, []byte{}, wire.ExporterLen)
	if err != nil {
		return out, err
	}
	if copy(out[:], b) != wire.ExporterLen {
		return out, errors.New("nw3: short exporter")
	}
	return out, nil
}

func exportConn(conn qio.Conn) (wire.Exporter, error) {
	var out wire.Exporter
	b, err := conn.Exporter()
	if err != nil {
		return out, err
	}
	if copy(out[:], b) != wire.ExporterLen {
		return out, errors.New("nw3: short exporter")
	}
	return out, nil
}

func timeLeft(ctx context.Context, fallback time.Duration) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return fallback
	}
	left := time.Until(deadline)
	if left < 0 {
		return 0
	}
	return left
}

type admit struct {
	mu   sync.Mutex
	cond *sync.Cond
	n    int
	per  map[string]int
}

func (a *admit) take(addr net.Addr) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.takeLocked(sourceKey(addr))
}

func (a *admit) takeLocked(key string) bool {
	if a.n >= maxUnauth || a.per[key] >= maxPerSource {
		return false
	}
	a.n++
	a.per[key]++
	return true
}

// wait blocks until a slot is taken, ctx ends, or deadline passes. The
// capacity check and the wait share one lock, so a release cannot pass
// unnoticed between them. It is used only for Morph TCP.
func (a *admit) wait(ctx context.Context, addr net.Addr, deadline time.Time) bool {
	a.mu.Lock()
	if a.cond == nil {
		a.cond = sync.NewCond(&a.mu)
	}
	key := sourceKey(addr)
	timer := time.NewTimer(time.Until(deadline))
	stop := make(chan struct{})
	defer func() {
		timer.Stop()
		close(stop)
	}()
	go func() {
		select {
		case <-timer.C:
		case <-ctx.Done():
		case <-stop:
			return
		}
		a.mu.Lock()
		a.cond.Broadcast()
		a.mu.Unlock()
	}()
	for {
		if a.takeLocked(key) {
			a.mu.Unlock()
			return true
		}
		if ctx.Err() != nil || !time.Now().Before(deadline) {
			a.mu.Unlock()
			return false
		}
		a.cond.Wait()
	}
}

func (a *admit) release(addr net.Addr) {
	key := sourceKey(addr)
	a.mu.Lock()
	if a.n > 0 {
		a.n--
	}
	if a.per[key] > 0 {
		a.per[key]--
	}
	if a.cond != nil {
		a.cond.Broadcast()
	}
	a.mu.Unlock()
}

func setZeroLinger(conn net.Conn) error {
	type linger interface {
		SetLinger(int) error
	}
	if conn, ok := conn.(linger); ok {
		return conn.SetLinger(0)
	}
	return nil
}

func parkUntil(deadline time.Time) {
	if wait := time.Until(deadline); wait > 0 {
		time.Sleep(wait)
	}
}

func sourceKey(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return host
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	v6 := ip.To16()
	if v6 == nil {
		return host
	}
	return hex.EncodeToString(v6[:8])
}

type gate struct {
	mu   sync.Mutex
	cond *sync.Cond
	n    int
}

func (g *gate) acquire() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.n >= maxFlows {
		return false
	}
	g.n++
	return true
}

// try reports whether another flow would fit without taking the slot.
func (g *gate) try() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.n < maxFlows
}

// wait blocks until a flow slot is free, ctx ends, or the bound passes.
func (g *gate) wait(ctx context.Context, bound time.Duration) bool {
	g.mu.Lock()
	if g.cond == nil {
		g.cond = sync.NewCond(&g.mu)
	}
	deadline := time.Now().Add(bound)
	timer := time.AfterFunc(bound, func() {
		g.mu.Lock()
		g.cond.Broadcast()
		g.mu.Unlock()
	})
	defer timer.Stop()
	stop := context.AfterFunc(ctx, func() {
		g.mu.Lock()
		g.cond.Broadcast()
		g.mu.Unlock()
	})
	defer stop()
	for g.n >= maxFlows && ctx.Err() == nil && time.Now().Before(deadline) {
		g.cond.Wait()
	}
	ok := g.n < maxFlows && ctx.Err() == nil
	g.mu.Unlock()
	return ok
}

func (g *gate) release() {
	g.mu.Lock()
	if g.n > 0 {
		g.n--
	}
	if g.cond != nil {
		g.cond.Broadcast()
	}
	g.mu.Unlock()
}
