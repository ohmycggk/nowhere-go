package portal

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ohmycggk/nowhere-go/dgram"
	"github.com/ohmycggk/nowhere-go/qio"
	"github.com/ohmycggk/nowhere-go/wire"
)

type noDatagramConn struct{ max int }

func (c *noDatagramConn) TLSVersion() uint16        { return 0x0304 }
func (c *noDatagramConn) ALPN() string              { return wire.ALPN }
func (c *noDatagramConn) Exporter() ([]byte, error) { return make([]byte, 32), nil }
func (c *noDatagramConn) AcceptStream(context.Context) (qio.Stream, error) {
	return nil, errors.New("unused")
}

func (c *noDatagramConn) OpenStream(context.Context) (qio.Stream, error) {
	return nil, errors.New("unused")
}

func (c *noDatagramConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (c *noDatagramConn) SendDatagram([]byte) error           { return nil }
func (c *noDatagramConn) MaxDatagramSize() int                { return c.max }
func (c *noDatagramConn) CloseWithError(uint64, string) error { return nil }
func (c *noDatagramConn) Context() context.Context            { return context.Background() }
func (c *noDatagramConn) RemoteAddr() net.Addr                { return nil }

// TestServeFlowRejectsUDPWithoutDatagrams pins the setup-time failure for a
// QUIC Vector whose connection did not negotiate DATAGRAM support: it must get
// INTERNAL_ERROR before any target dial or READY.
func TestServeFlowRejectsUDPWithoutDatagrams(t *testing.T) {
	local, remote := net.Pipe()
	client := &pipe{Reader: remote, write: local, closer: local}
	router := dgram.NewRouter(&noDatagramConn{}, 0)
	srv := &Server{}

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.serveFlow(context.Background(), wire.FlowUDP, wire.Target{}, client, router, 1, true)
	}()
	_ = remote.SetReadDeadline(time.Now().Add(5 * time.Second))
	res, err := wire.ReadSetupResult(remote)
	if err != nil {
		t.Fatalf("read setup result: %v", err)
	}
	if res != wire.SetupInternalError {
		t.Fatalf("setup result = %v, want %v", res, wire.SetupInternalError)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveFlow did not return")
	}
}


type blockingUDPConn struct {
	closed     chan struct{}
	closeOnce  sync.Once
	closeCount atomic.Int32
	writes     chan []byte
}

func newBlockingUDPConn() *blockingUDPConn {
	return &blockingUDPConn{
		closed: make(chan struct{}),
		writes: make(chan []byte, 8),
	}
}

func (c *blockingUDPConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *blockingUDPConn) Write(b []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case c.writes <- append([]byte(nil), b...):
		return len(b), nil
	}
}

func (c *blockingUDPConn) Close() error {
	c.closeCount.Add(1)
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *blockingUDPConn) LocalAddr() net.Addr              { return nil }
func (c *blockingUDPConn) RemoteAddr() net.Addr             { return nil }
func (c *blockingUDPConn) SetDeadline(time.Time) error      { return nil }
func (c *blockingUDPConn) SetReadDeadline(time.Time) error  { return nil }
func (c *blockingUDPConn) SetWriteDeadline(time.Time) error { return nil }

type stubPortalUpstream struct {
	tcp net.Conn
	udp net.Conn
}

func (u stubPortalUpstream) DialTCP(context.Context, wire.Target) (net.Conn, error) {
	if u.tcp != nil {
		return u.tcp, nil
	}
	l, r := net.Pipe()
	_ = r.Close()
	return l, nil
}

func (u stubPortalUpstream) DialUDP(context.Context, wire.Target) (net.Conn, error) {
	return u.udp, nil
}

type dgramFeedConn struct {
	noDatagramConn
	in chan []byte
}

func (c *dgramFeedConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case b, ok := <-c.in:
		if !ok {
			return nil, io.EOF
		}
		return b, nil
	}
}

type trackingStream struct {
	net.Conn
	id         uint64
	closeCount atomic.Int32
}

func (s *trackingStream) ID() uint64        { return s.id }
func (s *trackingStream) CloseWrite() error { return s.Conn.Close() }
func (s *trackingStream) Close() error      { s.closeCount.Add(1); return s.Conn.Close() }

type trackingRawConn struct {
	net.Conn
	closeCount atomic.Int32
}

func (c *trackingRawConn) Close() error {
	c.closeCount.Add(1)
	return c.Conn.Close()
}

func TestServeFlowQUICUDPUnblocksPeerWithoutReadDeadline(t *testing.T) {
	runtime.GC()
	time.Sleep(10 * time.Millisecond)
	baseGoroutines := runtime.NumGoroutine()

	peer := newBlockingUDPConn()
	qconn := &dgramFeedConn{noDatagramConn: noDatagramConn{max: 1200}, in: make(chan []byte, 4)}
	router := dgram.NewRouter(qconn, 64)
	rCtx, rCancel := context.WithCancel(context.Background())
	go router.Run(rCtx)

	srv, err := New(Config{
		SharedKey: "0123456789abcdef0123456789abcdef",
		TLS:       &tls.Config{Certificates: []tls.Certificate{testCert(t)}},
		Upstream:  stubPortalUpstream{udp: peer},
	})
	if err != nil {
		t.Fatal(err)
	}
	target, err := wire.NewIPTarget(netip.MustParseAddr("127.0.0.1"), 53)
	if err != nil {
		t.Fatal(err)
	}

	local, remote := net.Pipe()
	st := &trackingStream{Conn: local, id: 0}
	var req bytes.Buffer
	if err := wire.WriteFlowRequest(&req, wire.FlowUDP, target); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.readAndServe(context.Background(), router, st, bufio.NewReader(st), true)
	}()

	if _, err := remote.Write(req.Bytes()); err != nil {
		t.Fatal(err)
	}
	if res, err := wire.ReadSetupResult(remote); err != nil || res != wire.SetupReady {
		t.Fatalf("ReadSetupResult = %v, %v", res, err)
	}

	udpID, err := wire.UDPFlowID(0, false)
	if err != nil {
		t.Fatal(err)
	}
	frames, err := wire.EncodePacket(udpID, 1, []byte("ping"), 1000)
	if err != nil {
		t.Fatal(err)
	}
	var received bool
	for i := 0; i < 50 && !received; i++ {
		for _, f := range frames {
			qconn.in <- f
		}
		select {
		case got := <-peer.writes:
			if string(got) != "ping" {
				t.Fatalf("peer write = %q, want %q", got, "ping")
			}
			received = true
		case <-time.After(10 * time.Millisecond):
		}
	}
	if !received {
		t.Fatal("datagram was not written to UDP peer")
	}

	_ = remote.Close()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("readAndServe/serveFlow hung >100ms after control stream closed")
	}
	if peer.closeCount.Load() == 0 {
		t.Fatal("UDP peer Close was not called")
	}
	if st.closeCount.Load() == 0 {
		t.Fatal("QUIC stream Close was not called")
	}
	srv.flows.mu.Lock()
	flowsHeld := srv.flows.n
	srv.flows.mu.Unlock()
	if flowsHeld != 0 {
		t.Fatalf("srv.flows.n = %d, want 0", flowsHeld)
	}

	rCancel()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) && runtime.NumGoroutine() > baseGoroutines+1 {
		time.Sleep(10 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > baseGoroutines+1 {
		t.Fatalf("goroutines = %d, baseline = %d (leak detected)", got, baseGoroutines)
	}
}

func TestBridgeUoTClosesOnExit(t *testing.T) {
	qconn := &dgramFeedConn{noDatagramConn: noDatagramConn{max: 1200}, in: make(chan []byte, 4)}
	router := dgram.NewRouter(qconn, 64)
	rCtx, rCancel := context.WithCancel(context.Background())
	defer rCancel()
	go router.Run(rCtx)

	tlsLocal, tlsRemote := net.Pipe()
	defer tlsRemote.Close()
	tlsTracked := &trackingRawConn{Conn: tlsLocal}
	quicLocal, quicRemote := net.Pipe()
	defer quicRemote.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		bridgeUoT(
			&pipe{Reader: tlsTracked, write: tlsTracked, closer: tlsTracked},
			router, 11,
			&pipe{Reader: quicLocal, write: quicLocal, closer: quicLocal},
			nil, nil, false,
		)
	}()

	frames, err := wire.EncodePacket(11, 1, []byte("uot-framed"), 1000)
	if err != nil {
		t.Fatal(err)
	}
	var got []byte
	uotReadDone := make(chan error, 1)
	go func() {
		var rerr error
		got, rerr = wire.ReadUoT(tlsRemote)
		uotReadDone <- rerr
	}()

	for i := 0; i < 20; i++ {
		for _, f := range frames {
			qconn.in <- f
		}
		select {
		case err := <-uotReadDone:
			if err != nil {
				t.Fatalf("ReadUoT: %v", err)
			}
			if string(got) != "uot-framed" {
				t.Fatalf("ReadUoT payload = %q, want %q", got, "uot-framed")
			}
			goto closedCheck
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Fatal("timed out waiting for UoT packet")

closedCheck:
	_ = quicRemote.Close()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("bridgeUoT hung >100ms after control stream closed")
	}
	if tlsTracked.closeCount.Load() == 0 {
		t.Fatal("tls stream Close was not called")
	}
}

func TestServeTCPClosesUnderlyingConn(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef"
	cert := testCert(t)
	srv, err := New(Config{
		SharedKey: key,
		TLS:       &tls.Config{Certificates: []tls.Certificate{cert}},
		Upstream:  stubPortalUpstream{},
	})
	if err != nil {
		t.Fatal(err)
	}
	rawSrv, rawCli := net.Pipe()
	trackedSrv := &trackingRawConn{Conn: rawSrv}

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.serveTCP(context.Background(), trackedSrv)
	}()

	cliConn := tls.Client(rawCli, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{wire.ALPN},
		ServerName:         "nowhere",
	})
	if err := cliConn.Handshake(); err != nil {
		t.Fatalf("Handshake: %v", err)
	}
	exp, err := exportState(cliConn.ConnectionState())
	if err != nil {
		t.Fatal(err)
	}
	creds, err := wire.NewCredentials(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.WriteAuthFrame(cliConn, creds, wire.RoleVector, wire.AuthTLS, exp); err != nil {
		t.Fatal(err)
	}
	target, err := wire.NewIPTarget(netip.MustParseAddr("127.0.0.1"), 80)
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.WriteFlowRequest(cliConn, wire.FlowTCP, target); err != nil {
		t.Fatal(err)
	}
	if res, err := wire.ReadSetupResult(cliConn); err != nil || res != wire.SetupReady {
		t.Fatalf("ReadSetupResult = %v, %v", res, err)
	}
	go func() { _, _ = io.Copy(io.Discard, cliConn) }()
	_ = cliConn.CloseWrite()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("serveTCP did not finish")
	}
	if trackedSrv.closeCount.Load() == 0 {
		t.Fatal("underlying TCP connection Close() was not called")
	}
	_ = rawCli.Close()
}

func TestAdmitReleaseDeletesZeroCountKeys(t *testing.T) {
	a := &admit{per: make(map[string]int)}
	for i := 0; i < 100; i++ {
		addr := &net.TCPAddr{IP: net.IPv4(198, 51, 100, byte(i)), Port: 10000 + i}
		if !a.take(addr) {
			t.Fatalf("take(%v) failed", addr)
		}
		a.release(addr)
	}
	if len(a.per) != 0 {
		t.Fatalf("len(a.per) = %d, want 0", len(a.per))
	}
	if a.n != 0 {
		t.Fatalf("a.n = %d, want 0", a.n)
	}
}
