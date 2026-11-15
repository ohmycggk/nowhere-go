package egress

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ohmycggk/nowhere-go/dgram"
	"github.com/ohmycggk/nowhere-go/qio"
	nwruntime "github.com/ohmycggk/nowhere-go/runtime"
	"github.com/ohmycggk/nowhere-go/wire"
)

const testServiceKey = "0123456789abcdef0123456789abcdef"

type blockingUDPPeer struct {
	closed     chan struct{}
	closeOnce  sync.Once
	closeCount atomic.Int32
	writes     chan []byte
}

func newBlockingUDPPeer() *blockingUDPPeer {
	return &blockingUDPPeer{
		closed: make(chan struct{}),
		writes: make(chan []byte, 8),
	}
}

func (p *blockingUDPPeer) Read([]byte) (int, error) {
	<-p.closed
	return 0, net.ErrClosed
}

func (p *blockingUDPPeer) Write(b []byte) (int, error) {
	select {
	case <-p.closed:
		return 0, net.ErrClosed
	case p.writes <- append([]byte(nil), b...):
		return len(b), nil
	}
}

func (p *blockingUDPPeer) Close() error {
	p.closeCount.Add(1)
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}

func (p *blockingUDPPeer) LocalAddr() net.Addr              { return nil }
func (p *blockingUDPPeer) RemoteAddr() net.Addr             { return nil }
func (p *blockingUDPPeer) SetDeadline(time.Time) error      { return nil }
func (p *blockingUDPPeer) SetReadDeadline(time.Time) error  { return nil }
func (p *blockingUDPPeer) SetWriteDeadline(time.Time) error { return nil }

type stubUpstream struct {
	tcpPeer net.Conn
	udpPeer net.Conn
	err     error
}

func (u *stubUpstream) DialTCP(context.Context, wire.Target) (net.Conn, error) {
	if u.err != nil {
		return nil, u.err
	}
	if u.tcpPeer != nil {
		return u.tcpPeer, nil
	}
	local, remote := net.Pipe()
	_ = remote.Close()
	return local, nil
}

func (u *stubUpstream) DialUDP(context.Context, wire.Target) (net.Conn, error) {
	if u.err != nil {
		return nil, u.err
	}
	return u.udpPeer, nil
}

type trackingConn struct {
	net.Conn
	writeErr   error
	closeCount atomic.Int32
}

func (c *trackingConn) Write(b []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.Conn.Write(b)
}

func (c *trackingConn) Close() error {
	c.closeCount.Add(1)
	return c.Conn.Close()
}

type stubQIOConn struct {
	max int
	in  chan []byte
}

func (c *stubQIOConn) TLSVersion() uint16                               { return 0x0304 }
func (c *stubQIOConn) ALPN() string                                     { return wire.ALPN }
func (c *stubQIOConn) Exporter() ([]byte, error)                        { return make([]byte, 32), nil }
func (c *stubQIOConn) AcceptStream(context.Context) (qio.Stream, error) { return nil, io.EOF }
func (c *stubQIOConn) OpenStream(context.Context) (qio.Stream, error)   { return nil, io.EOF }
func (c *stubQIOConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
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
func (c *stubQIOConn) SendDatagram([]byte) error           { return nil }
func (c *stubQIOConn) MaxDatagramSize() int                { return c.max }
func (c *stubQIOConn) CloseWithError(uint64, string) error { return nil }
func (c *stubQIOConn) Context() context.Context            { return context.Background() }
func (c *stubQIOConn) RemoteAddr() net.Addr                { return nil }

type stubQIOStream struct {
	net.Conn
	id         uint64
	closeCount atomic.Int32
}

func (s *stubQIOStream) ID() uint64          { return s.id }
func (s *stubQIOStream) CloseWrite() error   { return s.Conn.Close() }
func (s *stubQIOStream) Close() error        { s.closeCount.Add(1); return s.Conn.Close() }

func TestServeOneClosesClientOnWriteSetupResultFailureAndRelayEnd(t *testing.T) {
	rt, err := nwruntime.Load(testServiceKey, false)
	if err != nil {
		t.Fatal(err)
	}
	creds, err := wire.NewCredentials(testServiceKey)
	if err != nil {
		t.Fatal(err)
	}
	target, err := wire.NewIPTarget(netip.MustParseAddr("127.0.0.1"), 80)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("setup write failure closes client", func(t *testing.T) {
		local, remote := net.Pipe()
		defer remote.Close()
		tc := &trackingConn{Conn: local, writeErr: errors.New("broken pipe")}
		s := newSession(Config{SharedKey: testServiceKey, Upstream: &stubUpstream{}}, creds, rt)
		s.serveOne(context.Background(), &pipe{Reader: bufio.NewReader(tc), write: tc, closer: tc}, nil, wire.FlowTCP, target, 1, true)
		if tc.closeCount.Load() == 0 {
			t.Fatal("client connection was not closed after WriteSetupResult error")
		}
	})

	t.Run("normal TCP relay closes client", func(t *testing.T) {
		local, remote := net.Pipe()
		tc := &trackingConn{Conn: local}
		peerLocal, peerRemote := net.Pipe()
		_ = peerRemote.Close()
		s := newSession(Config{SharedKey: testServiceKey, Upstream: &stubUpstream{tcpPeer: peerLocal}}, creds, rt)

		done := make(chan struct{})
		go func() {
			defer close(done)
			s.serveOne(context.Background(), &pipe{Reader: bufio.NewReader(tc), write: tc, closer: tc}, nil, wire.FlowTCP, target, 1, true)
		}()

		if res, err := wire.ReadSetupResult(remote); err != nil || res != wire.SetupReady {
			t.Fatalf("ReadSetupResult = %v, %v", res, err)
		}
		_ = remote.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("serveOne did not finish")
		}
		if tc.closeCount.Load() == 0 {
			t.Fatal("client connection was not closed after relay")
		}
	})
}

func TestRelayQUICUnblocksPeerWithoutReadDeadline(t *testing.T) {
	rt, err := nwruntime.Load(testServiceKey, false)
	if err != nil {
		t.Fatal(err)
	}
	creds, err := wire.NewCredentials(testServiceKey)
	if err != nil {
		t.Fatal(err)
	}
	target, err := wire.NewIPTarget(netip.MustParseAddr("127.0.0.1"), 53)
	if err != nil {
		t.Fatal(err)
	}

	peer := newBlockingUDPPeer()
	qconn := &stubQIOConn{max: 1200, in: make(chan []byte, 4)}
	router := dgram.NewRouter(qconn, 64)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go router.Run(ctx)

	local, remote := net.Pipe()
	st := &stubQIOStream{Conn: local, id: 1}
	s := newSession(Config{SharedKey: testServiceKey, Upstream: &stubUpstream{udpPeer: peer}}, creds, rt)

	var req bytes.Buffer
	if err := wire.WriteFlowRequest(&req, wire.FlowUDP, target); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.serveStream(ctx, router, st, true)
	}()

	if _, err := remote.Write(req.Bytes()); err != nil {
		t.Fatal(err)
	}
	if res, err := wire.ReadSetupResult(remote); err != nil || res != wire.SetupReady {
		t.Fatalf("ReadSetupResult = %v, %v", res, err)
	}

	udpID, err := wire.UDPFlowID(1, true)
	if err != nil {
		t.Fatal(err)
	}
	frames, err := wire.EncodePacket(udpID, 1, []byte("hello"), 1200)
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
			if string(got) != "hello" {
				t.Fatalf("peer got %q, want %q", got, "hello")
			}
			received = true
		case <-time.After(10 * time.Millisecond):
		}
	}
	if !received {
		t.Fatal("UDP packet did not reach upstream peer")
	}

	// Closing the control stream must close peer before wg.Wait() and return promptly.
	_ = remote.Close()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("serveStream hung >100ms waiting on blocking peer.Read")
	}
	if peer.closeCount.Load() == 0 {
		t.Fatal("blocking UDP peer was not closed")
	}
	if st.closeCount.Load() == 0 {
		t.Fatal("business stream was not closed")
	}
}
