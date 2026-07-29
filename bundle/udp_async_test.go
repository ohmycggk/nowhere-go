package bundle

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ohmycggk/nowhere-go/carrier"
	"github.com/ohmycggk/nowhere-go/wire"
)

func TestOpenUDPAsyncCloseCancelsPendingSetup(t *testing.T) {
	credentials, err := wire.NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	backend := &blockingQUICBackend{block: make(chan struct{})}
	bundle, err := NewCarrierBundle(BundleOptions{
		QUIC: backend, Credentials: credentials,
		Up: wire.CarrierQUIC, Down: wire.CarrierQUIC,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bundle.Close()

	target, err := wire.NewDomainTarget("example.com", 53)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := bundle.OpenUDPAsync(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		done <- pc.Close()
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close = %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Close blocked on pending OpenUDP")
	}
	close(backend.block)
}

func TestAsyncUDPConnQueuesFirstPacket(t *testing.T) {
	inner := &recordingPacketConn{}
	c := &asyncUDPConn{
		cancel: func() {},
		queue:  make(chan queuedUDPPacket, DefaultUDPSetupQueuePackets),
		ready:  make(chan struct{}),
		closed: make(chan struct{}),
	}
	if n, err := c.WriteTo([]byte("first"), &net.UDPAddr{}); err != nil || n != 5 {
		t.Fatalf("queued write = (%d, %v)", n, err)
	}
	c.mu.Lock()
	c.inner = inner
	c.mu.Unlock()
	close(c.ready)
	// Drain like runSetup.
	for {
		select {
		case pkt := <-c.queue:
			_, _ = inner.WriteTo(pkt.payload, pkt.addr)
		default:
			goto drained
		}
	}
drained:
	inner.mu.Lock()
	defer inner.mu.Unlock()
	if len(inner.writes) != 1 || string(inner.writes[0]) != "first" {
		t.Fatalf("drained writes = %v", inner.writes)
	}
	_ = c.Close()
}

type blockingQUICBackend struct {
	block chan struct{}
}

func (b *blockingQUICBackend) AcquireSession(ctx context.Context) (carrier.QuicSession, error) {
	select {
	case <-b.block:
		return nil, errors.New("released")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (*blockingQUICBackend) InvalidateSession(carrier.QuicSession) {}
func (*blockingQUICBackend) Close() error                          { return nil }

type recordingPacketConn struct {
	mu     sync.Mutex
	writes [][]byte
}

func (c *recordingPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (c *recordingPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}
func (*recordingPacketConn) Close() error                     { return nil }
func (*recordingPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*recordingPacketConn) SetDeadline(time.Time) error      { return nil }
func (*recordingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*recordingPacketConn) SetWriteDeadline(time.Time) error { return nil }
