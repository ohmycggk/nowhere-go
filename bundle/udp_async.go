package bundle

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ohmycggk/nowhere-go/wire"
)

// DefaultUDPSetupQueuePackets bounds first-packet buffering while an async UDP
// target tunnel is still opening (aligned with Rust Vector mpsc(64)).
const DefaultUDPSetupQueuePackets = 64

// OpenUDPAsync returns a PacketConn immediately and opens the UDP flow in the
// background. Writes before READY are queued (bounded); Close cancels setup.
// Prefer this for host UDP associations so a slow Portal dial cannot block the
// association loop. OpenUDP remains available when callers need a READY flow.
//
// Setup is detached from ctx cancel/deadline: hosts typically cancel the
// ListenPacket dial context as soon as the PacketConn is returned.
func (b *CarrierBundle) OpenUDPAsync(ctx context.Context, target wire.Target) (net.PacketConn, error) {
	if err := target.Validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	setupCtx, cancel := context.WithCancel(context.Background())
	c := &asyncUDPConn{
		bundle: b,
		target: target,
		cancel: cancel,
		queue:  make(chan queuedUDPPacket, DefaultUDPSetupQueuePackets),
		ready:  make(chan struct{}),
		closed: make(chan struct{}),
	}
	go c.runSetup(setupCtx)
	return c, nil
}

type queuedUDPPacket struct {
	payload []byte
	addr    net.Addr
}

type asyncUDPConn struct {
	bundle *CarrierBundle
	target wire.Target
	cancel context.CancelFunc

	queue chan queuedUDPPacket
	ready chan struct{}
	closed chan struct{}

	mu       sync.Mutex
	inner    net.PacketConn
	setupErr error
	closeErr error
	closedFlag bool

	rd deadlineWatch
	wd deadlineWatch
}

type deadlineWatch struct {
	mu sync.Mutex
	t  time.Time
}

func (d *deadlineWatch) set(t time.Time) {
	d.mu.Lock()
	d.t = t
	d.mu.Unlock()
}

func (d *deadlineWatch) expired() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return !d.t.IsZero() && time.Now().After(d.t)
}

func (c *asyncUDPConn) runSetup(ctx context.Context) {
	pc, err := c.bundle.OpenUDP(ctx, c.target)
	c.mu.Lock()
	if c.closedFlag {
		c.mu.Unlock()
		if pc != nil {
			_ = pc.Close()
		}
		return
	}
	if err != nil {
		c.setupErr = err
		c.mu.Unlock()
		close(c.ready)
		return
	}
	c.inner = pc
	c.mu.Unlock()
	close(c.ready)

	// Drain queued first packets onto the live flow.
	for {
		select {
		case <-c.closed:
			return
		case pkt, ok := <-c.queue:
			if !ok {
				return
			}
			if _, werr := pc.WriteTo(pkt.payload, pkt.addr); werr != nil {
				return
			}
		default:
			return
		}
	}
}

func (c *asyncUDPConn) waitReady(ctx context.Context) error {
	select {
	case <-c.ready:
		c.mu.Lock()
		err := c.setupErr
		c.mu.Unlock()
		return err
	case <-c.closed:
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *asyncUDPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.wd.expired() {
		return 0, osErrDeadline()
	}
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case <-c.ready:
		c.mu.Lock()
		inner := c.inner
		err := c.setupErr
		c.mu.Unlock()
		if err != nil {
			return 0, err
		}
		if inner == nil {
			return 0, net.ErrClosed
		}
		return inner.WriteTo(p, addr)
	default:
		payload := append([]byte(nil), p...)
		select {
		case c.queue <- queuedUDPPacket{payload: payload, addr: addr}:
			return len(p), nil
		default:
			// Bounded queue full: drop like Rust try_send Full.
			return len(p), nil
		case <-c.closed:
			return 0, net.ErrClosed
		case <-c.ready:
			c.mu.Lock()
			inner := c.inner
			err := c.setupErr
			c.mu.Unlock()
			if err != nil {
				return 0, err
			}
			if inner == nil {
				return 0, net.ErrClosed
			}
			return inner.WriteTo(p, addr)
		}
	}
}

func (c *asyncUDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.rd.expired() {
		return 0, nil, osErrDeadline()
	}
	if err := c.waitReady(context.Background()); err != nil {
		return 0, nil, err
	}
	c.mu.Lock()
	inner := c.inner
	c.mu.Unlock()
	if inner == nil {
		return 0, nil, net.ErrClosed
	}
	return inner.ReadFrom(p)
}

func (c *asyncUDPConn) Close() error {
	c.mu.Lock()
	if c.closedFlag {
		err := c.closeErr
		c.mu.Unlock()
		return err
	}
	c.closedFlag = true
	c.cancel()
	close(c.closed)
	inner := c.inner
	c.mu.Unlock()

	var errs []error
	if inner != nil {
		if err := inner.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	c.mu.Lock()
	c.closeErr = errors.Join(errs...)
	err := c.closeErr
	c.mu.Unlock()
	return err
}

func (c *asyncUDPConn) LocalAddr() net.Addr {
	c.mu.Lock()
	inner := c.inner
	c.mu.Unlock()
	if inner != nil {
		return inner.LocalAddr()
	}
	return &net.UDPAddr{}
}

func (c *asyncUDPConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *asyncUDPConn) SetReadDeadline(t time.Time) error {
	c.rd.set(t)
	c.mu.Lock()
	inner := c.inner
	c.mu.Unlock()
	if inner != nil {
		return inner.SetReadDeadline(t)
	}
	return nil
}

func (c *asyncUDPConn) SetWriteDeadline(t time.Time) error {
	c.wd.set(t)
	c.mu.Lock()
	inner := c.inner
	c.mu.Unlock()
	if inner != nil {
		return inner.SetWriteDeadline(t)
	}
	return nil
}

func osErrDeadline() error {
	return errDatagramDeadline
}

var _ net.PacketConn = (*asyncUDPConn)(nil)
var _ io.Closer = (*asyncUDPConn)(nil)
