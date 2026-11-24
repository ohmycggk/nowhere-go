package portal

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ohmycggk/nowhere-go/dgram"
	"github.com/ohmycggk/nowhere-go/qio"
)

// egressSlot is one registered Egress connection. TLS slots leave the FIFO
// when claimed. QUIC slots return to the tail and can carry another flow.
type egressSlot struct {
	conn    qio.Conn
	tlsConn net.Conn
	router  *dgram.Router
	tls     bool
	expires time.Time
	reader  io.Reader
	dead    chan struct{}
	once    sync.Once
	owned   bool

	timerMu sync.Mutex
	timer   *time.Timer
}

func (s *egressSlot) close() {
	s.once.Do(func() { close(s.dead) })
	s.timerMu.Lock()
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	s.timerMu.Unlock()
}

func (s *egressSlot) alive() bool {
	select {
	case <-s.dead:
		return false
	default:
		return true
	}
}

// registry is the Portal FIFO shared by TLS and QUIC Egress connections.
// It stores slots in a compact ring buffer, zeroing popped entries so closed
// connections are never retained in the backing array.
type registry struct {
	mu       sync.Mutex
	cond     *sync.Cond
	slots    []*egressSlot
	head     int
	count    int
	pending  int
	pendingN int
}

func newRegistry(pendingMax int) *registry {
	r := &registry{pendingN: pendingMax}
	r.cond = sync.NewCond(&r.mu)
	return r
}

func (r *registry) pushBackLocked(slot *egressSlot) {
	if r.count == len(r.slots) {
		newCap := len(r.slots) * 2
		if newCap < 8 {
			newCap = 8
		}
		grown := make([]*egressSlot, newCap)
		for i := 0; i < r.count; i++ {
			grown[i] = r.slots[(r.head+i)%len(r.slots)]
		}
		r.slots = grown
		r.head = 0
	}
	tail := (r.head + r.count) % len(r.slots)
	r.slots[tail] = slot
	r.count++
}

func (r *registry) popFrontLocked() (*egressSlot, bool) {
	if r.count == 0 {
		return nil, false
	}
	slot := r.slots[r.head]
	r.slots[r.head] = nil
	r.head = (r.head + 1) % len(r.slots)
	r.count--
	r.maybeShrinkLocked()
	return slot, true
}

func (r *registry) removeLocked(target *egressSlot) bool {
	for i := 0; i < r.count; i++ {
		idx := (r.head + i) % len(r.slots)
		if r.slots[idx] != target {
			continue
		}
		for j := i; j+1 < r.count; j++ {
			dst := (r.head + j) % len(r.slots)
			src := (r.head + j + 1) % len(r.slots)
			r.slots[dst] = r.slots[src]
		}
		last := (r.head + r.count - 1) % len(r.slots)
		r.slots[last] = nil
		r.count--
		r.maybeShrinkLocked()
		return true
	}
	return false
}

func (r *registry) maybeShrinkLocked() {
	if r.count == 0 {
		r.head = 0
		if len(r.slots) > 64 {
			r.slots = nil
		}
		return
	}
	if len(r.slots) > 64 && r.count*4 <= len(r.slots) {
		newCap := len(r.slots) / 2
		shrunk := make([]*egressSlot, newCap)
		for i := 0; i < r.count; i++ {
			shrunk[i] = r.slots[(r.head+i)%len(r.slots)]
		}
		r.slots = shrunk
		r.head = 0
	}
}

// reservePending counts one TLS connection that is still being accepted or
// is waiting for a flow. false means the Portal-wide cap is full.
func (r *registry) reservePending() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending >= r.pendingN {
		return false
	}
	r.pending++
	return true
}

func (r *registry) releasePending() {
	r.mu.Lock()
	if r.pending > 0 {
		r.pending--
	}
	r.mu.Unlock()
}

// push appends an accepted connection. A TLS slot with expires set is dropped
// at that instant. Activity does not move the deadline.
func (r *registry) push(slot *egressSlot) {
	r.mu.Lock()
	r.pushBackLocked(slot)
	r.cond.Broadcast()
	r.mu.Unlock()
	if slot.expires.IsZero() {
		return
	}
	wait := time.Until(slot.expires)
	if wait < 0 {
		wait = 0
	}
	t := time.AfterFunc(wait, func() {
		if r.expire(slot) {
			slot.close()
			if slot.tlsConn != nil {
				_ = slot.tlsConn.Close()
			}
		}
	})
	slot.timerMu.Lock()
	if !slot.alive() {
		t.Stop()
	} else {
		slot.timer = t
	}
	slot.timerMu.Unlock()
}

// take removes slot when it is still queued and no claim owns it. release
// returns one TLS pending allowance. false means the caller must not close
// the connection.
func (r *registry) take(slot *egressSlot, release bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if slot.owned {
		return false
	}
	if !r.removeLocked(slot) {
		return false
	}
	slot.owned = true
	if release && slot.tls && r.pending > 0 {
		r.pending--
	}
	return true
}

// expire is the standby timer's take. Ownership and the pending count move
// under the same lock as claim.
func (r *registry) expire(slot *egressSlot) bool {
	return r.take(slot, true)
}

func (r *registry) tryClaimLocked() (*egressSlot, bool, bool) {
	for r.count > 0 {
		slot, _ := r.popFrontLocked()
		if !slot.alive() || slot.owned {
			continue
		}
		if slot.tls {
			slot.owned = true
			if r.pending > 0 {
				r.pending--
			}
			return slot, true, true
		}
		r.pushBackLocked(slot)
		return slot, false, true
	}
	return nil, false, false
}

// claim waits until deadline for a live connection. A TLS claim leaves the
// FIFO and releases one pending-registration allowance. A QUIC claim moves
// the same slot to the tail. The bool is true when the claimed slot is TLS.
func (r *registry) claim(ctx context.Context, deadline time.Time) (*egressSlot, bool, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if slot, isTLS, ok := r.tryClaimLocked(); ok {
		return slot, isTLS, true
	}
	wait := time.Until(deadline)
	if ctx.Err() != nil || wait <= 0 {
		return nil, false, false
	}
	wake := func() {
		r.mu.Lock()
		r.cond.Broadcast()
		r.mu.Unlock()
	}
	timer := time.AfterFunc(wait, wake)
	defer timer.Stop()
	stopCtx := context.AfterFunc(ctx, wake)
	defer stopCtx()
	for {
		if slot, isTLS, ok := r.tryClaimLocked(); ok {
			return slot, isTLS, true
		}
		if ctx.Err() != nil || !time.Now().Before(deadline) {
			return nil, false, false
		}
		r.cond.Wait()
	}
}
