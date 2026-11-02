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
}

func (s *egressSlot) close() {
	s.once.Do(func() { close(s.dead) })
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
type registry struct {
	mu       sync.Mutex
	cond     *sync.Cond
	slots    []*egressSlot
	pending  int
	pendingN int
}

func newRegistry(pendingMax int) *registry {
	r := &registry{pendingN: pendingMax}
	r.cond = sync.NewCond(&r.mu)
	return r
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

// push appends an accepted connection. A TLS slot with Expires set is dropped
// at that instant. Activity does not move the deadline.
func (r *registry) push(slot *egressSlot) {
	r.mu.Lock()
	r.slots = append(r.slots, slot)
	r.cond.Broadcast()
	r.mu.Unlock()
	if slot.expires.IsZero() {
		return
	}
	wait := time.Until(slot.expires)
	if wait < 0 {
		wait = 0
	}
	timer := time.NewTimer(wait)
	go func() {
		select {
		case <-timer.C:
			if r.expire(slot) {
				slot.close()
				if slot.tlsConn != nil {
					_ = slot.tlsConn.Close()
				}
			}
		case <-slot.dead:
			timer.Stop()
		}
	}()
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
	found := false
	for i, cur := range r.slots {
		if cur == slot {
			r.slots = append(r.slots[:i], r.slots[i+1:]...)
			found = true
			break
		}
	}
	if !found {
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

// claim waits until deadline for a live connection. A TLS claim leaves the
// FIFO and releases one pending-registration allowance. A QUIC claim moves
// the same slot to the tail. The bool is true when the claimed slot is TLS.
func (r *registry) claim(ctx context.Context, deadline time.Time) (*egressSlot, bool, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-timer.C:
		case <-ctx.Done():
		case <-stop:
			return
		}
		r.mu.Lock()
		r.cond.Broadcast()
		r.mu.Unlock()
	}()
	for {
		for len(r.slots) > 0 {
			slot := r.slots[0]
			r.slots = r.slots[1:]
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
			r.slots = append(r.slots, slot)
			return slot, false, true
		}
		if ctx.Err() != nil || !time.Now().Before(deadline) {
			return nil, false, false
		}
		r.cond.Wait()
	}
}
