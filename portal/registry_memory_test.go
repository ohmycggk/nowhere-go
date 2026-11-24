package portal

import (
	"context"
	"runtime"
	"testing"
	"time"
)

func TestRegistryRingZerosPoppedSlotsAndShrinks(t *testing.T) {
	r := newRegistry(256)
	for i := 0; i < 128; i++ {
		if !r.reservePending() {
			t.Fatalf("reservePending failed at %d", i)
		}
		r.push(&egressSlot{
			tls:  true,
			dead: make(chan struct{}),
		})
	}
	if len(r.slots) < 128 {
		t.Fatalf("expected backing slice >= 128, got %d", len(r.slots))
	}

	// Claim all 128 in FIFO order and confirm slice shrinks cleanly.
	for i := 0; i < 128; i++ {
		slot, isTLS, ok := r.claim(context.Background(), time.Now().Add(time.Second))
		if !ok || !isTLS || slot == nil {
			t.Fatalf("claim %d = %v %v %v", i, slot, isTLS, ok)
		}
		slot.close()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.count != 0 || r.pending != 0 {
		t.Fatalf("count=%d pending=%d, want 0/0", r.count, r.pending)
	}
	if len(r.slots) > 64 {
		t.Fatalf("expected backing slice to shrink <= 64 after full drain, got len=%d", len(r.slots))
	}
	for i, s := range r.slots {
		if s != nil {
			t.Fatalf("slot[%d] still retains popped pointer", i)
		}
	}
}

func TestRegistryPushAndFastClaimNoGoroutineLeak(t *testing.T) {
	runtime.GC()
	time.Sleep(10 * time.Millisecond)
	base := runtime.NumGoroutine()

	r := newRegistry(256)
	for i := 0; i < 150; i++ {
		if !r.reservePending() {
			t.Fatal("reservePending failed")
		}
		s := &egressSlot{
			tls:     true,
			expires: time.Now().Add(time.Minute),
			dead:    make(chan struct{}),
		}
		r.push(s)
		got, isTLS, ok := r.claim(context.Background(), time.Now().Add(time.Second))
		if !ok || !isTLS || got != s {
			t.Fatalf("claim %d mismatch", i)
		}
		got.close()
	}

	runtime.GC()
	time.Sleep(20 * time.Millisecond)
	if now := runtime.NumGoroutine(); now > base+2 {
		t.Fatalf("goroutines = %d, baseline = %d (leak detected)", now, base)
	}
}

func TestParkUntilRespectsContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	start := time.Now()
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	parkUntil(ctx, time.Now().Add(30*time.Second))
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("parkUntil ignored context cancel: elapsed %s", elapsed)
	}
}
