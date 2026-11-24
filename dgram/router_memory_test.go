package dgram

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ohmycggk/nowhere-go/wire"
)

func TestRouterByteBudgetAcrossFlowsAndReclaim(t *testing.T) {
	r := NewRouter(&supportTestConn{max: 1200}, 100)
	f1 := r.Register(1)
	f2 := r.Register(2)

	p60 := bytes.Repeat([]byte("a"), 60)
	p50 := bytes.Repeat([]byte("b"), 50)
	r.deliver(1, p60)
	// Second 60-byte packet exceeds 100-byte connection-wide budget and must drop.
	r.deliver(2, p60)
	select {
	case got := <-f2.C:
		t.Fatalf("flow 2 received %d bytes despite full router budget", len(got))
	default:
	}

	// Reading from flow 1 reclaims its 60 bytes on the next deliver.
	if got := <-f1.C; len(got) != 60 {
		t.Fatalf("flow 1 got %d bytes, want 60", len(got))
	}
	r.deliver(2, p50)
	select {
	case got := <-f2.C:
		if len(got) != 50 {
			t.Fatalf("flow 2 got %d bytes, want 50", len(got))
		}
	default:
		t.Fatal("flow 2 was not delivered after flow 1 reclaimed budget")
	}

	// Unregistering flow 2 must release its queued bytes immediately.
	r.deliver(2, p50)
	r.Unregister(2)
	r.mu.Lock()
	rem := r.queuedBytes
	r.mu.Unlock()
	if rem != 0 {
		t.Fatalf("queuedBytes after unregister = %d, want 0", rem)
	}
}

func TestRouterConcurrentFragmentsAndUnregisterRace(t *testing.T) {
	conn := &supportTestConn{recv: make(chan []byte, 256), max: 1200}
	r := NewRouter(conn, 1<<20)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		r.Run(ctx)
	}()

	payload := bytes.Repeat([]byte("x"), 2500)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := uint32(1); i <= 40; i++ {
			id := (i % 4) + 1
			frames, err := wire.EncodePacket(id, i, payload, 1200)
			if err != nil {
				return
			}
			for _, f := range frames {
				conn.recv <- f
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 80; i++ {
			id := uint32((i % 4) + 1)
			f := r.Register(id)
			select {
			case <-f.C:
			default:
			}
			r.Unregister(id)
		}
	}()
	wg.Wait()
	close(conn.recv)
	<-runDone

	// On exit, Run must have cleared tab and reassembler.
	r.mu.Lock()
	tabs := len(r.tab)
	queued := r.queuedBytes
	r.mu.Unlock()
	if tabs != 0 || queued != 0 {
		t.Fatalf("after Run exit: tabs=%d queued=%d, want 0/0", tabs, queued)
	}
}

func TestRouterRunClosesFlowsOnExit(t *testing.T) {
	conn := &supportTestConn{recv: make(chan []byte), max: 1200}
	r := NewRouter(conn, 4096)
	f := r.Register(9)
	go r.Run(context.Background())
	close(conn.recv)
	select {
	case <-f.Done():
	case <-time.After(time.Second):
		t.Fatal("flow was not closed when Router.Run exited")
	}
}
