package tcptls

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMaxMuxCarriersMatchesNowhere2(t *testing.T) {
	if MaxMuxCarriers != 8 {
		t.Fatalf("MaxMuxCarriers=%d want 8 (Nowhere 2)", MaxMuxCarriers)
	}
}

func TestMuxOpenHonorsCanceledContext(t *testing.T) {
	mgr, err := NewMuxManager(&Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	_, err = mgr.Open(ctx, 1, MuxUp)
	if !errors.Is(err, context.Canceled) && err == nil {
		t.Fatalf("Open error = %v, want canceled or dial failure", err)
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("canceled Open returned after %s", elapsed)
	}
}
