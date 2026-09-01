package tcptls

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestFlowsPerShardMatchesNowhere181(t *testing.T) {
	if FlowsPerShard != 4 {
		t.Fatalf("FlowsPerShard=%d want 4 (Nowhere 1.8.1)", FlowsPerShard)
	}
}

func TestShardConnectSerializationHonorsContext(t *testing.T) {
	mgr, err := NewMuxManager(&Config{})
	if err != nil {
		t.Fatal(err)
	}
	set := mgr.up
	if err := set.acquireConnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer set.releaseConnect()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = mgr.Open(ctx, 1, MuxUp)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Open error = %v, want context deadline", err)
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("context-aware lock returned after %s", elapsed)
	}
}
