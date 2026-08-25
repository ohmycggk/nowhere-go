package tcptls

import "testing"

func TestFlowsPerShardMatchesNowhere181(t *testing.T) {
	if FlowsPerShard != 4 {
		t.Fatalf("FlowsPerShard=%d want 4 (Nowhere 1.8.1)", FlowsPerShard)
	}
}
