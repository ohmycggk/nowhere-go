package runtime

import (
	"os"
	"testing"
	"time"
)

func TestHandshakeTimeoutPinnedKey(t *testing.T) {
	got := HandshakeTimeout("0123456789abcdef0123456789abcdef")
	if got != 9100*time.Millisecond {
		t.Fatalf("derived timeout = %s, want 9100ms", got)
	}
}

func TestLoadUsesDerivedHandshakeAndOverride(t *testing.T) {
	if err := os.Unsetenv(EnvHandshakeTimeout); err != nil {
		t.Fatal(err)
	}
	got, err := Load("0123456789abcdef0123456789abcdef", false)
	if err != nil {
		t.Fatal(err)
	}
	if got.HandshakeTimeout != 9100*time.Millisecond {
		t.Fatalf("unset = %s", got.HandshakeTimeout)
	}
	t.Setenv(EnvHandshakeTimeout, "45s")
	got, err = Load("0123456789abcdef0123456789abcdef", false)
	if err != nil {
		t.Fatal(err)
	}
	if got.HandshakeTimeout != 45*time.Second {
		t.Fatalf("override = %s", got.HandshakeTimeout)
	}
}

func TestLoadRejectsBadDurationWithName(t *testing.T) {
	t.Setenv(EnvFlowSetupTimeout, "nope")
	_, err := Load("0123456789abcdef0123456789abcdef", false)
	if err == nil || len(err.Error()) < len(EnvFlowSetupTimeout) || err.Error()[:len(EnvFlowSetupTimeout)] != EnvFlowSetupTimeout {
		t.Fatalf("error = %v", err)
	}
}

func TestUDPPreludeRequiredOnlyForMorphClient(t *testing.T) {
	t.Setenv(EnvMorphUDPPrelude, "nope")
	if _, err := Load("k", false); err != nil {
		t.Fatal(err)
	}
	if _, err := Load("k", true); err == nil {
		t.Fatal("invalid udp prelude accepted")
	}
}
