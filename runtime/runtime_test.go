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

func TestTransportMemoryProfiles(t *testing.T) {
	t.Setenv(EnvMemoryProfile, "sentinel")
	if err := os.Unsetenv(EnvMemoryProfile); err != nil {
		t.Fatal(err)
	}
	got, err := Load("0123456789abcdef0123456789abcdef", false)
	if err != nil {
		t.Fatal(err)
	}
	const mib = 1 << 20
	if got.Profile != (Profile{Name: "throughput", Stream: 4 * mib, Connection: 32 * mib, Send: 32 * mib}) {
		t.Fatalf("default profile = %+v", got.Profile)
	}
	for _, tc := range []struct {
		name string
		want Profile
	}{
		{name: "memory", want: Profile{Name: "memory", Stream: 4 * mib, Connection: 16 * mib, Send: 8 * mib}},
		{name: "balanced", want: Profile{Name: "balanced", Stream: 4 * mib, Connection: 16 * mib, Send: 16 * mib}},
		{name: "throughput", want: Profile{Name: "throughput", Stream: 4 * mib, Connection: 32 * mib, Send: 32 * mib}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvMemoryProfile, tc.name)
			s, err := Load("0123456789abcdef0123456789abcdef", false)
			if err != nil {
				t.Fatal(err)
			}
			if s.Profile != tc.want {
				t.Fatalf("profile %s = %+v, want %+v", tc.name, s.Profile, tc.want)
			}
		})
	}
	t.Setenv(EnvMemoryProfile, "fast")
	if _, err := Load("0123456789abcdef0123456789abcdef", false); err == nil {
		t.Fatal("invalid memory profile accepted")
	}
}
