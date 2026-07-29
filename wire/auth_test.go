package wire

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestDeriveAuthKeyMatchesFixedVector(t *testing.T) {
	// Mirror of auth.rs::hkdf_and_auth_frames_match_fixed_vectors.
	key := DeriveAuthKey([]byte("secret"))
	want, _ := hex.DecodeString("1076221669fa28bcf70aa8545bddd6f760dcefbe279c3f38a5ff5d925708f867")
	if !bytes.Equal(key[:], want) {
		t.Fatalf("auth key mismatch\n got %x\nwant %x", key[:], want)
	}
}

func TestCredentialsRejectsBoundaryKeys(t *testing.T) {
	if _, err := NewCredentials(""); err == nil {
		t.Fatal("empty key accepted")
	}
	if _, err := NewCredentials(string(make([]byte, 256))); err == nil {
		t.Fatal("256-byte key accepted")
	}
	maxKey := string(make([]byte, MaxSharedKeyLen))
	if _, err := NewCredentials(maxKey); err != nil {
		t.Fatalf("255-byte key rejected: %v", err)
	}
}

func TestAuthFrameRoundTripAndReplayProtection(t *testing.T) {
	creds, err := NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	exporter := TLSExporter{}
	for i := range exporter {
		exporter[i] = byte(i)
	}
	sessionID := SessionID{}
	for i := range sessionID {
		sessionID[i] = byte(i)
	}

	for _, tc := range []struct {
		name      string
		transport AuthTransport
		wantHex   string
	}{
		{"tls_tcp", AuthTransportTLSTCP, "000102030405060708090a0b0c0d0e0f24a4c0d5f8946b65bcf270ed6e1c3dec"},
		{"quic", AuthTransportQUIC, "000102030405060708090a0b0c0d0e0f8176b984db64a1e2c811e751d955b635"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame, err := EncodeAuthFrame(creds, tc.transport, exporter, sessionID)
			if err != nil {
				t.Fatal(err)
			}
			if len(frame) != AuthFrameLen {
				t.Fatalf("frame len %d want %d", len(frame), AuthFrameLen)
			}
			want, _ := hex.DecodeString(tc.wantHex)
			if !bytes.Equal(frame[:], want) {
				t.Fatalf("frame mismatch\n got %x\nwant %x", frame[:], want)
			}
			got, err := ValidateAuthFrame(frame[:], creds, tc.transport, exporter)
			if err != nil {
				t.Fatalf("validate: %v", err)
			}
			if got != sessionID {
				t.Fatal("session id mismatch")
			}
		})
	}

	// Replay on a different exporter must fail.
	frame, err := EncodeAuthFrame(creds, AuthTransportQUIC, exporter, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	other := exporter
	other[0] ^= 1
	if _, err := ValidateAuthFrame(frame[:], creds, AuthTransportQUIC, other); err == nil {
		t.Fatal("replay on different exporter accepted")
	}
	// Replay on a different transport must fail.
	if _, err := ValidateAuthFrame(frame[:], creds, AuthTransportTLSTCP, exporter); err == nil {
		t.Fatal("replay on different transport accepted")
	}
	// Wrong key must fail.
	otherCreds, _ := NewCredentials("other")
	if _, err := ValidateAuthFrame(frame[:], otherCreds, AuthTransportQUIC, exporter); err == nil {
		t.Fatal("replay with wrong key accepted")
	}
}

func TestAuthFrameRejectsTruncatedAndTrailing(t *testing.T) {
	creds, _ := NewCredentials("secret")
	exporter := TLSExporter{}
	sessionID := SessionID{}
	frame, err := EncodeAuthFrame(creds, AuthTransportTLSTCP, exporter, sessionID)
	if err != nil {
		t.Fatal(err)
	}

	short := frame[:AuthFrameLen-1]
	if _, err := ValidateAuthFrame(short, creds, AuthTransportTLSTCP, exporter); err == nil {
		t.Fatal("truncated frame accepted")
	}
	trailing := append(append([]byte{}, frame[:]...), 0)
	if _, err := ValidateAuthFrame(trailing, creds, AuthTransportTLSTCP, exporter); err == nil {
		t.Fatal("trailing-byte frame accepted")
	}
}

func TestAuthFrameMutatedFieldsFail(t *testing.T) {
	creds, _ := NewCredentials("secret")
	exporter := TLSExporter{}
	sessionID := SessionID{}
	for i := range sessionID {
		sessionID[i] = byte(i)
	}
	frame, err := EncodeAuthFrame(creds, AuthTransportTLSTCP, exporter, sessionID)
	if err != nil {
		t.Fatal(err)
	}

	mutatedSession := frame
	mutatedSession[0] ^= 1
	if _, err := ValidateAuthFrame(mutatedSession[:], creds, AuthTransportTLSTCP, exporter); err == nil {
		t.Fatal("mutated session accepted")
	}
	mutatedTag := frame
	mutatedTag[AuthFrameLen-1] ^= 1
	if _, err := ValidateAuthFrame(mutatedTag[:], creds, AuthTransportTLSTCP, exporter); err == nil {
		t.Fatal("mutated tag accepted")
	}
}

func TestAuthTransportAndCredentialsValidation(t *testing.T) {
	creds, err := NewCredentials("secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EncodeAuthFrame(creds, AuthTransport(0xff), TLSExporter{}, SessionID{}); !errors.Is(err, ErrInvalidAuthTransport) {
		t.Fatalf("invalid transport error = %v", err)
	}
	if _, err := EncodeAuthFrame(nil, AuthTransportTLSTCP, TLSExporter{}, SessionID{}); !errors.Is(err, ErrMissingCredentials) {
		t.Fatalf("missing credentials error = %v", err)
	}
}
