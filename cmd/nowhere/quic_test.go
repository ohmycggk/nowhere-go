package main

import (
	"testing"
)

// TestNW3QuicConfigMorphMtu pins the Morph path-MTU policy: the 12-byte nonce
// sits below QUIC, so the packet size stays at the QUIC minimum instead of
// probing the path MTU and overshooting by the nonce.
func TestNW3QuicConfigMorphMtu(t *testing.T) {
	plain := nw3QuicConfig(0, testProfile(), nil, false)
	if plain.DisablePathMTUDiscovery || plain.InitialPacketSize != 0 {
		t.Fatalf("plain QUIC config changed MTU policy: %+v", plain)
	}
	morph := nw3QuicConfig(0, testProfile(), nil, true)
	if !morph.DisablePathMTUDiscovery || morph.InitialPacketSize != 1200 {
		t.Fatalf("morph QUIC config = PMTUD disabled %v, initial packet %d; want true/1200",
			morph.DisablePathMTUDiscovery, morph.InitialPacketSize)
	}
}
