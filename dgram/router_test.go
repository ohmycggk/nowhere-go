package dgram

import (
	"testing"

	"github.com/ohmycggk/nowhere-go/wire"
)

func TestFragmentBeforeReadyIsUnknown(t *testing.T) {
	r := NewRouter(nil, 0)
	frame := make([]byte, 14)
	// FRAGMENT, flow 7, packet 1, index 0 of 2, total 4, two payload bytes.
	// Each other fragment must be able to hold at least one byte.
	frame[0] = 0x40
	frame[3] = 7
	frame[7] = 1
	frame[9] = 2
	frame[11] = 4
	frame[12] = 1
	frame[13] = 2
	d, err := wire.DecodeDatagram(frame)
	if err != nil {
		t.Fatal(err)
	}
	if d.Type != 1 || d.FlowID != 7 {
		t.Fatalf("decoded %+v", d)
	}
	if r.known(d.FlowID) {
		t.Fatal("unregistered flow reported known")
	}
	r.Register(7)
	if !r.known(7) {
		t.Fatal("registered flow not known")
	}
	r.Unregister(7)
	if r.known(7) {
		t.Fatal("unregistered flow still known")
	}
}
