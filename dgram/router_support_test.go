package dgram

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"

	"github.com/ohmycggk/nowhere-go/qio"
	"github.com/ohmycggk/nowhere-go/wire"
)

type supportTestConn struct {
	recv chan []byte
	max  int
}

func (c *supportTestConn) TLSVersion() uint16        { return 0x0304 }
func (c *supportTestConn) ALPN() string              { return wire.ALPN }
func (c *supportTestConn) Exporter() ([]byte, error) { return make([]byte, 32), nil }
func (c *supportTestConn) AcceptStream(context.Context) (qio.Stream, error) {
	return nil, io.EOF
}
func (c *supportTestConn) OpenStream(context.Context) (qio.Stream, error) { return nil, io.EOF }
func (c *supportTestConn) ReceiveDatagram(context.Context) ([]byte, error) {
	pkt, ok := <-c.recv
	if !ok {
		return nil, io.EOF
	}
	return append([]byte(nil), pkt...), nil
}
func (c *supportTestConn) SendDatagram([]byte) error           { return nil }
func (c *supportTestConn) MaxDatagramSize() int                { return c.max }
func (c *supportTestConn) CloseWithError(uint64, string) error { return nil }
func (c *supportTestConn) Context() context.Context            { return context.Background() }
func (c *supportTestConn) RemoteAddr() net.Addr                { return nil }

// TestSendRejectsMissingDatagramSupport pins the Core rule that a missing
// DATAGRAM capability is not replaced by a fallback carrier or a guessed MTU.
func TestSendRejectsMissingDatagramSupport(t *testing.T) {
	r := NewRouter(&supportTestConn{max: 0}, 0)
	if err := r.Send(1, []byte("payload")); err == nil {
		t.Fatal("Send accepted a connection without DATAGRAM support")
	}
}

// TestFragmentsForUnknownFlowTakeNoSlot checks that a FRAGMENT for an
// unregistered flow is discarded before it consumes a reassembly reservation.
// The byte budget is sized to hold one payload; a registered flow's packet can
// only be delivered if the unknown flow's fragment never reserved a slot.
func TestFragmentsForUnknownFlowTakeNoSlot(t *testing.T) {
	const budget = 4000
	conn := &supportTestConn{recv: make(chan []byte, 16), max: 1200}
	r := NewRouter(conn, budget)
	known := r.Register(8)

	payload := bytes.Repeat([]byte("z"), 3000)
	unknownFrames, err := wire.EncodePacket(7, 1, payload, 1200)
	if err != nil {
		t.Fatal(err)
	}
	knownFrames, err := wire.EncodePacket(8, 2, payload, 1200)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		r.Run(context.Background())
		close(done)
	}()
	for _, frame := range unknownFrames {
		conn.recv <- frame
	}
	for _, frame := range knownFrames {
		conn.recv <- frame
	}
	close(conn.recv)
	<-done

	select {
	case got := <-known.C:
		if !bytes.Equal(got, payload) {
			t.Fatalf("reassembled %d bytes, want %d", len(got), len(payload))
		}
	default:
		t.Fatal("the known flow was starved by an unknown flow's reassembly slot")
	}
}

// TestFragmentsForKnownFlowReassemble is the positive counterpart: once the
// control stream registers the flow, its fragments are reassembled and
// delivered.
func TestFragmentsForKnownFlowReassemble(t *testing.T) {
	conn := &supportTestConn{recv: make(chan []byte, 8), max: 1200}
	r := NewRouter(conn, 1<<20)
	flow := r.Register(7)
	payload := bytes.Repeat([]byte("y"), 3000)
	frames, err := wire.EncodePacket(7, 2, payload, 1200)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		r.Run(context.Background())
		close(done)
	}()
	for _, frame := range frames {
		conn.recv <- frame
	}
	close(conn.recv)
	<-done

	select {
	case got := <-flow.C:
		if !bytes.Equal(got, payload) {
			t.Fatalf("reassembled %d bytes, want %d", len(got), len(payload))
		}
	default:
		t.Fatal("the registered flow received no datagram")
	}
}
