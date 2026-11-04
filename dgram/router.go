// Package dgram routes QUIC DATAGRAM frames to connection-local UDP flows.
package dgram

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ohmycggk/nowhere-go/qio"
	"github.com/ohmycggk/nowhere-go/wire"
)

const queueLen = 64

// Flow receives complete UDP payloads for one flow id.
type Flow struct {
	ID     uint32
	C      chan []byte
	closed chan struct{}
	once   sync.Once
}

// Close unblocks receivers.
func (f *Flow) Close() {
	if f == nil {
		return
	}
	f.once.Do(func() { close(f.closed) })
}

// Router demultiplexes datagrams on one QUIC connection.
type Router struct {
	conn     qio.Conn
	overhead int
	mu       sync.Mutex
	tab      map[uint32]*Flow
	re       *wire.Reassembler
	pkt      atomic.Uint32
}

// NewRouter returns a router whose reassembly reservation is maxBytes.
// Zero uses the 4 MiB default. Call Run to start the receive loop.
func NewRouter(conn qio.Conn, maxBytes int) *Router {
	if maxBytes <= 0 {
		maxBytes = 4 << 20
	}
	return &Router{
		conn: conn,
		tab:  map[uint32]*Flow{},
		re:   wire.NewReassembler(64, maxBytes, 0),
	}
}

// SetOverhead reserves bytes that sit below the QUIC datagram, such as the
// Morph UDP nonce. Encoding uses MaxDatagramSize minus this many bytes so the
// prefix counts toward the path MTU. Zero leaves the transport size unchanged.
func (r *Router) SetOverhead(n int) {
	if r == nil || n < 0 {
		return
	}
	r.mu.Lock()
	r.overhead = n
	r.mu.Unlock()
}

// Register installs a flow. The previous flow with the same id is closed.
func (r *Router) Register(id uint32) *Flow {
	f := &Flow{ID: id, C: make(chan []byte, queueLen), closed: make(chan struct{})}
	r.mu.Lock()
	if old := r.tab[id]; old != nil {
		old.Close()
	}
	r.tab[id] = f
	r.mu.Unlock()
	return f
}

// Unregister drops a flow and its partial packets.
func (r *Router) Unregister(id uint32) {
	r.mu.Lock()
	f := r.tab[id]
	delete(r.tab, id)
	r.mu.Unlock()
	if f != nil {
		f.Close()
	}
	r.re.RemoveFlow(id)
}

// MaxDatagramSize reports the peer's DATAGRAM payload limit for this
// connection, or zero when the peer did not negotiate DATAGRAM support.
func (r *Router) MaxDatagramSize() int { return r.conn.MaxDatagramSize() }

// Send encodes one payload and writes it without blocking the caller on a peer flow.
func (r *Router) Send(id uint32, payload []byte) error {
	n := r.pkt.Add(1)
	if n == 0 {
		n = r.pkt.Add(1)
	}
	max := r.conn.MaxDatagramSize()
	if max <= 0 {
		// Core forbids a fallback carrier when DATAGRAM support is missing.
		return errors.New("nw3: DATAGRAM support unavailable")
	}
	r.mu.Lock()
	overhead := r.overhead
	r.mu.Unlock()
	if overhead > 0 && max > overhead {
		max -= overhead
	}
	frames, err := wire.EncodePacket(id, n, payload, max)
	if err != nil {
		return err
	}
	for _, frame := range frames {
		if err := r.conn.SendDatagram(frame); err != nil {
			return err
		}
	}
	return nil
}

// CloseFlow sends an auxiliary CLOSE and unregisters the flow.
func (r *Router) CloseFlow(id uint32) {
	if frame, err := wire.EncodeClose(id); err == nil {
		_ = r.conn.SendDatagram(frame)
	}
	r.Unregister(id)
}

// Run reads datagrams until ctx ends or the connection fails.
func (r *Router) Run(ctx context.Context) {
	for {
		buf, err := r.conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		d, err := wire.DecodeDatagram(buf)
		if err != nil {
			continue
		}
		switch d.Type {
		case 0:
			r.deliver(d.FlowID, append([]byte(nil), d.Payload...))
		case 1:
			// An unknown or not-yet-ready flow must not take a reassembly
			// slot. The control stream installs the route before READY.
			if !r.known(d.FlowID) {
				continue
			}
			pkt, err := r.re.Push(d, time.Now())
			if err != nil || pkt == nil {
				continue
			}
			r.deliver(d.FlowID, pkt)
		case 2:
			// CLOSE is auxiliary. The control stream owns lifetime.
		}
	}
}

func (r *Router) known(id uint32) bool {
	r.mu.Lock()
	_, ok := r.tab[id]
	r.mu.Unlock()
	return ok
}

func (r *Router) deliver(id uint32, payload []byte) {
	r.mu.Lock()
	f := r.tab[id]
	r.mu.Unlock()
	if f == nil {
		return
	}
	select {
	case <-f.closed:
	case f.C <- payload:
	default:
	}
}

// PacketConn adapts a flow to a connected packet connection.
type PacketConn struct {
	Router *Router
	Flow   *Flow
	Done   chan struct{}
	once   sync.Once
}

func (p *PacketConn) Write(b []byte) (int, error) {
	if err := p.Router.Send(p.Flow.ID, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (p *PacketConn) Read(b []byte) (int, error) {
	select {
	case <-p.Done:
		return 0, io.EOF
	case <-p.Flow.closed:
		return 0, io.EOF
	case pkt := <-p.Flow.C:
		n := copy(b, pkt)
		return n, nil
	}
}

func (p *PacketConn) Close() error {
	p.once.Do(func() {
		if p.Done != nil {
			close(p.Done)
		}
	})
	p.Router.CloseFlow(p.Flow.ID)
	return nil
}
