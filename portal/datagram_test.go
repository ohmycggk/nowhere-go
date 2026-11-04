package portal

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/ohmycggk/nowhere-go/dgram"
	"github.com/ohmycggk/nowhere-go/qio"
	"github.com/ohmycggk/nowhere-go/wire"
)

type noDatagramConn struct{ max int }

func (c *noDatagramConn) TLSVersion() uint16        { return 0x0304 }
func (c *noDatagramConn) ALPN() string              { return wire.ALPN }
func (c *noDatagramConn) Exporter() ([]byte, error) { return make([]byte, 32), nil }
func (c *noDatagramConn) AcceptStream(context.Context) (qio.Stream, error) {
	return nil, errors.New("unused")
}

func (c *noDatagramConn) OpenStream(context.Context) (qio.Stream, error) {
	return nil, errors.New("unused")
}

func (c *noDatagramConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (c *noDatagramConn) SendDatagram([]byte) error           { return nil }
func (c *noDatagramConn) MaxDatagramSize() int                { return c.max }
func (c *noDatagramConn) CloseWithError(uint64, string) error { return nil }
func (c *noDatagramConn) Context() context.Context            { return context.Background() }
func (c *noDatagramConn) RemoteAddr() net.Addr                { return nil }

// TestServeFlowRejectsUDPWithoutDatagrams pins the setup-time failure for a
// QUIC Vector whose connection did not negotiate DATAGRAM support: it must get
// INTERNAL_ERROR before any target dial or READY.
func TestServeFlowRejectsUDPWithoutDatagrams(t *testing.T) {
	local, remote := net.Pipe()
	client := &pipe{Reader: remote, write: local, closer: local}
	router := dgram.NewRouter(&noDatagramConn{}, 0)
	srv := &Server{}

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.serveFlow(context.Background(), wire.FlowUDP, wire.Target{}, client, router, 1, true)
	}()
	_ = remote.SetReadDeadline(time.Now().Add(5 * time.Second))
	res, err := wire.ReadSetupResult(remote)
	if err != nil {
		t.Fatalf("read setup result: %v", err)
	}
	if res != wire.SetupInternalError {
		t.Fatalf("setup result = %v, want %v", res, wire.SetupInternalError)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveFlow did not return")
	}
}
