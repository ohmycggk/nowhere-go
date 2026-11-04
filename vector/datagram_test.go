package vector

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/ohmycggk/nowhere-go/qio"
	"github.com/ohmycggk/nowhere-go/wire"
)

type noDatagramVectorConn struct {
	opened bool
}

func (c *noDatagramVectorConn) TLSVersion() uint16        { return 0x0304 }
func (c *noDatagramVectorConn) ALPN() string              { return wire.ALPN }
func (c *noDatagramVectorConn) Exporter() ([]byte, error) { return make([]byte, 32), nil }
func (c *noDatagramVectorConn) AcceptStream(context.Context) (qio.Stream, error) {
	return nil, errors.New("unused")
}

func (c *noDatagramVectorConn) OpenStream(context.Context) (qio.Stream, error) {
	c.opened = true
	return nil, errors.New("unused")
}

func (c *noDatagramVectorConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (c *noDatagramVectorConn) SendDatagram([]byte) error           { return nil }
func (c *noDatagramVectorConn) MaxDatagramSize() int                { return 0 }
func (c *noDatagramVectorConn) CloseWithError(uint64, string) error { return nil }
func (c *noDatagramVectorConn) Context() context.Context            { return context.Background() }
func (c *noDatagramVectorConn) RemoteAddr() net.Addr                { return nil }

// TestOpenUDPRejectsMissingDatagramSupport pins the client-side Core rule: no
// fallback carrier, and no stream opened for a flow the carrier cannot carry.
func TestOpenUDPRejectsMissingDatagramSupport(t *testing.T) {
	conn := &noDatagramVectorConn{}
	client, err := New(Config{
		SharedKey: "0123456789abcdef0123456789abcdef",
		DialQUIC: func(context.Context) (qio.Conn, error) {
			return conn, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if _, err := client.OpenUDP(context.Background(), wire.Target{}); err == nil {
		t.Fatal("OpenUDP accepted a connection without DATAGRAM support")
	}
	if conn.opened {
		t.Fatal("OpenUDP opened a stream despite missing DATAGRAM support")
	}
}
