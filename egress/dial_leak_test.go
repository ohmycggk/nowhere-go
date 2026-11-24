package egress

import (
	"context"
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"
	"time"

	nwruntime "github.com/ohmycggk/nowhere-go/runtime"
	"github.com/ohmycggk/nowhere-go/wire"
)

func TestTLSOnceClosesConnOnDialTimeoutRace(t *testing.T) {
	creds, err := wire.NewCredentials(testServiceKey)
	if err != nil {
		t.Fatal(err)
	}
	var closed atomic.Int32
	dialReturned := make(chan struct{})
	s := newSession(Config{
		SharedKey:  testServiceKey,
		PortalAddr: "127.0.0.1:1",
		TLS:        &tls.Config{InsecureSkipVerify: true, ServerName: "nowhere"},
		DialTCP: func(ctx context.Context, _ string) (net.Conn, error) {
			<-ctx.Done()
			// Return a live connection after dialCtx expired (simulating a
			// dialer that succeeded concurrently with timeout).
			l, r := net.Pipe()
			_ = r.Close()
			defer close(dialReturned)
			return &closeCounterConn{Conn: l, closed: &closed}, nil
		},
		Upstream: &stubUpstream{},
	}, creds, nwruntime.Settings{
		HandshakeTimeout: 20 * time.Millisecond,
		ServiceCooldown:  time.Millisecond,
	})
	if replace := s.tlsOnce(context.Background()); replace != 0 {
		t.Fatalf("replace = %d, want 0", replace)
	}
	<-dialReturned
	deadline := time.Now().Add(time.Second)
	for closed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if closed.Load() == 0 {
		t.Fatal("timed-out DialTCP connection was leaked without Close")
	}
}

type closeCounterConn struct {
	net.Conn
	closed *atomic.Int32
}

func (c *closeCounterConn) Close() error {
	c.closed.Add(1)
	return c.Conn.Close()
}
