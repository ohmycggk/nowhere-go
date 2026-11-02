// Package qio is the host-injected QUIC surface for Nowhere 3.
// The library does not import a QUIC implementation.
package qio

import (
	"context"
	"io"
	"net"
	"time"
)

// Stream is one bidirectional QUIC stream.
// CloseWrite sends FIN and leaves the read side open.
type Stream interface {
	io.Reader
	io.Writer
	CloseWrite() error
	Close() error
	ID() uint64
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// Conn is one QUIC connection whose TLS handshake has already finished.
type Conn interface {
	TLSVersion() uint16
	ALPN() string
	Exporter() ([]byte, error)
	AcceptStream(ctx context.Context) (Stream, error)
	OpenStream(ctx context.Context) (Stream, error)
	ReceiveDatagram(ctx context.Context) ([]byte, error)
	SendDatagram(b []byte) error
	MaxDatagramSize() int
	CloseWithError(code uint64, message string) error
	Context() context.Context
	RemoteAddr() net.Addr
}

// PreAuth is implemented by a Portal QUIC connection that starts with a small
// receive window. Release lets the window grow after AuthFrame succeeds.
type PreAuth interface {
	ReleasePreAuth()
}

// Listener accepts QUIC connections.
type Listener interface {
	Accept(ctx context.Context) (Conn, error)
	Close() error
}
