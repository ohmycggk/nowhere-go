package nowhere

import "github.com/ohmycggk/nowhere-go/wire"

// Convenience re-exports; prefer importing wire directly in new code.

const (
	// DefaultALPN is the sole ALPN every Nowhere 2 carrier negotiates.
	DefaultALPN = wire.DefaultALPN
	// SessionIDLen is the fixed length of a logical session identifier.
	SessionIDLen = wire.SessionIDLen
)

// SessionID identifies one logical session shared by a transport bundle.
type SessionID = wire.SessionID

// TLSExporter carries the TLS 1.3 exporter bound to one physical connection.
type TLSExporter = wire.TLSExporter

// AuthTransport is the physical carrier domain separator bound into the auth tag.
type AuthTransport = wire.AuthTransport

const (
	// AuthTransportTLSTCP identifies a TLS-over-TCP authentication frame.
	AuthTransportTLSTCP = wire.AuthTransportTLSTCP
	// AuthTransportQUIC identifies a QUIC authentication frame.
	AuthTransportQUIC = wire.AuthTransportQUIC
)
