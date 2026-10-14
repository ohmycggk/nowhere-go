package nowhere

import "github.com/ohmycggk/nowhere-go/wire"

// Convenience re-exports for the default nw3 wire. Prefer importing wire directly.

const (
	// ALPN is the only ALPN an nw3 carrier offers or accepts.
	ALPN = wire.ALPN
	// ExporterLabel is the TLS exporter label bound into every nw3 authentication tag.
	ExporterLabel = wire.ExporterLabel
)
