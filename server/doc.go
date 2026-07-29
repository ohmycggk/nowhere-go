// Package server implements the inbound side of the Nowhere v1.5 protocol.
//
// Handler supports host-owned TLS/TCP and QUIC listeners, while Server provides
// standalone listener orchestration. Both authenticate physical carriers,
// validate and pair logical flows, enforce bounded session and UDP resources,
// and hand established streams or packet connections to an injected Upstream.
// Graceful shutdown closes flow admission before draining READY relays within
// one caller-owned deadline. Concrete QUIC implementations and product routing
// remain host-owned.
package server
