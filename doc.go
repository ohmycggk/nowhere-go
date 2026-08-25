// Package nowhere is the shared Go protocol core for Nowhere v1.8 client and Portal server.
// Prefer subpackages (wire, carrier, carrier/tcptls, carrier/mux, carrier/quic, bundle, server).
// Root re-exports a few wire identifiers; concrete QUIC stays host-injected.
package nowhere
