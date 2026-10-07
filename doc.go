// Package nowhere is the shared Go protocol core for the Nowhere v2 (`nw2`)
// client and Portal server. Prefer subpackages (wire, carrier, carrier/tcptls,
// carrier/mux, carrier/quic, bundle, server). Root re-exports a few wire
// identifiers; concrete QUIC stays host-injected.
package nowhere
