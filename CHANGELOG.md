# Changelog

All notable user-visible changes to `nowhere-go` are recorded here. This
project follows semantic versioning for its Go API, while protocol
compatibility is also tied to the explicit Nowhere version named in each
release.

Because the module is still pre-1.0, preview releases may contain breaking Go
API changes. A wire-protocol baseline change requires a lockstep upgrade of the
Rust Portal and all clients.

## Unreleased

### Changed

- Align the protocol oracle, FLOW vectors, and lock metadata with Nowhere
  v1.7.0 at upstream commit `362091688e36b6f305f17b921aa39d66886d1462`.
- Encode the Nowhere 1.7 HOPS budget in the FLOW header high three bits and
  include it in OPEN/ATTACH metadata matching.
- Close inbound flow admission before shutdown, reject pending or late setup
  with `FLOW_LIMIT`, and drain already-READY relays within the shared shutdown
  deadline.

### Added

- Add explicit-hop TCP/UDP Bundle APIs while preserving HOPS=0 for all existing
  direct-open APIs.
- Add `server.FlowInfoFromContext` and non-owning `server.PortalUpstream` for
  native TCP/UDP Portal chaining across all carrier matrices, including hop
  limiting and exact downstream setup-result propagation.

### Documentation

- Correct the outbound example for the current v1.5 bundle-owned credentials
  API and add a compile-checked constructor example.
- Document 1.5/1.6/1.7 compatibility, native Portal construction, and the
  required Server-before-Bundle shutdown order.
- Document the public server package and previously undocumented exported API
  groups.
- Update the security support policy for the v0.5 preview line.

## v0.5.1-rc.1 - 2026-07-21

### Changed

- Align the protocol baseline and vector metadata with Nowhere v1.5.1 at
  upstream commit `1133040065029678c8b76b2b3fda9efa3260ada9`.
- Keep UDP flows alive when a retried QUIC DATAGRAM remains too large, while
  reporting the dropped packet through diagnostics.
- Remove the eager UDP fragment collection API in favor of lazy fragment
  encoding.

## v0.5.0-rc.6 - 2026-07-20

### Added

- Implement the Nowhere v1.5 connection-bound authentication, FLOW/setup
  result, NOWU fragmentation, and typed UoT data plane.
- Add the four-matrix outbound bundle and Portal-like inbound server core.
- Add host-injected QUIC contracts, adapter conformance checks, bounded UDP
  reassembly, PMTU retry handling, and structured diagnostics.
- Add Rust-exported vector round-trip checks, wire fuzz targets, race/shuffle
  CI, and deterministic lifecycle tests.

### Changed

- Bind bundle credentials and ALPN inside the shared core.
- Harden TLS/TCP pool sizing, close ownership, setup-result propagation, and
  server resource limits.
