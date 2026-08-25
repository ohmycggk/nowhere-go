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

- Align the protocol oracle, FLOW vectors, Mux codec, and lock metadata with
  Nowhere v1.8.1 at upstream commit `cd8820c7b30ffcd5ba9896fb1c2e6915613f5ffd`.
- Tighten Mux shard density from 12 to 4 active flows, matching Nowhere 1.8.1.
  QUIC flow-control remains host-injected; the Rust binary now defaults
  `NOW_QUIC_MEMORY_PROFILE` to `throughput`.
- Accept OPEN/ATTACH FlowHeaders whose uplink and downlink carriers are equal,
  matching the 1.8 decoder. Vector-originated equal-carrier flows still use
  DUPLEX.
- Preserve inbound `FlowInfo` (including HOPS) when a transferable transport
  is claimed as a route task.

### Added

- Implement the Nowhere 1.8 TLS Mux wire (0xff marker, 8-byte MuxHeader,
  STREAM/WINDOW/DATAGRAM) and the credit-windowed stream engine in
  `carrier/mux`.
- Auto-detect dedicated vs marked Mux TLS after AuthFrame on inbound
  `Handler.ServeTCP`. Portal remains optionless.
- Add `bundle.BundleOptions.Mux` (`0` dedicated, `1` shards). Mux shards open
  lazily at 4 active flows per direction, idle-close after 30s, and never
  reuse the dedicated warm pool. `PoolSize` must be zero when Mux is enabled.
- Export Mux header vectors derived from `Nowhere/src/tests/mux/wire.rs`.

### Documentation

- Document 1.8 Mux auto-detect, client `mux=0|1`, and OPEN/ATTACH equal-carrier
  decoding. Dedicated mux=0 envelopes remain the 1.7 TLS lane.

## v1.7.0 - 2026-08-12

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
