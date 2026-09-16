# Changelog

All notable user-visible changes to `nowhere-go` are recorded here. This
project follows semantic versioning for its Go API, while protocol
compatibility is also tied to the explicit Nowhere version named in each
release.

A wire-protocol baseline change requires a lockstep upgrade of the Rust Portal
and all clients.

## Unreleased

### Added

- Portal SOCKS5 outbound (`portal://...?socks=host:port`) for TCP CONNECT and
  UDP ASSOCIATE. There is no direct fallback; `socks` and `next` stay mutually
  exclusive.

## v2.0.0 - 2026-09-16

### Changed

- Align the protocol oracle, vectors, Mux engine, and lock metadata with
  Nowhere v2.0.0 at upstream commit `0453efd28659468a4be5cccc7a16d1cd67bbb1ff`.
  The sole ALPN is `nw2`. 1.8 `now/1` peers cannot complete a handshake.
- Derive AuthFrame keys from salt `nowhere/nw2/auth-root`.
- Constrain flow IDs to `1..=0x3fffffff` on FlowHeader, Mux, and QUIC UDP.
- Replace the 8-byte STREAM/WINDOW/DATAGRAM Mux header with the 7-byte
  OPEN/DATA/WINDOW/FIN/RESET layout. WINDOW/OPEN values are 1 KiB units.
- Pack QUIC UDP DATA/CLOSE into 4-byte headers and FRAGMENT into 12 bytes.
- Default Mux windows to 16/32 MiB with a 4,096-stream resource ceiling.
- Share at most eight full-duplex Mux TLS carriers per session and place
  flows by occupancy instead of a 4-stream shard density.
- Raise Portal claim admission to 4,096 per session and 65,536 globally.

### Added

- Add the Morph socket transform (`carrier/morph`) with HKDF-SHA256 keys and
  ChaCha20-XOR wrappers for TCP and UDP. Enable it with `TCPOptions.MorphSharedKey`
  and `server.ConfigOptions.MorphSharedKey`.
- Add a standalone `nowhere` Portal/Vector CLI (`cmd/nowhere`) that speaks
  `portal://` and `vector://` URLs, including TLS, QUIC, Morph, mix/mux, SOCKS5,
  and native `next` chaining.
- Publish `nowhere` and `nowhere-check` Linux, Windows, and macOS binaries from
  GitHub Actions on `v*.*.*` tags (`make dist`).

### Documentation

- Document the nw2 ALPN, 7-byte Mux frames, packed QUIC UDP headers, 30-bit
  flow IDs, occupancy Mux pool, Morph shared-key option, and release artifacts.

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
