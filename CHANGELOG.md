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
- Run library and Portal CLI tests on FreeBSD 15.1 amd64, and publish
  `nowhere` and `nowhere-check` FreeBSD `amd64` and `arm64` binaries from
  `make dist`.

### Changed

- Upgrade the Portal CLI to [quic-go](https://github.com/quic-go/quic-go)
  v0.62.0 (`*quic.Conn` / `*quic.Stream`). The CLI module now requires Go 1.26.
  Library tests still run on Go 1.20; CI skips the CLI on that matrix entry.

### Fixed

- Deliver Mux DATA, FIN, and RESET when the inbound queue is full instead of
  dropping frames. Silent drops truncated payloads and stalled credit-window
  tests under load.

## v2.1.0 - 2026-09-23

### Changed

- Align the Morph transform, Mux flow semantics, and lock metadata with
  Nowhere v2.1.0 at upstream commit
  `568031335b72a925e4904f15f8e39053ffc32866`. `morph=1` hops are
  wire-incompatible with Nowhere 2.0.x peers; upgrade both ends of every
  Morph-enabled hop together. `morph=0` connections keep their existing
  wire contract.
- Send a 64-byte opaque TCP prelude before the 12-byte Morph nonce, for a
  76-byte client bootstrap. The default `low7` policy clears each prelude
  byte's high bit; `NOW_MORPH_TCP_PRELUDE=full8` keeps all eight random
  bits. Servers consume the prelude without interpreting it.
- Derive directional UDP keys `udp c2s` and `udp s2c` from the Morph root
  instead of one shared `udp` key; `WrapPacketConn` now keys datagrams by
  client/server role.
- Retain Mux flow state after the local application fully releases a stream
  until both directions terminate. Peer DATA on retained flows is
  window-checked, debited, and discarded while only connection credit
  returns, so in-flight bytes stay bounded by the stream debit.
- Report DATA for never-established, FIN-received, or fully retired flows as
  a carrier error instead of silently ignoring it.
- Mark local FIN state only after the FIN frame reaches the wire and retire
  retained state as soon as both sides finish.
- Count only application-owned flows for `ActiveStreams`, idle detection,
  and pool pressure; the 4,096-state ceiling covers active plus retained
  states.
- Skip Mux carriers that still retain a requested flow ID, and retire an
  idle carrier when the pool is full with no eligible carrier, so flow-ID
  reuse cannot reopen retired protocol state.

### Documentation

- Re-pin the vector manifest metadata and tree hash for the Nowhere v2.1.0
  corpus; the nw2 auth, flow, datagram, UoT, result, and mux vectors are
  byte-identical to v2.0.0.

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
