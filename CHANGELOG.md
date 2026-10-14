# Changelog

All notable user-visible changes to `nowhere-go` are recorded here. This
project follows semantic versioning for its Go API, while protocol
compatibility is also tied to the explicit Nowhere version named in each
release.

A wire-protocol baseline change requires a lockstep upgrade of the Rust Portal
and all clients.

## Unreleased

### Added

- Nowhere 3 (`nw3`) Portal, Vector, and Egress beside the existing Nowhere 2
  stack. A URL with no `up`, `down`, `mux`, `next`, or `socks` parameter starts
  nw3 and offers only ALPN `nw3`. A URL that uses any of those parameters starts
  nw2 and offers only ALPN `nw2`. The two versions do not share a handshake,
  and one process runs only the selected version. nw3 follows Nowhere 3.0
  (`501138f`): 16-byte role authentication, one-byte FlowStart, Egress slot
  registration, and HMAC Morph under `nowhere/nw3/morph`. `UPSTREAM.lock` pins
  that Nowhere 3 commit. The previous nw2 pin lives in `UPSTREAM-nw2.lock`.
- Alignment with upstream Nowhere v2.2.1
  (commit `0000696910dc9ee56c3ec87995a0b1ca8e4fc11b`). The `nw2` wire contract
  is unchanged, so `nowhere-go` stays interoperable with Nowhere 2.0.x–2.2.x
  peers; `UPSTREAM-nw2.lock` and the vector manifest are re-pinned.
- Toolbox subcommands: `nowhere generate-key` prints one 32-character lowercase
  hex key; `nowhere fingerprint` accepts `nowhere://` share links and prints the
  leaf certificate SHA-256 suitable for `pin=`; `nowhere probe <vector-url>
  <host:port>` opens one real TCP flow through the full client stack and exits 0
  only when the setup result is `OK`. Upstream's `nowhere status` and the TUI
  are deliberately not ported because the Go build has no telemetry registry or
  IPC (recorded as a known divergence).
- `dial4=<ipv4|auto>` and `dial6=<ipv6|auto>` Portal URL parameters for
  dual-stack outbound source binding, covering Portal direct dials, SOCKS5
  outbound control and relay sockets, and `next` hops. `dial` stays mutually
  exclusive with them.
- `scripts/generate-upstream-lock.sh` and `make upstream-lock` regenerate
  `UPSTREAM-nw2.lock` and `internal/upstreamlock/generated.go` from a local
  Nowhere checkout, with the protocol-hash coverage set documented.
- Portal SOCKS5 outbound (`portal://...?socks=host:port`) for TCP CONNECT and
  UDP ASSOCIATE. There is no direct fallback; `socks` and `next` stay mutually
  exclusive.
- Run library and Portal CLI tests on FreeBSD 15.1 amd64, and publish
  `nowhere` and `nowhere-check` FreeBSD `amd64` and `arm64` binaries from
  `make dist`.

### Changed

- Releases no longer ship the `nowhere-check` conformance binary: `make dist`
  and the release workflow publish the `nowhere` Portal/Vector binaries and
  `SHA256SUMS` only. The tool still exists for local protocol verification
  (`make nowhere-check`, `go run ./cmd/nowhere-check`) and CI keeps running it
  on every push and pull request.
- **Breaking (CLI default):** `nowhere <url>` with no nw2-only option (`up`,
  `down`, `mux`, `next`, `socks`) is Nowhere 3. Morph defaults to on and the
  shared key must be exactly 32 lowercase hex characters. Keep an nw2-only
  option, for example `socks=` or `up=tcp`, to start the previous stack.
- **Breaking (client trust):** client carriers now verify the Portal
  certificate against the system trust roots and the endpoint host name unless
  `pin=` is set; `sni=none` no longer disables verification, and missing system
  roots fail startup. Connections to the default self-signed Portal fail unless
  pinned; the Portal logs `TLS certificate SHA-256 fingerprint: <hex>` at
  startup as the canonical way to obtain a `pin=`.
- **Breaking (configuration):** Portal listener keys and every `next` hop key
  must be 32–64 lowercase hexadecimal characters after percent-decoding, or
  startup fails before listen. Vector client keys remain free-form.
- The TCP Morph prelude default policy is now `full8` (unset
  `NOW_MORPH_TCP_PRELUDE`); a set-but-empty value now errors; `low7` stays
  selectable. Receivers never interpret prelude contents, so interop with
  2.1.x peers is unaffected in both directions.
- `log=event` is rejected; log levels are `none`, `debug`, `info`, `warn`,
  `error`, and the Portal reports the TLS certificate fingerprint at info.
- Mux robustness aligned with upstream 2.1.2: per-flow protocol failures reset
  the offending flow instead of tearing down the carrier; carriers record a
  first close reason (application close, idle timeout, unexpected EOF, reader
  or writer failure, protocol violation); outbound frames carry per-flow
  generations so a reused flow ID cannot receive a previous generation's bytes;
  a stream open cancelled between reservation and commit rolls back; the pooled
  TCP carrier retires as soon as its last acquisition closes; TLS Mux pools
  reject acquires after `Close` and join their monitors; QUIC session and UDP
  route setup paths cancel cleanly during shutdown; the CLI races pending
  SOCKS5 setups against shutdown.
- `nowhere-check -version` reports the aligned upstream release as 2.2.1.
- Upgrade the Portal CLI to [quic-go](https://github.com/quic-go/quic-go)
  v0.62.0 (`*quic.Conn` / `*quic.Stream`). The CLI module now requires Go 1.26.
  Library tests still run on Go 1.20; CI skips the CLI on that matrix entry.

### Removed

- The `mix` client carrier policy. `BundleOptions` no longer accepts
  `MixUp`, `MixDown`, or `MixFallbackTimeout`; `CarrierMode` no longer has
  `ModeMix`; `ParseCarrierMode` accepts only `tcp` or `udp`;
  `(*CarrierBundle).MixEnabled`, `CarrierMode.IsMix`,
  `CarrierMode.Selectors` (now returning a single `wire.Carrier`), and
  `DefaultMixFallbackTimeout` are gone. Vector and Portal URLs reject
  `up=mix` / `down=mix`. `tcp`/`udp` pairs and the tcp/udp dual-stack server
  listener are unchanged; the wire format never carried mix.

### Fixed

- QUIC sessions flush uplink UDP drops on shutdown again. The datagram pump is
  now stopped before the session closes, so every datagram already received is
  handled and its drop recorded before `flushUDPDrop` emits the aggregate
  `udp_queue_drop_total` event. Previously a datagram handled during the
  shutdown window was counted but never reported.
- The nw3 Vector SOCKS5 server accepts a UDP ASSOCIATE request again. The
  request address is a source constraint, not a dial target, so the standard
  `0.0.0.0:0` form no longer fails target validation and drop the connection
  without a reply. A domain or foreign source IP is refused with reply `0x02`,
  and datagrams must come from the control peer, pinned to the requested port
  when the request names one. The same unchecked request parse applies to the
  nw2 Vector path.
- A failed pooled-carrier dial no longer leaves the failed shard registered in
  the pool while the `Open` call falls back to a live carrier.
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
  The sole ALPN is `nw2`.
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
