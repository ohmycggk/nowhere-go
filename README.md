# Nowhere-Go

Go implementation of the [Nowhere](https://github.com/NodePassProject/Nowhere) v2 (`nw2`) protocol — both **outbound** (client) and **inbound** (server). The exact upstream version, commit, protocol hash, and vector-tree hash are canonicalized in [`UPSTREAM.lock`](UPSTREAM.lock).

This is a library, not a standalone proxy. Hosts such as [sing-box](https://github.com/SagerNet/sing-box) or [mihomo](https://github.com/MetaCubeX/mihomo) import it and supply platform pieces: TLS material, dialers, QUIC stacks, and routing.

Protocol behavior follows the official Rust project:

- Spec: [protocol.md](https://github.com/NodePassProject/Nowhere/blob/main/docs/protocol.md)
- Integration notes: [integrations.md](https://github.com/NodePassProject/Nowhere/blob/main/docs/integrations.md)

```text
module github.com/ohmycggk/nowhere-go
go 1.20
```

License: **GPL-3.0** (same family as upstream Nowhere).

Project policies: [changelog](CHANGELOG.md) · [contributing](CONTRIBUTING.md) ·
[security](SECURITY.md)

> **Compatibility:** Nowhere 2 uses ALPN `nw2` only. Authentication, Mux frames, and QUIC UDP headers are not interoperable with 1.8 `now/1`. Mix remains a client-side policy that resolves to TT, TQ, QT, or QQ before FlowHeader; `mix/mix` is TT or QQ. Optional `morph=1` sits below TLS/QUIC with no negotiation. Dedicated `mux=0` and marked Mux still share one TLS listener via the `0xff` marker.

---

## What you get

| Side | Packages | Responsibility |
|---|---|---|
| Shared wire | `wire` | Credentials, exporter-bound auth, FLOW/setup results, TLS Mux, NOWU fragmentation, typed UoT |
| Outbound | `carrier/tcptls`, `carrier/mux`, `carrier/quic`, `bundle` | Dedicated TLS pool or Mux shards, injected QUIC dial backend, four-matrix session orchestration |
| Inbound | `server` | Listen / accept orchestration, auth, flow pairing, NOWU/UoT state, QUIC session loop, upstream handoff |

Hosts keep:

- Concrete QUIC (`quic-go`, `sing-quic`, …) behind injected interfaces
- Product config schemas, listeners, certificates, and routers
- Zero reverse dependency: this module never imports mihomo or sing-box

---

## Package map

```text
nowhere-go/
├── wire/                       # shared nw2 codec, credentials, HOPS, Mux, and typed targets
├── carrier/
│   ├── tcptls/                 # TLS/TCP pool and Mux pool (TCPDialer / TLSDialer injected)
│   ├── mux/                    # TLS Mux stream engine (OPEN/DATA/WINDOW KiB credit)
│   ├── morph/                  # optional ChaCha20 socket transform below TLS/QUIC
│   └── quic/                   # outbound QuicBackend interfaces (no implementation)
├── bundle/                     # outbound CarrierBundle (up/down = tcp|udp)
├── server/                     # inbound Server / Handler / Upstream
├── testdata/vectors/           # module-local conformance corpus derived from the pinned Rust tests
├── cmd/nowhere-check/          # CI helper (vectors / version) — not a proxy
└── tests/
```

Prefer importing subpackages. The root package only re-exports a few `wire` symbols for convenience.

---

## Outbound (client)

Typical path used by mihomo / sing-box outbound adapters:

1. Build `wire.Credentials` from the shared password and use typed `wire.Target` values.
2. Build an immutable `tcptls.Config` with host dialers.
3. If either direction is UDP, inject a `carrier.QuicBackend`.
4. Open flows through `bundle.CarrierBundle`.

```go
import (
    "github.com/ohmycggk/nowhere-go/bundle"
    "github.com/ohmycggk/nowhere-go/carrier/tcptls"
    "github.com/ohmycggk/nowhere-go/wire"
)

credentials, err := wire.NewCredentials(password)
if err != nil {
    return err
}

tcp, err := tcptls.NewConfig(tcptls.TCPOptions{
	Address:   serverAddr,
	Dialer:    hostTCPDialer,
	TLSDialer: hostTLSDialer,
	Observer:  hostObserver,
})
if err != nil {
	return err
}

up, down := wire.CarrierTLSTCP, wire.CarrierQUIC
b, err := bundle.NewCarrierBundle(bundle.BundleOptions{
	TCP:         tcp,
	QUIC:        hostQuicBackend, // required when Up, Down, or mix can select QUIC
	Credentials: credentials,     // bundle owns v1.5 carrier authentication
	PoolSize:    0,               // required when either direction uses QUIC, mix, or Mux=1
	Up:          up,
	Down:        down,
	Mux:         bundle.MuxDisabled, // MuxEnabled originates marked TLS shards
})
if err != nil {
    return err
}
defer b.Close()

target, err := wire.NewDomainTarget("example.com", 443)
if err != nil {
    return err
}
conn, err := b.OpenTCP(ctx, target)
```

See [`bundle/example_test.go`](bundle/example_test.go) for a compile-checked
`tcp/tcp` constructor example. Host adapters remain responsible for concrete
dialer, TLS, and QUIC implementations.

Supported `Up`/`Down` pairs: `tcp/tcp`, `udp/udp`, `tcp/udp`, `udp/tcp`. Set `MixUp` and/or `MixDown` for the 1.8.3 `tcp|udp|mix` matrix; `mix/mix` resolves only to `tcp/tcp` or `udp/udp`. Mix is client-side: the primary pair has a one-second preparation budget, then the other allowed pair is tried once with a new flow ID. Starting a FlowHeader or Target write commits the flow. Every logical TCP or UDP flow starts with a typed FLOW envelope; symmetric flows use `DUPLEX`, while mixed-carrier flows use `OPEN` plus `ATTACH`. `Mux` defaults to dedicated TLS lanes. `MuxEnabled` writes AuthFrame + `0xff` and multiplexes logical streams; Portal auto-detects both on the same TLS listener. QUIC never uses TLS Mux frames. `udp/udp&mux=1` canonicalizes to `mux=0`.

---

## Inbound (server)

The `server` package is a full inbound implementation: auth, FLOW/setup-result handling, typed UoT, mixed-carrier pairing, NOWU reassembly, QUIC session replacement, and upstream handoff.

Two integration styles:

### A. Standalone Portal-like process

`server.Server` owns TCP accept + `crypto/tls` handshake, then runs the protocol. Forwarding goes to an `Upstream` — use `NewDialUpstream` for dial-and-copy, or plug in your own router.

```go
import (
    "crypto/tls"

    "github.com/ohmycggk/nowhere-go/server"
)

cfg, err := server.NewConfig(server.ConfigOptions{
	Credentials: credentials,
	Networks:    []server.Network{server.NetworkTCP},
})
if err != nil {
    return err
}

srv, err := server.NewServer(server.ServerOptions{
	Config:       cfg,
	TLS:          tlsConfig,
	Upstream:     server.NewDialUpstream(nil),
	Observer:     hostObserver,
	QUICListener: hostQuicListener, // required only when UDP is enabled
})
if err != nil {
	return err
}
return srv.ListenAndServe(ctx, ":443")
```

`Networks`: `NetworkTCP`, `NetworkUDP`, both, or empty (defaults to both). Unknown and duplicate entries are rejected.
UDP without `QuicListener` returns `server.ErrQUICNotConfigured`.

### B. Host-owned listener (e.g. sing-box)

Keep your own accept / TLS / QUIC stack. After the carrier is ready, call the protocol handler:

```go
h, err := server.NewHandler(server.HandlerOptions{
	Config:   cfg,
	Upstream: routerUpstream, // adapts host RouteConnection / RoutePacket
	Observer: hostObserver,
})
if err != nil {
	return err
}
err = h.ServeTCP(ctx, rawConn, remoteAddr, hostTLSHandshake, onClose)
```

QUIC: adapt your connection to `server.QuicConn` / `server.QuicListener`, then call `Handler.ServeQUIC` or `Server.ServeQUIC`.

### Upstream interface

```go
type Upstream interface {
    HandleStream(ctx context.Context, conn net.Conn, source net.Addr, target wire.Target, readiness FlowReadiness) error
    HandlePacket(ctx context.Context, pc net.PacketConn, source net.Addr, target wire.Target, readiness FlowReadiness) error
}
```

The Upstream calls `readiness.Ready()` only after the target route is established, or `readiness.Reject(err)` when setup fails. The selected downlink carries the resulting typed setup result.

`server.FlowInfoFromContext(ctx)` exposes the current FLOW metadata to custom
Upstream implementations without changing the `Upstream` interface. In 1.7+,
`FlowInfo.Hops` is the incoming native forwarding budget.

### Native Portal chaining

Use `server.NewPortalUpstream` when an inbound Portal should forward through
another Nowhere Portal instead of dialing the target directly. The next-hop
`CarrierBundle` may use any of the four symmetric or asymmetric carrier
matrices; downstream setup rejection codes are returned unchanged.

```go
nextBundle, err := bundle.NewCarrierBundle(nextPortalOptions)
if err != nil {
	return err
}
portalUpstream, err := server.NewPortalUpstream(nextBundle)
if err != nil {
	_ = nextBundle.Close()
	return err
}
srv, err := server.NewServer(server.ServerOptions{
	Config: cfg, TLS: tlsConfig, Upstream: portalUpstream,
	QUICListener: hostQuicListener,
})
if err != nil {
	_ = nextBundle.Close()
	return err
}

// Shutdown order matters: PortalUpstream borrows, but does not own, the Bundle.
_ = srv.Close()        // first stop and drain inbound handlers
_ = nextBundle.Close() // then close next-hop carriers
```

An incoming HOPS=0 is initialized to 7, values 2..7 are decremented, and an
attempt to forward HOPS=1 is rejected with `FLOW_LIMIT`. Direct
`OpenTCP`, `OpenTCPWithPayload`, `OpenUDP`, and `OpenUDPAsync` calls always send
HOPS=0; only Portal forwarding should normally use `OpenTCPWithHops` or
`OpenUDPWithHops`.

On success the Upstream owns the wrapped connection lifecycle. Closing the wrapper or invoking the context `CloseHandler` closes every physical carrier and invokes each host callback exactly once. Normal close passes `nil`; terminal failures pass their cause. Callbacks run synchronously after close, must not block, and panics are isolated and reported to the Observer.

For host-owned listeners, call `Handler.BeginDrain()` before stopping transport
admission, then call `Handler.Shutdown(ctx)` with one absolute deadline. Pending
and late setup receives `FLOW_LIMIT`; relays that committed `READY` before the
barrier may finish until the deadline. `Server.Close()` applies the normalized
five-second default automatically.

### Default server guardrails

- Authentication: 5 seconds with `[0.8, 1.2]` jitter; request idle: 40 seconds
- Pre-auth admission: 256 global, 32 per source (IPv4 `/32`, IPv6 `/64`)
- Pending mixed-carrier flows: 1024 per session; pair timeout: 15 seconds
- UDP: 256 flows/session, 64 queued packets/flow, 4 MiB queued/session, 120 second idle
- Authenticated idle TCP halves: 4096; active QUIC sessions: 1024
- A matching QUIC session ID replaces the previous carrier and cancels its pending/active flows

### Default outbound TCP guardrails

- Warm pool only for `tcp/tcp` (default target 5, max 9); consumed carriers never return
- Fresh-first replenish: warm prepare starts only after a successful business dial
- Max concurrent physical dials per outbound: 16
- Warm-prepare failure backoff: 1s → 30s with jitter

---

## Design boundaries

| In nowhere-go | In the host |
|---|---|
| FLOW/NOWU/typed-UoT codecs and session/flow state machines | Listen addresses, certs, ALPN product policy |
| TLS/TCP pool logic (dialers injected) | Actual `net.Dial` / TLS stacks |
| Inbound Handler, pairing, fragmentation and reassembly | Router / firewall / detour |
| QUIC *interfaces* | QUIC *implementations*; no host-side wire codec or flow registry |

Local development against a monorepo checkout: use a **gitignored**
`go.work` at the workspace root (do **not** put `replace` in host `go.mod`):

```bash
# from mihomo-nowhere/
go work init ./nowhere-go ./sing-box ./sing-box/test ./mihomo ./mihomo/test
# or: go work use ./nowhere-go ./sing-box ...
```

Host `go.mod` keeps only a published `nowhere-go` version that targets the same Nowhere 2 protocol baseline. Push/CI resolve that module; local edits to `nowhere-go/` are picked up via `go.work`.

Temporarily ignore the workspace:

```bash
GOWORK=off go test ./...
```

---

## Develop & CI

```bash
go test ./...
go test -race -shuffle=on -count=20 ./...
go vet ./...
staticcheck ./...
go run ./cmd/nowhere-check            # wire vectors + self-check
go run ./cmd/nowhere-check -version
```

GitHub Actions ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) validates Go **1.20.x / 1.24.x / stable** on push (`main`/`test`/tags), PR, and `workflow_dispatch`.

The standalone **Portal / Vector** binary lives in [`cmd/nowhere`](cmd/nowhere). It accepts the same `portal://` and `vector://` URLs as the Rust `nowhere` CLI (TUI is not included).

```bash
make nowhere
./nowhere 'portal://secret@:2000?log=info'
./nowhere 'vector://secret@127.0.0.1:2000?up=tcp&down=tcp&socks=127.0.0.1:1080'
```

Pushing a `v*.*.*` tag runs [`.github/workflows/release.yml`](.github/workflows/release.yml): tests, then `nowhere` and `nowhere-check` binaries for Linux, Windows, and macOS (`amd64` and `arm64`) plus `SHA256SUMS`. Reproduce locally with `make dist`. Consume the library with `go get`.

```bash
go get github.com/ohmycggk/nowhere-go@v2.0.0
make dist VERSION=v2.0.0
```
