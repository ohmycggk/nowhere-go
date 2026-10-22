# Contributing

Protocol changes must update the upstream specification/reference implementation first, export fixed Rust vectors, synchronize the workspace vector corpus, and then update Go codecs. Do not introduce a second hand-maintained set of wire hex values.

Before submitting a change, run:

```sh
go test ./...
go test -race -shuffle=on -count=20 ./...
go vet ./...
staticcheck ./...
go run ./cmd/nowhere-check
make dist
```

Changes to pairing, session, pool, or close ownership require deterministic cancellation/timeout tests. Runtime packages must retain zero third-party dependencies.

## Re-pinning the upstream lock

Two lock files pin the two protocol baselines. Both record the upstream identity
(version from `Cargo.toml`, commit from `git HEAD`) and two `sha256-tree-v1`
hashes:

| Lock | Baseline | `protocol_sha256` coverage | `vector_tree_sha256` coverage |
|---|---|---|---|
| `UPSTREAM.lock` | Nowhere 3 (`nw3`) | `src/protocol/**`, `src/transport/morph.rs`, `src/transport/morph/**` | `testdata/vectors/nw3` |
| `UPSTREAM-nw2.lock` | Nowhere 2 (`nw2`) | the above plus `src/mux/wire.rs` | `testdata/vectors`, excluding `nw3/` |

`protocol_sha256` covers the wire-defining Rust sources and nothing else, so it
changes exactly when the wire contract does; the Rust repository ships no such
tooling. nw3 has no Mux, hence the narrower nw3 set (`ProtocolHashNW3`).
`vector_tree_sha256` is `sha256-tree-v1` over that lock's own corpus directory,
so both locks share one semantics.

The file name list is sorted before hashing (`sha256-tree-v1` requires a sorted
list); never hash in filesystem order, which is not stable across machines.

Regenerate both locks from a local Nowhere checkout:

```sh
make upstream-lock   # or: scripts/generate-upstream-lock.sh /path/to/Nowhere
```

The script rewrites both lock files and `internal/upstreamlock/generated.go`
(mirroring the nw2 lock). Run it after editing `testdata/vectors/manifest.json`
or `testdata/vectors/nw3/` so the vector-tree hashes track the corpora, and
commit the lock and `internal/upstreamlock/generated.go` together.

The nw3 corpus (`testdata/vectors/nw3`) is exported from the pinned Nowhere
commit's `src/tests/protocol/vectors.json` plus Morph KDF vectors; refresh it
alongside the nw3 lock. Do not maintain wire hex tables by hand.

## Documentation and public API

- Keep README examples aligned with the current public API. Prefer a companion
  executable `Example` test whenever an example constructs public types.
- Add Go documentation for every exported package, type, function, method, and
  constant group. Comments should begin with the exported identifier or name
  the complete group they describe.
- Update `CHANGELOG.md` for user-visible behavior, compatibility, security, or
  public API changes. Update `SECURITY.md` when the supported preview line
  changes.
- Run `gofmt` on every touched Go file and verify examples with `go test ./...`.
