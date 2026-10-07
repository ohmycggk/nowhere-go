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

`UPSTREAM.lock` records the aligned Nowhere release (version, commit, protocol
hash, vector-tree hash). To re-pin against a local Nowhere checkout:

```sh
make upstream-lock   # or: scripts/generate-upstream-lock.sh /path/to/Nowhere
```

`protocol_sha256` is a `sha256-tree-v1` hash over the wire-defining Rust sources
only (`src/protocol/**`, `src/mux/wire.rs`, `src/transport/morph.rs`,
`src/transport/morph/**`), so it changes exactly when the wire contract does;
the Rust repository ships no such tooling. Run the script after editing
`testdata/vectors/manifest.json` so the vector-tree hash tracks the corpus, and
commit the lock and `internal/upstreamlock/generated.go` together.

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
