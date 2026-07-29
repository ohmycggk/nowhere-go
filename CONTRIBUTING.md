# Contributing

Protocol changes must update the upstream specification/reference implementation first, export fixed Rust vectors, synchronize the workspace vector corpus, and then update Go codecs. Do not introduce a second hand-maintained set of wire hex values.

Before submitting a change, run:

```sh
go test ./...
go test -race -shuffle=on -count=20 ./...
go vet ./...
staticcheck ./...
go run ./cmd/nowhere-check
```

Changes to pairing, session, pool, or close ownership require deterministic cancellation/timeout tests. Runtime packages must retain zero third-party dependencies.

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
