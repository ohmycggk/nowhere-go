# Security Policy

## Supported versions

Security fixes are provided for the current Nowhere 3.1 baseline recorded in
`UPSTREAM.lock` and for the latest Nowhere 2 line pinned in `UPSTREAM-nw2.lock`.
The v2.0 and older lines are unsupported after host adapters migrate.

The 3.1 Morph TCP replay registry is process memory only. It limits a tagged
prelude to 16384 identities and a 1024-counter window, with no TTL or disk
record. A tag that does not match skips that registry and follows the 3.0
admission path; this transitional fallback means replay protection is not
mandatory. The tag does not cover the whole ClientHello, a captured prelude can
be altered to bypass the registry, and a leaked Shared Key reveals historical
identity and counter values. It does not provide forward secrecy for those
fields. Do not describe this release as enforcing replay protection.

Hosts must pin an explicit tagged release and upgrade the Rust Portal and every
Nowhere client together when the documented protocol baseline changes.

## Reporting

Do not file public issues for authentication bypasses, resource-exhaustion
paths, allocation bombs, or connection ownership vulnerabilities. Use the
repository's private vulnerability reporting channel, or another private
maintainer contact when that channel is unavailable. Include a minimal
reproducer, the affected commit or tag, the expected impact, and whether the
Rust reference implementation is also affected.

The library intentionally returns generic authentication failures to peers.
Detailed causes are local diagnostic events only. Do not include production
credentials, TLS keys, session identifiers, or user traffic in a report.
