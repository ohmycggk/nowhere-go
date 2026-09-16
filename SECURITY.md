# Security Policy

## Supported versions

Security fixes are provided for the latest release in the **v2.0** line, which
tracks Nowhere 2 (`nw2`). The current development baseline is recorded in
`UPSTREAM.lock`. The v1.8 and older lines are unsupported after host adapters
migrate.

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
