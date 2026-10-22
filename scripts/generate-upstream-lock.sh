#!/bin/sh
# Regenerate the upstream lock files from a local Nowhere checkout
# (https://github.com/NodePassProject/Nowhere).
#
# Usage: scripts/generate-upstream-lock.sh [/path/to/Nowhere]
#
# Two locks, one semantics. Each records the upstream identity (version from
# Cargo.toml, commit from git HEAD) and two sha256-tree-v1 hashes:
#   protocol_sha256      over the wire-defining Rust sources
#                        (src/protocol/**, src/mux/wire.rs for nw2 only,
#                        src/transport/morph.rs, src/transport/morph/**)
#   vector_tree_sha256   over that lock's own corpus directory
#
# UPSTREAM-nw2.lock   Nowhere 2 pin; mirrors into internal/upstreamlock/generated.go
#                     vectors: testdata/vectors (excluding the nw3/ subdirectory)
# UPSTREAM.lock       Nowhere 3 pin
#                     vectors: testdata/vectors/nw3
#
# The nw3 corpus (testdata/vectors/nw3) is exported from the pinned Nowhere
# commit's src/tests/protocol/vectors.json; refresh it alongside the lock.
set -eu

upstream="${1:-../Nowhere}"
cd "$(dirname "$0")/.."

if [ ! -f "$upstream/Cargo.toml" ]; then
	echo "generate-upstream-lock: $upstream is not a Nowhere checkout" >&2
	exit 1
fi

go run ./internal/upstreamlock/tool.go \
	-upstream "$upstream" \
	-lock UPSTREAM-nw2.lock \
	-vectors testdata/vectors \
	-write

go run ./internal/upstreamlock/tool.go \
	-upstream "$upstream" \
	-lock UPSTREAM.lock \
	-vectors testdata/vectors \
	-write
