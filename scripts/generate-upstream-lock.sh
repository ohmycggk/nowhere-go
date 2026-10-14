#!/bin/sh
# Regenerate UPSTREAM-nw2.lock and internal/upstreamlock/generated.go from a local
# Nowhere 2 checkout (https://github.com/NodePassProject/Nowhere).
# UPSTREAM.lock is the Nowhere 3 pin and is left untouched.
#
# Usage: scripts/generate-upstream-lock.sh [/path/to/Nowhere]
#
# The lock records the upstream identity (version from Cargo.toml, commit from
# git HEAD) and two hashes:
#   protocol_sha256      sha256-tree-v1 over the wire-defining Rust sources
#                        (src/protocol/**, src/mux/wire.rs,
#                        src/transport/morph.rs, src/transport/morph/**)
#   vector_tree_sha256   sha256-tree-v1 over testdata/vectors
set -eu

upstream="${1:-../Nowhere}"
cd "$(dirname "$0")/.."

if [ ! -f "$upstream/Cargo.toml" ]; then
	echo "generate-upstream-lock: $upstream is not a Nowhere checkout" >&2
	exit 1
fi

exec go run ./internal/upstreamlock/tool.go \
	-upstream "$upstream" \
	-lock UPSTREAM-nw2.lock \
	-vectors testdata/vectors \
	-write
