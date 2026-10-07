package upstreamlock

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// protocolFiles lists, relative to a Nowhere checkout root, the wire-defining
// Rust sources pinned by the lock's protocol_sha256. It documents the coverage
// set of the value; see scripts/generate-upstream-lock.sh for the regeneration
// entry point.
//
// Coverage rationale: the nw2 wire contract is fixed since Nowhere 2.0. The
// files below define every byte on the wire (frame and header layout, auth,
// morph transform) and nothing else, so the hash changes exactly when the wire
// contract does.
func protocolFiles(upstream string) ([]string, error) {
	var names []string
	err := filepath.WalkDir(filepath.Join(upstream, "src"), func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".rs") {
			return nil
		}
		rel, err := filepath.Rel(upstream, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		switch {
		case strings.HasPrefix(rel, "src/protocol/"):
		case rel == "src/mux/wire.rs":
		case rel == "src/transport/morph.rs" || strings.HasPrefix(rel, "src/transport/morph/"):
		default:
			return nil
		}
		names = append(names, rel)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("nowhere: no protocol sources under %s", upstream)
	}
	return names, nil
}

// ProtocolHash computes protocol_sha256 over the documented wire-defining
// sources of a Nowhere checkout (see protocolFiles for the coverage set).
func ProtocolHash(upstream string) (string, error) {
	names, err := protocolFiles(upstream)
	if err != nil {
		return "", err
	}
	return FilesTreeHash(func(name string) ([]byte, error) {
		return os.ReadFile(filepath.Join(upstream, filepath.FromSlash(name)))
	}, names...)
}
