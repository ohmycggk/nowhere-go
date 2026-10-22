// Command nowhere-check prints version info and validates wire conformance
// vectors. Release builds ship Linux, Windows, and macOS binaries.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/ohmycggk/nowhere-go/internal/upstreamlock"
	"github.com/ohmycggk/nowhere-go/internal/veccheck"
	"github.com/ohmycggk/nowhere-go/internal/vectors"
	"github.com/ohmycggk/nowhere-go/nw2/wire"
)

// Version is overridden at link time: -ldflags "-X main.Version=v1.2.3"
var Version = "dev"

func main() {
	fs := flag.NewFlagSet("nowhere-check", flag.ExitOnError)
	showVersion := fs.Bool("version", false, "print version and exit")
	vectorsOnly := fs.Bool("vectors", false, "validate conformance vectors and exit")
	vectorsDir := fs.String("vectors-dir", "", "vector directory (default: auto-detect / GO_NOWHERE_VECTORS)")
	selfCheck := fs.Bool("self-check", true, "run a small in-process wire self-check")
	_ = fs.Parse(os.Args[1:])

	if *showVersion {
		printVersion()
		return
	}

	if *vectorsOnly {
		if err := runVectors(*vectorsDir); err != nil {
			fmt.Fprintf(os.Stderr, "vectors: %v\n", err)
			os.Exit(1)
		}
		return
	}

	printVersion()
	if err := checkBuildToolchain(); err != nil {
		fmt.Fprintf(os.Stderr, "toolchain: %v\n", err)
		os.Exit(1)
	}
	if *selfCheck {
		if err := runSelfCheck(); err != nil {
			fmt.Fprintf(os.Stderr, "self-check: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("self-check: ok")
	}
	if err := runVectors(*vectorsDir); err != nil {
		fmt.Fprintf(os.Stderr, "vectors: %v\n", err)
		os.Exit(1)
	}
}

func printVersion() {
	fmt.Printf("nowhere-check %s\n", resolveVersion())
	fmt.Printf("go %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	fmt.Printf("module github.com/ohmycggk/nowhere-go\n")
	fmt.Printf("upstream nowhere (nw2) v%s %s\n", upstreamlock.Version, upstreamlock.Commit)
	fmt.Printf("upstream lock (nw2) protocol=%s vectors=%s:%s\n",
		upstreamlock.ProtocolSHA256, upstreamlock.VectorTreeHashAlgorithm, upstreamlock.VectorTreeSHA256)
	if nw3, err := readNW3Lock(); err == nil {
		fmt.Printf("upstream nowhere (nw3) v%s %s\n", nw3.Version, nw3.Commit)
		fmt.Printf("upstream lock (nw3) protocol=%s vectors=%s:%s\n",
			nw3.ProtocolSHA256, nw3.VectorTreeHashAlgorithm, nw3.VectorTreeSHA256)
	}
}

// readNW3Lock loads UPSTREAM.lock beside the nw2 corpus so the report covers
// both protocol baselines.
func readNW3Lock() (upstreamlock.Lock, error) {
	dir, err := vectors.Dir()
	if err != nil {
		return upstreamlock.Lock{}, err
	}
	return upstreamlock.Read(filepath.Join(moduleRoot(dir), "UPSTREAM.lock"))
}

func resolveVersion() string {
	if Version != "" && Version != "dev" {
		return Version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Version != "" && info.Main.Version != "(devel)" {
			return info.Main.Version
		}
	}
	return Version
}

// fixedToolchain maps a Go minor series to the earliest patch release carrying
// the CVE-2026-111943 crypto/x509 mitigation (untrusted eMudhra intermediate
// certificates). Extend it when a newer minor series ships its own fixed patch.
var fixedToolchain = map[[2]int]string{
	{1, 26}: "1.26.10",
	{1, 27}: "1.27.3",
}

// checkBuildToolchain reports whether this binary was built with a Go
// toolchain that blocks the compromised intermediate certificates from
// CVE-2026-111943 (Red Hat RHSB-2026-012, golang/go#82345). Builds on
// supported-but-vulnerable series fail; EOL series (which can never receive
// the fix and are test-only) only warn.
func checkBuildToolchain() error {
	v := runtime.Version()
	if strings.HasPrefix(v, "devel") {
		fmt.Println("toolchain: devel build; skipping CVE-2026-111943 check")
		return nil
	}
	rel := strings.TrimPrefix(v, "go")
	triple, ok := versionTriple(rel)
	if !ok {
		fmt.Printf("toolchain: go%s (unrecognized version; skipping CVE-2026-111943 check)\n", rel)
		return nil
	}
	fixed, known := fixedToolchain[[2]int{triple[0], triple[1]}]
	if !known {
		if triple[0] == 1 && triple[1] < 26 {
			fmt.Printf("toolchain: go%s predates the CVE-2026-111943 crypto/x509 fix and is EOL; rebuild release artifacts with go1.26.10+ or go1.27.3+\n", rel)
			return nil
		}
		fmt.Printf("toolchain: go%s (newer than the CVE-2026-111943 advisory)\n", rel)
		return nil
	}
	if verLessThan(rel, fixed) {
		return fmt.Errorf("go%s lacks the CVE-2026-111943 crypto/x509 mitigation (fixed in go%s); rebuild with go%s or newer", rel, fixed, fixed)
	}
	fmt.Printf("toolchain: go%s includes the CVE-2026-111943 crypto/x509 mitigation\n", rel)
	return nil
}

// versionTriple parses a dotted release version such as "1.27.3" into a
// comparable triple. It accepts only digit components and requires at least
// major.minor.
func versionTriple(s string) ([3]int, bool) {
	var t [3]int
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return t, false
	}
	for i, p := range parts {
		if p == "" {
			return t, false
		}
		n := 0
		for _, r := range p {
			if r < '0' || r > '9' {
				return t, false
			}
			n = n*10 + int(r-'0')
		}
		t[i] = n
	}
	return t, true
}

// verLessThan reports whether dotted version a sorts before b. Unparseable
// inputs never compare as less (callers pre-filter unrecognized versions).
func verLessThan(a, b string) bool {
	ta, oka := versionTriple(a)
	tb, okb := versionTriple(b)
	if !oka || !okb {
		return false
	}
	for i := range ta {
		if ta[i] != tb[i] {
			return ta[i] < tb[i]
		}
	}
	return false
}

func runSelfCheck() error {
	target, err := wire.NewDomainTarget("example.com", 443)
	if err != nil {
		return err
	}
	frame, err := wire.EncodeTarget(target)
	if err != nil {
		return err
	}
	if len(frame) == 0 {
		return fmt.Errorf("empty target frame")
	}
	if _, err := wire.WriteFlowHeader(wire.FlowHeader{
		Role:     wire.FlowRoleOpen,
		FlowID:   1,
		Kind:     wire.FlowKindTCP,
		Uplink:   wire.CarrierQUIC,
		Downlink: wire.CarrierTLSTCP,
	}); err != nil {
		return err
	}
	// Auth frame sanity: validates against its connection-bound exporter.
	creds, err := wire.NewCredentials("secret")
	if err != nil {
		return err
	}
	exporter := wire.TLSExporter{}
	for i := range exporter {
		exporter[i] = byte(i)
	}
	authFrame, err := wire.EncodeAuthFrame(creds, wire.AuthTransportTLSTCP, exporter, wire.SessionID{})
	if err != nil {
		return err
	}
	if _, err := wire.ValidateAuthFrame(authFrame[:], creds, wire.AuthTransportTLSTCP, exporter); err != nil {
		return err
	}
	header, err := wire.OpenMuxHeader(0x01020304, 0x0506)
	if err != nil {
		return err
	}
	encoded, err := wire.EncodeMuxHeader(header)
	if err != nil {
		return err
	}
	want := [wire.MuxHeaderLen]byte{1, 5, 6, 1, 2, 3, 4}
	if encoded != want {
		return fmt.Errorf("mux header vector mismatch")
	}
	return nil
}

func runVectors(dirFlag string) error {
	dir := dirFlag
	var err error
	if dir == "" {
		dir, err = vectors.Dir()
		if err != nil {
			return err
		}
	}
	nw3Dir := filepath.Join(dir, "nw3")

	nw2, err := veccheck.CheckDir(dir)
	if err != nil {
		return err
	}
	// UPSTREAM-nw2.lock pins the nw2 corpus directory itself (excluding nw3/).
	nw2Tree, err := upstreamlock.TreeHash(dir, "nw3")
	if err != nil {
		return err
	}
	if nw2Tree != upstreamlock.VectorTreeSHA256 {
		return fmt.Errorf("nw2 vector tree hash %s, want %s", nw2Tree, upstreamlock.VectorTreeSHA256)
	}

	nw3, err := veccheck.CheckNW3Dir(nw3Dir)
	if err != nil {
		return err
	}
	// UPSTREAM.lock pins the nw3 corpus directory, giving both locks the same
	// vector_tree_sha256 semantics: sha256-tree-v1 over their own corpus.
	nw3Lock, err := upstreamlock.Read(filepath.Join(moduleRoot(dir), "UPSTREAM.lock"))
	if err != nil {
		return err
	}
	nw3Tree, err := upstreamlock.TreeHash(nw3Dir)
	if err != nil {
		return err
	}
	if nw3Tree != nw3Lock.VectorTreeSHA256 {
		return fmt.Errorf("nw3 vector tree hash %s, want %s", nw3Tree, nw3Lock.VectorTreeSHA256)
	}

	fmt.Printf("vectors: ok (%d nw2 + %d nw3 cases) dir=%s\n", nw2, nw3, dir)
	return nil
}

// moduleRoot walks up from dir to the directory holding UPSTREAM.lock.
func moduleRoot(dir string) string {
	for {
		if _, err := os.Stat(filepath.Join(dir, "UPSTREAM.lock")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "."
		}
		dir = parent
	}
}
