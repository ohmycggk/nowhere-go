// Command nowhere-check prints version info and validates wire conformance
// vectors. Release builds ship Linux, Windows, and macOS binaries.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"

	"github.com/ohmycggk/nowhere-go/internal/upstreamlock"
	"github.com/ohmycggk/nowhere-go/internal/veccheck"
	"github.com/ohmycggk/nowhere-go/internal/vectors"
	"github.com/ohmycggk/nowhere-go/wire"
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
	fmt.Printf("upstream nowhere v%s %s\n", upstreamlock.Version, upstreamlock.Commit)
	fmt.Printf("upstream lock protocol=%s vectors=%s:%s\n",
		upstreamlock.ProtocolSHA256, upstreamlock.VectorTreeHashAlgorithm, upstreamlock.VectorTreeSHA256)
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
	n, err := veccheck.CheckDir(dir)
	if err != nil {
		return err
	}
	treeHash, err := upstreamlock.TreeHash(dir)
	if err != nil {
		return err
	}
	if treeHash != upstreamlock.VectorTreeSHA256 {
		return fmt.Errorf("vector tree hash %s, want %s", treeHash, upstreamlock.VectorTreeSHA256)
	}
	fmt.Printf("vectors: ok (%d cases) dir=%s\n", n, dir)
	return nil
}
