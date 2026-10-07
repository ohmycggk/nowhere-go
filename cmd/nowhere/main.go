package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

// Version is overridden at link time: -ldflags "-X main.Version=v2.0.0"
var Version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		switch {
		case errors.Is(err, errProbeFailed):
			// A probe that reached the flow stage but did not report OK exits
			// non-zero silently, mirroring upstream's ProbeFailed sentinel.
		case errors.Is(err, context.Canceled):
			// SIGINT/SIGTERM shutdown is a clean exit, not an error.
			os.Exit(0)
		default:
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
		}
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Print(helpText)
		return nil
	}
	switch args[0] {
	case "-h", "--help", "help":
		if len(args) != 1 {
			return fmt.Errorf("usage: nowhere --help")
		}
		fmt.Print(helpText)
		return nil
	case "-v", "--version", "version":
		if len(args) != 1 {
			return fmt.Errorf("usage: nowhere --version")
		}
		fmt.Printf("nowhere-v%s %s/%s\n", Version, runtime.GOOS, runtime.GOARCH)
		return nil
	case "tui":
		if len(args) != 1 {
			return fmt.Errorf("usage: nowhere tui")
		}
		return fmt.Errorf("tui is not included in the Go nowhere binary; use the Rust nowhere tui")
	case "generate-key":
		if len(args) != 1 {
			return fmt.Errorf("usage: nowhere generate-key")
		}
		key, err := generateKey()
		if err != nil {
			return err
		}
		fmt.Println(key)
		return nil
	case "fingerprint":
		if len(args) != 2 {
			return fmt.Errorf("usage: nowhere fingerprint <nowhere-url>")
		}
		return runFingerprint(args[1])
	case "probe":
		if len(args) != 3 {
			return fmt.Errorf("usage: nowhere probe <URL> <TARGET>")
		}
		return runProbe(args[1], args[2])
	}
	if len(args) > 1 {
		return fmt.Errorf("expected exactly one configuration URL; run \"nowhere --help\" for usage")
	}

	cfg, err := parseCommandURL(args[0])
	if err != nil {
		return err
	}
	log := newLogger(cfg.log)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch cfg.kind {
	case kindPortal:
		log.info("starting portal %s", cfg.endpoint.tcpAddr())
		return runPortal(ctx, cfg, log)
	case kindVector:
		log.info("starting vector socks %s -> %s", cfg.socks, cfg.endpoint.tcpAddr())
		return runVector(ctx, cfg, log)
	default:
		return fmt.Errorf("unknown command")
	}
}

// generateKey prints 16 crypto/rand bytes as 32 lowercase hex characters, the
// Nowhere 2.2 Portal key format.
func generateKey() (string, error) {
	var key [16]byte
	if _, err := rand.Read(key[:]); err != nil {
		return "", fmt.Errorf("failed to generate a random key: %w", err)
	}
	return hex.EncodeToString(key[:]), nil
}
