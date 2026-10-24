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

// Version is overridden at link time: -ldflags "-X main.Version=3.1.0".
// A leading v from git describe is accepted and not doubled.
var Version = "3.1.0"

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
		version := Version
		if len(version) > 0 && version[0] == 'v' {
			version = version[1:]
		}
		fmt.Printf("nowhere-v%s %s/%s\n", version, runtime.GOOS, runtime.GOARCH)
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

	edition, err := urlEdition(args[0])
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if edition == "nw2" {
		cfg, err := parseCommandURL(args[0])
		if err != nil {
			return err
		}
		log := newLogger(cfg.log)
		switch cfg.kind {
		case kindPortal:
			log.info("starting nw2 portal %s", cfg.endpoint.tcpAddr())
			return runPortal(ctx, cfg, log)
		case kindVector:
			log.info("starting nw2 vector socks %s -> %s", cfg.socks, cfg.endpoint.tcpAddr())
			return runVector(ctx, cfg, log)
		default:
			return fmt.Errorf("unknown command")
		}
	}
	cfg, err := parseNW3(args[0], true)
	if err != nil {
		return err
	}
	log := newLogger(cfg.log)
	return runNW3(ctx, cfg, log)
}

// generateKey prints 16 crypto/rand bytes as 32 lowercase hex characters.
func generateKey() (string, error) {
	var key [16]byte
	if _, err := rand.Read(key[:]); err != nil {
		return "", fmt.Errorf("failed to generate a random key: %w", err)
	}
	return hex.EncodeToString(key[:]), nil
}
