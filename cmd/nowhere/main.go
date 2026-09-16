package main

import (
	"context"
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
		fmt.Fprintln(os.Stderr, err)
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
		fmt.Print(helpText)
		return nil
	case "-v", "--version", "version":
		fmt.Printf("nowhere %s %s/%s\n", Version, runtime.GOOS, runtime.GOARCH)
		return nil
	case "tui":
		return fmt.Errorf("tui is not included in the Go nowhere binary; use the Rust nowhere tui")
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
