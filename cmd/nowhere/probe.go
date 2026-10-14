package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ohmycggk/nowhere-go/nw2/wire"
	nw3wire "github.com/ohmycggk/nowhere-go/wire"
)

func runProbeNW3(rawURL, rawTarget string) error {
	cfg, err := parseNW3(rawURL, false)
	if err != nil {
		return err
	}
	if cfg.kind != nw3Vector {
		return fmt.Errorf("probe requires a vector:// URL")
	}
	target, err := parseProbeTarget(rawTarget)
	if err != nil {
		return err
	}
	nt, err := toNW3Target(target)
	if err != nil {
		return err
	}
	client, err := newNW3Vector(context.Background(), cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize Flow client: %w", err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), probeSetupTimeout)
	defer cancel()
	start := time.Now()
	conn, openErr := client.OpenTCP(ctx, nt)
	elapsed := time.Since(start)
	result := probeOK
	if openErr != nil {
		var setup nw3wire.SetupError
		if errors.As(openErr, &setup) {
			result = strings.ToUpper(strings.ReplaceAll(setup.Result.Error(), " ", "_"))
		} else {
			result = probeTransportFailed
		}
	} else {
		if closeConnWrite(conn) != nil || conn.Close() != nil {
			result = probeCleanupFailed
		}
	}
	route := "TLS"
	if cfg.endpoint.hasUDP() && !cfg.endpoint.hasTCP() {
		route = "QUIC"
	}
	rows := [][2]string{
		{"Result", result},
		{"Portal", canonicalEndpoint(cfg.endpoint)},
		{"Target", targetAddr(target)},
		{"Route", route},
		{"Setup", formatProbeDuration(elapsed)},
	}
	fmt.Println(renderPanel("NOWHERE PROBE", rows))
	if result == probeOK {
		return nil
	}
	return errProbeFailed
}

// targetAddr is defined for nw2 targets. Keep this alias so the probe file
// references wire only when the nw2 target type is required.
var _ = wire.SetupResultReady
