package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/ohmycggk/nowhere-go/bundle"
	"github.com/ohmycggk/nowhere-go/wire"
)

// errProbeFailed is returned when a probe reaches the flow stage but does not
// report OK. main() exits non-zero without printing it, mirroring upstream's
// ProbeFailed sentinel.
var errProbeFailed = errors.New("probe failed")

const (
	// probeTransportTimeout reflects the Go library's TLS/TCP physical dial
	// bound. There is no NOW_HANDSHAKE_TIMEOUT on the Go side.
	probeTransportTimeout = 15 * time.Second
	// probeSetupTimeout mirrors upstream's 2×handshake + flow-setup budget
	// using the Go library's own bounded operations.
	probeSetupTimeout = 2*probeTransportTimeout + bundle.DefaultFlowSetupTimeout
)

const (
	probeOK              = "OK"
	probeCleanupFailed   = "CLEANUP_FAILED"
	probeTransportFailed = "TRANSPORT_FAILED"
)

type probeReport struct {
	result   string
	ready    bool
	up, down wire.Carrier
	elapsed  time.Duration
}

// runProbe opens one real TCP flow through the normal Vector client stack, sends
// no payload, closes the write side (flushing the FIN) then the flow, and prints
// a NOWHERE PROBE panel. Only OK exits 0; every other outcome exits 1 silently.
func runProbe(rawURL, rawTarget string) error {
	cfg, err := parseCommandURLMode(rawURL, false)
	if err != nil {
		return err
	}
	if cfg.kind != kindVector {
		return fmt.Errorf("probe requires a vector:// URL")
	}
	target, err := parseProbeTarget(rawTarget)
	if err != nil {
		return err
	}
	report, err := probeFlow(cfg, target)
	if err != nil {
		return fmt.Errorf("failed to initialize Flow client: %w", err)
	}
	fmt.Println(renderProbePanel(cfg.endpoint, target, report))
	if report.result == probeOK {
		return nil
	}
	return errProbeFailed
}

func probeFlow(cfg appConfig, target wire.Target) (probeReport, error) {
	// Suppress library chatter so a failed probe produces no stderr output; the
	// panel is the only user-facing result.
	log := newLogger(logNone)
	fd := familyDialer{policy: cfg.dial}
	client, err := newBundle(cfg.key, cfg.endpoint, cfg.up, cfg.down, cfg.mux, cfg.sni, cfg.pin, cfg.morph, fd, log)
	if err != nil {
		return probeReport{}, err
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), probeSetupTimeout)
	defer cancel()

	start := time.Now()
	conn, openErr := client.OpenTCP(ctx, target)
	elapsed := time.Since(start)

	report := probeReport{
		elapsed: elapsed,
		up:      client.UpCarrier(),
		down:    client.DownCarrier(),
	}
	if openErr != nil {
		report.result = classifyOpenError(openErr)
		return report, nil
	}
	// Close the write side first so the FIN reaches the peer before teardown,
	// then close the flow.
	cleanupOK := true
	if cerr := closeConnWrite(conn); cerr != nil {
		cleanupOK = false
	}
	if cerr := conn.Close(); cerr != nil {
		cleanupOK = false
	}
	if cleanupOK {
		report.result = probeOK
	} else {
		report.result = probeCleanupFailed
	}
	report.ready = true
	return report, nil
}

// classifyOpenError maps a failed flow-open to a probe Result label. A non-READY
// SetupResult surfaces as its uppercased name; anything else is a transport
// failure (mirrors upstream's error.setup_result() vs transport/protocol split).
func classifyOpenError(err error) string {
	var sre *bundle.SetupResultError
	if errors.As(err, &sre) {
		return setupResultName(sre.SetupResultCode())
	}
	return probeTransportFailed
}

func setupResultName(code wire.SetupResult) string {
	return strings.ToUpper(strings.ReplaceAll(code.String(), " ", "_"))
}

func closeConnWrite(conn net.Conn) error {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func parseProbeTarget(raw string) (wire.Target, error) {
	target, err := parseDialTarget(raw)
	if err != nil {
		return wire.Target{}, fmt.Errorf("invalid TCP target; expected host:port or [IPv6]:port")
	}
	return target, nil
}

func renderProbePanel(endpoint serviceEndpoint, target wire.Target, report probeReport) string {
	rows := [][2]string{
		{"Result", report.result},
		{"Portal", canonicalEndpoint(endpoint)},
		{"Target", targetAddr(target)},
		{"Route", report.route()},
		{"Setup", formatProbeDuration(report.elapsed)},
	}
	return renderPanel("NOWHERE PROBE", rows)
}

func (r probeReport) route() string {
	if !r.ready {
		return "—"
	}
	return fmt.Sprintf("↑ %s · ↓ %s", carrierDisplay(r.up), carrierDisplay(r.down))
}

func carrierDisplay(c wire.Carrier) string {
	if c == wire.CarrierQUIC {
		return "QUIC"
	}
	return "TLS"
}

// renderPanel reproduces upstream toolbox::panel formatting: a title line, a
// U+2500 rule sized to the title, then right-aligned labels padded to the
// widest label, two spaces, and the value.
func renderPanel(title string, rows [][2]string) string {
	width := 0
	for _, row := range rows {
		if len(row[0]) > width {
			width = len(row[0])
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n%s\n", title, strings.Repeat("─", len(title)))
	for _, row := range rows {
		fmt.Fprintf(&b, "%*s  %s\n", width, row[0], row[1])
	}
	return strings.TrimSuffix(b.String(), "\n")
}

func formatProbeDuration(d time.Duration) string {
	ms := float64(d) / float64(time.Millisecond)
	if ms < 10 {
		return fmt.Sprintf("%.1f ms", ms)
	}
	return fmt.Sprintf("%.0f ms", ms)
}

// canonicalEndpoint mirrors upstream ServiceEndpoint::canonical so the Portal
// row matches how upstream renders the probe endpoint.
func canonicalEndpoint(e serviceEndpoint) string {
	if e.tcp != nil && e.udp != nil && e.tcp.family == familyAny && e.udp.family == familyAny && e.tcp.port == e.udp.port {
		return net.JoinHostPort(e.host, strconv.Itoa(e.tcp.port))
	}
	var b strings.Builder
	b.WriteString(formatHost(e.host))
	if e.tcp != nil {
		fmt.Fprintf(&b, "/tcp%s:%d", familySuffix(e.tcp.family), e.tcp.port)
	}
	if e.udp != nil {
		fmt.Fprintf(&b, "/udp%s:%d", familySuffix(e.udp.family), e.udp.port)
	}
	return b.String()
}

func formatHost(host string) string {
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return "[" + host + "]"
	}
	return host
}

func familySuffix(f addressFamily) string {
	switch f {
	case familyV4:
		return "4"
	case familyV6:
		return "6"
	default:
		return ""
	}
}
