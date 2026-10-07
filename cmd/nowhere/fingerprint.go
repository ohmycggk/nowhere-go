package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/ohmycggk/nowhere-go/carrier/morph"
	"github.com/ohmycggk/nowhere-go/wire"
)

// fingerprintTimeout bounds the TCP dial plus TLS handshake for one share link.
// There is no NOW_HANDSHAKE_TIMEOUT on the Go side, so this mirrors the Rust
// default handshake/deadline pair.
const fingerprintTimeout = 15 * time.Second

// runFingerprint reads the leaf TLS certificate SHA-256 from a Nowhere share
// link (nowhere://) and prints it as 64 lowercase hex characters. It dials only
// the TCP carrier, performs an inspector TLS handshake (chain/CA/pin skipped,
// handshake signature still verified), and closes without sending any auth
// frame or flow data.
func runFingerprint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid Nowhere share link: %w", err)
	}
	if u.Scheme != "nowhere" {
		return fmt.Errorf("fingerprint requires a nowhere:// share link")
	}
	if u.User == nil {
		return fmt.Errorf("invalid Nowhere share link: missing shared key before '@'")
	}
	key, err := url.QueryUnescape(u.User.Username())
	if err != nil || key == "" {
		return fmt.Errorf("invalid Nowhere share link: missing shared key before '@'")
	}
	if len(key) > 255 {
		return fmt.Errorf("invalid Nowhere share link: shared key exceeds the 255-byte limit")
	}
	// Carrier paths accept only plain tcp/udp; the r4/r6 suffixes are rejected.
	if u.Path != "" && u.Path != "/" {
		for _, seg := range strings.Split(strings.TrimPrefix(u.Path, "/"), "/") {
			carrier, _, ok := strings.Cut(seg, ":")
			if !ok || (carrier != "tcp" && carrier != "udp") {
				return fmt.Errorf("Nowhere share-link carrier paths support only tcp and udp")
			}
		}
	}
	endpoint, err := parseServiceEndpoint(u, false, "Nowhere share-link endpoint")
	if err != nil {
		return fmt.Errorf("invalid Nowhere share link: %w", err)
	}
	if !endpoint.hasTCP() {
		return fmt.Errorf("fingerprint requires a TCP carrier in the Nowhere share link")
	}

	query := u.Query()
	morphEnabled := query.Get("morph") == "1"
	sni := query.Get("sni")
	if sni == "none" {
		sni = ""
	}

	fp, err := fetchCertificateFingerprint(endpoint.tcpAddr(), key, endpoint.host, sni, morphEnabled)
	if err != nil {
		return err
	}
	fmt.Println(fp)
	return nil
}

func fetchCertificateFingerprint(addr, key, host, sni string, morphEnabled bool) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), fingerprintTimeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve Portal TLS certificate: TCP connection failed: %w", err)
	}
	defer conn.Close()

	var carrier net.Conn = conn
	if morphEnabled {
		carrier, err = morph.WrapTCPClient(conn, morph.Derive([]byte(key)))
		if err != nil {
			return "", fmt.Errorf("failed to retrieve Portal TLS certificate: %w", err)
		}
	}

	serverName := sni
	if serverName == "" {
		serverName = host
	}
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{wire.DefaultALPN},
		InsecureSkipVerify: true,
		ServerName:         serverName,
	}
	tlsConn := tls.Client(carrier, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return "", fmt.Errorf("failed to retrieve Portal TLS certificate: TLS/Morph handshake failed: %w", err)
	}
	state := tlsConn.ConnectionState()
	if state.NegotiatedProtocol != wire.DefaultALPN {
		return "", fmt.Errorf("failed to retrieve Portal TLS certificate: Portal did not negotiate nw2 ALPN")
	}
	if len(state.PeerCertificates) == 0 {
		return "", fmt.Errorf("failed to retrieve Portal TLS certificate: Portal did not provide a TLS certificate")
	}
	return wire.LeafCertificateSHA256Hex(state.PeerCertificates[0].Raw), nil
}
