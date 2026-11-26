package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/ohmycggk/nowhere-go/runtime"

	nw3morph "github.com/ohmycggk/nowhere-go/morph"
	"github.com/ohmycggk/nowhere-go/nw2/carrier/morph"
	"github.com/ohmycggk/nowhere-go/nw2/wire"
	nw3wire "github.com/ohmycggk/nowhere-go/wire"
)

func fingerprintALPN(nw3 bool) string {
	if nw3 {
		return nw3wire.ALPN
	}
	return wire.DefaultALPN
}

// fingerprintTimeout bounds the TCP dial plus TLS handshake for one share link
// when the Shared Key has not been validated yet. A validated key uses the
// derived NOW_HANDSHAKE_TIMEOUT instead.

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

	edition, edErr := urlEdition(raw)
	if edErr != nil {
		return edErr
	}
	var morphEnabled bool
	var sni string
	var cipher nw3morph.Cipher
	var grade nw3morph.Grade
	if edition == "nw2" {
		query := u.Query()
		morphEnabled = query.Get("morph") == "1"
		sni = query.Get("sni")
		if sni == "none" {
			sni = ""
		}
	} else {
		if _, hasPass := u.User.Password(); hasPass {
			return fmt.Errorf("password credentials are not supported; put the shared key before '@'")
		}
		if err := nw3wire.ValidateServiceKey(key); err != nil {
			return err
		}
		q, err := parseNW3Query(u.RawQuery, "net", "morph", "grade", "cipher", "sni")
		if err != nil {
			return err
		}
		rawMorph, hasMorph := q["morph"]
		if !hasMorph {
			return fmt.Errorf("fingerprint requires morph=0 or morph=1")
		}
		if v, ok := q["net"]; ok && v != "tcp" && v != "udp" {
			return fmt.Errorf("share link net must be tcp or udp")
		}
		switch rawMorph {
		case "0":
			morphEnabled = false
		case "1":
			morphEnabled = true
		default:
			return fmt.Errorf("morph must be 0 or 1")
		}
		if v, ok := q["grade"]; ok {
			grade, err = nw3morph.ParseGrade(v)
			if err != nil {
				return err
			}
		}
		if v, ok := q["cipher"]; ok {
			cipher, err = nw3morph.ParseCipher(v)
			if err != nil {
				return err
			}
		}
		if morphEnabled {
			if err := nw3morph.ValidateTCPPreludeEnv(); err != nil {
				return err
			}
		}
		if v, ok := q["sni"]; ok && v != "none" {
			sni = v
		}
	}

	fp, err := fetchCertificateFingerprint(endpoint.tcpAddr(), key, endpoint.host, sni, morphEnabled, edition != "nw2", cipher, grade)
	if err != nil {
		return err
	}
	fmt.Println(fp)
	return nil
}

func fetchCertificateFingerprint(addr, key, host, sni string, morphEnabled, nw3 bool, cipher nw3morph.Cipher, grade nw3morph.Grade) (string, error) {
	timeout := 15 * time.Second
	if nw3 {
		rt, err := runtime.Load(key, false)
		if err != nil {
			return "", err
		}
		timeout = rt.HandshakeTimeout
		if morphEnabled {
			if err := nw3morph.ValidateTCPPreludeEnv(); err != nil {
				return "", err
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve Portal TLS certificate: TCP connection failed: %w", err)
	}
	defer conn.Close()

	var carrier net.Conn = conn
	if morphEnabled {
		if nw3 {
			keys, kerr := nw3morph.DeriveWithOptions([]byte(key), cipher, grade)
			if kerr != nil {
				return "", fmt.Errorf("failed to retrieve Portal TLS certificate: %w", kerr)
			}
			carrier, err = nw3morph.WrapTCPClient(conn, keys)
		} else {
			carrier, err = morph.WrapTCPClient(conn, morph.Derive([]byte(key)))
		}
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
		NextProtos:         []string{fingerprintALPN(nw3)},
		InsecureSkipVerify: true,
		ServerName:         serverName,
	}
	tlsConn := tls.Client(carrier, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return "", fmt.Errorf("failed to retrieve Portal TLS certificate: TLS/Morph handshake failed: %w", err)
	}
	state := tlsConn.ConnectionState()
	if state.NegotiatedProtocol != fingerprintALPN(nw3) {
		return "", fmt.Errorf("failed to retrieve Portal TLS certificate: Portal did not negotiate %s ALPN", fingerprintALPN(nw3))
	}
	if len(state.PeerCertificates) == 0 {
		return "", fmt.Errorf("failed to retrieve Portal TLS certificate: Portal did not provide a TLS certificate")
	}
	return wire.LeafCertificateSHA256Hex(state.PeerCertificates[0].Raw), nil
}
