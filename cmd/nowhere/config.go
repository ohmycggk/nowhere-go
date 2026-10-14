package main

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/ohmycggk/nowhere-go/wire"
)

type nw3Kind int

const (
	nw3Portal nw3Kind = iota
	nw3Vector
	nw3Egress
)

type nw3Exit int

const (
	nw3ExitDirect nw3Exit = iota
	nw3ExitEgress
	nw3ExitSocks
)

type nw3Config struct {
	kind      nw3Kind
	key       string
	endpoint  serviceEndpoint
	tlsMode   int
	certPath  string
	keyPath   string
	inAddr    string
	inUser    string
	inPass    string
	exit      nw3Exit
	socks     string
	socksUser string
	socksPass string
	sni       string
	pin       string
	morph     bool
	log       logLevel
	dial      dialPolicy
	rate      int
	etar      int
}

// urlEdition reports which stack a service URL selects. The choice is fixed
// before the handshake: nw2 URLs speak only nw2, everything else speaks only nw3.
func urlEdition(raw string) (string, error) {
	if !strings.Contains(raw, "://") {
		return "", fmt.Errorf("unsupported URL scheme")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "egress":
		return "nw3", nil
	case "portal", "vector", "nowhere":
	default:
		return "", fmt.Errorf("unsupported URL scheme")
	}
	q := u.Query()
	nw2 := hasQuery(q, "up", "down", "mux", "next", "socks")
	nw3 := hasQuery(q, "in", "out", "rate", "etar")
	if nw2 && nw3 {
		return "", fmt.Errorf("nw2 and nw3 options cannot be combined")
	}
	if nw2 {
		return "nw2", nil
	}
	return "nw3", nil
}

func hasQuery(q url.Values, names ...string) bool {
	for _, name := range names {
		if _, ok := q[name]; ok {
			return true
		}
	}
	return false
}

func parseNW3(raw string, vectorRequiresIn bool) (nw3Config, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nw3Config{}, err
	}
	if u.User == nil || u.User.Username() == "" {
		return nw3Config{}, fmt.Errorf("missing shared key before '@'")
	}
	if _, ok := u.User.Password(); ok {
		return nw3Config{}, fmt.Errorf("password credentials are not supported; put the shared key before '@'")
	}
	key, err := url.QueryUnescape(u.User.Username())
	if err != nil || key == "" {
		return nw3Config{}, fmt.Errorf("invalid shared key encoding")
	}
	if err := wire.ValidateServiceKey(key); err != nil {
		return nw3Config{}, err
	}
	cfg := nw3Config{key: key, tlsMode: 1, morph: true, log: logInfo}
	switch u.Scheme {
	case "portal":
		cfg.kind = nw3Portal
		cfg.endpoint, err = parseServiceEndpoint(u, true, "Portal listener")
	case "vector":
		cfg.kind = nw3Vector
		cfg.endpoint, err = parseServiceEndpoint(u, false, "Vector endpoint")
	case "egress":
		cfg.kind = nw3Egress
		cfg.endpoint, err = parseServiceEndpoint(u, false, "Egress endpoint")
	default:
		return nw3Config{}, fmt.Errorf("URL must use portal://, vector://, or egress://")
	}
	if err != nil {
		return nw3Config{}, err
	}
	if err := normalizeNW3Endpoint(&cfg); err != nil {
		return nw3Config{}, err
	}
	q := u.Query()
	first := func(name string) (string, bool) {
		vs, ok := q[name]
		if !ok || len(vs) == 0 {
			return "", false
		}
		return vs[0], true
	}
	if v, ok := first("tls"); ok {
		mode, err := strconv.Atoi(v)
		if err != nil || (mode != 1 && mode != 2) {
			return nw3Config{}, fmt.Errorf("tls must be 1 or 2")
		}
		cfg.tlsMode = mode
	}
	if v, ok := first("crt"); ok {
		cfg.certPath = v
	}
	if v, ok := first("key"); ok {
		cfg.keyPath = v
	}
	if cfg.tlsMode == 2 && (cfg.certPath == "" || cfg.keyPath == "") {
		return nw3Config{}, fmt.Errorf("tls=2 requires crt and key")
	}
	if v, ok := first("morph"); ok {
		switch v {
		case "0":
			cfg.morph = false
		case "1":
			cfg.morph = true
		default:
			return nw3Config{}, fmt.Errorf("morph must be 0 or 1")
		}
	}
	if v, ok := first("log"); ok {
		level, err := parseLogLevel(v)
		if err != nil {
			return nw3Config{}, err
		}
		cfg.log = level
	}
	if v, ok := first("sni"); ok && v != "none" {
		cfg.sni = v
	}
	if v, ok := first("pin"); ok && v != "none" {
		cfg.pin = v
	}
	if _, err := parsePin(cfg.pin); err != nil {
		return nw3Config{}, err
	}
	cfg.dial, err = parseDialPolicy(q)
	if err != nil {
		return nw3Config{}, err
	}
	if v, ok := first("rate"); ok {
		cfg.rate, err = parseMbps(v, "rate")
		if err != nil {
			return nw3Config{}, err
		}
	}
	if v, ok := first("etar"); ok {
		cfg.etar, err = parseMbps(v, "etar")
		if err != nil {
			return nw3Config{}, err
		}
	}
	if v, ok := first("in"); ok && v != "" {
		user, pass, addr, err := parseSocksEndpoint(v)
		if err != nil {
			return nw3Config{}, err
		}
		cfg.inUser, cfg.inPass, cfg.inAddr = user, pass, addr
	}
	if v, ok := first("out"); ok && v != "" && v != "direct" {
		if v == "egress" {
			cfg.exit = nw3ExitEgress
		} else {
			user, pass, addr, err := parseSocksEndpoint(v)
			if err != nil {
				return nw3Config{}, fmt.Errorf("out: %w", err)
			}
			cfg.exit = nw3ExitSocks
			cfg.socks, cfg.socksUser, cfg.socksPass = addr, user, pass
		}
	}
	if cfg.kind == nw3Portal && cfg.exit == nw3ExitEgress {
		if !cfg.endpoint.hasUDP() {
			return nw3Config{}, fmt.Errorf("out=egress requires a QUIC listener")
		}
		if cfg.dial.configured() {
			return nw3Config{}, fmt.Errorf("out=egress conflicts with dial, dial4, or dial6")
		}
	}
	if cfg.kind == nw3Vector && vectorRequiresIn && cfg.inAddr == "" {
		return nw3Config{}, fmt.Errorf("vector requires in=<listen-endpoint>")
	}
	if cfg.kind != nw3Portal && (cfg.certPath != "" || cfg.keyPath != "") {
		return nw3Config{}, fmt.Errorf("crt and key are portal options")
	}
	return cfg, nil
}

func normalizeNW3Endpoint(cfg *nw3Config) error {
	switch cfg.kind {
	case nw3Vector:
		if cfg.endpoint.hasTCP() && cfg.endpoint.hasUDP() && cfg.endpoint.tcp.port == cfg.endpoint.udp.port && cfg.endpoint.tcp.family == cfg.endpoint.udp.family {
			cfg.endpoint.udp = nil
		}
		if cfg.endpoint.hasTCP() && cfg.endpoint.hasUDP() {
			return fmt.Errorf("vector endpoint declares exactly one carrier")
		}
	case nw3Egress:
		if cfg.endpoint.hasTCP() && cfg.endpoint.hasUDP() && cfg.endpoint.tcp.port == cfg.endpoint.udp.port {
			cfg.endpoint.tcp = nil
		}
		if cfg.endpoint.hasTCP() || !cfg.endpoint.hasUDP() {
			return fmt.Errorf("egress endpoint declares exactly one QUIC carrier")
		}
	default:
		if !cfg.endpoint.hasTCP() && !cfg.endpoint.hasUDP() {
			return fmt.Errorf("portal endpoint declares no carrier")
		}
	}
	return nil
}

func parseMbps(v, name string) (int, error) {
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > 2147483647 {
		return 0, fmt.Errorf("%s must be 0..=2147483647", name)
	}
	return n, nil
}

func parsePin(pin string) (string, error) {
	if pin == "" {
		return "", nil
	}
	if len(pin) != 64 {
		return "", fmt.Errorf("pin must be 64 lowercase hexadecimal characters")
	}
	for i := 0; i < len(pin); i++ {
		c := pin[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", fmt.Errorf("pin must be 64 lowercase hexadecimal characters")
		}
	}
	return pin, nil
}
