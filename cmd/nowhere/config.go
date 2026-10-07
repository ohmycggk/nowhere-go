package main

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/ohmycggk/nowhere-go/bundle"
	"github.com/ohmycggk/nowhere-go/wire"
)

type logLevel int

const (
	logNone logLevel = iota
	logError
	logWarn
	logInfo
	logDebug
)

type commandKind int

const (
	kindPortal commandKind = iota
	kindVector
)

type nextHop struct {
	key      string
	endpoint serviceEndpoint
}

type appConfig struct {
	kind      commandKind
	key       string
	endpoint  serviceEndpoint
	tlsMode   int // 1 generated, 2 files
	certPath  string
	keyPath   string
	up        string
	down      string
	mux       bundle.MuxMode
	sni       string
	pin       string
	morph     bool
	socks     string
	socksUser string
	socksPass string
	next      *nextHop
	log       logLevel
	dial      dialPolicy
}

func parseCommandURL(raw string) (appConfig, error) {
	return parseCommandURLMode(raw, true)
}

// parseCommandURLMode parses a portal/vector configuration URL. probe passes
// vectorRequiresSocks=false because upstream PortalClientConfig::from_probe_url
// treats socks= as optional there.
func parseCommandURLMode(raw string, vectorRequiresSocks bool) (appConfig, error) {
	if strings.Contains(raw, "://") {
		if !strings.HasPrefix(raw, "portal://") && !strings.HasPrefix(raw, "vector://") {
			return appConfig{}, fmt.Errorf("unsupported URL scheme")
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return appConfig{}, err
	}
	if u.User == nil || u.User.Username() == "" {
		return appConfig{}, fmt.Errorf("missing shared key before '@'")
	}
	if _, ok := u.User.Password(); ok {
		return appConfig{}, fmt.Errorf("password credentials are not supported; put the shared key before '@'")
	}
	key, err := url.QueryUnescape(u.User.Username())
	if err != nil {
		return appConfig{}, fmt.Errorf("invalid shared key encoding")
	}
	if key == "" {
		return appConfig{}, fmt.Errorf("missing shared key before '@'")
	}

	cfg := appConfig{key: key, tlsMode: 1, log: logInfo, up: "", down: ""}
	query := u.Query()
	first := func(name string) string {
		if vs := query[name]; len(vs) > 0 {
			return vs[0]
		}
		return ""
	}

	switch u.Scheme {
	case "portal":
		cfg.kind = kindPortal
		if err := validateListenerKey(key); err != nil {
			return appConfig{}, fmt.Errorf("Portal listener: %w", err)
		}
		cfg.endpoint, err = parseServiceEndpoint(u, true, "Portal listener")
		if err != nil {
			return appConfig{}, err
		}
	case "vector":
		cfg.kind = kindVector
		if len(key) > 255 {
			return appConfig{}, fmt.Errorf("shared key exceeds the 255-byte limit")
		}
		cfg.endpoint, err = parseServiceEndpoint(u, false, "Vector endpoint")
		if err != nil {
			return appConfig{}, err
		}
	default:
		return appConfig{}, fmt.Errorf("URL must use portal:// or vector://")
	}

	if v := first("tls"); v != "" {
		mode, err := strconv.Atoi(v)
		if err != nil || (mode != 1 && mode != 2) {
			return appConfig{}, fmt.Errorf("tls must be 1 or 2")
		}
		cfg.tlsMode = mode
	}
	cfg.certPath = first("crt")
	cfg.keyPath = first("key")
	if cfg.tlsMode == 2 && (cfg.certPath == "" || cfg.keyPath == "") {
		return appConfig{}, fmt.Errorf("tls=2 requires crt and key")
	}

	if v := first("up"); v != "" {
		if err := validateCarrier(v); err != nil {
			return appConfig{}, err
		}
		cfg.up = v
	}
	if v := first("down"); v != "" {
		if err := validateCarrier(v); err != nil {
			return appConfig{}, err
		}
		cfg.down = v
	}
	if v := first("mux"); v != "" {
		switch v {
		case "0":
			cfg.mux = bundle.MuxDisabled
		case "1":
			cfg.mux = bundle.MuxEnabled
		default:
			return appConfig{}, fmt.Errorf("mux must be 0 or 1")
		}
	}
	cfg.sni = first("sni")
	if cfg.sni == "none" {
		cfg.sni = ""
	}
	cfg.pin = first("pin")
	if cfg.pin == "none" {
		cfg.pin = ""
	}
	if _, err := wire.ParseCertificatePin(cfg.pin); err != nil {
		return appConfig{}, err
	}
	if v := first("morph"); v != "" {
		switch v {
		case "0":
			cfg.morph = false
		case "1":
			cfg.morph = true
		default:
			return appConfig{}, fmt.Errorf("morph must be 0 or 1")
		}
	}
	if v := first("log"); v != "" {
		level, err := parseLogLevel(v)
		if err != nil {
			return appConfig{}, err
		}
		cfg.log = level
	}
	cfg.dial, err = parseDialPolicy(query)
	if err != nil {
		return appConfig{}, err
	}

	if v := first("socks"); v != "" && v != "none" {
		user, pass, addr, err := parseSocksEndpoint(v)
		if err != nil {
			return appConfig{}, err
		}
		cfg.socks, cfg.socksUser, cfg.socksPass = addr, user, pass
	}
	if v := first("next"); v != "" && v != "none" {
		hop, err := parseNext(v)
		if err != nil {
			return appConfig{}, err
		}
		cfg.next = &hop
	}
	if cfg.kind == kindPortal && cfg.socks != "" && cfg.next != nil {
		return appConfig{}, fmt.Errorf("socks and next are mutually exclusive")
	}
	if cfg.kind == kindVector && vectorRequiresSocks && cfg.socks == "" {
		return appConfig{}, fmt.Errorf("vector requires socks=<listen-endpoint>")
	}
	if err := cfg.normalizeRoute(); err != nil {
		return appConfig{}, err
	}
	return cfg, nil
}

func (c *appConfig) normalizeRoute() error {
	onlyUDP := c.endpoint.hasUDP() && !c.endpoint.hasTCP()
	if c.up == "" {
		if onlyUDP {
			c.up = "udp"
		} else {
			c.up = "tcp"
		}
	}
	if c.down == "" {
		if onlyUDP {
			c.down = "udp"
		} else {
			c.down = "tcp"
		}
	}
	if (c.up == "udp" || c.down == "udp") && !c.endpoint.hasUDP() {
		return fmt.Errorf("udp route requires a UDP carrier")
	}
	if (c.up == "tcp" || c.down == "tcp") && !c.endpoint.hasTCP() {
		return fmt.Errorf("tcp route requires a TCP carrier")
	}
	if !c.endpoint.hasTCP() {
		c.mux = bundle.MuxDisabled
	}
	if c.up == "udp" && c.down == "udp" {
		c.mux = bundle.MuxDisabled
	}
	return nil
}

func validateCarrier(v string) error {
	switch v {
	case "tcp", "udp":
		return nil
	default:
		return fmt.Errorf("up/down must be tcp or udp")
	}
}

func parseLogLevel(v string) (logLevel, error) {
	switch v {
	case "none":
		return logNone, nil
	case "error":
		return logError, nil
	case "warn":
		return logWarn, nil
	case "info":
		return logInfo, nil
	case "debug":
		return logDebug, nil
	default:
		return 0, fmt.Errorf("log must be none, debug, info, warn, or error; found %q", v)
	}
}

func parseSocksEndpoint(v string) (user, pass, addr string, err error) {
	if strings.Contains(v, "@") {
		var creds string
		creds, addr, _ = strings.Cut(v, "@")
		user, pass, _ = strings.Cut(creds, ":")
		user, err = url.QueryUnescape(user)
		if err != nil {
			return "", "", "", err
		}
		pass, err = url.QueryUnescape(pass)
		if err != nil {
			return "", "", "", err
		}
	} else {
		addr = v
	}
	if strings.HasPrefix(addr, ":") {
		addr = net.JoinHostPort("", strings.TrimPrefix(addr, ":"))
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return "", "", "", fmt.Errorf("invalid socks endpoint %q", v)
	}
	return user, pass, addr, nil
}

func parseNext(v string) (nextHop, error) {
	if !strings.Contains(v, "@") {
		return nextHop{}, fmt.Errorf("Portal next endpoint: shared key and endpoint must be separated by '@'")
	}
	key, rest, _ := strings.Cut(v, "@")
	key, err := url.QueryUnescape(key)
	if err != nil || key == "" {
		return nextHop{}, fmt.Errorf("invalid next shared key")
	}
	if err := validateListenerKey(key); err != nil {
		return nextHop{}, fmt.Errorf("Portal next endpoint: %w", err)
	}
	u, err := url.Parse("portal://x@" + rest)
	if err != nil {
		return nextHop{}, fmt.Errorf("Portal next endpoint: invalid endpoint")
	}
	endpoint, err := parseServiceEndpoint(u, false, "Portal next endpoint")
	if err != nil {
		return nextHop{}, err
	}
	return nextHop{key: key, endpoint: endpoint}, nil
}

// validateListenerKey enforces the Nowhere 2.2 Portal shared-key rule: after URL
// percent-decoding the key must be 32–64 lowercase hexadecimal characters. Both
// the Portal listener and each next= hop use this rule; Vector client keys are
// intentionally exempt (1–255 raw bytes).
func validateListenerKey(key string) error {
	if len(key) < 32 || len(key) > 64 {
		return errSharedKeyRule
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return errSharedKeyRule
		}
	}
	return nil
}

var errSharedKeyRule = fmt.Errorf("shared key must be 32\u201364 lowercase hexadecimal characters; use nowhere generate-key")

func routeCarriers(up, down string) (wire.Carrier, wire.Carrier) {
	var upC, downC wire.Carrier
	if up == "udp" {
		upC = wire.CarrierQUIC
	}
	if down == "udp" {
		downC = wire.CarrierQUIC
	}
	return upC, downC
}
