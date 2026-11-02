// Package runtime loads the Nowhere 3.3 process settings.
//
// Every duration is validated at startup, including settings the selected
// role does not use. An invalid value fails with the variable name. An unset
// variable uses its default. The handshake default is derived once from the
// validated Shared Key and then reused for the life of the process.
package runtime

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

const (
	EnvTCPDataBuf       = "NOW_TCP_DATA_BUF_SIZE"
	EnvTCPDialTimeout   = "NOW_TCP_DIAL_TIMEOUT"
	EnvUDPDialTimeout   = "NOW_UDP_DIAL_TIMEOUT"
	EnvHandshakeTimeout = "NOW_HANDSHAKE_TIMEOUT"
	EnvFlowSetupTimeout = "NOW_FLOW_SETUP_TIMEOUT"
	EnvTCPReadTimeout   = "NOW_TCP_READ_TIMEOUT"
	EnvUDPIdleTimeout   = "NOW_UDP_IDLE_TIMEOUT"
	EnvQUICUDPQueue     = "NOW_QUIC_UDP_QUEUE_BYTES"
	EnvShutdownTimeout  = "NOW_SHUTDOWN_TIMEOUT"
	EnvServiceCooldown  = "NOW_SERVICE_COOLDOWN"
	EnvEgressTLSPoolMax = "NOW_EGRESS_TLS_POOL_MAX"
	EnvPortalTLSIdleMax = "NOW_PORTAL_TLS_IDLE_MAX"
	EnvMemoryProfile    = "NOW_TRANSPORT_MEMORY_PROFILE"
	EnvMorphUDPPrelude  = "NOW_MORPH_UDP_PRELUDE"

	DefaultTCPDataBuf       = 32768
	DefaultTCPDialTimeout   = 15 * time.Second
	DefaultUDPDialTimeout   = 15 * time.Second
	DefaultFlowSetupTimeout = 20 * time.Second
	DefaultTCPReadTimeout   = 30 * time.Second
	DefaultUDPIdleTimeout   = 120 * time.Second
	DefaultQUICUDPQueue     = 4 << 20
	DefaultShutdownTimeout  = 5 * time.Second
	DefaultServiceCooldown  = 3 * time.Second
	DefaultEgressTLSPoolMax = 128
	DefaultPortalTLSIdleMax = 128

	// TLSStandbyTTL is the fixed lifetime of an unused TLS Egress registration.
	// Activity does not renew it.
	TLSStandbyTTL = 120 * time.Second
	// ReassemblyTTL is the partial-packet lifetime.
	ReassemblyTTL = 10 * time.Second
	// PreAuthConnWindow is the QUIC connection receive window before AuthFrame.
	PreAuthConnWindow = 64 << 10

	maxPortalTLSIdle = 1023
	maxQUICUDPQueue  = int64(^uint32(0))
	maxInt           = int64(^uint(0) >> 1)
)

// Profile is a QUIC window preset. Windows are stream, connection, and send.
type Profile struct {
	Name       string
	Stream     uint64
	Connection uint64
	Send       uint64
}

// Settings is one validated process configuration.
type Settings struct {
	TCPDataBuf       int
	TCPDialTimeout   time.Duration
	UDPDialTimeout   time.Duration
	HandshakeTimeout time.Duration
	FlowSetupTimeout time.Duration
	TCPReadTimeout   time.Duration
	UDPIdleTimeout   time.Duration
	QUICUDPQueue     int
	ShutdownTimeout  time.Duration
	ServiceCooldown  time.Duration
	EgressTLSPoolMax int
	PortalTLSIdleMax int
	Profile          Profile
	// UDPPrelude is set only when ValidateUDPPrelude ran for a Morph QUIC client.
	UDPPrelude string
}

// Load reads the environment. sharedKey is the validated ASCII key and is
// used only when NOW_HANDSHAKE_TIMEOUT is unset. morphUDP requires a valid
// NOW_MORPH_UDP_PRELUDE; Portal and morph=0 pass false.
func Load(sharedKey string, morphUDP bool) (Settings, error) {
	s := Settings{
		TCPDataBuf:       DefaultTCPDataBuf,
		TCPDialTimeout:   DefaultTCPDialTimeout,
		UDPDialTimeout:   DefaultUDPDialTimeout,
		FlowSetupTimeout: DefaultFlowSetupTimeout,
		TCPReadTimeout:   DefaultTCPReadTimeout,
		UDPIdleTimeout:   DefaultUDPIdleTimeout,
		QUICUDPQueue:     DefaultQUICUDPQueue,
		ShutdownTimeout:  DefaultShutdownTimeout,
		ServiceCooldown:  DefaultServiceCooldown,
		EgressTLSPoolMax: DefaultEgressTLSPoolMax,
		PortalTLSIdleMax: DefaultPortalTLSIdleMax,
		Profile:          profiles["throughput"],
	}
	var err error
	if s.TCPDataBuf, err = envInt(EnvTCPDataBuf, int64(s.TCPDataBuf), 1, maxInt); err != nil {
		return Settings{}, err
	}
	if s.TCPDialTimeout, err = envDuration(EnvTCPDialTimeout, s.TCPDialTimeout); err != nil {
		return Settings{}, err
	}
	if s.UDPDialTimeout, err = envDuration(EnvUDPDialTimeout, s.UDPDialTimeout); err != nil {
		return Settings{}, err
	}
	if s.HandshakeTimeout, err = handshake(sharedKey); err != nil {
		return Settings{}, err
	}
	if s.FlowSetupTimeout, err = envDuration(EnvFlowSetupTimeout, s.FlowSetupTimeout); err != nil {
		return Settings{}, err
	}
	if s.TCPReadTimeout, err = envDuration(EnvTCPReadTimeout, s.TCPReadTimeout); err != nil {
		return Settings{}, err
	}
	if s.UDPIdleTimeout, err = envDuration(EnvUDPIdleTimeout, s.UDPIdleTimeout); err != nil {
		return Settings{}, err
	}
	queueMax := maxQUICUDPQueue
	if maxInt < queueMax {
		queueMax = maxInt
	}
	queue, err := envInt(EnvQUICUDPQueue, int64(s.QUICUDPQueue), 1, queueMax)
	if err != nil {
		return Settings{}, err
	}
	s.QUICUDPQueue = queue
	if s.ShutdownTimeout, err = envDuration(EnvShutdownTimeout, s.ShutdownTimeout); err != nil {
		return Settings{}, err
	}
	if s.ServiceCooldown, err = envDuration(EnvServiceCooldown, s.ServiceCooldown); err != nil {
		return Settings{}, err
	}
	if s.EgressTLSPoolMax, err = envInt(EnvEgressTLSPoolMax, int64(s.EgressTLSPoolMax), 1, maxInt); err != nil {
		return Settings{}, err
	}
	if s.PortalTLSIdleMax, err = envInt(EnvPortalTLSIdleMax, int64(s.PortalTLSIdleMax), 1, int64(maxPortalTLSIdle)); err != nil {
		return Settings{}, err
	}
	if s.Profile, err = memoryProfile(); err != nil {
		return Settings{}, err
	}
	if morphUDP {
		if s.UDPPrelude, err = UDPPreludePolicy(); err != nil {
			return Settings{}, err
		}
	}
	return s, nil
}

// HandshakeTimeout derives the default 3.0–30.0s timeout. The key is ASCII
// and is not hex-decoded. 0123456789abcdef0123456789abcdef yields 9100ms.
func HandshakeTimeout(sharedKey string) time.Duration {
	mac := hmac.New(sha256.New, []byte(sharedKey))
	_, _ = mac.Write([]byte("nowhere/handshake-timeout"))
	sum := mac.Sum(nil)
	value := binary.BigEndian.Uint64(sum[:8])
	return time.Duration(3000+100*(value%271)) * time.Millisecond
}

func handshake(sharedKey string) (time.Duration, error) {
	value, ok := os.LookupEnv(EnvHandshakeTimeout)
	if !ok {
		return HandshakeTimeout(sharedKey), nil
	}
	d, err := time.ParseDuration(value)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s: %w", EnvHandshakeTimeout, errDuration)
	}
	return d, nil
}

// UDPPreludePolicy reads NOW_MORPH_UDP_PRELUDE. Unset is fade.
func UDPPreludePolicy() (string, error) {
	value, ok := os.LookupEnv(EnvMorphUDPPrelude)
	if !ok {
		return "fade", nil
	}
	switch value {
	case "fade", "full8", "low7":
		return value, nil
	default:
		return "", fmt.Errorf("%s must be fade, full8 or low7", EnvMorphUDPPrelude)
	}
}

var (
	profiles = map[string]Profile{
		"memory":     {Name: "memory", Stream: 4 << 20, Connection: 8 << 20, Send: 8 << 20},
		"balanced":   {Name: "balanced", Stream: 8 << 20, Connection: 16 << 20, Send: 16 << 20},
		"throughput": {Name: "throughput", Stream: 16 << 20, Connection: 32 << 20, Send: 32 << 20},
	}
	errDuration = errors.New("invalid duration")
	errInteger  = errors.New("invalid integer")
)

func memoryProfile() (Profile, error) {
	value, ok := os.LookupEnv(EnvMemoryProfile)
	if !ok {
		return profiles["throughput"], nil
	}
	profile, ok := profiles[value]
	if !ok {
		return Profile{}, fmt.Errorf("%s must be memory, balanced or throughput", EnvMemoryProfile)
	}
	return profile, nil
}

func envDuration(name string, fallback time.Duration) (time.Duration, error) {
	value, ok := os.LookupEnv(name)
	if !ok {
		return fallback, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s: %w", name, errDuration)
	}
	return d, nil
}

func envInt(name string, fallback, min, max int64) (int, error) {
	value, ok := os.LookupEnv(name)
	if !ok {
		return int(fallback), nil
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n < min || n > max {
		return 0, fmt.Errorf("%s: %w", name, errInteger)
	}
	return int(n), nil
}
