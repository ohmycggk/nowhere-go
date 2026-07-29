// Package bundle orchestrates symmetric/asymmetric Nowhere carrier sessions.
package bundle

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"sync/atomic"

	"github.com/ohmycggk/nowhere-go/carrier"
	"github.com/ohmycggk/nowhere-go/carrier/tcptls"
	"github.com/ohmycggk/nowhere-go/diagnostic"
	"github.com/ohmycggk/nowhere-go/wire"
)

const (
	// DefaultMaxUDPQueueBytes is the shared DATA/reassembly budget per physical
	// QUIC session.
	DefaultMaxUDPQueueBytes = 4 * 1024 * 1024
	// DefaultMaxPendingCloses bounds reliable, de-duplicated CLOSE delivery.
	DefaultMaxPendingCloses = 1024
)

// BundleOptions builds an immutable carrier bundle.
type BundleOptions struct {
	// QUIC is required when either direction selects CarrierQUIC.
	QUIC carrier.QuicBackend
	// TCP is required when either direction selects CarrierTLSTCP.
	TCP *tcptls.Config
	// Credentials authenticates every physical carrier in the bundle.
	Credentials *wire.Credentials
	// ALPN is the expected carrier ALPN; empty uses wire.DefaultALPN.
	ALPN string
	// Observer receives structured lifecycle and failure events.
	Observer diagnostic.Observer
	// PoolSize is the TLS/TCP idle target for tcp/tcp and must be zero
	// whenever either direction uses QUIC.
	PoolSize int
	// MaxUDPQueueBytes bounds queued and reassembling QUIC DATAGRAM payload.
	MaxUDPQueueBytes int
	// MaxPendingCloses bounds reliable, de-duplicated CLOSE delivery.
	MaxPendingCloses int
	// PrewarmOnStart starts TLS/TCP pool preparation during construction.
	PrewarmOnStart bool
	// Up selects the client-to-target physical carrier.
	Up wire.Carrier
	// Down selects the target-to-client physical carrier.
	Down wire.Carrier
}

type bundleConfig struct {
	quic             carrier.QuicBackend
	tcp              *tcptls.Config
	credentials      *wire.Credentials
	alpn             string
	observer         diagnostic.Observer
	poolSize         int
	maxUDPQueueBytes int
	maxPendingCloses int
	prewarmOnStart   bool
	up               wire.Carrier
	down             wire.Carrier
}

// CarrierBundle shares one session id across carriers and allocates flow ids.
//
// In Nowhere 1.5 the bundle owns the session id and the QUIC auth handshake:
// it generates a session id with crypto/rand, reads the TLS exporter off each
// physical session, and prefixes the first flow with the connection-bound auth
// frame. The injected QUIC backend never learns the session id.
type CarrierBundle struct {
	cfg bundleConfig

	sessionIDOnce sync.Once
	sessionID     wire.SessionID
	sessionIDErr  error

	quicOnce sync.Once
	quic     carrier.QuicBackend
	quicErr  error

	tcpOnce sync.Once
	tcp     *tcptls.TCPPool
	tcpErr  error

	// nextFlowID is the next 1.5 flow id to hand out. Flow ids are uint32 and
	// must skip zero; the allocator wraps within the nonzero u32 space.
	nextFlowID atomic.Uint32

	lifecycleMu sync.Mutex
	closed      bool
	closeOnce   sync.Once
	closeErr    error
}

// NewCarrierBundle validates options and returns an isolated session bundle.
func NewCarrierBundle(options BundleOptions) (*CarrierBundle, error) {
	if !isCarrier(options.Up) || !isCarrier(options.Down) {
		return nil, errors.New("nowhere: invalid carrier selector")
	}
	if options.Credentials == nil {
		return nil, wire.ErrMissingCredentials
	}
	alpn, err := wire.NormalizeALPN(options.ALPN)
	if err != nil {
		return nil, err
	}
	usesTCP := options.Up == wire.CarrierTLSTCP || options.Down == wire.CarrierTLSTCP
	usesQUIC := options.Up == wire.CarrierQUIC || options.Down == wire.CarrierQUIC
	if usesTCP && options.TCP == nil {
		return nil, errors.New("nowhere: nil TCP carrier config")
	}
	if (options.Up == wire.CarrierQUIC || options.Down == wire.CarrierQUIC) && options.QUIC == nil {
		return nil, errors.New("nowhere: nil quic backend")
	}
	if options.PoolSize < 0 || options.PoolSize > tcptls.MaxPoolSize {
		return nil, errors.New("nowhere: TCP pool size outside 0..256")
	}
	if usesQUIC && options.PoolSize != 0 {
		return nil, errors.New("nowhere: pool must be zero when either carrier is QUIC")
	}
	maxUDPQueueBytes := options.MaxUDPQueueBytes
	if maxUDPQueueBytes == 0 {
		maxUDPQueueBytes = DefaultMaxUDPQueueBytes
	}
	if maxUDPQueueBytes < 0 {
		return nil, errors.New("nowhere: negative UDP queue byte limit")
	}
	maxPendingCloses := options.MaxPendingCloses
	if maxPendingCloses == 0 {
		maxPendingCloses = DefaultMaxPendingCloses
	}
	if maxPendingCloses < 0 {
		return nil, errors.New("nowhere: negative pending CLOSE limit")
	}
	bundle := &CarrierBundle{cfg: bundleConfig{
		quic: options.QUIC, tcp: options.TCP, credentials: options.Credentials,
		alpn: alpn, observer: options.Observer, poolSize: options.PoolSize,
		maxUDPQueueBytes: maxUDPQueueBytes, maxPendingCloses: maxPendingCloses,
		prewarmOnStart: options.PrewarmOnStart,
		up:             options.Up, down: options.Down,
	}}
	bundle.nextFlowID.Store(1)
	if _, err := bundle.SessionID(); err != nil {
		return nil, err
	}
	if options.PrewarmOnStart && options.PoolSize > 0 {
		if _, err := bundle.tcpPool(); err != nil {
			return nil, err
		}
	}
	return bundle, nil
}

func isCarrier(value wire.Carrier) bool {
	return value == wire.CarrierTLSTCP || value == wire.CarrierQUIC
}

// SessionID returns the lazily generated identity shared by all bundle carriers.
//
// The session id is generated with crypto/rand and never leaves the bundle for
// QUIC (the TCP carrier needs it to build the auth frame, since the TCP carrier
// performs auth on the physical connection). A random-source failure makes the
// bundle unusable.
func (b *CarrierBundle) SessionID() (wire.SessionID, error) {
	b.sessionIDOnce.Do(func() {
		if _, err := rand.Read(b.sessionID[:]); err != nil {
			b.sessionIDErr = err
			return
		}
		// TCP carrier needs the session id to bind the auth frame to the
		// bundle identity. The QUIC backend is NOT told the session id; the
		// bundle reads the exporter and writes the auth frame itself.
		if b.cfg.tcp != nil {
			b.cfg.tcp, b.sessionIDErr = b.cfg.tcp.BindSession(b.cfg.credentials, b.sessionID, b.cfg.alpn)
		}
	})
	return b.sessionID, b.sessionIDErr
}

// UpCarrier returns the configured uplink carrier.
func (b *CarrierBundle) UpCarrier() wire.Carrier { return b.cfg.up }

// DownCarrier returns the configured downlink carrier.
func (b *CarrierBundle) DownCarrier() wire.Carrier { return b.cfg.down }

// Asymmetric reports whether uplink and downlink use different carriers.
func (b *CarrierBundle) Asymmetric() bool { return b.cfg.up != b.cfg.down }

// PoolTarget returns the configured TLS/TCP idle-pool target.
func (b *CarrierBundle) PoolTarget() int { return b.cfg.poolSize }

// ErrFlowIDExhausted is returned after a bundle has allocated every nonzero flow ID.
var ErrFlowIDExhausted = errors.New("nowhere: flow id space exhausted")

// allocFlowID returns the next nonzero uint32 flow id, skipping zero on wrap
// and failing once every nonzero value has been handed out (full u32 cycle).
// The monotonic counter is sufficient because flow ids are never reused within
// an active bundle's lifetime; pending/active tracking lives at the
// session/carrier layer where flows are paired and released.
func (b *CarrierBundle) allocFlowID() (wire.FlowID, error) {
	for {
		next := b.nextFlowID.Load()
		if next == 0 {
			// Should never happen: initialized to 1; treated as exhaustion.
			return 0, ErrFlowIDExhausted
		}
		cand := next + 1
		if cand == 0 {
			// Wrapped past maxuint32: the next valid id is 1. If 1 is already
			// back in circulation this would collide, but a bundle that issues
			// 2^32-1 flows is treated as exhausted instead.
			return 0, ErrFlowIDExhausted
		}
		if b.nextFlowID.CompareAndSwap(next, cand) {
			return next, nil
		}
	}
}

func (b *CarrierBundle) quicClient() (carrier.QuicBackend, error) {
	if b.cfg.up != wire.CarrierQUIC && b.cfg.down != wire.CarrierQUIC {
		return nil, nil
	}
	b.quicOnce.Do(func() {
		b.lifecycleMu.Lock()
		defer b.lifecycleMu.Unlock()
		if b.closed {
			b.quicErr = net.ErrClosed
			return
		}
		sessionID, err := b.SessionID()
		if err != nil {
			b.quicErr = err
			return
		}
		auth := func(_ context.Context, session carrier.QuicSession) (wire.AuthFrame, error) {
			return buildQUICAuthFrame(session, b.cfg.credentials, b.cfg.alpn, sessionID)
		}
		b.quic = newQUICMuxBackend(b.cfg.quic, auth, b.cfg.maxUDPQueueBytes, b.cfg.maxPendingCloses, b.cfg.observer)
	})
	return b.quic, b.quicErr
}

// buildQUICAuthFrame binds one physical QUIC session to the bundle identity.
// The returned frame is retained by the mux and prepended atomically when the
// first flow commits its setup bytes on the first stream.
func buildQUICAuthFrame(session carrier.QuicSession, creds *wire.Credentials, alpn string, sessionID wire.SessionID) (wire.AuthFrame, error) {
	if session == nil {
		return wire.AuthFrame{}, errors.New("nowhere: nil quic session")
	}
	handshake, err := session.TLSHandshakeInfo()
	if err != nil {
		return wire.AuthFrame{}, err
	}
	if err := handshake.Validate(alpn); err != nil {
		return wire.AuthFrame{}, err
	}
	return wire.EncodeAuthFrame(creds, wire.AuthTransportQUIC, handshake.Exporter, sessionID)
}

func (b *CarrierBundle) tcpPool() (*tcptls.TCPPool, error) {
	if b.cfg.up != wire.CarrierTLSTCP && b.cfg.down != wire.CarrierTLSTCP {
		return nil, nil
	}
	b.tcpOnce.Do(func() {
		b.lifecycleMu.Lock()
		defer b.lifecycleMu.Unlock()
		if b.closed {
			b.tcpErr = net.ErrClosed
			return
		}
		if _, err := b.SessionID(); err != nil {
			b.tcpErr = err
			return
		}
		b.tcp, b.tcpErr = tcptls.NewTCPPool(b.cfg.tcp, b.cfg.poolSize)
		if b.tcpErr == nil && b.cfg.prewarmOnStart && b.cfg.poolSize > 0 {
			b.tcp.Prewarm()
		}
	})
	return b.tcp, b.tcpErr
}

// Close releases initialized carrier resources. It is safe on a nil bundle.
func (b *CarrierBundle) Close() error {
	if b == nil {
		return nil
	}
	b.closeOnce.Do(func() {
		b.lifecycleMu.Lock()
		b.closed = true
		quicClient := b.quic
		tcpPool := b.tcp
		b.lifecycleMu.Unlock()
		var errs []error
		if quicClient != nil {
			errs = append(errs, quicClient.Close())
		}
		if tcpPool != nil {
			errs = append(errs, tcpPool.Close())
		}
		b.closeErr = errors.Join(errs...)
	})
	return b.closeErr
}
