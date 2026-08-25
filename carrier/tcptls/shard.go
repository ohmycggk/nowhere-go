package tcptls

import (
	"context"
	"errors"
	"net"
	"sync"

	carriermux "github.com/ohmycggk/nowhere-go/carrier/mux"
	"github.com/ohmycggk/nowhere-go/wire"
)

// FlowsPerShard is the 1.8.1 client shard density. A new Mux TLS carrier opens
// when every live shard in the direction already has this many active streams.
// Sharding is runtime placement and does not add wire fields.
const FlowsPerShard = 4

// MuxDirection selects the client uplink or downlink shard set.
type MuxDirection uint8

const (
	// MuxUp is the uplink shard set. Symmetric tcp/tcp flows use this set.
	MuxUp MuxDirection = iota
	// MuxDown is the downlink shard set, used for ATTACH on TLS.
	MuxDown
)

// MuxManager owns lazily opened Mux TLS shards for one bundle session.
type MuxManager struct {
	cfg *Config

	mu     sync.Mutex
	closed bool
	up     *shardSet
	down   *shardSet
}

type shardSet struct {
	mgr       *MuxManager
	connectMu sync.Mutex
	mu        sync.Mutex
	shards    []*muxShard
}

type muxShard struct {
	handle *carriermux.Handle
}

// NewMuxManager binds a TLS config to Mux shard sets.
func NewMuxManager(cfg *Config) (*MuxManager, error) {
	if cfg == nil {
		return nil, errors.New("nowhere: nil TCP carrier config")
	}
	m := &MuxManager{cfg: cfg}
	m.up = &shardSet{mgr: m}
	m.down = &shardSet{mgr: m}
	return m, nil
}

func (m *MuxManager) set(dir MuxDirection) *shardSet {
	if dir == MuxDown {
		return m.down
	}
	return m.up
}

// Open assigns flowID to the least-loaded live shard, dialing a new one if needed.
func (m *MuxManager) Open(ctx context.Context, flowID uint32, dir MuxDirection) (net.Conn, error) {
	if m == nil {
		return nil, errors.New("nowhere: mux manager unavailable")
	}
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	return m.set(dir).open(ctx, flowID)
}

func (m *MuxManager) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	m.mu.Unlock()
	m.up.closeAll()
	m.down.closeAll()
	return nil
}

func (s *shardSet) open(ctx context.Context, flowID uint32) (net.Conn, error) {
	s.connectMu.Lock()
	defer s.connectMu.Unlock()
	if shard := s.selectAvailable(); shard != nil {
		return shard.handle.OpenStream(flowID)
	}
	shard, err := s.dial(ctx)
	if err != nil {
		return nil, err
	}
	return shard.handle.OpenStream(flowID)
}

func (s *shardSet) selectAvailable() *muxShard {
	s.mu.Lock()
	defer s.mu.Unlock()
	var best *muxShard
	bestActive := FlowsPerShard
	live := s.shards[:0]
	for _, shard := range s.shards {
		if shard.handle.IsClosed() {
			continue
		}
		live = append(live, shard)
		n := shard.handle.ActiveStreams()
		if n < bestActive {
			bestActive = n
			best = shard
		}
	}
	s.shards = live
	if best == nil || bestActive >= FlowsPerShard {
		return nil
	}
	return best
}

func (s *shardSet) dial(ctx context.Context) (*muxShard, error) {
	conn, err := dialMuxCarrier(ctx, s.mgr.cfg)
	if err != nil {
		return nil, err
	}
	handle, incoming, err := carriermux.Start(conn, carriermux.DefaultConfig())
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	incoming.Discard()
	shard := &muxShard{handle: handle}
	s.mu.Lock()
	s.shards = append(s.shards, shard)
	s.mu.Unlock()
	go s.monitor(shard)
	return shard, nil
}

func (s *shardSet) monitor(shard *muxShard) {
	ctx := context.Background()
	for {
		if shard.handle.IsClosed() {
			s.remove(shard)
			return
		}
		if !shard.handle.IdleFor(ctx, carriermux.IdleTimeout) {
			if shard.handle.IsClosed() {
				s.remove(shard)
				return
			}
			continue
		}
		s.connectMu.Lock()
		if shard.handle.ActiveStreams() == 0 && !shard.handle.IsClosed() {
			s.removeLocked(shard)
			s.connectMu.Unlock()
			shard.handle.Close()
			return
		}
		s.connectMu.Unlock()
	}
}

func (s *shardSet) remove(shard *muxShard) {
	s.mu.Lock()
	s.removeLocked(shard)
	s.mu.Unlock()
}

func (s *shardSet) removeLocked(shard *muxShard) {
	out := s.shards[:0]
	for _, item := range s.shards {
		if item != shard {
			out = append(out, item)
		}
	}
	s.shards = out
}

func (s *shardSet) closeAll() {
	s.mu.Lock()
	shards := append([]*muxShard(nil), s.shards...)
	s.shards = nil
	s.mu.Unlock()
	for _, shard := range shards {
		shard.handle.Close()
	}
}

func dialMuxCarrier(ctx context.Context, cfg *Config) (net.Conn, error) {
	if cfg == nil || cfg.dialer == nil || cfg.tlsDialer == nil {
		return nil, errors.New("nowhere: incomplete TCP carrier config")
	}
	raw, err := cfg.dialer.DialContext(ctx, "tcp", dialAddr(cfg))
	if err != nil {
		return nil, err
	}
	handshaked, err := cfg.tlsDialer.DialTLSConn(ctx, raw)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	tlsConn := handshaked.Conn
	if tlsConn == nil {
		_ = raw.Close()
		return nil, errors.New("nowhere: TLS dialer returned nil connection")
	}
	if err := handshaked.TLSHandshakeInfo.Validate(cfg.alpn); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	auth, err := tcpAuthFrame(cfg, handshaked.Exporter)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	opening := make([]byte, 0, len(auth)+1)
	opening = append(opening, auth...)
	opening = append(opening, wire.MuxMarker)
	if _, err := writeFullTimed(tlsConn, opening); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	return tlsConn, nil
}
