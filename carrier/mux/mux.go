// Package mux implements the Nowhere 1.8 TLS Mux stream engine.
//
// AuthFrame and the 0xff marker are consumed before Start. The reconstructed
// logical stream then carries FlowHeader, Target, SetupResult, and payload.
package mux

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ohmycggk/nowhere-go/wire"
)

const (
	// FrameBytes is the sender cap per STREAM payload.
	FrameBytes = 32 * 1024
	// WindowUpdateBytes coalesces WINDOW frames; it is not on the wire.
	WindowUpdateBytes = 4 * 1024
	flowChannelFrames = 512
	minFairCredit     = 256 * 1024

	// IdleTimeout closes an authenticated Mux carrier with no active streams.
	IdleTimeout = 30 * time.Second
)

var (
	errClosed         = errors.New("nowhere: mux carrier is closed")
	errUnknownFlow    = errors.New("nowhere: frame for unknown mux flow")
	errWindowExceeded = errors.New("nowhere: peer exceeded mux window")
	errWindowOverflow = errors.New("nowhere: mux window overflow")
	errDatagram       = errors.New("nowhere: mux datagram is not registered")
	errStreamLimit    = errors.New("nowhere: mux stream limit reached")
	errFlowExists     = errors.New("nowhere: mux flow already exists")
	errInvalidLimits  = errors.New("nowhere: invalid mux limits")
	errReset          = errors.New("nowhere: mux flow reset")
)

// Config is the per-carrier Mux window and queue budget.
type Config struct {
	StreamWindowBytes     int
	ConnectionWindowBytes int
	MaxStreams            int
	OutboundFrames        int
}

// DefaultConfig returns the protocol defaults.
func DefaultConfig() Config {
	return Config{
		StreamWindowBytes:     512 * 1024,
		ConnectionWindowBytes: 512 * 1024,
		MaxStreams:            256,
		OutboundFrames:        512,
	}
}

func (c Config) validate() (Config, error) {
	if c.StreamWindowBytes < FrameBytes ||
		c.ConnectionWindowBytes < c.StreamWindowBytes ||
		c.MaxStreams <= 0 ||
		c.OutboundFrames <= 0 {
		return Config{}, errInvalidLimits
	}
	return c, nil
}

// Handle is one authenticated Mux TLS carrier.
type Handle struct {
	shared *shared
}

// Incoming accepts peer-opened streams. Client shards should Discard it.
type Incoming struct {
	ch     <-chan *Stream
	cancel context.CancelFunc
}

type inboundKind uint8

const (
	inboundData inboundKind = iota
	inboundFin
	inboundReset
)

type inbound struct {
	kind    inboundKind
	payload []byte
	charge  int
}

type outbound struct {
	header  wire.MuxHeader
	payload []byte
	flushed chan error
}

type flowState struct {
	inbound        chan inbound
	sendCredit     *semaphore
	fairSend       *semaphore
	fairLimit      int
	fairDebt       int
	receiveCredit  int
	pendingReceive int
	windowQueued   bool
	localParts     uint8
}

type sendCredits struct {
	stream *semaphore
	fair   *semaphore
}

type shared struct {
	config Config
	conn   net.Conn

	flowsMu sync.Mutex
	flows   map[uint32]*flowState

	connSend    *semaphore
	connRecvMu  sync.Mutex
	connRecv    int
	pendingConn atomic.Int64
	readyMu     sync.Mutex
	ready       []uint32

	dataTx   chan outbound
	control  chan struct{}
	incoming chan *Stream

	activeNotify chan struct{}

	closed   atomic.Bool
	closedCh chan struct{}
	closeMu  sync.Mutex

	local  net.Addr
	remote net.Addr
}

// Start runs reader and writer tasks on conn.
func Start(conn net.Conn, config Config) (*Handle, *Incoming, error) {
	if conn == nil {
		return nil, nil, errors.New("nowhere: nil mux connection")
	}
	config, err := config.validate()
	if err != nil {
		return nil, nil, err
	}
	incomingCtx, incomingCancel := context.WithCancel(context.Background())
	shared := &shared{
		config:       config,
		conn:         conn,
		flows:        make(map[uint32]*flowState),
		connSend:     newSemaphore(config.ConnectionWindowBytes),
		connRecv:     config.ConnectionWindowBytes,
		dataTx:       make(chan outbound, config.OutboundFrames),
		control:      make(chan struct{}, 1),
		incoming:     make(chan *Stream, config.MaxStreams),
		activeNotify: make(chan struct{}, 1),
		closedCh:     make(chan struct{}),
		local:        conn.LocalAddr(),
		remote:       conn.RemoteAddr(),
	}
	handle := &Handle{shared: shared}
	incoming := &Incoming{ch: shared.incoming, cancel: incomingCancel}
	go shared.runReader(conn)
	go shared.runWriter(conn)
	go func() {
		<-incomingCtx.Done()
		shared.rejectIncoming()
	}()
	return handle, incoming, nil
}

func (s *shared) rejectIncoming() {
	s.flowsMu.Lock()
	s.incoming = nil
	s.flowsMu.Unlock()
}

// OpenStream creates a local stream and emits STREAM SYN.
func (h *Handle) OpenStream(flowID uint32) (*Stream, error) {
	if h == nil || h.shared == nil {
		return nil, errClosed
	}
	stream, err := h.shared.insertFlow(flowID)
	if err != nil {
		return nil, err
	}
	header, err := wire.StreamMuxHeader(flowID, wire.MuxFlagSYN, 0)
	if err != nil {
		h.shared.removeFlow(flowID)
		return nil, err
	}
	if err := h.shared.sendOutbound(outbound{header: header}); err != nil {
		h.shared.removeFlow(flowID)
		return nil, err
	}
	return stream, nil
}

func (h *Handle) IsClosed() bool {
	return h == nil || h.shared == nil || h.shared.closed.Load()
}

func (h *Handle) ActiveStreams() int {
	if h == nil || h.shared == nil {
		return 0
	}
	h.shared.flowsMu.Lock()
	n := len(h.shared.flows)
	h.shared.flowsMu.Unlock()
	return n
}

func (h *Handle) Close() {
	if h == nil || h.shared == nil {
		return
	}
	h.shared.close()
}

func (h *Handle) SameCarrier(other *Handle) bool {
	return h != nil && other != nil && h.shared != nil && h.shared == other.shared
}

// IdleFor reports whether the carrier stays at zero streams for duration.
func (h *Handle) IdleFor(ctx context.Context, duration time.Duration) bool {
	if h == nil || h.shared == nil {
		return false
	}
	for {
		if h.IsClosed() {
			return false
		}
		if h.ActiveStreams() != 0 {
			select {
			case <-ctx.Done():
				return false
			case <-h.shared.closedCh:
				return false
			case <-h.shared.activeNotify:
			}
			continue
		}
		timer := time.NewTimer(duration)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false
		case <-h.shared.closedCh:
			timer.Stop()
			return false
		case <-h.shared.activeNotify:
			timer.Stop()
		case <-timer.C:
			if h.ActiveStreams() == 0 && !h.IsClosed() {
				return true
			}
		}
	}
}

func (h *Handle) Closed() <-chan struct{} {
	if h == nil || h.shared == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return h.shared.closedCh
}

func (in *Incoming) Accept(ctx context.Context) (*Stream, error) {
	if in == nil {
		return nil, errClosed
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-in.waitClosed():
		return nil, errClosed
	case stream, ok := <-in.ch:
		if !ok {
			return nil, errClosed
		}
		return stream, nil
	}
}

func (in *Incoming) waitClosed() <-chan struct{} {
	return nil
}

func (in *Incoming) Discard() {
	if in != nil && in.cancel != nil {
		in.cancel()
	}
}

func (s *shared) close() {
	if !s.closed.CompareAndSwap(false, true) {
		return
	}
	close(s.closedCh)
	s.connSend.close()
	s.flowsMu.Lock()
	for _, flow := range s.flows {
		flow.sendCredit.close()
		flow.fairSend.close()
	}
	s.flows = make(map[uint32]*flowState)
	s.flowsMu.Unlock()
	s.notifyActive()
	s.closeMu.Lock()
	if s.conn != nil {
		_ = s.conn.Close()
	}
	s.closeMu.Unlock()
}

func (s *shared) insertFlow(flowID uint32) (*Stream, error) {
	if flowID == 0 || s.closed.Load() {
		return nil, errClosed
	}
	s.flowsMu.Lock()
	if len(s.flows) >= s.config.MaxStreams {
		s.flowsMu.Unlock()
		return nil, errStreamLimit
	}
	if _, exists := s.flows[flowID]; exists {
		s.flowsMu.Unlock()
		return nil, errFlowExists
	}
	state := &flowState{
		inbound:       make(chan inbound, flowChannelFrames),
		sendCredit:    newSemaphore(s.config.StreamWindowBytes),
		fairSend:      newSemaphore(s.config.StreamWindowBytes),
		fairLimit:     s.config.StreamWindowBytes,
		receiveCredit: s.config.StreamWindowBytes,
		localParts:    2,
	}
	s.flows[flowID] = state
	s.rebalanceFairLocked()
	n := len(s.flows)
	s.flowsMu.Unlock()
	s.notifyActiveCount(n)
	return newStream(s, flowID, state.inbound), nil
}

func (s *shared) notifyActiveCount(n int) {
	_ = n
	s.notifyActive()
}

func (s *shared) notifyActive() {
	select {
	case s.activeNotify <- struct{}{}:
	default:
	}
}

func (s *shared) notifyControl() {
	select {
	case s.control <- struct{}{}:
	default:
	}
}

func (s *shared) sendCredits(flowID uint32) (sendCredits, error) {
	s.flowsMu.Lock()
	flow, ok := s.flows[flowID]
	s.flowsMu.Unlock()
	if !ok {
		return sendCredits{}, errClosed
	}
	return sendCredits{stream: flow.sendCredit, fair: flow.fairSend}, nil
}

func (s *shared) rebalanceFairLocked() {
	n := len(s.flows)
	if n == 0 {
		return
	}
	fairLimit := s.config.ConnectionWindowBytes / n
	if fairLimit < minFairCredit {
		fairLimit = minFairCredit
	}
	if fairLimit > s.config.StreamWindowBytes {
		fairLimit = s.config.StreamWindowBytes
	}
	for _, flow := range s.flows {
		if fairLimit < flow.fairLimit {
			reduction := flow.fairLimit - fairLimit
			removed := flow.fairSend.forget(reduction)
			flow.fairDebt += reduction - removed
		} else if fairLimit > flow.fairLimit {
			increase := fairLimit - flow.fairLimit
			debtRepaid := increase
			if debtRepaid > flow.fairDebt {
				debtRepaid = flow.fairDebt
			}
			flow.fairDebt -= debtRepaid
			flow.fairSend.add(increase - debtRepaid)
		}
		flow.fairLimit = fairLimit
	}
}

func (s *shared) returnFairCredit(flow *flowState, credit int) {
	debtRepaid := credit
	if debtRepaid > flow.fairDebt {
		debtRepaid = flow.fairDebt
	}
	flow.fairDebt -= debtRepaid
	returned := credit - debtRepaid
	room := flow.fairLimit - flow.fairSend.availablePermits()
	if room < 0 {
		room = 0
	}
	if returned > room {
		returned = room
	}
	flow.fairSend.add(returned)
}

func (s *shared) removeFlow(flowID uint32) *flowState {
	s.flowsMu.Lock()
	flow := s.flows[flowID]
	if flow != nil {
		delete(s.flows, flowID)
		s.rebalanceFairLocked()
	}
	s.flowsMu.Unlock()
	s.notifyActive()
	return flow
}

func (s *shared) admitReceive(flowID uint32, charge int) (chan inbound, error) {
	s.connRecvMu.Lock()
	s.flowsMu.Lock()
	flow := s.flows[flowID]
	if flow == nil {
		s.flowsMu.Unlock()
		s.connRecvMu.Unlock()
		return nil, errUnknownFlow
	}
	if flow.receiveCredit < charge || s.connRecv < charge {
		s.flowsMu.Unlock()
		s.connRecvMu.Unlock()
		return nil, errWindowExceeded
	}
	flow.receiveCredit -= charge
	s.connRecv -= charge
	ch := flow.inbound
	s.flowsMu.Unlock()
	s.connRecvMu.Unlock()
	return ch, nil
}

func (s *shared) releaseReceive(flowID uint32, charge int) {
	if s.closed.Load() {
		return
	}
	s.connRecvMu.Lock()
	s.connRecv += charge
	if s.connRecv > s.config.ConnectionWindowBytes {
		s.connRecv = s.config.ConnectionWindowBytes
	}
	s.connRecvMu.Unlock()

	s.flowsMu.Lock()
	flow := s.flows[flowID]
	if flow == nil {
		s.flowsMu.Unlock()
		return
	}
	flow.receiveCredit += charge
	if flow.receiveCredit > s.config.StreamWindowBytes {
		flow.receiveCredit = s.config.StreamWindowBytes
	}
	flow.pendingReceive += charge
	ready := false
	if !flow.windowQueued {
		flow.windowQueued = true
		ready = true
	}
	notify := flow.pendingReceive >= WindowUpdateBytes
	s.flowsMu.Unlock()
	if ready {
		s.readyMu.Lock()
		s.ready = append(s.ready, flowID)
		s.readyMu.Unlock()
	}
	previous := s.pendingConn.Add(int64(charge))
	if notify || previous >= int64(WindowUpdateBytes) {
		s.notifyControl()
	}
}

func (s *shared) releasePart(flowID uint32) {
	s.flowsMu.Lock()
	flow := s.flows[flowID]
	if flow == nil {
		s.flowsMu.Unlock()
		return
	}
	flush := flow.pendingReceive != 0
	if flow.localParts > 0 {
		flow.localParts--
	}
	if flow.localParts == 0 {
		delete(s.flows, flowID)
		s.rebalanceFairLocked()
	}
	s.flowsMu.Unlock()
	s.notifyActive()
	if flush {
		s.notifyControl()
	}
}

func (s *shared) sendOutbound(item outbound) error {
	select {
	case <-s.closedCh:
		return errClosed
	case s.dataTx <- item:
		return nil
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var _ io.ReadWriteCloser = (*Stream)(nil)
var _ net.Conn = (*Stream)(nil)
