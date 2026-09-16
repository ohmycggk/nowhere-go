package mux

import (
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/ohmycggk/nowhere-go/wire"
)

// Stream is one reconstructed Mux logical stream. It implements net.Conn.
type Stream struct {
	shared  *shared
	flowID  uint32
	local   net.Addr
	remote  net.Addr
	inbound <-chan inbound

	readMu        sync.Mutex
	current       []byte
	currentCharge int
	currentOff    int
	eof           bool
	readDead      time.Time
	readerClosed  bool

	writeMu      sync.Mutex
	writeClosed  bool
	writeDead    time.Time
	terminalSent bool
}

func newStream(s *shared, flowID uint32, inbound <-chan inbound) *Stream {
	return &Stream{
		shared:  s,
		flowID:  flowID,
		local:   s.local,
		remote:  s.remote,
		inbound: inbound,
	}
}

func (st *Stream) FlowID() uint32 { return st.flowID }

func (st *Stream) Read(p []byte) (int, error) {
	st.readMu.Lock()
	defer st.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if len(st.current) > st.currentOff {
			n := copy(p, st.current[st.currentOff:])
			st.currentOff += n
			if st.currentOff == len(st.current) {
				st.shared.releaseReceive(st.flowID, st.currentCharge)
				st.current = nil
				st.currentCharge = 0
				st.currentOff = 0
			}
			return n, nil
		}
		if st.eof {
			return 0, io.EOF
		}
		if st.readerClosed {
			return 0, errClosed
		}
		msg, err := st.waitInbound()
		if err != nil {
			return 0, err
		}
		switch msg.kind {
		case inboundData:
			st.current = msg.payload
			st.currentCharge = msg.charge
			st.currentOff = 0
		case inboundFin:
			st.eof = true
			return 0, io.EOF
		case inboundReset:
			st.eof = true
			return 0, errReset
		}
	}
}

func (st *Stream) waitInbound() (inbound, error) {
	timer, timeout := deadlineChan(st.readDead)
	if timer != nil {
		defer timer.Stop()
	}
	select {
	case <-st.shared.closedCh:
		return inbound{}, errClosed
	case <-timeout:
		return inbound{}, os.ErrDeadlineExceeded
	case msg, ok := <-st.inbound:
		if !ok {
			st.eof = true
			return inbound{kind: inboundFin}, nil
		}
		return msg, nil
	}
}

func (st *Stream) Write(p []byte) (int, error) {
	st.writeMu.Lock()
	defer st.writeMu.Unlock()
	if st.writeClosed {
		return 0, errClosed
	}
	if len(p) == 0 {
		return 0, nil
	}
	written := 0
	for written < len(p) {
		if err := st.checkWriteDeadline(); err != nil {
			return written, err
		}
		chunk := p[written:]
		if len(chunk) > FrameBytes {
			chunk = chunk[:FrameBytes]
		}
		if err := st.shared.sendData(st.flowID, chunk); err != nil {
			if written == 0 {
				return 0, err
			}
			return written, err
		}
		written += len(chunk)
	}
	return written, nil
}

func (st *Stream) checkWriteDeadline() error {
	if st.writeDead.IsZero() {
		return nil
	}
	if !time.Now().Before(st.writeDead) {
		return os.ErrDeadlineExceeded
	}
	return nil
}

func (st *Stream) Close() error {
	err := st.CloseWrite()
	st.closeReader()
	return err
}

func (st *Stream) CloseWrite() error {
	st.writeMu.Lock()
	defer st.writeMu.Unlock()
	if st.writeClosed {
		return nil
	}
	st.writeClosed = true
	st.terminalSent = true
	header, err := wire.FinMuxHeader(st.flowID)
	if err != nil {
		st.shared.releasePart(st.flowID)
		return err
	}
	sendErr := st.shared.sendOutbound(outbound{header: header})
	st.shared.releasePart(st.flowID)
	return sendErr
}

func (st *Stream) CloseRead() error {
	st.closeReader()
	return nil
}

func (st *Stream) closeReader() {
	st.readMu.Lock()
	defer st.readMu.Unlock()
	if st.readerClosed {
		return
	}
	st.readerClosed = true
	if st.current != nil {
		st.shared.releaseReceive(st.flowID, st.currentCharge)
		st.current = nil
		st.currentCharge = 0
	}
	for {
		select {
		case msg, ok := <-st.inbound:
			if !ok {
				st.shared.releasePart(st.flowID)
				return
			}
			if msg.kind == inboundData {
				st.shared.releaseReceive(st.flowID, msg.charge)
			}
		default:
			st.shared.releasePart(st.flowID)
			return
		}
	}
}

func (st *Stream) LocalAddr() net.Addr  { return st.local }
func (st *Stream) RemoteAddr() net.Addr { return st.remote }

func (st *Stream) SetDeadline(t time.Time) error {
	if err := st.SetReadDeadline(t); err != nil {
		return err
	}
	return st.SetWriteDeadline(t)
}

func (st *Stream) SetReadDeadline(t time.Time) error {
	st.readMu.Lock()
	st.readDead = t
	st.readMu.Unlock()
	return nil
}

func (st *Stream) SetWriteDeadline(t time.Time) error {
	st.writeMu.Lock()
	st.writeDead = t
	st.writeMu.Unlock()
	return nil
}

func deadlineChan(t time.Time) (*time.Timer, <-chan time.Time) {
	if t.IsZero() {
		return nil, nil
	}
	d := time.Until(t)
	if d <= 0 {
		ch := make(chan time.Time, 1)
		ch <- time.Time{}
		return nil, ch
	}
	timer := time.NewTimer(d)
	return timer, timer.C
}
