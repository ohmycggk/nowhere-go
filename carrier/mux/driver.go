package mux

import (
	"io"

	"github.com/ohmycggk/nowhere-go/wire"
)

func (s *shared) runReader(r io.Reader) {
	if err := s.readLoop(r); err != nil {
		s.close()
	}
}

func (s *shared) readLoop(r io.Reader) error {
	var headerBuf [wire.MuxHeaderLen]byte
	for {
		if _, err := io.ReadFull(r, headerBuf[:]); err != nil {
			return err
		}
		header, err := wire.DecodeMuxHeader(headerBuf[:])
		if err != nil {
			return err
		}
		payloadLen := wire.MuxPayloadLen(header)
		var payload []byte
		if payloadLen > 0 {
			payload = make([]byte, payloadLen)
			if _, err := io.ReadFull(r, payload); err != nil {
				return err
			}
		}
		switch header.Kind {
		case wire.MuxFrameStream:
			if err := s.receiveStream(header, payload); err != nil {
				return err
			}
		case wire.MuxFrameWindow:
			if err := s.receiveWindow(header); err != nil {
				return err
			}
		case wire.MuxFrameDatagram:
			return errDatagram
		}
	}
}

func (s *shared) receiveStream(header wire.MuxHeader, payload []byte) error {
	if header.Flags&wire.MuxFlagSYN != 0 {
		stream, err := s.insertFlow(header.FlowID)
		if err != nil {
			return err
		}
		if err := s.offerIncoming(stream); err != nil {
			return err
		}
	}
	if header.Flags&wire.MuxFlagRST != 0 {
		if flow := s.removeFlow(header.FlowID); flow != nil {
			select {
			case flow.inbound <- inbound{kind: inboundReset}:
			default:
			}
		}
		return nil
	}
	if len(payload) > 0 {
		ch, err := s.admitReceive(header.FlowID, len(payload))
		if err != nil {
			return err
		}
		select {
		case <-s.closedCh:
			return errClosed
		case ch <- inbound{kind: inboundData, payload: payload, charge: len(payload)}:
		}
	}
	if header.Flags&wire.MuxFlagFIN != 0 {
		s.flowsMu.Lock()
		flow := s.flows[header.FlowID]
		var ch chan inbound
		if flow != nil {
			ch = flow.inbound
		}
		s.flowsMu.Unlock()
		if ch != nil {
			select {
			case ch <- inbound{kind: inboundFin}:
			case <-s.closedCh:
			}
		}
	}
	return nil
}

func (s *shared) receiveWindow(header wire.MuxHeader) error {
	credit := int(header.Value)
	if header.FlowID == 0 {
		if s.connSend.availablePermits()+credit > s.config.ConnectionWindowBytes {
			return errWindowOverflow
		}
		s.connSend.add(credit)
		return nil
	}
	s.flowsMu.Lock()
	flow := s.flows[header.FlowID]
	if flow == nil {
		s.flowsMu.Unlock()
		return nil
	}
	if flow.sendCredit.availablePermits()+credit > s.config.StreamWindowBytes {
		s.flowsMu.Unlock()
		return errWindowOverflow
	}
	flow.sendCredit.add(credit)
	s.returnFairCredit(flow, credit)
	s.flowsMu.Unlock()
	return nil
}

func (s *shared) runWriter(w io.Writer) {
	if err := s.writeLoop(w); err != nil {
		s.close()
	}
}

func (s *shared) writeLoop(w io.Writer) error {
	for {
		if s.closed.Load() {
			return errClosed
		}
		select {
		case <-s.closedCh:
			return errClosed
		case <-s.control:
			if err := s.writePendingWindows(w); err != nil {
				return err
			}
		default:
		}
		select {
		case <-s.closedCh:
			return errClosed
		case <-s.control:
			if err := s.writePendingWindows(w); err != nil {
				return err
			}
		case item, ok := <-s.dataTx:
			if !ok {
				return errClosed
			}
			if err := s.writeItem(w, item); err != nil {
				return err
			}
		}
	}
}

func (s *shared) writeItem(w io.Writer, item outbound) error {
	if item.flushed != nil && len(item.payload) == 0 && item.header.Flags == 0 {
		err := flushWriter(w)
		select {
		case item.flushed <- err:
		default:
		}
		return err
	}
	encoded, err := wire.EncodeMuxHeader(item.header)
	if err != nil {
		return err
	}
	if err := writeFull(w, encoded[:]); err != nil {
		return err
	}
	if len(item.payload) > 0 {
		if err := writeFull(w, item.payload); err != nil {
			return err
		}
	}
	return nil
}

func (s *shared) writePendingWindows(w io.Writer) error {
	connection := int(s.pendingConn.Swap(0))
	s.readyMu.Lock()
	ready := append([]uint32(nil), s.ready...)
	s.ready = s.ready[:0]
	s.readyMu.Unlock()

	var frames []byte
	var err error
	frames, err = appendWindows(frames, 0, connection)
	if err != nil {
		return err
	}
	s.flowsMu.Lock()
	for _, flowID := range ready {
		flow := s.flows[flowID]
		if flow == nil {
			continue
		}
		credit := flow.pendingReceive
		flow.pendingReceive = 0
		flow.windowQueued = false
		if credit == 0 {
			continue
		}
		frames, err = appendWindows(frames, flowID, credit)
		if err != nil {
			s.flowsMu.Unlock()
			return err
		}
	}
	s.flowsMu.Unlock()
	if len(frames) == 0 {
		return nil
	}
	return writeFull(w, frames)
}

func appendWindows(encoded []byte, flowID uint32, credit int) ([]byte, error) {
	for credit > 0 {
		delta := credit
		if delta > 0xffff {
			delta = 0xffff
		}
		header, err := wire.WindowMuxHeader(flowID, delta)
		if err != nil {
			return encoded, err
		}
		frame, err := wire.EncodeMuxHeader(header)
		if err != nil {
			return encoded, err
		}
		encoded = append(encoded, frame[:]...)
		credit -= delta
	}
	return encoded, nil
}

func (s *shared) sendData(flowID uint32, payload []byte) error {
	charge := len(payload)
	credits, err := s.sendCredits(flowID)
	if err != nil {
		return err
	}
	if err := credits.fair.acquire(charge, s.closedCh); err != nil {
		return err
	}
	if err := credits.stream.acquire(charge, s.closedCh); err != nil {
		credits.fair.add(charge)
		return err
	}
	if err := s.connSend.acquire(charge, s.closedCh); err != nil {
		credits.fair.add(charge)
		credits.stream.add(charge)
		return err
	}
	header, err := wire.StreamMuxHeader(flowID, 0, len(payload))
	if err != nil {
		credits.fair.add(charge)
		credits.stream.add(charge)
		s.connSend.add(charge)
		return err
	}
	copied := append([]byte(nil), payload...)
	if err := s.sendOutbound(outbound{header: header, payload: copied}); err != nil {
		credits.fair.add(charge)
		credits.stream.add(charge)
		s.connSend.add(charge)
		return err
	}
	return nil
}

func (s *shared) offerIncoming(stream *Stream) error {
	s.flowsMu.Lock()
	ch := s.incoming
	s.flowsMu.Unlock()
	if ch == nil {
		return errClosed
	}
	select {
	case <-s.closedCh:
		return errClosed
	case ch <- stream:
		return nil
	}
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func flushWriter(w io.Writer) error {
	type flusher interface{ Flush() error }
	if f, ok := w.(flusher); ok {
		return f.Flush()
	}
	return nil
}
