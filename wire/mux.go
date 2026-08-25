package wire

import (
	"encoding/binary"
	"errors"
	"io"
)

// MuxMarker is written once on the client-to-Portal TLS half immediately after
// AuthFrame. Portal does not echo it. 0xff cannot be a valid FlowHeader flags
// byte because its role bits are 0b11.
const MuxMarker byte = 0xff

// MuxHeaderLen is the fixed Mux frame header length.
const MuxHeaderLen = 8

// STREAM flag bits. WINDOW and DATAGRAM require flags=0.
const (
	MuxFlagSYN byte = 0x01
	MuxFlagFIN byte = 0x02
	MuxFlagRST byte = 0x04
)

const muxStreamFlagMask = MuxFlagSYN | MuxFlagFIN | MuxFlagRST

// MuxFrameKind is the MuxHeader kind byte.
type MuxFrameKind uint8

const (
	// MuxFrameStream carries optional payload for one logical stream.
	MuxFrameStream MuxFrameKind = 0x01
	// MuxFrameWindow returns byte credit. flow_id 0 is connection-wide.
	MuxFrameWindow MuxFrameKind = 0x02
	// MuxFrameDatagram is recognized by the codec but is not a runtime plane.
	MuxFrameDatagram MuxFrameKind = 0x03
)

// MuxHeader is the 8-byte Mux frame header.
type MuxHeader struct {
	Kind   MuxFrameKind
	Flags  byte
	Value  uint16
	FlowID FlowID
}

// Validate enforces kind, flag, flow-id, and value invariants.
func (h MuxHeader) Validate() error {
	switch h.Kind {
	case MuxFrameStream:
		if h.FlowID == 0 {
			return ErrInvalidMuxHeader
		}
		if h.Flags&^muxStreamFlagMask != 0 {
			return ErrInvalidMuxHeader
		}
		if h.Flags&MuxFlagRST != 0 && (h.Flags != MuxFlagRST || h.Value != 0) {
			return ErrInvalidMuxHeader
		}
	case MuxFrameWindow:
		if h.Flags != 0 || h.Value == 0 {
			return ErrInvalidMuxHeader
		}
	case MuxFrameDatagram:
		if h.FlowID == 0 || h.Flags != 0 {
			return ErrInvalidMuxHeader
		}
	default:
		return ErrInvalidMuxHeader
	}
	return nil
}

// StreamMuxHeader builds a STREAM header.
func StreamMuxHeader(flowID FlowID, flags byte, payloadLen int) (MuxHeader, error) {
	if payloadLen < 0 || payloadLen > 0xffff {
		return MuxHeader{}, errors.New("nowhere: mux frame value exceeds u16")
	}
	header := MuxHeader{Kind: MuxFrameStream, Flags: flags, Value: uint16(payloadLen), FlowID: flowID}
	if err := header.Validate(); err != nil {
		return MuxHeader{}, err
	}
	return header, nil
}

// WindowMuxHeader builds a WINDOW header. flowID 0 replenishes connection credit.
func WindowMuxHeader(flowID FlowID, credit int) (MuxHeader, error) {
	if credit <= 0 || credit > 0xffff {
		return MuxHeader{}, errors.New("nowhere: mux window credit out of range")
	}
	header := MuxHeader{Kind: MuxFrameWindow, Value: uint16(credit), FlowID: flowID}
	if err := header.Validate(); err != nil {
		return MuxHeader{}, err
	}
	return header, nil
}

// DatagramMuxHeader builds a DATAGRAM header. The runtime rejects this kind.
func DatagramMuxHeader(flowID FlowID, payloadLen int) (MuxHeader, error) {
	if payloadLen < 0 || payloadLen > 0xffff {
		return MuxHeader{}, errors.New("nowhere: mux frame value exceeds u16")
	}
	header := MuxHeader{Kind: MuxFrameDatagram, Value: uint16(payloadLen), FlowID: flowID}
	if err := header.Validate(); err != nil {
		return MuxHeader{}, err
	}
	return header, nil
}

// EncodeMuxHeader writes one validated 8-byte header.
func EncodeMuxHeader(h MuxHeader) ([MuxHeaderLen]byte, error) {
	if err := h.Validate(); err != nil {
		return [MuxHeaderLen]byte{}, err
	}
	var out [MuxHeaderLen]byte
	out[0] = byte(h.Kind)
	out[1] = h.Flags
	binary.BigEndian.PutUint16(out[2:4], h.Value)
	encodeUint32BE(out[4:], h.FlowID)
	return out, nil
}

// DecodeMuxHeader decodes exactly one 8-byte header.
func DecodeMuxHeader(b []byte) (MuxHeader, error) {
	if len(b) != MuxHeaderLen {
		return MuxHeader{}, ErrInvalidMuxHeader
	}
	header := MuxHeader{
		Kind:   MuxFrameKind(b[0]),
		Flags:  b[1],
		Value:  binary.BigEndian.Uint16(b[2:4]),
		FlowID: decodeUint32BE(b[4:]),
	}
	if err := header.Validate(); err != nil {
		return MuxHeader{}, ErrInvalidMuxHeader
	}
	return header, nil
}

// ReadMuxHeader reads exactly one header, leaving any following payload.
func ReadMuxHeader(r io.Reader) (MuxHeader, error) {
	var buf [MuxHeaderLen]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return MuxHeader{}, err
	}
	return DecodeMuxHeader(buf[:])
}

// MuxPayloadLen is the number of bytes that follow a header on the wire.
func MuxPayloadLen(h MuxHeader) int {
	switch h.Kind {
	case MuxFrameStream, MuxFrameDatagram:
		return int(h.Value)
	default:
		return 0
	}
}
