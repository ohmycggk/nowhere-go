package wire

import (
	"errors"
	"fmt"
)

// UDPFrameDATA / FRAGMENT / CLOSE are the wire frame types carried in the low
// two bits of the flags byte. High six bits are reserved and must be zero.
const (
	UDPFrameDATA     byte = 0
	UDPFrameFRAGMENT byte = 1
	UDPFrameCLOSE    byte = 2
)

const (
	udpFrameTypeMask byte = 0b0000_0011
	udpReservedMask  byte = 0b1111_1100

	// UDPHeaderLen is the common unfragmented DATA / CLOSE header length.
	UDPHeaderLen = 5
	// UDPFragmentHeaderLen is the FRAGMENT header length.
	UDPFragmentHeaderLen = 13
	// UDPPacketMax is the largest UDP payload representable by the protocol.
	UDPPacketMax = 0xffff
)

// UDPFragment carries metadata for one fragment of a larger UDP packet.
type UDPFragment struct {
	PacketID      uint32
	FragmentIndex uint8
	FragmentCount uint8
	TotalLen      uint16
	Payload       []byte
}

// UDPFrameType is the decoded frame type.
type UDPFrameType uint8

const (
	// UDPFrameTypeData carries one complete UDP packet.
	UDPFrameTypeData UDPFrameType = 0
	// UDPFrameTypeFragment carries one fragment of a larger UDP packet.
	UDPFrameTypeFragment UDPFrameType = 1
	// UDPFrameTypeClose releases a UDP flow.
	UDPFrameTypeClose UDPFrameType = 2
)

// UDPFrame is one decoded QUIC DATAGRAM frame.
type UDPFrame struct {
	Type     UDPFrameType
	FlowID   FlowID
	Payload  []byte // DATA only
	Fragment UDPFragment
}

// EncodeUDPDataHeader encodes a 5-byte unfragmented DATA header.
func EncodeUDPDataHeader(flowID FlowID) ([UDPHeaderLen]byte, error) {
	return encodeUDPBaseHeader(UDPFrameDATA, flowID)
}

// EncodeUDPClose encodes a 5-byte CLOSE frame.
func EncodeUDPClose(flowID FlowID) ([UDPHeaderLen]byte, error) {
	return encodeUDPBaseHeader(UDPFrameCLOSE, flowID)
}

// EncodeUDPFragmentHeader encodes a validated 13-byte FRAGMENT header.
func EncodeUDPFragmentHeader(flowID FlowID, fragment UDPFragment) ([UDPFragmentHeaderLen]byte, error) {
	if err := validateFlowID(flowID); err != nil {
		return [UDPFragmentHeaderLen]byte{}, err
	}
	if err := validatePacketID(fragment.PacketID); err != nil {
		return [UDPFragmentHeaderLen]byte{}, err
	}
	if err := validateFragmentMetadata(fragment); err != nil {
		return [UDPFragmentHeaderLen]byte{}, err
	}
	var out [UDPFragmentHeaderLen]byte
	out[0] = UDPFrameFRAGMENT
	encodeUint32BE(out[1:5], flowID)
	encodeUint32BE(out[5:9], fragment.PacketID)
	out[9] = fragment.FragmentIndex
	out[10] = fragment.FragmentCount
	out[11] = byte(fragment.TotalLen >> 8)
	out[12] = byte(fragment.TotalLen)
	return out, nil
}

// EncodeUDPData encodes one complete unfragmented DATA frame (header+payload).
// A zero-length payload is a legal UDP packet and must use DATA, never FRAGMENT.
func EncodeUDPData(flowID FlowID, payload []byte) ([]byte, error) {
	if err := validateFlowID(flowID); err != nil {
		return nil, err
	}
	if err := validateUDPPayload(payload); err != nil {
		return nil, err
	}
	header, err := encodeUDPBaseHeader(UDPFrameDATA, flowID)
	if err != nil {
		return nil, err
	}
	out := make([]byte, UDPHeaderLen+len(payload))
	copy(out[:UDPHeaderLen], header[:])
	copy(out[UDPHeaderLen:], payload)
	return out, nil
}

// EncodeUDPDataFragments returns either one minimal DATA frame or the required
// FRAGMENT frames. A packet that fits in one DATAGRAM must never be fragmented.
func EncodeUDPDataFragments(flowID FlowID, packetID uint32, payload []byte, maxDatagramSize int) ([][]byte, error) {
	frames := make([][]byte, 0, 1)
	err := EncodeUDPDataFragmentsYield(flowID, packetID, payload, maxDatagramSize, func(frame []byte) error {
		frames = append(frames, frame)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return frames, nil
}

// EncodeUDPDataFragmentsYield lazily encodes a packet and yields one owned
// frame at a time. Packet ID is required only when the packet actually needs
// fragmentation.
func EncodeUDPDataFragmentsYield(flowID FlowID, packetID uint32, payload []byte, maxDatagramSize int, yield func([]byte) error) error {
	if err := validateFlowID(flowID); err != nil {
		return err
	}
	if err := validateUDPPayload(payload); err != nil {
		return err
	}
	if maxDatagramSize < UDPHeaderLen {
		return fmt.Errorf("nowhere: datagram size %d smaller than header %d", maxDatagramSize, UDPHeaderLen)
	}
	if len(payload) <= maxDatagramSize-UDPHeaderLen {
		frame, err := EncodeUDPData(flowID, payload)
		if err != nil {
			return err
		}
		return yield(frame)
	}
	if err := validatePacketID(packetID); err != nil {
		return err
	}
	return yieldUDPFragments(flowID, packetID, payload, maxDatagramSize, yield)
}

func yieldUDPFragments(flowID FlowID, packetID uint32, payload []byte, maxDatagramSize int, yield func([]byte) error) error {
	capacity := maxDatagramSize - UDPFragmentHeaderLen
	if capacity <= 0 {
		return errors.New("nowhere: no fragment payload capacity")
	}
	count := (len(payload) + capacity - 1) / capacity
	if count < 2 || count > 255 {
		return fmt.Errorf("nowhere: invalid fragment count %d", count)
	}
	totalLen := uint16(len(payload))
	for i := 0; i < count; i++ {
		start := i * capacity
		end := start + capacity
		if end > len(payload) {
			end = len(payload)
		}
		header, err := EncodeUDPFragmentHeader(flowID, UDPFragment{
			PacketID:      packetID,
			FragmentIndex: uint8(i),
			FragmentCount: uint8(count),
			TotalLen:      totalLen,
			Payload:       payload[start:end],
		})
		if err != nil {
			return err
		}
		frame := make([]byte, UDPFragmentHeaderLen+(end-start))
		copy(frame[:UDPFragmentHeaderLen], header[:])
		copy(frame[UDPFragmentHeaderLen:], payload[start:end])
		if err := yield(frame); err != nil {
			return err
		}
	}
	return nil
}

// DecodeUDPFrame decodes one complete QUIC DATAGRAM frame.
func DecodeUDPFrame(buf []byte) (UDPFrame, error) {
	if len(buf) < UDPHeaderLen {
		return UDPFrame{}, ErrInvalidFrame
	}
	flags := buf[0]
	if flags&udpReservedMask != 0 {
		return UDPFrame{}, ErrInvalidFrame
	}
	flowID := decodeUint32BE(buf[1:5])
	if err := validateFlowID(flowID); err != nil {
		return UDPFrame{}, ErrInvalidFrame
	}
	switch flags & udpFrameTypeMask {
	case UDPFrameDATA:
		payload := buf[UDPHeaderLen:]
		if err := validateUDPPayload(payload); err != nil {
			return UDPFrame{}, ErrInvalidFrame
		}
		return UDPFrame{Type: UDPFrameTypeData, FlowID: flowID, Payload: payload}, nil
	case UDPFrameFRAGMENT:
		return decodeUDPFragmentFrame(buf, flowID)
	case UDPFrameCLOSE:
		if len(buf) != UDPHeaderLen {
			return UDPFrame{}, ErrInvalidFrame
		}
		return UDPFrame{Type: UDPFrameTypeClose, FlowID: flowID}, nil
	default:
		return UDPFrame{}, ErrInvalidFrame
	}
}

func decodeUDPFragmentFrame(buf []byte, flowID FlowID) (UDPFrame, error) {
	if len(buf) < UDPFragmentHeaderLen {
		return UDPFrame{}, ErrInvalidFrame
	}
	packetID := decodeUint32BE(buf[5:9])
	if err := validatePacketID(packetID); err != nil {
		return UDPFrame{}, ErrInvalidFrame
	}
	fragment := UDPFragment{
		PacketID:      packetID,
		FragmentIndex: buf[9],
		FragmentCount: buf[10],
		TotalLen:      uint16(buf[11])<<8 | uint16(buf[12]),
		Payload:       buf[UDPFragmentHeaderLen:],
	}
	if err := validateFragmentMetadata(fragment); err != nil {
		return UDPFrame{}, ErrInvalidFrame
	}
	if len(fragment.Payload) == 0 ||
		len(fragment.Payload)+int(fragment.FragmentCount)-1 > int(fragment.TotalLen) {
		return UDPFrame{}, ErrInvalidFrame
	}
	return UDPFrame{Type: UDPFrameTypeFragment, FlowID: flowID, Fragment: fragment}, nil
}

func encodeUDPBaseHeader(frameType byte, flowID FlowID) ([UDPHeaderLen]byte, error) {
	if err := validateFlowID(flowID); err != nil {
		return [UDPHeaderLen]byte{}, err
	}
	var out [UDPHeaderLen]byte
	out[0] = frameType
	encodeUint32BE(out[1:], flowID)
	return out, nil
}

func validateFlowID(flowID FlowID) error {
	if flowID == 0 {
		return errors.New("nowhere: zero flow id")
	}
	return nil
}

func validatePacketID(packetID uint32) error {
	if packetID == 0 {
		return errors.New("nowhere: zero packet id")
	}
	return nil
}

func validateUDPPayload(payload []byte) error {
	if len(payload) > UDPPacketMax {
		return fmt.Errorf("nowhere: udp payload too large: %d", len(payload))
	}
	return nil
}

func validateFragmentMetadata(fragment UDPFragment) error {
	if fragment.FragmentCount < 2 || fragment.FragmentIndex >= fragment.FragmentCount {
		return errors.New("nowhere: invalid fragment index or count")
	}
	if fragment.TotalLen == 0 {
		return errors.New("nowhere: zero fragmented packet length")
	}
	if fragment.TotalLen < uint16(fragment.FragmentCount) {
		return errors.New("nowhere: total length smaller than fragment count")
	}
	return nil
}
