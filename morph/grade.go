package morph

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Grade selects which transport bytes Morph masks below TLS and QUIC.
// The zero value is GradeFull ("full"), matching the Nowhere 3.5 default.
type Grade uint8

const (
	// GradeFull masks all TLS stream and QUIC datagram bytes.
	GradeFull Grade = iota
	// GradeCore masks TLS Record headers and selected TLS and QUIC bytes
	// per the Nowhere 3.5 Grade Extension.
	GradeCore
)

const (
	coreTLSAppData        = 23
	coreMaxSkippedPayload = 18432
	coreUDPLongHeaderMask = 0x80
	coreUDPShortThreshold = 41
	coreUDPHeadMaskLen    = 25
	coreUDPTailMaskLen    = 16
)

var errInvalidGrade = errors.New("grade must be full or core")

// ParseGrade parses a Nowhere 3.5 Morph grade option ("full" or "core").
// Values are case-sensitive; an empty or unrecognized string fails.
func ParseGrade(value string) (Grade, error) {
	switch value {
	case "full":
		return GradeFull, nil
	case "core":
		return GradeCore, nil
	default:
		return 0, errInvalidGrade
	}
}

// String returns the canonical URL option value ("full" or "core").
func (g Grade) String() string {
	switch g {
	case GradeFull:
		return "full"
	case GradeCore:
		return "core"
	default:
		return fmt.Sprintf("grade(%d)", uint8(g))
	}
}

// Valid reports whether g is a supported Nowhere 3.5 Morph grade.
func (g Grade) Valid() bool {
	return g == GradeFull || g == GradeCore
}

// recordState tracks TLS Record boundaries for Core Morph TCP masking.
// It is a value type so partial or failed writes can retain the previous state
// and commit only the accepted prefix.
type recordState struct {
	header      [tlsRecordHeader]byte
	headerLen   int
	payloadLeft int
	skipPayload bool
}

func (s recordState) span(available int) (count int, mask bool) {
	if s.payloadLeft == 0 {
		need := len(s.header) - s.headerLen
		if available < need {
			return available, true
		}
		return need, true
	}
	if available < s.payloadLeft {
		return available, !s.skipPayload
	}
	return s.payloadLeft, !s.skipPayload
}

func (s *recordState) advance(plain []byte) {
	if s.payloadLeft != 0 {
		s.payloadLeft -= len(plain)
		return
	}
	end := s.headerLen + len(plain)
	copy(s.header[s.headerLen:end], plain)
	s.headerLen = end
	if end == len(s.header) {
		s.headerLen = 0
		s.payloadLeft = int(binary.BigEndian.Uint16(s.header[3:5]))
		s.skipPayload = s.header[0] == coreTLSAppData &&
			s.header[1] == 0x03 &&
			s.header[2] == 0x03 &&
			s.payloadLeft <= coreMaxSkippedPayload
	}
}

func (s *recordState) advanceSlice(plain []byte) {
	for len(plain) > 0 {
		count, _ := s.span(len(plain))
		s.advance(plain[:count])
		plain = plain[count:]
	}
}

func (s *recordState) apply(c *tcpCipher, offset uint64, data []byte, opening bool) error {
	if uint64(len(data)) > c.remaining(offset) {
		return c.exhaustedErr()
	}
	rest := data
	for len(rest) > 0 {
		count, mask := s.span(len(rest))
		part := rest[:count]
		if !opening {
			s.advance(part)
		}
		if mask {
			if err := c.applyAt(offset, part); err != nil {
				return err
			}
		}
		if opening {
			s.advance(part)
		}
		rest = rest[count:]
		offset += uint64(count)
	}
	return nil
}

// ApplyTCPCore masks or unmasks a complete TLS byte sequence starting at
// stream offset 0 using Nowhere 3.5 Core Morph. dst and src must have the same
// length and may alias. Set opening to false when sealing plaintext and true
// when recovering ciphertext.
func ApplyTCPCore(c Cipher, directionKey *[32]byte, nonce *[12]byte, opening bool, dst, src []byte) error {
	if len(dst) != len(src) {
		return errLengthMismatch
	}
	tc, err := newTCPCipher(c, directionKey, nonce)
	if err != nil {
		return err
	}
	if len(src) == 0 {
		return nil
	}
	copy(dst, src)
	var state recordState
	return state.apply(tc, 0, dst, opening)
}
