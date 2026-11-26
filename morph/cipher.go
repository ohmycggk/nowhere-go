package morph

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ohmycggk/nowhere-go/internal/chacha20"
)

// Cipher selects the Morph wire-masking algorithm. The zero value is
// CipherChaCha (ChaCha20-IETF), matching the Nowhere 3.5 default.
type Cipher uint8

const (
	// CipherChaCha masks TLS and QUIC wire images with ChaCha20-IETF.
	CipherChaCha Cipher = iota
	// CipherAES masks TLS and QUIC wire images with AES-128-CTR.
	CipherAES
)

const (
	chachaStreamLimit uint64 = (1 << 38) - 64
	aesStreamLimit    uint64 = 1 << 48
)

var (
	errInvalidCipher   = errors.New("cipher must be chacha or aes")
	errChaChaExhausted = errors.New("nw3: Morph ChaCha20 TCP keystream exhausted")
	errAESExhausted    = errors.New("nw3: Morph AES TCP keystream exhausted")
	errLengthMismatch  = errors.New("nw3: Morph input and output buffer lengths differ")
	errNotBootstrapped = errors.New("nw3: Morph TCP stream not bootstrapped")
)

// ParseCipher parses a Nowhere 3.5 Morph cipher option ("chacha" or "aes").
// Values are case-sensitive; an empty or unrecognized string fails.
func ParseCipher(value string) (Cipher, error) {
	switch value {
	case "chacha":
		return CipherChaCha, nil
	case "aes":
		return CipherAES, nil
	default:
		return 0, errInvalidCipher
	}
}

// String returns the canonical URL option value ("chacha" or "aes").
func (c Cipher) String() string {
	switch c {
	case CipherChaCha:
		return "chacha"
	case CipherAES:
		return "aes"
	default:
		return fmt.Sprintf("cipher(%d)", uint8(c))
	}
}

// Valid reports whether c is a supported Nowhere 3.5 Morph cipher.
func (c Cipher) Valid() bool {
	return c == CipherChaCha || c == CipherAES
}

type tcpCipher struct {
	kind   Cipher
	key    [32]byte
	nonce  [nonceLen]byte
	offset uint64
	block  cipher.Block
	stream cipher.Stream
	aesCtr [aes.BlockSize]byte
	aesKS  [aes.BlockSize]byte
}

func newTCPCipher(kind Cipher, directionKey *[32]byte, nonce *[nonceLen]byte) (*tcpCipher, error) {
	switch kind {
	case CipherChaCha:
		return &tcpCipher{
			kind:  CipherChaCha,
			key:   *directionKey,
			nonce: *nonce,
		}, nil
	case CipherAES:
		derived := hmacSHA256(directionKey[:], nonce[:])
		block, err := aes.NewCipher(derived[:16])
		if err != nil {
			return nil, err
		}
		var zeroIV [aes.BlockSize]byte
		return &tcpCipher{
			kind:   CipherAES,
			block:  block,
			stream: cipher.NewCTR(block, zeroIV[:]),
		}, nil
	default:
		return nil, errInvalidCipher
	}
}

func (c *tcpCipher) limit() uint64 {
	if c.kind == CipherAES {
		return aesStreamLimit
	}
	return chachaStreamLimit
}

func (c *tcpCipher) exhaustedErr() error {
	if c.kind == CipherAES {
		return errAESExhausted
	}
	return errChaChaExhausted
}

func (c *tcpCipher) remaining(offset uint64) uint64 {
	limit := c.limit()
	if offset >= limit {
		return 0
	}
	return limit - offset
}

func (c *tcpCipher) seek(offset uint64) error {
	if offset > c.limit() {
		return c.exhaustedErr()
	}
	c.offset = offset
	if c.kind == CipherAES {
		var iv [aes.BlockSize]byte
		binary.BigEndian.PutUint64(iv[8:], offset/aes.BlockSize)
		c.stream = cipher.NewCTR(c.block, iv[:])
		if skip := int(offset % aes.BlockSize); skip > 0 {
			var discard [aes.BlockSize]byte
			c.stream.XORKeyStream(discard[:skip], discard[:skip])
		}
	}
	return nil
}

func (c *tcpCipher) xorKeyStream(dst, src []byte) {
	if len(src) == 0 {
		return
	}
	if c.kind == CipherAES {
		c.stream.XORKeyStream(dst, src)
	} else {
		chacha20.XORKeyStreamAt(dst, src, &c.key, &c.nonce, c.offset)
	}
	c.offset += uint64(len(src))
}

func (c *tcpCipher) applyAt(offset uint64, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if uint64(len(data)) > c.remaining(offset) {
		return c.exhaustedErr()
	}
	if c.kind == CipherChaCha {
		chacha20.XORKeyStreamAt(data, data, &c.key, &c.nonce, offset)
		c.offset = offset + uint64(len(data))
		return nil
	}
	if c.offset == offset {
		c.xorKeyStream(data, data)
		return nil
	}
	if len(data) <= 32 {
		c.applyAESSmallAt(offset, data)
		return nil
	}
	if err := c.seek(offset); err != nil {
		return err
	}
	c.xorKeyStream(data, data)
	return nil
}

func (c *tcpCipher) applyAESSmallAt(offset uint64, data []byte) {
	var zeroIV [aes.BlockSize]byte
	c.aesCtr = addCtr128BE(zeroIV, offset/aes.BlockSize)
	skip := int(offset % aes.BlockSize)
	for len(data) > 0 {
		c.block.Encrypt(c.aesKS[:], c.aesCtr[:])
		take := aes.BlockSize - skip
		if take > len(data) {
			take = len(data)
		}
		for i := 0; i < take; i++ {
			data[i] ^= c.aesKS[skip+i]
		}
		data = data[take:]
		skip = 0
		incCtr128BE(&c.aesCtr)
	}
}

func addCtr128BE(base [aes.BlockSize]byte, blocks uint64) [aes.BlockSize]byte {
	lo := binary.BigEndian.Uint64(base[8:])
	newLo := lo + blocks
	binary.BigEndian.PutUint64(base[8:], newLo)
	if newLo < lo {
		hi := binary.BigEndian.Uint64(base[:8])
		binary.BigEndian.PutUint64(base[:8], hi+1)
	}
	return base
}

func incCtr128BE(ctr *[aes.BlockSize]byte) {
	for i := aes.BlockSize - 1; i >= 0; i-- {
		ctr[i]++
		if ctr[i] != 0 {
			return
		}
	}
}

func aesCTRApplyAt(block cipher.Block, baseIV [aes.BlockSize]byte, offset uint64, dst, src []byte) {
	ctr := addCtr128BE(baseIV, offset/aes.BlockSize)
	skip := int(offset % aes.BlockSize)
	var ks [aes.BlockSize]byte
	for len(src) > 0 {
		block.Encrypt(ks[:], ctr[:])
		take := aes.BlockSize - skip
		if take > len(src) {
			take = len(src)
		}
		for i := 0; i < take; i++ {
			dst[i] = src[i] ^ ks[skip+i]
		}
		dst = dst[take:]
		src = src[take:]
		skip = 0
		incCtr128BE(&ctr)
	}
}

// ApplyTCPAt XORs src into dst using the Nowhere 3.5 Morph TCP cipher at the
// given byte offset. dst and src must have the same length and may alias.
func ApplyTCPAt(c Cipher, directionKey *[32]byte, nonce *[12]byte, offset uint64, dst, src []byte) error {
	if len(dst) != len(src) {
		return errLengthMismatch
	}
	tc, err := newTCPCipher(c, directionKey, nonce)
	if err != nil {
		return err
	}
	if uint64(len(src)) > tc.remaining(offset) {
		return tc.exhaustedErr()
	}
	if err := tc.seek(offset); err != nil {
		return err
	}
	tc.xorKeyStream(dst, src)
	return nil
}

// ApplyDatagram XORs src into dst using the Nowhere 3.5 Full Morph UDP cipher
// for one datagram and its 12-byte nonce. dst and src must have the same
// length and may alias.
func ApplyDatagram(c Cipher, directionKey *[32]byte, nonce *[12]byte, dst, src []byte) error {
	return ApplyDatagramWithGrade(c, GradeFull, false, directionKey, nonce, dst, src)
}

// ApplyDatagramWithGrade masks or unmasks one UDP datagram using the selected
// Nowhere 3.5 Morph cipher and grade. dst and src must have the same length
// and may alias. Set opening to false when sealing plaintext and true when
// recovering ciphertext.
func ApplyDatagramWithGrade(c Cipher, g Grade, opening bool, directionKey *[32]byte, nonce *[12]byte, dst, src []byte) error {
	if len(dst) != len(src) {
		return errLengthMismatch
	}
	if !g.Valid() {
		return errInvalidGrade
	}
	var block cipher.Block
	switch c {
	case CipherChaCha:
	case CipherAES:
		var err error
		block, err = aes.NewCipher(directionKey[:16])
		if err != nil {
			return err
		}
	default:
		return errInvalidCipher
	}
	applyDatagramWithBlock(c, g, opening, directionKey, block, nonce, dst, src)
	return nil
}

func applyDatagramWithBlock(c Cipher, g Grade, opening bool, directionKey *[32]byte, block cipher.Block, nonce *[nonceLen]byte, dst, src []byte) {
	if len(src) == 0 {
		return
	}
	if g == GradeFull || len(src) <= coreUDPShortThreshold || (!opening && src[0]&coreUDPLongHeaderMask != 0) {
		applyDatagramRange(c, directionKey, block, nonce, 0, dst, src)
		return
	}
	applyDatagramRange(c, directionKey, block, nonce, 0, dst[:coreUDPHeadMaskLen], src[:coreUDPHeadMaskLen])
	if opening && dst[0]&coreUDPLongHeaderMask != 0 {
		applyDatagramRange(c, directionKey, block, nonce, coreUDPHeadMaskLen, dst[coreUDPHeadMaskLen:], src[coreUDPHeadMaskLen:])
		return
	}
	tail := len(src) - coreUDPTailMaskLen
	copy(dst[coreUDPHeadMaskLen:tail], src[coreUDPHeadMaskLen:tail])
	applyDatagramRange(c, directionKey, block, nonce, uint64(tail), dst[tail:], src[tail:])
}

func applyDatagramRange(c Cipher, directionKey *[32]byte, block cipher.Block, nonce *[nonceLen]byte, offset uint64, dst, src []byte) {
	if len(src) == 0 {
		return
	}
	if c == CipherChaCha {
		chacha20.XORKeyStreamAt(dst, src, directionKey, nonce, offset)
		return
	}
	var baseIV [aes.BlockSize]byte
	copy(baseIV[:nonceLen], nonce[:])
	if len(src) <= 32 {
		aesCTRApplyAt(block, baseIV, offset, dst, src)
		return
	}
	ctr := addCtr128BE(baseIV, offset/aes.BlockSize)
	stream := cipher.NewCTR(block, ctr[:])
	if skip := int(offset % aes.BlockSize); skip > 0 {
		var discard [aes.BlockSize]byte
		stream.XORKeyStream(discard[:skip], discard[:skip])
	}
	stream.XORKeyStream(dst, src)
}
