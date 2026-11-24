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
// CipherChaCha (ChaCha20-IETF), matching the Nowhere 3.4 default.
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

// ParseCipher parses a Nowhere 3.4 Morph cipher option ("chacha" or "aes").
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

// Valid reports whether c is a supported Nowhere 3.4 Morph cipher.
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

// ApplyTCPAt XORs src into dst using the Nowhere 3.4 Morph TCP cipher at the
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

// ApplyDatagram XORs src into dst using the Nowhere 3.4 Morph UDP cipher for
// one datagram and its 12-byte nonce. dst and src must have the same length and
// may alias.
func ApplyDatagram(c Cipher, directionKey *[32]byte, nonce *[12]byte, dst, src []byte) error {
	if len(dst) != len(src) {
		return errLengthMismatch
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
	applyDatagramWithBlock(c, directionKey, block, nonce, dst, src)
	return nil
}

func applyDatagramWithBlock(c Cipher, directionKey *[32]byte, block cipher.Block, nonce *[nonceLen]byte, dst, src []byte) {
	if len(src) == 0 {
		return
	}
	if c == CipherAES {
		var iv [aes.BlockSize]byte
		copy(iv[:nonceLen], nonce[:])
		cipher.NewCTR(block, iv[:]).XORKeyStream(dst, src)
		return
	}
	chacha20.XORKeyStreamAt(dst, src, directionKey, nonce, 0)
}
