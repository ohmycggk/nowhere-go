// Package morph is the Nowhere 3 keyed transform below TLS and QUIC.
// Key derivation uses HMAC with the root label "nowhere/nw3/morph". It does
// not call the Nowhere 2 Morph KDF.
//
// A Morph TCP connection starts with a 64-byte prelude and a 12-byte nonce.
// Since Nowhere 3.2 that prelude must authenticate a Vector identity and a
// counter in 1..=2^48-1. A tag mismatch, a zero counter, a replay, or a
// counter outside the window is rejected before ClientHello parsing and does
// not consult the replay registry. There is no legacy prelude fallback. QUIC
// and non-Morph TCP do not use this prelude.
package morph

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/ohmycggk/nowhere-go/internal/bufpool"
	"github.com/ohmycggk/nowhere-go/internal/chacha20"
	"github.com/ohmycggk/nowhere-go/runtime"
)

const (
	nonceLen          = 12
	udpPreludeLen     = 12
	preludeLen        = 64
	maxPooledUDPMask  = 2048
	maxRetainedUDPBuf = bufpool.UDPSize + nonceLen
	preludeEnv        = "NOW_MORPH_TCP_PRELUDE"
	morphRootSalt     = "nowhere/nw3/morph"
)

var udpMaskPool = sync.Pool{
	New: func() any {
		b := make([]byte, maxPooledUDPMask)
		return &b
	},
}

// Keys are the directional Morph outputs for one shared key.
//
// Copies made from the same Derive or DeriveWithCipher call share one Vector
// prelude identity and one Portal replay registry. Keys constructed field by
// field have neither and cannot send or accept an authenticated Morph TCP
// prelude. The zero value of Cipher selects ChaCha20-IETF.
type Keys struct {
	TCPC2S [32]byte
	TCPS2C [32]byte
	UDPC2S [32]byte
	UDPS2C [32]byte
	Cipher Cipher
	state  *preludeState
}

// Derive builds Morph keys using the default ChaCha20-IETF cipher. sharedKey is
// the same raw text used for authentication.
func Derive(sharedKey []byte) Keys {
	root := hmacSHA256([]byte(morphRootSalt), sharedKey)
	return Keys{
		TCPC2S: expand(root, "tcp c2s"),
		TCPS2C: expand(root, "tcp s2c"),
		UDPC2S: expand(root, "udp c2s"),
		UDPS2C: expand(root, "udp s2c"),
		Cipher: CipherChaCha,
		state:  newPreludeState(root),
	}
}

// DeriveWithCipher builds Morph keys using the selected Nowhere 3.4 cipher.
func DeriveWithCipher(sharedKey []byte, c Cipher) (Keys, error) {
	if !c.Valid() {
		return Keys{}, errInvalidCipher
	}
	keys := Derive(sharedKey)
	keys.Cipher = c
	return keys, nil
}

func hmacSHA256(key, data []byte) [32]byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func expand(root [32]byte, info string) [32]byte {
	input := make([]byte, len(info)+1)
	copy(input, info)
	input[len(info)] = 0x01
	return hmacSHA256(root[:], input)
}

type preludePolicy uint8

const (
	// preludeFade is the Nowhere 3.0.1 default. It is not negotiated.
	preludeFade preludePolicy = iota
	preludeFull8
	preludeLow7
)

func preludePolicyFromEnv() (preludePolicy, error) {
	value, ok := os.LookupEnv(preludeEnv)
	if !ok {
		return preludeFade, nil
	}
	switch value {
	case "fade":
		return preludeFade, nil
	case "full8":
		return preludeFull8, nil
	case "low7":
		return preludeLow7, nil
	default:
		return 0, fmt.Errorf("%s must be fade, full8 or low7", preludeEnv)
	}
}

func generatePrelude(policy preludePolicy) ([preludeLen]byte, error) {
	return generatePreludeWith(policy, readEntropy)
}

func generatePreludeWith(policy preludePolicy, fill func([]byte) error) ([preludeLen]byte, error) {
	var prelude [preludeLen]byte
	if err := fill(prelude[:]); err != nil {
		return prelude, err
	}
	switch policy {
	case preludeFade:
		var boundaries [2]byte
		if err := fill(boundaries[:]); err != nil {
			return prelude, err
		}
		aSample, err := sampleBelow(boundaries[0], 5, fill)
		if err != nil {
			return prelude, err
		}
		bSample, err := sampleBelow(boundaries[1], 17, fill)
		if err != nil {
			return prelude, err
		}
		a := 8 + int(aSample)
		b := 16 + int(bSample)
		for i := 0; i < a; i++ {
			printable, err := sampleBelow(prelude[i], 95, fill)
			if err != nil {
				return prelude, err
			}
			prelude[i] = 0x20 + printable
		}
		for i := a; i < b; i++ {
			prelude[i] &= 0x7f
		}
	case preludeFull8:
	case preludeLow7:
		for i := range prelude {
			prelude[i] &= 0x7f
		}
	default:
		return prelude, fmt.Errorf("%s must be fade, full8 or low7", preludeEnv)
	}
	return prelude, nil
}

// sampleBelow returns a uniform value in [0, upper) from one random byte.
// Bytes at or above 256-256%upper are rejected and replaced, so the modulo
// does not bias the result.
func sampleBelow(b byte, upper byte, fill func([]byte) error) (byte, error) {
	if upper == 0 {
		return 0, errors.New("nw3: empty Morph sample range")
	}
	limit := 256 - 256%int(upper)
	for int(b) >= limit {
		var next [1]byte
		if err := fill(next[:]); err != nil {
			return 0, err
		}
		b = next[0]
	}
	return b % upper, nil
}

// WrapTCPClient allocates this Vector's next prelude counter, writes the
// authenticated 64-byte prelude and 12-byte nonce, then masks TLS bytes.
// The counter is consumed even when prelude generation later fails. QUIC and
// packet Morph never call this and therefore allocate nothing.
func WrapTCPClient(conn net.Conn, keys Keys) (net.Conn, error) {
	if keys.state == nil {
		return nil, errPreludeState
	}
	if !keys.Cipher.Valid() {
		return nil, errInvalidCipher
	}
	identity, counter, err := keys.state.allocate()
	if err != nil {
		return nil, err
	}
	policy, err := preludePolicyFromEnv()
	if err != nil {
		return nil, err
	}
	prelude, err := generatePrelude(policy)
	if err != nil {
		return nil, err
	}
	var nonce [nonceLen]byte
	if err := readEntropy(nonce[:]); err != nil {
		return nil, err
	}
	readCipher, err := newTCPCipher(keys.Cipher, &keys.TCPS2C, &nonce)
	if err != nil {
		return nil, err
	}
	writeCipher, err := newTCPCipher(keys.Cipher, &keys.TCPC2S, &nonce)
	if err != nil {
		return nil, err
	}
	encodePrelude(keys.state, &prelude, &nonce, identity, counter)
	pref := make([]byte, 0, preludeLen+nonceLen)
	pref = append(pref, prelude[:]...)
	pref = append(pref, nonce[:]...)
	return &tcpConn{
		Conn:        conn,
		cipher:      keys.Cipher,
		readKey:     keys.TCPS2C,
		writeKey:    keys.TCPC2S,
		nonce:       nonce,
		readCipher:  readCipher,
		writeCipher: writeCipher,
		writePref:   pref,
	}, nil
}

// WrapTCPServer accepts one Morph TCP connection. The first read requires an
// authenticated prelude with a counter in 1..=2^48-1, checks it against the
// Portal replay window, then buffers one structurally complete ClientHello
// before any byte is exposed to TLS. A tag mismatch or an invalid counter is
// rejected before ClientHello parsing and does not touch the replay registry.
// Linger stays at whatever the caller set until ReleaseAuthenticated.
func WrapTCPServer(conn net.Conn, keys Keys) net.Conn {
	return &tcpConn{
		Conn:     conn,
		cipher:   keys.Cipher,
		readKey:  keys.TCPC2S,
		writeKey: keys.TCPS2C,
		server:   true,
		state:    keys.state,
	}
}

// ReleaseAuthenticated restores normal socket linger after a Morph TCP server
// has authenticated a Vector. deadline is the handshake deadline captured at
// accept. A deadline that has already passed keeps zero linger and returns
// ErrHandshakeDeadline. Non-Morph connections and Morph clients are unchanged.
// Call it only after a complete Vector AuthFrame; every earlier failure must
// leave the abortive close in place.
func ReleaseAuthenticated(conn net.Conn, deadline time.Time) error {
	tcp, ok := conn.(*tcpConn)
	if !ok || !tcp.server {
		return nil
	}
	if !deadline.After(time.Now()) {
		_ = setLinger(tcp.Conn, 0)
		return ErrHandshakeDeadline
	}
	if err := setLinger(tcp.Conn, -1); err != nil {
		return err
	}
	if !deadline.After(time.Now()) {
		_ = setLinger(tcp.Conn, 0)
		return ErrHandshakeDeadline
	}
	return nil
}

type tcpConn struct {
	net.Conn
	cipher            Cipher
	readKey, writeKey [32]byte
	nonce             [nonceLen]byte
	readCipher        *tcpCipher
	writeCipher       *tcpCipher
	readOff, writeOff uint64
	writePref         []byte
	server            bool
	state             *preludeState
	pending           []byte
	bootstrapped      bool
	bootErr           error
	readMu, writeMu   sync.Mutex
}

func (c *tcpConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.server {
		if err := c.bootstrap(); err != nil {
			if errors.Is(err, ErrPreludeRejected) || errors.Is(err, ErrClientHello) {
				// crypto/tls reads the record header before returning a handshake
				// error, and it does not preserve this error. Swap in a reader
				// that fails without touching the socket so the rejected bytes
				// stay unread. The Portal holds the socket until its deadline.
				c.Conn = &silentConn{Conn: c.Conn, err: err}
			}
			return 0, err
		}
		if len(c.pending) > 0 {
			n := copy(p, c.pending)
			c.pending = c.pending[n:]
			return n, nil
		}
	}
	if len(p) == 0 {
		return 0, nil
	}
	remaining := c.readCipher.remaining(c.readOff)
	if remaining == 0 {
		return 0, c.readCipher.exhaustedErr()
	}
	if uint64(len(p)) > remaining {
		p = p[:int(remaining)]
	}
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.readCipher.xorKeyStream(p[:n], p[:n])
		c.readOff += uint64(n)
	}
	return n, err
}

func (c *tcpConn) bootstrap() error {
	if c.bootErr != nil {
		return c.bootErr
	}
	if c.bootstrapped {
		return nil
	}
	if err := c.bootstrapOnce(); err != nil {
		c.bootErr = err
		return err
	}
	c.bootstrapped = true
	return nil
}

func (c *tcpConn) bootstrapOnce() error {
	if c.state == nil {
		return errPreludeState
	}
	if !c.cipher.Valid() {
		return errInvalidCipher
	}
	if err := setLinger(c.Conn, 0); err != nil {
		return err
	}
	var head [preludeLen + nonceLen]byte
	if _, err := io.ReadFull(c.Conn, head[:]); err != nil {
		return err
	}
	var prelude [preludeLen]byte
	copy(prelude[:], head[:preludeLen])
	copy(c.nonce[:], head[preludeLen:])
	identity, counter, matched := decodePrelude(c.state, &prelude, &c.nonce)
	if !matched || !counterValid(counter) {
		return ErrPreludeRejected
	}
	if !c.state.registry().precheck(identity, counter) {
		return ErrPreludeRejected
	}
	rc, err := newTCPCipher(c.cipher, &c.readKey, &c.nonce)
	if err != nil {
		return err
	}
	wc, err := newTCPCipher(c.cipher, &c.writeKey, &c.nonce)
	if err != nil {
		return err
	}
	c.readCipher = rc
	c.writeMu.Lock()
	c.writeCipher = wc
	c.writeMu.Unlock()
	pending, err := c.readClientHello()
	if err != nil {
		return err
	}
	if !c.state.registry().commit(identity, counter) {
		return ErrPreludeRejected
	}
	c.pending = pending
	return nil
}

func (c *tcpConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if len(c.writePref) > 0 {
		n, err := c.Conn.Write(c.writePref)
		c.writePref = c.writePref[n:]
		if err != nil || len(c.writePref) > 0 {
			if err == nil {
				err = io.ErrShortWrite
			}
			return 0, err
		}
	}
	if len(p) == 0 {
		return 0, nil
	}
	if c.writeCipher == nil {
		return 0, errNotBootstrapped
	}
	remaining := c.writeCipher.remaining(c.writeOff)
	if remaining == 0 {
		return 0, c.writeCipher.exhaustedErr()
	}
	count := len(p)
	exhaustedAfter := false
	if uint64(count) > remaining {
		count = int(remaining)
		exhaustedAfter = true
	}
	bp := bufpool.GetTCP()
	defer bufpool.PutTCP(bp)
	scratch := *bp
	written := 0
	for written < count {
		chunk := count - written
		if chunk > len(scratch) {
			chunk = len(scratch)
		}
		buf := scratch[:chunk]
		c.writeCipher.xorKeyStream(buf, p[written:written+chunk])
		n, err := c.Conn.Write(buf)
		if n > 0 {
			c.writeOff += uint64(n)
			written += n
		}
		if n != chunk {
			_ = c.writeCipher.seek(c.writeOff)
			return written, err
		}
		if err != nil {
			return written, err
		}
	}
	if exhaustedAfter {
		return written, c.writeCipher.exhaustedErr()
	}
	return written, nil
}

// silentConn keeps a rejected Morph TCP socket from being drained. Reads fail
// with the admission error. Writes and close still reach the underlying socket.
type silentConn struct {
	net.Conn
	err error
}

func (c *silentConn) Read([]byte) (int, error) { return 0, c.err }

// WrapPacketConn masks each UDP datagram with a fresh nonce.
// Client sockets send with udp c2s and receive with udp s2c.
// A server socket drops a long-header QUIC datagram whose version is not one
// that Nowhere 3.2's quinn 0.11.19 accepts, before the host QUIC stack can
// answer it. Short headers pass. Clients do not filter.
//
// A client socket also sends one independent 12-byte UDP Prelude before the
// first QUIC datagram on that socket. The Prelude is not masked and carries no
// nonce. Portal discards datagrams of 12 bytes or fewer and does not require
// one to arrive. Server sockets send no Prelude.
//
// The result is not a *net.UDPConn, so quic-go does not take its batching path.
// It reads through PacketConn.ReadFrom, which is where the server filter runs.
// No extra socket is opened per peer. A future batching socket must still give
// every QUIC segment its own nonce and must not treat the Prelude as a segment.
func WrapPacketConn(pc net.PacketConn, keys Keys, client bool) (net.PacketConn, error) {
	if !keys.Cipher.Valid() {
		return nil, errInvalidCipher
	}
	tx, rx := keys.UDPC2S, keys.UDPS2C
	if !client {
		tx, rx = keys.UDPS2C, keys.UDPC2S
	}
	var txBlock, rxBlock cipher.Block
	if keys.Cipher == CipherAES {
		var err error
		txBlock, err = aes.NewCipher(tx[:16])
		if err != nil {
			return nil, err
		}
		rxBlock, err = aes.NewCipher(rx[:16])
		if err != nil {
			return nil, err
		}
	}
	c := &packetConn{
		PacketConn: pc,
		cipher:     keys.Cipher,
		txKey:      tx,
		rxKey:      rx,
		txBlock:    txBlock,
		rxBlock:    rxBlock,
		server:     !client,
	}
	if err := c.nonces.reseed(); err != nil {
		return nil, err
	}
	if client {
		policy, err := udpPreludePolicy()
		if err != nil {
			return nil, err
		}
		prelude, err := generateUDPPrelude(policy)
		if err != nil {
			return nil, err
		}
		c.prelude = prelude[:]
	}
	return c, nil
}

type udpNonceGen struct {
	mu        sync.Mutex
	seed      [32]byte
	generated uint64
}

func (g *udpNonceGen) reseed() error {
	_, err := io.ReadFull(rand.Reader, g.seed[:])
	if err != nil {
		return err
	}
	g.generated = 0
	return nil
}

// next produces one 12-byte UDP nonce using ChaCha20 from a CSPRNG seed,
// reseeding before the ChaCha20 stream limit, matching Nowhere's UdpNonceGenerator.
func (g *udpNonceGen) next() ([nonceLen]byte, error) {
	var nonce [nonceLen]byte
	var zero [nonceLen]byte
	g.mu.Lock()
	defer g.mu.Unlock()
	if chachaStreamLimit-g.generated < nonceLen {
		if err := g.reseed(); err != nil {
			return nonce, err
		}
	}
	chacha20.XORKeyStreamAt(nonce[:], nonce[:], &g.seed, &zero, g.generated)
	g.generated += nonceLen
	return nonce, nil
}

type packetConn struct {
	net.PacketConn
	cipher  Cipher
	txKey   [32]byte
	rxKey   [32]byte
	txBlock cipher.Block
	rxBlock cipher.Block
	server  bool
	txMu    sync.Mutex
	rxMu    sync.Mutex
	readBuf []byte
	nonces  udpNonceGen
	// prelude is the one unsent UDP Prelude. Nil after a successful submit
	// and on server sockets.
	prelude []byte
}

// quinnVersions are quinn-proto 0.11.19 DEFAULT_SUPPORTED_VERSIONS, the set
// Nowhere 3.2 uses to suppress Version Negotiation on Morph UDP. quic-go
// negotiates only v1 from this list; draft versions are accepted so a peer
// that speaks them is not answered with a negotiation packet either.
var quinnVersions = []uint32{
	0x00000001,
	0xff00001d,
	0xff00001e,
	0xff00001f,
	0xff000020,
	0xff000021,
	0xff000022,
}

// supportedQUICPacket reports whether one decrypted datagram may be delivered
// to a Morph UDP server. A short header always passes. A long header passes
// only when its 4-byte version is in quinnVersions.
func supportedQUICPacket(packet []byte) bool {
	if len(packet) == 0 {
		return false
	}
	if packet[0]&0x80 == 0 {
		return true
	}
	if len(packet) < 5 {
		return false
	}
	version := binary.BigEndian.Uint32(packet[1:5])
	for _, supported := range quinnVersions {
		if version == supported {
			return true
		}
	}
	return false
}

func (c *packetConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	// The lock covers only the pending Prelude. Holding it across the socket
	// write deadlocks with ReadFrom, which quic-go runs concurrently.
	c.txMu.Lock()
	prelude := c.prelude
	c.prelude = nil
	c.txMu.Unlock()
	if len(prelude) > 0 {
		n, err := c.PacketConn.WriteTo(prelude, addr)
		if n < len(prelude) {
			c.txMu.Lock()
			if c.prelude == nil {
				c.prelude = prelude
			}
			c.txMu.Unlock()
			if err == nil {
				err = io.ErrShortWrite
			}
			return 0, err
		}
	}
	nonce, err := c.nonces.next()
	if err != nil {
		return 0, err
	}
	wireLen := nonceLen + len(p)
	var bp *[]byte
	var wire []byte
	if wireLen <= maxPooledUDPMask {
		bp = udpMaskPool.Get().(*[]byte)
		defer udpMaskPool.Put(bp)
		wire = (*bp)[:wireLen]
	} else {
		wire = make([]byte, wireLen)
	}
	copy(wire, nonce[:])
	if len(p) > 0 {
		applyDatagramWithBlock(c.cipher, &c.txKey, c.txBlock, &nonce, wire[nonceLen:], p)
	}
	n, err := c.PacketConn.WriteTo(wire, addr)
	if n < nonceLen {
		return 0, err
	}
	return n - nonceLen, err
}

func udpPreludePolicy() (string, error) {
	return runtime.UDPPreludePolicy()
}

// generateUDPPrelude builds the independent 12-byte client datagram.
// fade is 2 printable ASCII, 8 low7, and 2 full8 bytes.
func generateUDPPrelude(policy string) ([udpPreludeLen]byte, error) {
	return generateUDPPreludeWith(policy, readEntropy)
}

func generateUDPPreludeWith(policy string, fill func([]byte) error) ([udpPreludeLen]byte, error) {
	var out [udpPreludeLen]byte
	if err := fill(out[:]); err != nil {
		return out, err
	}
	switch policy {
	case "full8":
	case "low7":
		for i := range out {
			out[i] &= 0x7f
		}
	case "fade":
		for i := 0; i < 2; i++ {
			printable, err := sampleBelow(out[i], 95, fill)
			if err != nil {
				return out, err
			}
			out[i] = 0x20 + printable
		}
		for i := 2; i < 10; i++ {
			out[i] &= 0x7f
		}
	default:
		return out, fmt.Errorf("%s must be fade, full8 or low7", runtime.EnvMorphUDPPrelude)
	}
	return out, nil
}

func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	need := nonceLen + len(p)
	c.rxMu.Lock()
	buf := c.readBuf
	c.readBuf = nil
	c.rxMu.Unlock()
	if cap(buf) < need {
		buf = make([]byte, need)
	}
	buf = buf[:need]
	defer func() {
		if cap(buf) > maxRetainedUDPBuf {
			return
		}
		c.rxMu.Lock()
		if cap(c.readBuf) < cap(buf) {
			c.readBuf = buf
		}
		c.rxMu.Unlock()
	}()
	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, addr, err
		}
		n, ok := unmaskDatagram(p, buf[:n], c.cipher, &c.rxKey, c.rxBlock, c.server)
		if !ok {
			continue
		}
		return n, addr, nil
	}
}

// unmaskDatagram decrypts one datagram into p. ok is false when a server drops
// the datagram, or when it carried no payload. n is the plaintext length.
// The decrypted bytes temporarily overwrite the ciphertext in wire, which the
// caller does not reuse.
func unmaskDatagram(p, wire []byte, c Cipher, key *[32]byte, block cipher.Block, server bool) (int, bool) {
	if len(wire) <= nonceLen {
		return 0, false
	}
	var nonce [nonceLen]byte
	copy(nonce[:], wire[:nonceLen])
	payload := wire[nonceLen:]
	applyDatagramWithBlock(c, key, block, &nonce, payload, payload)
	if server && !supportedQUICPacket(payload) {
		return 0, false
	}
	n := copy(p, payload)
	return n, true
}
