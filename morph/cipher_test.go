package morph

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseCipher(t *testing.T) {
	if got, err := ParseCipher("chacha"); err != nil || got != CipherChaCha || got.String() != "chacha" || !got.Valid() {
		t.Fatalf("chacha = %v %v", got, err)
	}
	if got, err := ParseCipher("aes"); err != nil || got != CipherAES || got.String() != "aes" || !got.Valid() {
		t.Fatalf("aes = %v %v", got, err)
	}
	for _, bad := range []string{"", "AES", "ChaCha", "aes-128-ctr", "chacha20", " aes", "aes "} {
		if _, err := ParseCipher(bad); err == nil {
			t.Fatalf("ParseCipher(%q) succeeded", bad)
		}
	}
	invalid := Cipher(99)
	if invalid.Valid() {
		t.Fatal("Cipher(99) reported valid")
	}
	if _, err := DeriveWithCipher([]byte("0123456789abcdef0123456789abcdef"), invalid); err == nil {
		t.Fatal("DeriveWithCipher accepted invalid cipher")
	}
}

func TestAESMatchesUpstreamTCPAndUDPVectors(t *testing.T) {
	keys, err := DeriveWithCipher([]byte("0123456789abcdef0123456789abcdef"), CipherAES)
	if err != nil {
		t.Fatal(err)
	}
	var nonce [12]byte
	for i := range nonce {
		nonce[i] = byte(i)
	}
	var plain [37]byte
	for i := range plain {
		plain[i] = byte(i)
	}

	// Vectors from Nowhere v3.4.0 src/tests/transport/morph/cipher.rs.
	for _, tc := range []struct {
		name   string
		key    [32]byte
		offset uint64
		want   string
	}{
		{
			name:   "tcp_c2s_offset_0",
			key:    keys.TCPC2S,
			offset: 0,
			want:   "8e59faa695f33a1a5ffc8369938132d677a1536e730205de8b4767a560fd155b7ed13833e3",
		},
		{
			name:   "tcp_s2c_offset_0",
			key:    keys.TCPS2C,
			offset: 0,
			want:   "17a4869bfb790fa12b676b42a6ad4f40f8eaff0566051e81313ca1a59486b0f766ba989ce2",
		},
		{
			name:   "tcp_c2s_high_offset",
			key:    keys.TCPC2S,
			offset: (1 << 40) + 19,
			want:   "dda378cb6a89ab5e74c5081119eb5fe3a06c0ee6563feacd15afa86af9b77425f0519188a2",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cipher, err := newTCPCipher(CipherAES, &tc.key, &nonce)
			if err != nil {
				t.Fatal(err)
			}
			if err := cipher.seek(tc.offset); err != nil {
				t.Fatal(err)
			}
			actual := plain
			cipher.xorKeyStream(actual[:21], actual[:21])
			cipher.xorKeyStream(actual[21:], actual[21:])
			assertHex(t, actual[:], tc.want)

			out := make([]byte, len(plain))
			if err := ApplyTCPAt(CipherAES, &tc.key, &nonce, tc.offset, out, plain[:]); err != nil {
				t.Fatal(err)
			}
			assertHex(t, out, tc.want)
		})
	}

	for _, tc := range []struct {
		name string
		key  [32]byte
		want string
	}{
		{
			name: "udp_c2s",
			key:  keys.UDPC2S,
			want: "4378463322b3680c1d1ad62068c536c0fc5e1eac063187dcb2cf48d0ab609405aa9f4fea6b",
		},
		{
			name: "udp_s2c",
			key:  keys.UDPS2C,
			want: "2813cf0312ebdcc2beb4ff955b4667eb3ab282761d5d5ecc3b1b111d8531262cb6ea62744a",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := make([]byte, len(plain))
			if err := ApplyDatagram(CipherAES, &tc.key, &nonce, out, plain[:]); err != nil {
				t.Fatal(err)
			}
			assertHex(t, out, tc.want)
		})
	}
}

func TestTCPRoundTripBothCiphers(t *testing.T) {
	for _, c := range []Cipher{CipherChaCha, CipherAES} {
		t.Run(c.String(), func(t *testing.T) {
			clientSide, serverSide := net.Pipe()
			defer clientSide.Close()
			defer serverSide.Close()
			keys, err := DeriveWithCipher([]byte("0123456789abcdef0123456789abcdef"), c)
			if err != nil {
				t.Fatal(err)
			}
			client, err := WrapTCPClient(clientSide, keys)
			if err != nil {
				t.Fatal(err)
			}
			server := WrapTCPServer(serverSide, keys)
			payload := append(minimalClientHello(), bytes.Repeat([]byte("morph-payload"), 13)...)
			errCh := make(chan error, 1)
			go func() {
				buf := make([]byte, len(payload))
				if _, err := io.ReadFull(server, buf); err != nil {
					errCh <- err
					return
				}
				if !bytes.Equal(buf, payload) {
					errCh <- errors.New("server payload mismatch")
					return
				}
				_, err := server.Write(payload)
				errCh <- err
			}()
			if _, err := client.Write(payload); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, len(payload))
			if _, err := io.ReadFull(client, buf); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(buf, payload) {
				t.Fatalf("client read mismatch")
			}
			if err := <-errCh; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTCPCipherMismatchRejectsClientHello(t *testing.T) {
	for _, tc := range []struct {
		name         string
		serverCipher Cipher
		clientCipher Cipher
	}{
		{name: "aes_vs_chacha", serverCipher: CipherAES, clientCipher: CipherChaCha},
		{name: "chacha_vs_aes", serverCipher: CipherChaCha, clientCipher: CipherAES},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientSide, serverSide := net.Pipe()
			defer clientSide.Close()
			defer serverSide.Close()
			serverKeys, err := DeriveWithCipher([]byte("0123456789abcdef0123456789abcdef"), tc.serverCipher)
			if err != nil {
				t.Fatal(err)
			}
			clientKeys, err := DeriveWithCipher([]byte("0123456789abcdef0123456789abcdef"), tc.clientCipher)
			if err != nil {
				t.Fatal(err)
			}
			client, err := WrapTCPClient(clientSide, clientKeys)
			if err != nil {
				t.Fatal(err)
			}
			server := WrapTCPServer(serverSide, serverKeys)
			go func() {
				_, _ = client.Write(minimalClientHello())
				_ = client.Close()
			}()
			buf := make([]byte, 64)
			if _, err := server.Read(buf); !errors.Is(err, ErrClientHello) {
				t.Fatalf("server read = %v, want ErrClientHello", err)
			}
		})
	}
}

func TestTCPRetriesChangedInputAfterShortWriteAndError(t *testing.T) {
	for _, c := range []Cipher{CipherChaCha, CipherAES} {
		t.Run(c.String(), func(t *testing.T) {
			keys, err := DeriveWithCipher([]byte("shared"), c)
			if err != nil {
				t.Fatal(err)
			}
			var nonce [nonceLen]byte
			for i := range nonce {
				nonce[i] = 12
			}
			rc, err := newTCPCipher(c, &keys.TCPS2C, &nonce)
			if err != nil {
				t.Fatal(err)
			}
			wc, err := newTCPCipher(c, &keys.TCPC2S, &nonce)
			if err != nil {
				t.Fatal(err)
			}
			inner := &scriptedWriteConn{
				outcomes: []writeOutcome{
					{n: 2},
					{n: 1, err: errors.New("transient")},
					{n: 100},
				},
			}
			conn := &tcpConn{
				Conn:        inner,
				cipher:      c,
				readKey:     keys.TCPS2C,
				writeKey:    keys.TCPC2S,
				nonce:       nonce,
				readCipher:  rc,
				writeCipher: wc,
			}
			if n, err := conn.Write([]byte("abcd")); err != nil || n != 2 {
				t.Fatalf("first write = %d %v, want 2 nil", n, err)
			}
			if n, err := conn.Write([]byte("cd")); err == nil || n != 1 {
				t.Fatalf("second write = %d %v, want 1 err", n, err)
			}
			if n, err := conn.Write([]byte("z")); err != nil || n != 1 {
				t.Fatalf("third write = %d %v, want 1 nil", n, err)
			}
			plain := make([]byte, len(inner.written))
			if err := ApplyTCPAt(c, &keys.TCPC2S, &nonce, 0, plain, inner.written); err != nil {
				t.Fatal(err)
			}
			if string(plain) != "abcz" {
				t.Fatalf("decrypted = %q, want %q", plain, "abcz")
			}
		})
	}
}

func TestAESLimitsEachTCPDirection(t *testing.T) {
	keys, err := DeriveWithCipher([]byte("0123456789abcdef0123456789abcdef"), CipherAES)
	if err != nil {
		t.Fatal(err)
	}
	var nonce [nonceLen]byte
	for i := range nonce {
		nonce[i] = byte(i)
	}
	rc, err := newTCPCipher(CipherAES, &keys.TCPS2C, &nonce)
	if err != nil {
		t.Fatal(err)
	}
	wc, err := newTCPCipher(CipherAES, &keys.TCPC2S, &nonce)
	if err != nil {
		t.Fatal(err)
	}
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()
	stream := &tcpConn{
		Conn:        clientSide,
		cipher:      CipherAES,
		readKey:     keys.TCPS2C,
		writeKey:    keys.TCPC2S,
		nonce:       nonce,
		readCipher:  rc,
		writeCipher: wc,
		writeOff:    aesStreamLimit - 8,
	}
	if err := stream.writeCipher.seek(stream.writeOff); err != nil {
		t.Fatal(err)
	}

	wireCh := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 8)
		_, _ = io.ReadFull(serverSide, buf)
		wireCh <- buf
	}()

	// Writing 9 bytes with 8 remaining transmits the 8 final bytes and reports
	// AES exhaustion to honor Go's io.Writer contract (n < len(p) => err != nil).
	n, err := stream.Write([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8})
	if n != 8 || err == nil || !strings.Contains(err.Error(), "AES") {
		t.Fatalf("boundary write = %d %v, want 8 and AES error", n, err)
	}
	gotWire := <-wireCh
	wantWire, _ := hex.DecodeString("8e053ffe0fc59c76")
	if !bytes.Equal(gotWire, wantWire) {
		t.Fatalf("boundary ciphertext = %x, want %x", gotWire, wantWire)
	}
	// Further non-empty writes fail with AES exhaustion; empty write succeeds.
	if n, err := stream.Write([]byte{8}); n != 0 || err == nil || !strings.Contains(err.Error(), "AES") {
		t.Fatalf("exhausted write = %d %v, want 0 and AES error", n, err)
	}
	if n, err := stream.Write(nil); n != 0 || err != nil {
		t.Fatalf("empty write after exhaustion = %d %v, want 0 nil", n, err)
	}
	if stream.readOff != 0 {
		t.Fatalf("readOff = %d, want 0", stream.readOff)
	}
}

func TestUDPRoundTripAndVersionFilterAES(t *testing.T) {
	keys, err := DeriveWithCipher([]byte("0123456789abcdef0123456789abcdef"), CipherAES)
	if err != nil {
		t.Fatal(err)
	}
	rawClient, rawServer := packetPipe()
	defer rawClient.Close()
	defer rawServer.Close()

	client, err := WrapPacketConn(rawClient, keys, true)
	if err != nil {
		t.Fatal(err)
	}
	server, err := WrapPacketConn(rawServer, keys, false)
	if err != nil {
		t.Fatal(err)
	}

	rejected := []byte{0xc0, 0x0a, 0x1a, 0x2a, 0x3a, 1, 2, 3}
	accepted := []byte{0x40, 9, 8, 7, 6}
	errCh := make(chan error, 1)
	go func() {
		if _, err := client.WriteTo(rejected, nil); err != nil {
			errCh <- err
			return
		}
		if _, err := client.WriteTo(accepted, nil); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	buf := make([]byte, 64)
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := server.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], accepted) {
		t.Fatalf("server read %x, want %x", buf[:n], accepted)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}

	reply := []byte{0x40, 1, 2, 3, 4}
	go func() {
		_, _ = server.WriteTo(reply, nil)
	}()
	n, _, err = client.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], reply) {
		t.Fatalf("client read %x, want %x", buf[:n], reply)
	}
}

type writeOutcome struct {
	n   int
	err error
}

type scriptedWriteConn struct {
	net.Conn
	outcomes []writeOutcome
	written  []byte
}

func (c *scriptedWriteConn) Write(p []byte) (int, error) {
	if len(c.outcomes) == 0 {
		c.written = append(c.written, p...)
		return len(p), nil
	}
	out := c.outcomes[0]
	c.outcomes = c.outcomes[1:]
	n := out.n
	if n > len(p) {
		n = len(p)
	}
	c.written = append(c.written, p[:n]...)
	return n, out.err
}
