package morph

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseGrade(t *testing.T) {
	if got, err := ParseGrade("full"); err != nil || got != GradeFull || got.String() != "full" || !got.Valid() {
		t.Fatalf("full = %v %v", got, err)
	}
	if got, err := ParseGrade("core"); err != nil || got != GradeCore || got.String() != "core" || !got.Valid() {
		t.Fatalf("core = %v %v", got, err)
	}
	for _, bad := range []string{"", "FULL", "CORE", "Core", " full", "core ", "partial", "off"} {
		if _, err := ParseGrade(bad); err == nil {
			t.Fatalf("ParseGrade(%q) succeeded", bad)
		}
	}
	invalid := Grade(99)
	if invalid.Valid() {
		t.Fatal("Grade(99) reported valid")
	}
	if _, err := DeriveWithOptions([]byte("0123456789abcdef0123456789abcdef"), CipherChaCha, invalid); err == nil {
		t.Fatal("DeriveWithOptions accepted invalid grade")
	}
	keys := Derive([]byte("0123456789abcdef0123456789abcdef"))
	keys.Grade = invalid
	if _, err := WrapTCPClient(nil, keys); err == nil {
		t.Fatal("WrapTCPClient accepted invalid grade")
	}
	rawClient, rawServer := packetPipe()
	defer rawClient.Close()
	defer rawServer.Close()
	if _, err := WrapPacketConn(rawClient, keys, true); err == nil {
		t.Fatal("WrapPacketConn accepted invalid grade")
	}
	var nonce [12]byte
	if err := ApplyDatagramWithGrade(CipherChaCha, invalid, false, &keys.UDPC2S, &nonce, make([]byte, 8), make([]byte, 8)); err == nil {
		t.Fatal("ApplyDatagramWithGrade accepted invalid grade")
	}
	if err := ApplyTCPCore(Cipher(99), &keys.TCPC2S, &nonce, false, make([]byte, 8), make([]byte, 8)); err == nil {
		t.Fatal("ApplyTCPCore accepted invalid cipher")
	}
	if err := ApplyTCPCore(CipherChaCha, &keys.TCPC2S, &nonce, false, make([]byte, 7), make([]byte, 8)); !errors.Is(err, errLengthMismatch) {
		t.Fatalf("ApplyTCPCore mismatched lengths = %v, want errLengthMismatch", err)
	}
	if err := ApplyTCPCore(CipherChaCha, &keys.TCPC2S, &nonce, false, nil, nil); err != nil {
		t.Fatalf("ApplyTCPCore empty = %v, want nil", err)
	}
	clientPipe, serverPipe := net.Pipe()
	defer clientPipe.Close()
	defer serverPipe.Close()
	srv := WrapTCPServer(serverPipe, keys)
	if _, err := srv.Read(make([]byte, 8)); !errors.Is(err, errInvalidGrade) {
		t.Fatalf("WrapTCPServer invalid grade = %v, want errInvalidGrade", err)
	}
}

func TestCoreTCPMasksHeadersAndUsesAbsoluteOffsets(t *testing.T) {
	// Mirrors Nowhere v3.5.0 src/tests/transport/morph/tcp.rs
	// core_masks_headers_and_uses_absolute_offsets_across_records.
	for _, suite := range []Cipher{CipherChaCha, CipherAES} {
		t.Run(suite.String(), func(t *testing.T) {
			var key [32]byte
			for i := range key {
				key[i] = 0x27
			}
			var nonce [nonceLen]byte
			for i := range nonce {
				nonce[i] = 11
			}
			var plain []byte
			var ranges [][2]int
			for _, rec := range []struct {
				prefix [3]byte
				size   uint16
				skip   bool
			}{
				{[3]byte{23, 3, 3}, 18432, true},
				{[3]byte{23, 3, 1}, 31, false},
				{[3]byte{22, 3, 3}, 19, false},
				{[3]byte{23, 3, 3}, 18433, false},
				{[3]byte{23, 3, 3}, 0, true},
				{[3]byte{23, 3, 3}, 47, true},
			} {
				start := len(plain)
				plain = append(plain, rec.prefix[:]...)
				var sz [2]byte
				binary.BigEndian.PutUint16(sz[:], rec.size)
				plain = append(plain, sz[:]...)
				payload := bytes.Repeat([]byte{0x92}, int(rec.size))
				plain = append(plain, payload...)
				if rec.skip {
					ranges = append(ranges, [2]int{start, start + 5})
				} else {
					ranges = append(ranges, [2]int{start, len(plain)})
				}
			}

			full := make([]byte, len(plain))
			if err := ApplyTCPAt(suite, &key, &nonce, 0, full, plain); err != nil {
				t.Fatal(err)
			}
			expected := append([]byte(nil), plain...)
			for _, r := range ranges {
				copy(expected[r[0]:r[1]], full[r[0]:r[1]])
			}

			// Seal in 7-byte chunks crossing record headers and payloads.
			encoded := append([]byte(nil), plain...)
			sealCipher, err := newTCPCipher(suite, &key, &nonce)
			if err != nil {
				t.Fatal(err)
			}
			var sealState recordState
			for off := 0; off < len(encoded); off += 7 {
				end := off + 7
				if end > len(encoded) {
					end = len(encoded)
				}
				if err := sealState.apply(sealCipher, uint64(off), encoded[off:end], false); err != nil {
					t.Fatal(err)
				}
			}
			if !bytes.Equal(encoded, expected) {
				t.Fatalf("encoded mismatch for %s", suite)
			}

			// Open in 3-byte chunks.
			openCipher, err := newTCPCipher(suite, &key, &nonce)
			if err != nil {
				t.Fatal(err)
			}
			var openState recordState
			decoded := append([]byte(nil), encoded...)
			for off := 0; off < len(decoded); off += 3 {
				end := off + 3
				if end > len(decoded) {
					end = len(decoded)
				}
				if err := openState.apply(openCipher, uint64(off), decoded[off:end], true); err != nil {
					t.Fatal(err)
				}
			}
			if !bytes.Equal(decoded, plain) {
				t.Fatalf("decoded mismatch for %s", suite)
			}

			// One-shot public helper matches as well.
			oneShot := make([]byte, len(plain))
			if err := ApplyTCPCore(suite, &key, &nonce, false, oneShot, plain); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(oneShot, expected) {
				t.Fatalf("ApplyTCPCore seal mismatch for %s", suite)
			}
			if err := ApplyTCPCore(suite, &key, &nonce, true, oneShot, oneShot); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(oneShot, plain) {
				t.Fatalf("ApplyTCPCore in-place open mismatch for %s", suite)
			}
		})
	}
}

func TestCoreTCPCommitsOnlyAcceptedWriteBytes(t *testing.T) {
	// Mirrors Nowhere v3.5.0 src/tests/transport/morph/tcp.rs
	// core_commits_only_accepted_write_bytes.
	for _, suite := range []Cipher{CipherChaCha, CipherAES} {
		t.Run(suite.String(), func(t *testing.T) {
			keys, err := DeriveWithOptions([]byte("shared"), suite, GradeCore)
			if err != nil {
				t.Fatal(err)
			}
			var nonce [nonceLen]byte
			for i := range nonce {
				nonce[i] = 17
			}
			rc, err := newTCPCipher(suite, &keys.TCPS2C, &nonce)
			if err != nil {
				t.Fatal(err)
			}
			wc, err := newTCPCipher(suite, &keys.TCPC2S, &nonce)
			if err != nil {
				t.Fatal(err)
			}
			inner := &scriptedWriteConn{
				outcomes: []writeOutcome{
					{n: 2},
					{n: 0, err: nil},
					{n: 0, err: errors.New("would block")},
					{n: 0, err: errors.New("interrupted")},
					{n: 100},
				},
			}
			conn := &tcpConn{
				Conn:        inner,
				cipher:      suite,
				grade:       GradeCore,
				readKey:     keys.TCPS2C,
				writeKey:    keys.TCPC2S,
				nonce:       nonce,
				readCipher:  rc,
				writeCipher: wc,
			}
			accepted := []byte{23, 3, 3, 0, 3, 10, 20, 30, 22, 3, 3, 0, 1, 43}
			abandoned := []byte{1, 0, 1, 0xcc, 0xdd}

			if n, err := conn.Write(accepted); err != nil || n != 2 {
				t.Fatalf("first write = %d %v, want 2 nil", n, err)
			}
			if n, err := conn.Write(abandoned); !errors.Is(err, io.ErrShortWrite) || n != 0 {
				t.Fatalf("zero write = %d %v, want 0 io.ErrShortWrite", n, err)
			}
			if n, err := conn.Write(abandoned); err == nil || n != 0 {
				t.Fatalf("second write = %d %v, want 0 err", n, err)
			}
			if n, err := conn.Write(abandoned); err == nil || n != 0 {
				t.Fatalf("third write = %d %v, want 0 err", n, err)
			}
			if n, err := conn.Write(accepted[2:]); err != nil || n != 12 {
				t.Fatalf("fourth write = %d %v, want 12 nil", n, err)
			}

			expected := make([]byte, len(accepted))
			if err := ApplyTCPCore(suite, &keys.TCPC2S, &nonce, false, expected, accepted); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(inner.written, expected) {
				t.Fatalf("wire = %x, want %x", inner.written, expected)
			}
		})
	}
}

func TestCoreTCPSkippedPayloadStillExhaustsStream(t *testing.T) {
	// Mirrors Nowhere v3.5.0 src/tests/transport/morph/tcp.rs
	// core_skipped_payload_still_exhausts_the_stream.
	for _, suite := range []Cipher{CipherChaCha, CipherAES} {
		t.Run(suite.String(), func(t *testing.T) {
			keys, err := DeriveWithOptions([]byte("shared"), suite, GradeCore)
			if err != nil {
				t.Fatal(err)
			}
			var nonce [nonceLen]byte
			for i := range nonce {
				nonce[i] = 7
			}
			rc, err := newTCPCipher(suite, &keys.TCPS2C, &nonce)
			if err != nil {
				t.Fatal(err)
			}
			wc, err := newTCPCipher(suite, &keys.TCPC2S, &nonce)
			if err != nil {
				t.Fatal(err)
			}
			clientSide, serverSide := net.Pipe()
			defer clientSide.Close()
			defer serverSide.Close()
			conn := &tcpConn{
				Conn:        clientSide,
				cipher:      suite,
				grade:       GradeCore,
				readKey:     keys.TCPS2C,
				writeKey:    keys.TCPC2S,
				nonce:       nonce,
				readCipher:  rc,
				writeCipher: wc,
			}

			go func() {
				_, _ = io.Copy(io.Discard, serverSide)
			}()

			if n, err := conn.Write([]byte{23, 3, 3, 0, 10}); err != nil || n != 5 {
				t.Fatalf("header write = %d %v", n, err)
			}
			conn.writeOff = conn.writeCipher.limit() - 1
			n, err := conn.Write([]byte{1, 2})
			if n != 1 || err == nil {
				t.Fatalf("boundary skipped write = %d %v, want 1 and exhaustion error", n, err)
			}
			if suite == CipherAES && !strings.Contains(err.Error(), "AES") {
				t.Fatalf("unexpected AES error: %v", err)
			}
			if n, err := conn.Write([]byte{2}); n != 0 || err == nil {
				t.Fatalf("exhausted skipped write = %d %v, want 0 and error", n, err)
			}
			if n, err := conn.Write(nil); n != 0 || err != nil {
				t.Fatalf("empty write after exhaustion = %d %v, want 0 nil", n, err)
			}

			// Verify receive side also exhausts on skipped payload bytes.
			readClient, readServer := net.Pipe()
			defer readClient.Close()
			defer readServer.Close()
			rc2, err := newTCPCipher(suite, &keys.TCPS2C, &nonce)
			if err != nil {
				t.Fatal(err)
			}
			wc2, err := newTCPCipher(suite, &keys.TCPC2S, &nonce)
			if err != nil {
				t.Fatal(err)
			}
			reader := &tcpConn{
				Conn:        readClient,
				cipher:      suite,
				grade:       GradeCore,
				readKey:     keys.TCPS2C,
				writeKey:    keys.TCPC2S,
				nonce:       nonce,
				readCipher:  rc2,
				writeCipher: wc2,
			}
			hdr := []byte{23, 3, 3, 0, 10}
			maskedHdr := make([]byte, len(hdr))
			if err := ApplyTCPCore(suite, &keys.TCPS2C, &nonce, false, maskedHdr, hdr); err != nil {
				t.Fatal(err)
			}
			go func() {
				_, _ = readServer.Write(maskedHdr)
				_, _ = readServer.Write([]byte{0xaa, 0xbb})
			}()
			gotHdr := make([]byte, 5)
			if _, err := io.ReadFull(reader, gotHdr); err != nil || !bytes.Equal(gotHdr, hdr) {
				t.Fatalf("read header = %x %v", gotHdr, err)
			}
			reader.readOff = reader.readCipher.limit() - 1
			buf := make([]byte, 2)
			if n, err := reader.Read(buf); err != nil || n != 1 || buf[0] != 0xaa {
				t.Fatalf("boundary skipped read = %d %x %v, want 1 [aa] nil", n, buf[:n], err)
			}
			if n, err := reader.Read(buf); n != 0 || err == nil {
				t.Fatalf("exhausted skipped read = %d %v, want 0 and error", n, err)
			}
			if n, err := reader.Read(nil); n != 0 || err != nil {
				t.Fatalf("empty read after exhaustion = %d %v, want 0 nil", n, err)
			}
		})
	}
}

func TestCoreTCPFullRoundTripAndGradeMismatch(t *testing.T) {
	for _, suite := range []Cipher{CipherChaCha, CipherAES} {
		t.Run(suite.String(), func(t *testing.T) {
			keys, err := DeriveWithOptions([]byte("0123456789abcdef0123456789abcdef"), suite, GradeCore)
			if err != nil {
				t.Fatal(err)
			}
			hello := splitRecords(minimalClientHello())
			appData := append([]byte{23, 3, 3, 0, 24}, bytes.Repeat([]byte("A"), 24)...)
			appData2 := append([]byte{23, 3, 3, 0, 0}, []byte{23, 3, 3, 0, 12}...)
			appData2 = append(appData2, bytes.Repeat([]byte("B"), 12)...)
			payload := append(append(append([]byte(nil), hello...), appData...), appData2...)

			clientSide, serverSide := net.Pipe()
			defer clientSide.Close()
			defer serverSide.Close()
			client, err := WrapTCPClient(clientSide, keys)
			if err != nil {
				t.Fatal(err)
			}
			server := WrapTCPServer(serverSide, keys)

			errCh := make(chan error, 1)
			go func() {
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(server, got); err != nil {
					errCh <- err
					return
				}
				if !bytes.Equal(got, payload) {
					errCh <- errors.New("server payload mismatch")
					return
				}
				_, err := server.Write(appData)
				errCh <- err
			}()
			if _, err := client.Write(payload); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, len(appData))
			if _, err := io.ReadFull(client, reply); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(reply, appData) {
				t.Fatalf("client read mismatch")
			}
			if err := <-errCh; err != nil {
				t.Fatal(err)
			}

			// Grade mismatch: ClientHello (type 22) matches, but AppData (type 23) diverges.
			fullKeys, err := DeriveWithOptions([]byte("0123456789abcdef0123456789abcdef"), suite, GradeFull)
			if err != nil {
				t.Fatal(err)
			}
			c2, s2 := net.Pipe()
			defer c2.Close()
			defer s2.Close()
			coreClient, err := WrapTCPClient(c2, keys)
			if err != nil {
				t.Fatal(err)
			}
			fullServer := WrapTCPServer(s2, fullKeys)
			gotCh := make(chan []byte, 1)
			go func() {
				buf := make([]byte, len(hello)+len(appData))
				_, _ = io.ReadFull(fullServer, buf)
				gotCh <- buf
			}()
			if _, err := coreClient.Write(append(append([]byte(nil), hello...), appData...)); err != nil {
				t.Fatal(err)
			}
			got := <-gotCh
			if !bytes.Equal(got[:len(hello)], hello) {
				t.Fatal("ClientHello unexpectedly differed between Core and Full")
			}
			if bytes.Equal(got[len(hello)+5:], appData[5:]) {
				t.Fatal("AppData payload unexpectedly matched across Core and Full")
			}
		})
	}
}

func TestCoreDatagramMasksExpectedRangesAtAbsoluteOffsets(t *testing.T) {
	// Mirrors Nowhere v3.5.0 src/tests/transport/morph/cipher.rs
	// core_datagram_masks_the_expected_ranges_at_absolute_offsets.
	var key [32]byte
	for i := range key {
		key[i] = 12
	}
	var nonce [12]byte
	for i := range nonce {
		nonce[i] = 5
	}
	for _, suite := range []Cipher{CipherChaCha, CipherAES} {
		for _, first := range []byte{0x40, 0xc0} {
			for _, length := range []int{1, 40, 41, 42, 139} {
				plain := bytes.Repeat([]byte{0x27}, length)
				plain[0] = first

				full := make([]byte, length)
				if err := ApplyDatagramWithGrade(suite, GradeFull, false, &key, &nonce, full, plain); err != nil {
					t.Fatal(err)
				}
				core := make([]byte, length)
				if err := ApplyDatagramWithGrade(suite, GradeCore, false, &key, &nonce, core, plain); err != nil {
					t.Fatal(err)
				}
				expected := append([]byte(nil), full...)
				if first&0x80 == 0 && length > 41 {
					copy(expected[25:length-16], plain[25:length-16])
				}
				if !bytes.Equal(core, expected) {
					t.Fatalf("%s first=%#x len=%d core seal mismatch", suite, first, length)
				}

				opened := make([]byte, length)
				if err := ApplyDatagramWithGrade(suite, GradeCore, true, &key, &nonce, opened, core); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(opened, plain) {
					t.Fatalf("%s first=%#x len=%d core open mismatch", suite, first, length)
				}

				// Verify in-place aliasing matches as well.
				inPlace := append([]byte(nil), plain...)
				if err := ApplyDatagramWithGrade(suite, GradeCore, false, &key, &nonce, inPlace, inPlace); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(inPlace, expected) {
					t.Fatalf("%s first=%#x len=%d in-place seal mismatch", suite, first, length)
				}
				if err := ApplyDatagramWithGrade(suite, GradeCore, true, &key, &nonce, inPlace, inPlace); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(inPlace, plain) {
					t.Fatalf("%s first=%#x len=%d in-place open mismatch", suite, first, length)
				}
			}
		}
	}
}

func TestCoreUDPRoundTripAndVersionFilter(t *testing.T) {
	for _, suite := range []Cipher{CipherChaCha, CipherAES} {
		t.Run(suite.String(), func(t *testing.T) {
			keys, err := DeriveWithOptions([]byte("0123456789abcdef0123456789abcdef"), suite, GradeCore)
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

			rejectedLong := append([]byte{0xc0, 0x0a, 0x1a, 0x2a, 0x3a}, bytes.Repeat([]byte{0x55}, 60)...)
			acceptedLong := append([]byte{0xc0, 0x00, 0x00, 0x00, 0x01}, bytes.Repeat([]byte{0x33}, 60)...)
			acceptedShortSmall := append([]byte{0x40}, bytes.Repeat([]byte{0x44}, 40)...)
			acceptedShortLarge := append([]byte{0x40}, bytes.Repeat([]byte{0x66}, 119)...)

			errCh := make(chan error, 1)
			go func() {
				for _, pkt := range [][]byte{rejectedLong, acceptedLong, acceptedShortSmall, acceptedShortLarge} {
					if _, err := client.WriteTo(pkt, nil); err != nil {
						errCh <- err
						return
					}
				}
				errCh <- nil
			}()

			buf := make([]byte, 256)
			_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
			for _, want := range [][]byte{acceptedLong, acceptedShortSmall, acceptedShortLarge} {
				n, _, err := server.ReadFrom(buf)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(buf[:n], want) {
					t.Fatalf("server read len=%d mismatch", n)
				}
			}
			if err := <-errCh; err != nil {
				t.Fatal(err)
			}

			go func() {
				_, _ = server.WriteTo(acceptedShortLarge, nil)
			}()
			n, _, err := client.ReadFrom(buf)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(buf[:n], acceptedShortLarge) {
				t.Fatalf("client read mismatch")
			}
		})
	}
}

func TestReplayLazyInitAndRepeatedRotation(t *testing.T) {
	reg := newReplayRegistry()
	if len(reg.slots) != 0 || reg.count != 0 {
		t.Fatalf("fresh registry slots=%d count=%d, want 0", len(reg.slots), reg.count)
	}
	if !reg.precheck(1, 1) || len(reg.slots) != 0 {
		t.Fatal("precheck initialized slots")
	}
	if !reg.commit(1, 1) || len(reg.slots) != 1 {
		t.Fatalf("first commit slots=%d, want 1", len(reg.slots))
	}
	for id := uint64(2); id <= replayCapacity; id++ {
		if !reg.commit(id, 1) {
			t.Fatalf("fill commit %d failed", id)
		}
	}
	if len(reg.slots) != replayCapacity || reg.start != 0 {
		t.Fatalf("full registry slots=%d start=%d", len(reg.slots), reg.start)
	}
	// Rotate through more than two full capacities and verify bounded storage.
	for id := uint64(replayCapacity + 1); id <= uint64(replayCapacity*3+7); id++ {
		if !reg.commit(id, 1) {
			t.Fatalf("rotation commit %d failed", id)
		}
		if reg.commit(id, 1) {
			t.Fatalf("duplicate after rotation %d accepted", id)
		}
	}
	if len(reg.slots) != replayCapacity || len(reg.index) != replayCapacity || reg.count != replayCapacity {
		t.Fatalf("post-rotation slots=%d index=%d count=%d, want %d", len(reg.slots), len(reg.index), reg.count, replayCapacity)
	}
	// Oldest surviving identity is (3*replayCapacity+7) - replayCapacity + 1.
	oldestSurviving := uint64(replayCapacity*2 + 8)
	if !reg.precheck(oldestSurviving-1, 1) {
		t.Fatalf("evicted identity %d still rejected", oldestSurviving-1)
	}
	if reg.precheck(oldestSurviving, 1) {
		t.Fatalf("surviving identity %d unexpectedly accepted", oldestSurviving)
	}
}
