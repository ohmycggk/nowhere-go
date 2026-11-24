package morph

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func TestReplayRegistryPointerFreeFIFOEviction(t *testing.T) {
	reg := newReplayRegistry()
	for id := uint64(1); id <= replayCapacity; id++ {
		if !reg.commit(id, 1) {
			t.Fatalf("commit %d failed", id)
		}
	}
	if len(reg.slots) != replayCapacity || reg.count != replayCapacity {
		t.Fatalf("slots=%d count=%d, want %d", len(reg.slots), reg.count, replayCapacity)
	}
	// Evict the oldest 500 identities in strict FIFO order.
	for i := uint64(1); i <= 500; i++ {
		newID := replayCapacity + i
		if !reg.commit(newID, 1) {
			t.Fatalf("eviction commit %d failed", newID)
		}
		if !reg.precheck(i, 1) {
			t.Fatalf("evicted identity %d still rejected", i)
		}
		if reg.precheck(i+1, 1) {
			t.Fatalf("non-evicted identity %d unexpectedly accepted", i+1)
		}
	}
	if len(reg.slots) != replayCapacity || len(reg.index) != replayCapacity {
		t.Fatalf("after eviction: slots=%d index=%d, want %d", len(reg.slots), len(reg.index), replayCapacity)
	}
}

func TestUDPNonceGenUniqueAndReseeds(t *testing.T) {
	var g udpNonceGen
	if err := g.reseed(); err != nil {
		t.Fatal(err)
	}
	first, err := g.next()
	if err != nil {
		t.Fatal(err)
	}
	second, err := g.next()
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("consecutive UDP nonces collided")
	}
	// Trigger reseed at stream limit boundary.
	g.generated = chachaStreamLimit - nonceLen + 1
	oldSeed := g.seed
	if _, err := g.next(); err != nil {
		t.Fatal(err)
	}
	if g.generated != nonceLen {
		t.Fatalf("generated after reseed = %d, want %d", g.generated, nonceLen)
	}
	if g.seed == oldSeed {
		t.Fatal("seed did not change on reseed")
	}
}

func TestTCPWriteChunkedLargePayload(t *testing.T) {
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
			hello := minimalClientHello()
			large := bytes.Repeat([]byte("0123456789abcdef"), 6500) // > 100 KiB (> 32 KiB pool chunk)
			payload := append(append([]byte(nil), hello...), large...)
			errCh := make(chan error, 1)
			go func() {
				got := make([]byte, len(payload))
				_, err := io.ReadFull(server, got)
				if err == nil && !bytes.Equal(got, payload) {
					err = io.ErrUnexpectedEOF
				}
				errCh <- err
			}()
			if n, err := client.Write(payload); err != nil || n != len(payload) {
				t.Fatalf("Write = %d %v, want %d nil", n, err, len(payload))
			}
			if err := <-errCh; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func BenchmarkMorphTCPWriteChaCha(b *testing.B) { benchmarkMorphTCPWrite(b, CipherChaCha) }
func BenchmarkMorphTCPWriteAES(b *testing.B)    { benchmarkMorphTCPWrite(b, CipherAES) }

func benchmarkMorphTCPWrite(b *testing.B, c Cipher) {
	keys, err := DeriveWithCipher([]byte("0123456789abcdef0123456789abcdef"), c)
	if err != nil {
		b.Fatal(err)
	}
	conn, err := WrapTCPClient(discardConn{}, keys)
	if err != nil {
		b.Fatal(err)
	}
	payload := make([]byte, 16<<10)
	if _, err := conn.Write(payload); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := conn.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMorphUDPWriteChaCha(b *testing.B) { benchmarkMorphUDPWrite(b, CipherChaCha) }
func BenchmarkMorphUDPWriteAES(b *testing.B)    { benchmarkMorphUDPWrite(b, CipherAES) }

func benchmarkMorphUDPWrite(b *testing.B, c Cipher) {
	keys, err := DeriveWithCipher([]byte("0123456789abcdef0123456789abcdef"), c)
	if err != nil {
		b.Fatal(err)
	}
	pc, err := WrapPacketConn(discardPacketConn{}, keys, true)
	if err != nil {
		b.Fatal(err)
	}
	payload := make([]byte, 1200)
	if _, err := pc.WriteTo(payload, nil); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := pc.WriteTo(payload, nil); err != nil {
			b.Fatal(err)
		}
	}
}

type discardConn struct{ net.Conn }

func (discardConn) Write(p []byte) (int, error) { return len(p), nil }

type discardPacketConn struct{ net.PacketConn }

func (discardPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
