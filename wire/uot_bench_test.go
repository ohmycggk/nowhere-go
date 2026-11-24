package wire

import (
	"bytes"
	"testing"
)

type writeCountBuffer struct {
	bytes.Buffer
	writes int
}

func (b *writeCountBuffer) Write(p []byte) (int, error) {
	b.writes++
	return b.Buffer.Write(p)
}

func TestWriteUoTSingleWriteAndReadUoTInto(t *testing.T) {
	var w writeCountBuffer
	payload := bytes.Repeat([]byte("u"), 1200)
	if err := WriteUoT(&w, payload); err != nil {
		t.Fatal(err)
	}
	if w.writes != 1 {
		t.Fatalf("WriteUoT made %d Write calls, want 1", w.writes)
	}
	scratch := make([]byte, 2048)
	got, err := ReadUoTInto(&w, scratch)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("ReadUoTInto payload mismatch")
	}
	if &got[0] != &scratch[0] {
		t.Fatal("ReadUoTInto did not reuse caller buffer")
	}
}

func BenchmarkWriteReadUoT(b *testing.B) {
	var buf bytes.Buffer
	payload := make([]byte, 1200)
	scratch := make([]byte, 2048)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		if err := WriteUoT(&buf, payload); err != nil {
			b.Fatal(err)
		}
		if _, err := ReadUoTInto(&buf, scratch); err != nil {
			b.Fatal(err)
		}
	}
}
