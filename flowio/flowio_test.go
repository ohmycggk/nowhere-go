package flowio

import (
	"bytes"
	"io"
	"testing"
)

func TestCopySizeCustomAndPooled(t *testing.T) {
	data := bytes.Repeat([]byte("nowhere-flowio-"), 5000)
	for _, size := range []int{0, 4096, copyBuf, 64 << 10} {
		var dst bytes.Buffer
		n, err := CopySize(&dst, bytes.NewReader(data), nil, size)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if int(n) != len(data) || !bytes.Equal(dst.Bytes(), data) {
			t.Fatalf("size %d: copied %d bytes, want %d", size, n, len(data))
		}
	}
}

func BenchmarkCopy(b *testing.B) {
	data := make([]byte, 32<<10)
	var r bytes.Reader
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Reset(data)
		if _, err := Copy(io.Discard, &r, nil); err != nil {
			b.Fatal(err)
		}
	}
}
