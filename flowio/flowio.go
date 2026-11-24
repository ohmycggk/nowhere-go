// Package flowio copies bounded streams and applies optional rate limits.
package flowio

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/ohmycggk/nowhere-go/internal/bufpool"
)

const copyBuf = bufpool.TCPSize

// Limiter is a token bucket in bytes per second. A nil or zero limiter is unlimited.
type Limiter struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

// NewMbps returns a limiter for the given megabits per second. Zero disables it.
func NewMbps(mbps int) *Limiter {
	if mbps <= 0 {
		return nil
	}
	rate := float64(mbps) * 1_000_000 / 8
	return &Limiter{rate: rate, burst: rate, tokens: rate, last: time.Now()}
}

// WaitN blocks until n bytes are allowed or ctx ends.
func (l *Limiter) WaitN(ctx context.Context, n int) error {
	if l == nil || l.rate <= 0 || n <= 0 {
		return nil
	}
	for {
		l.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(l.last).Seconds()
		l.last = now
		l.tokens += elapsed * l.rate
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
		if float64(n) <= l.tokens {
			l.tokens -= float64(n)
			l.mu.Unlock()
			return nil
		}
		need := float64(n) - l.tokens
		wait := time.Duration(need / l.rate * float64(time.Second))
		l.mu.Unlock()
		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// Relay copies both directions until one side ends, then half-closes the other.
func Relay(left, right io.ReadWriteCloser, leftToRight, rightToLeft *Limiter) {
	RelaySize(left, right, leftToRight, rightToLeft, copyBuf)
}

// RelaySize copies both directions with a caller-specified buffer size (for
// example NOW_TCP_DATA_BUF_SIZE) until one side ends, then half-closes the
// other. Zero or negative sizes use the pooled 32 KiB default.
func RelaySize(left, right io.ReadWriteCloser, leftToRight, rightToLeft *Limiter, bufSize int) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = CopySize(right, left, leftToRight, bufSize)
		closeWrite(right)
	}()
	go func() {
		defer wg.Done()
		_, _ = CopySize(left, right, rightToLeft, bufSize)
		closeWrite(left)
	}()
	wg.Wait()
}

// Copy copies src to dst using a pooled 32 KiB buffer, optionally rate-limited.
func Copy(dst io.Writer, src io.Reader, lim *Limiter) (int64, error) {
	return CopySize(dst, src, lim, copyBuf)
}

// CopySize copies src to dst with a buffer of bufSize bytes, optionally
// rate-limited. The default 32 KiB size borrows from a reusable pool.
func CopySize(dst io.Writer, src io.Reader, lim *Limiter, bufSize int) (int64, error) {
	var buf []byte
	if bufSize <= 0 || bufSize == copyBuf {
		bp := bufpool.GetTCP()
		defer bufpool.PutTCP(bp)
		buf = *bp
	} else {
		buf = make([]byte, bufSize)
	}
	var total int64
	ctx := context.Background()
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			if err := lim.WaitN(ctx, n); err != nil {
				return total, err
			}
			wn, werr := dst.Write(buf[:n])
			total += int64(wn)
			if werr != nil {
				return total, werr
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return total, nil
			}
			return total, rerr
		}
	}
}

func closeWrite(c io.Closer) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}
