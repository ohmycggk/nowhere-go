// Package bufpool provides bounded-size reusable byte-slice pools for hot
// TCP and UDP relay paths without introducing external dependencies.
package bufpool

import "sync"

const (
	// TCPSize is the default 32 KiB TCP stream copy buffer size.
	TCPSize = 32 << 10
	// UDPSize is the maximum single UDP datagram payload size (65535 bytes).
	UDPSize = 65535
)

var (
	tcpPool = sync.Pool{
		New: func() any {
			b := make([]byte, TCPSize)
			return &b
		},
	}
	udpPool = sync.Pool{
		New: func() any {
			b := make([]byte, UDPSize)
			return &b
		},
	}
)

// GetTCP borrows a 32 KiB scratch buffer. Call PutTCP when done.
func GetTCP() *[]byte {
	bp := tcpPool.Get().(*[]byte)
	*bp = (*bp)[:TCPSize]
	return bp
}

// PutTCP returns a 32 KiB buffer borrowed from GetTCP. Oversized or undersized
// buffers are dropped so the pool never retains high-water allocations.
func PutTCP(bp *[]byte) {
	if bp == nil || cap(*bp) != TCPSize {
		return
	}
	*bp = (*bp)[:TCPSize]
	tcpPool.Put(bp)
}

// GetUDP borrows a 65535-byte scratch buffer for UDP datagrams. Call PutUDP
// when done.
func GetUDP() *[]byte {
	bp := udpPool.Get().(*[]byte)
	*bp = (*bp)[:UDPSize]
	return bp
}

// PutUDP returns a 65535-byte buffer borrowed from GetUDP.
func PutUDP(bp *[]byte) {
	if bp == nil || cap(*bp) != UDPSize {
		return
	}
	*bp = (*bp)[:UDPSize]
	udpPool.Put(bp)
}
