package wire

import (
	"bytes"
	"testing"
)

func TestMuxHeaderStableStreamSYNVector(t *testing.T) {
	header, err := StreamMuxHeader(0x01020304, MuxFlagSYN, 0x0506)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeMuxHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	want := [MuxHeaderLen]byte{1, MuxFlagSYN, 0x05, 0x06, 1, 2, 3, 4}
	if encoded != want {
		t.Fatalf("got %x want %x", encoded[:], want[:])
	}
	decoded, err := DecodeMuxHeader(encoded[:])
	if err != nil {
		t.Fatal(err)
	}
	if decoded != header {
		t.Fatalf("decoded %+v want %+v", decoded, header)
	}
}

func TestMuxHeaderWindowAcceptsZeroFlowID(t *testing.T) {
	if _, err := WindowMuxHeader(0, 1); err != nil {
		t.Fatalf("connection window: %v", err)
	}
	if _, err := StreamMuxHeader(0, 0, 1); err == nil {
		t.Fatal("stream accepted zero flow id")
	}
	if _, err := DatagramMuxHeader(0, 1); err == nil {
		t.Fatal("datagram accepted zero flow id")
	}
}

func TestMuxHeaderResetIsExclusiveAndEmpty(t *testing.T) {
	if _, err := StreamMuxHeader(1, MuxFlagRST, 0); err != nil {
		t.Fatalf("rst: %v", err)
	}
	if _, err := StreamMuxHeader(1, MuxFlagRST|MuxFlagFIN, 0); err == nil {
		t.Fatal("rst+fin accepted")
	}
	if _, err := StreamMuxHeader(1, MuxFlagRST, 1); err == nil {
		t.Fatal("rst with payload accepted")
	}
}

func TestMuxMarkerCannotBeFlowHeaderFlags(t *testing.T) {
	if _, err := DecodeFlowHeader([]byte{MuxMarker, 0, 0, 0, 1}); err == nil {
		t.Fatal("0xff decoded as a flow header")
	}
}

func TestReadMuxHeaderLeavesPayload(t *testing.T) {
	header, err := StreamMuxHeader(7, MuxFlagSYN, 0)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeMuxHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	input := append(encoded[:], []byte("payload")...)
	decoded, err := ReadMuxHeader(bytes.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if decoded != header {
		t.Fatalf("decoded %+v want %+v", decoded, header)
	}
}
