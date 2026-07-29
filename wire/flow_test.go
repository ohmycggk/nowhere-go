package wire

import (
	"bytes"
	"testing"
)

func TestFlowHeaderFixedVectors(t *testing.T) {
	cases := []struct {
		name   string
		header FlowHeader
		want   [FlowHeaderLen]byte
	}{
		{
			"duplex-tcp-tls-tls",
			FlowHeader{Role: FlowRoleDuplex, FlowID: 0x01020304, Kind: FlowKindTCP, Uplink: CarrierTLSTCP, Downlink: CarrierTLSTCP},
			[FlowHeaderLen]byte{0x00, 1, 2, 3, 4},
		},
		{
			"open-udp-quic-tcp",
			FlowHeader{Role: FlowRoleOpen, FlowID: 0x11223344, Kind: FlowKindUDP, Uplink: CarrierQUIC, Downlink: CarrierTLSTCP},
			[FlowHeaderLen]byte{0x0d, 0x11, 0x22, 0x33, 0x44},
		},
		{
			"attach-udp-tcp-quic",
			FlowHeader{Role: FlowRoleAttach, FlowID: 7, Kind: FlowKindUDP, Uplink: CarrierTLSTCP, Downlink: CarrierQUIC},
			[FlowHeaderLen]byte{0x16, 0, 0, 0, 7},
		},
		{
			"duplex-udp-quic-quic",
			FlowHeader{Role: FlowRoleDuplex, FlowID: 0x01020304, Kind: FlowKindUDP, Uplink: CarrierQUIC, Downlink: CarrierQUIC},
			[FlowHeaderLen]byte{0x1c, 1, 2, 3, 4},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := WriteFlowHeader(tc.header)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if !bytes.Equal(got[:], tc.want[:]) {
				t.Fatalf("header mismatch\n got %x\nwant %x", got[:], tc.want[:])
			}
			decoded, err := DecodeFlowHeader(got[:])
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if decoded != tc.header {
				t.Fatalf("decoded mismatch\n got %+v\nwant %+v", decoded, tc.header)
			}
		})
	}
}

func TestFlowHeaderRejectsInvalid(t *testing.T) {
	invalids := [][]byte{
		{},                 // empty
		{0, 0, 0, 0},       // short
		{0, 0, 0, 0, 0, 0}, // long
		{0, 0, 0, 0, 0},    // zero flow id
		{0x20, 0, 0, 0, 1}, // reserved bit
		{0x40, 0, 0, 0, 1}, // reserved bit
		{0x80, 0, 0, 0, 1}, // reserved bit
		{0x03, 0, 0, 0, 1}, // invalid role
		{0x10, 0, 0, 0, 1}, // duplex carrier mismatch
		{0x01, 0, 0, 0, 1}, // open split carrier match
	}
	for _, frame := range invalids {
		if _, err := DecodeFlowHeader(frame); err == nil {
			t.Fatalf("expected decode error for %x", frame)
		}
	}
}

func TestFlowHeaderValidateOnCarrier(t *testing.T) {
	open := FlowHeader{Role: FlowRoleOpen, FlowID: 1, Kind: FlowKindTCP, Uplink: CarrierTLSTCP, Downlink: CarrierQUIC}
	if err := open.ValidateOn(CarrierTLSTCP); err != nil {
		t.Fatalf("open on uplink carrier: %v", err)
	}
	if err := open.ValidateOn(CarrierQUIC); err == nil {
		t.Fatal("open accepted on downlink carrier")
	}
	attach := FlowHeader{Role: FlowRoleAttach, FlowID: 1, Kind: FlowKindTCP, Uplink: CarrierTLSTCP, Downlink: CarrierQUIC}
	if err := attach.ValidateOn(CarrierQUIC); err != nil {
		t.Fatalf("attach on downlink carrier: %v", err)
	}
	if err := attach.ValidateOn(CarrierTLSTCP); err == nil {
		t.Fatal("attach accepted on uplink carrier")
	}
	if open.CarriesTarget() != true {
		t.Fatal("open must carry target")
	}
	if attach.CarriesTarget() {
		t.Fatal("attach must not carry target")
	}
}

func TestFlowHeaderMaxFlowIDRoundTrips(t *testing.T) {
	header := FlowHeader{Role: FlowRoleDuplex, FlowID: 0xffffffff, Kind: FlowKindTCP, Uplink: CarrierQUIC, Downlink: CarrierQUIC}
	encoded, err := WriteFlowHeader(header)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeFlowHeader(encoded[:])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded != header {
		t.Fatalf("decoded mismatch\n got %+v\nwant %+v", decoded, header)
	}
}
