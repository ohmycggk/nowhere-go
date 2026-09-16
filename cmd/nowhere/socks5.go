package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/ohmycggk/nowhere-go/wire"
)

const (
	socksVer5      = 0x05
	socksCmdConnect = 0x01
	socksCmdUDP     = 0x03
	socksAuthNone   = 0x00
	socksAuthPass   = 0x02
	socksAtypIPv4   = 0x01
	socksAtypDomain = 0x03
	socksAtypIPv6   = 0x04
)

func socksHandshake(rw io.ReadWriter, user, pass string) error {
	head := make([]byte, 2)
	if _, err := io.ReadFull(rw, head); err != nil {
		return err
	}
	if head[0] != socksVer5 {
		return fmt.Errorf("unsupported socks version %d", head[0])
	}
	nmethods := int(head[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(rw, methods); err != nil {
		return err
	}
	want := byte(socksAuthNone)
	if user != "" {
		want = socksAuthPass
	}
	ok := false
	for _, m := range methods {
		if m == want {
			ok = true
			break
		}
	}
	if !ok {
		_, _ = rw.Write([]byte{socksVer5, 0xff})
		return fmt.Errorf("socks auth method %d not offered", want)
	}
	if _, err := rw.Write([]byte{socksVer5, want}); err != nil {
		return err
	}
	if want == socksAuthPass {
		return socksUserPass(rw, user, pass)
	}
	return nil
}

func socksUserPass(rw io.ReadWriter, user, pass string) error {
	head := make([]byte, 2)
	if _, err := io.ReadFull(rw, head); err != nil {
		return err
	}
	if head[0] != 0x01 {
		return fmt.Errorf("unsupported socks auth version")
	}
	ulen := int(head[1])
	ubuf := make([]byte, ulen)
	if _, err := io.ReadFull(rw, ubuf); err != nil {
		return err
	}
	plenBuf := make([]byte, 1)
	if _, err := io.ReadFull(rw, plenBuf); err != nil {
		return err
	}
	pbuf := make([]byte, int(plenBuf[0]))
	if _, err := io.ReadFull(rw, pbuf); err != nil {
		return err
	}
	if string(ubuf) != user || string(pbuf) != pass {
		_, _ = rw.Write([]byte{0x01, 0x01})
		return fmt.Errorf("socks authentication failed")
	}
	_, err := rw.Write([]byte{0x01, 0x00})
	return err
}

func socksReadRequest(r io.Reader) (cmd byte, target wire.Target, err error) {
	hdr := make([]byte, 4)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return 0, wire.Target{}, err
	}
	if hdr[0] != socksVer5 {
		return 0, wire.Target{}, fmt.Errorf("invalid socks request")
	}
	cmd = hdr[1]
	rest := []byte{hdr[3]}
	switch hdr[3] {
	case socksAtypIPv4:
		buf := make([]byte, 4+2)
		if _, err = io.ReadFull(r, buf); err != nil {
			return 0, wire.Target{}, err
		}
		rest = append(rest, buf...)
	case socksAtypIPv6:
		buf := make([]byte, 16+2)
		if _, err = io.ReadFull(r, buf); err != nil {
			return 0, wire.Target{}, err
		}
		rest = append(rest, buf...)
	case socksAtypDomain:
		l := make([]byte, 1)
		if _, err = io.ReadFull(r, l); err != nil {
			return 0, wire.Target{}, err
		}
		buf := make([]byte, int(l[0])+2)
		if _, err = io.ReadFull(r, buf); err != nil {
			return 0, wire.Target{}, err
		}
		rest = append(rest, l[0])
		rest = append(rest, buf...)
	default:
		return 0, wire.Target{}, fmt.Errorf("unsupported atyp %d", hdr[3])
	}
	target, _, err = wire.DecodeTarget(rest)
	return cmd, target, err
}

func socksReply(w io.Writer, rep byte, addr net.Addr) error {
	buf := []byte{socksVer5, rep, 0x00}
	host, port := "0.0.0.0", 0
	if addr != nil {
		h, p, err := net.SplitHostPort(addr.String())
		if err == nil {
			host = h
			port, _ = strconv.Atoi(p)
		}
	}
	ip := net.ParseIP(host)
	switch {
	case ip != nil && ip.To4() != nil:
		buf = append(buf, socksAtypIPv4)
		buf = append(buf, ip.To4()...)
	case ip != nil:
		buf = append(buf, socksAtypIPv6)
		buf = append(buf, ip.To16()...)
	default:
		buf = append(buf, socksAtypIPv4, 0, 0, 0, 0)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	buf = append(buf, pb[:]...)
	_, err := w.Write(buf)
	return err
}

func decodeSocksUDP(pkt []byte) (wire.Target, []byte, error) {
	if len(pkt) < 7 || pkt[2] != 0 {
		return wire.Target{}, nil, fmt.Errorf("invalid socks udp packet")
	}
	target, n, err := wire.DecodeTarget(pkt[3:])
	if err != nil {
		return wire.Target{}, nil, err
	}
	return target, pkt[3+n:], nil
}

func encodeSocksUDP(target wire.Target, payload []byte) ([]byte, error) {
	addr, err := wire.EncodeTarget(target)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 3+len(addr)+len(payload))
	out = append(out, 0, 0, 0)
	out = append(out, addr...)
	out = append(out, payload...)
	return out, nil
}
