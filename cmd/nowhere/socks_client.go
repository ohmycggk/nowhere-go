package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/ohmycggk/nowhere-go/wire"
)

// socksDialer is a Portal outbound Dialer that sends all TCP and UDP target
// traffic through a SOCKS5 proxy. There is no direct fallback.
type socksDialer struct {
	addr string
	user string
	pass string
	d    net.Dialer
}

func (s *socksDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return s.dialTCP(ctx, address)
	case "udp", "udp4", "udp6":
		return s.dialUDP(ctx, address)
	default:
		return nil, fmt.Errorf("socks outbound: unsupported network %s", network)
	}
}

func (s *socksDialer) dialTCP(ctx context.Context, address string) (net.Conn, error) {
	target, err := parseDialTarget(address)
	if err != nil {
		return nil, err
	}
	conn, err := s.d.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if err := socksClientHandshake(conn, s.user, s.pass); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := socksClientCommand(conn, socksCmdConnect, target); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func (s *socksDialer) dialUDP(ctx context.Context, address string) (net.Conn, error) {
	target, err := parseDialTarget(address)
	if err != nil {
		return nil, err
	}
	control, err := s.d.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = control.SetDeadline(dl)
	}
	ok := false
	defer func() {
		if !ok {
			_ = control.Close()
		}
	}()
	if err := socksClientHandshake(control, s.user, s.pass); err != nil {
		return nil, err
	}
	unspec := unspecifiedTarget(control.RemoteAddr())
	bindHost, bindPort, err := socksClientUDPAssociate(control, unspec)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(bindHost); ip != nil && ip.IsUnspecified() {
		proxyHost, _, splitErr := net.SplitHostPort(s.addr)
		if splitErr == nil {
			bindHost = proxyHost
		}
	}
	relay := net.JoinHostPort(bindHost, strconv.Itoa(bindPort))
	udp, err := net.Dial("udp", relay)
	if err != nil {
		return nil, err
	}
	_ = control.SetDeadline(time.Time{})
	ok = true
	return &socksUDPConn{control: control, udp: udp, target: target}, nil
}

func unspecifiedTarget(proxy net.Addr) []byte {
	host, _, _ := net.SplitHostPort(proxy.String())
	ip := net.ParseIP(host)
	if ip != nil && ip.To4() == nil {
		return []byte{socksAtypIPv6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	}
	return []byte{socksAtypIPv4, 0, 0, 0, 0, 0, 0}
}

func parseDialTarget(address string) (wire.Target, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return wire.Target{}, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return wire.Target{}, fmt.Errorf("invalid target port")
	}
	if ip := net.ParseIP(host); ip != nil {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			return wire.Target{}, fmt.Errorf("invalid ip target")
		}
		return wire.NewIPTarget(addr.Unmap(), uint16(port))
	}
	return wire.NewDomainTarget(host, uint16(port))
}

func socksClientHandshake(rw io.ReadWriter, user, pass string) error {
	method := byte(socksAuthNone)
	if user != "" {
		method = socksAuthPass
	}
	if _, err := rw.Write([]byte{socksVer5, 1, method}); err != nil {
		return err
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(rw, rep); err != nil {
		return err
	}
	if rep[0] != socksVer5 || rep[1] != method {
		return fmt.Errorf("socks proxy rejected auth method")
	}
	if method == socksAuthPass {
		ubuf := []byte(user)
		pbuf := []byte(pass)
		req := make([]byte, 0, 3+len(ubuf)+len(pbuf))
		req = append(req, 0x01, byte(len(ubuf)))
		req = append(req, ubuf...)
		req = append(req, byte(len(pbuf)))
		req = append(req, pbuf...)
		if _, err := rw.Write(req); err != nil {
			return err
		}
		authRep := make([]byte, 2)
		if _, err := io.ReadFull(rw, authRep); err != nil {
			return err
		}
		if authRep[1] != 0 {
			return fmt.Errorf("socks proxy authentication failed")
		}
	}
	return nil
}

func socksClientCommand(rw io.ReadWriter, cmd byte, target wire.Target) error {
	addr, err := wire.EncodeTarget(target)
	if err != nil {
		return err
	}
	req := append([]byte{socksVer5, cmd, 0x00}, addr...)
	if _, err := rw.Write(req); err != nil {
		return err
	}
	_, _, _, err = socksReadBind(rw)
	return err
}

func socksClientUDPAssociate(rw io.ReadWriter, atypAddr []byte) (host string, port int, err error) {
	req := append([]byte{socksVer5, socksCmdUDP, 0x00}, atypAddr...)
	if _, err := rw.Write(req); err != nil {
		return "", 0, err
	}
	rep, host, port, err := socksReadBind(rw)
	if err != nil {
		return "", 0, err
	}
	if rep != 0 {
		return "", 0, fmt.Errorf("socks udp associate failed: reply %d", rep)
	}
	if port == 0 {
		return "", 0, fmt.Errorf("socks udp associate returned port 0")
	}
	return host, port, nil
}

func socksReadBind(r io.Reader) (rep byte, host string, port int, err error) {
	hdr := make([]byte, 4)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return 0, "", 0, err
	}
	if hdr[0] != socksVer5 {
		return 0, "", 0, fmt.Errorf("invalid socks reply")
	}
	rep = hdr[1]
	if rep != 0 {
		// Drain the bind address so the connection stays well-formed.
		_, _, _ = readSOCKSAddr(r, hdr[3])
		return rep, "", 0, fmt.Errorf("socks command failed: reply %d", rep)
	}
	host, port, err = readSOCKSAddr(r, hdr[3])
	return rep, host, port, err
}

func readSOCKSAddr(r io.Reader, atyp byte) (host string, port int, err error) {
	var addr []byte
	switch atyp {
	case socksAtypIPv4:
		addr = make([]byte, 4+2)
	case socksAtypIPv6:
		addr = make([]byte, 16+2)
	case socksAtypDomain:
		l := make([]byte, 1)
		if _, err = io.ReadFull(r, l); err != nil {
			return "", 0, err
		}
		addr = make([]byte, int(l[0])+2)
	default:
		return "", 0, fmt.Errorf("unsupported socks atyp %d", atyp)
	}
	if _, err = io.ReadFull(r, addr); err != nil {
		return "", 0, err
	}
	port = int(binary.BigEndian.Uint16(addr[len(addr)-2:]))
	switch atyp {
	case socksAtypIPv4:
		host = net.IP(addr[:4]).String()
	case socksAtypIPv6:
		host = net.IP(addr[:16]).String()
	case socksAtypDomain:
		host = string(addr[:len(addr)-2])
	}
	return host, port, nil
}

type socksUDPConn struct {
	control net.Conn
	udp     net.Conn
	target  wire.Target
}

func (c *socksUDPConn) Read(p []byte) (int, error) {
	buf := make([]byte, 3+1+255+2+len(p))
	n, err := c.udp.Read(buf)
	if err != nil {
		return 0, err
	}
	_, payload, err := decodeSocksUDP(buf[:n])
	if err != nil {
		return 0, err
	}
	return copy(p, payload), nil
}

func (c *socksUDPConn) Write(p []byte) (int, error) {
	pkt, err := encodeSocksUDP(c.target, p)
	if err != nil {
		return 0, err
	}
	if _, err := c.udp.Write(pkt); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *socksUDPConn) Close() error {
	err := c.udp.Close()
	_ = c.control.Close()
	return err
}

func (c *socksUDPConn) LocalAddr() net.Addr  { return c.udp.LocalAddr() }
func (c *socksUDPConn) RemoteAddr() net.Addr { return c.udp.RemoteAddr() }

func (c *socksUDPConn) SetDeadline(t time.Time) error {
	_ = c.control.SetDeadline(t)
	return c.udp.SetDeadline(t)
}
func (c *socksUDPConn) SetReadDeadline(t time.Time) error {
	return c.udp.SetReadDeadline(t)
}
func (c *socksUDPConn) SetWriteDeadline(t time.Time) error {
	return c.udp.SetWriteDeadline(t)
}
