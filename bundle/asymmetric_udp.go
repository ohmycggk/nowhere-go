package bundle

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ohmycggk/nowhere-go/wire"
)

func (b *CarrierBundle) openAsymmetricUDP(ctx context.Context, target wire.Target) (net.PacketConn, error) {
	up, down := b.cfg.up, b.cfg.down
	flowID, err := b.allocFlowID()
	if err != nil {
		return nil, err
	}
	started := time.Now()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	switch {
	case up == wire.CarrierTLSTCP && down == wire.CarrierQUIC:
		return b.openTCPUDP(ctx, cancel, target, flowID, up, down, started)
	case up == wire.CarrierQUIC && down == wire.CarrierTLSTCP:
		return b.openUDPTCP(ctx, cancel, target, flowID, up, down, started)
	default:
		return nil, errors.New("nowhere: asymmetric udp requires mixed carriers")
	}
}

// openTCPUDP: TCP uplink (UoT OPEN) + QUIC downlink (Attach).
func (b *CarrierBundle) openTCPUDP(
	ctx context.Context,
	cancel context.CancelFunc,
	target wire.Target,
	flowID wire.FlowID,
	up, down wire.Carrier,
	started time.Time,
) (net.PacketConn, error) {
	openHeader := wire.FlowHeader{Role: wire.FlowRoleOpen, FlowID: flowID, Kind: wire.FlowKindUDP, Uplink: up, Downlink: down}
	attachHeader := wire.FlowHeader{Role: wire.FlowRoleAttach, FlowID: flowID, Kind: wire.FlowKindUDP, Uplink: up, Downlink: down}

	pool, err := b.tcpPool()
	if err != nil {
		b.emitAsymmetric(ctx, "asymmetric_udp_open", flowID, target, up, down, 0, 0, started, err)
		return nil, fmtError("prepare tcp pool", err)
	}
	if pool == nil {
		return nil, errors.New("nowhere: tcp uplink carrier unavailable")
	}
	tcpHalf, err := pool.PrepareAuthenticatedFlowHalf(ctx, target, openHeader)
	if err != nil {
		b.emitAsymmetric(ctx, "asymmetric_udp_open", flowID, target, up, down, 0, 0, started, err)
		return nil, fmtError("prepare tcp open half", err)
	}
	tcpCarrierID := tcpHalf.CarrierID()
	defer func() {
		if tcpHalf != nil {
			_ = tcpHalf.Close()
		}
	}()

	quicPrep, err := b.prepareQUICStream(ctx, attachHeader.FlowID)
	if err != nil {
		cancel()
		b.emitAsymmetric(ctx, "asymmetric_udp_open", flowID, target, up, down, tcpCarrierID, 0, started, err)
		return nil, fmtError("prepare quic attach half", err)
	}
	defer func() {
		if quicPrep != nil {
			_ = quicPrep.Close()
		}
	}()

	tcpConn, err := tcpHalf.Commit()
	if err != nil {
		cancel()
		b.emitAsymmetric(ctx, "asymmetric_udp_open", flowID, target, up, down, tcpCarrierID, 0, started, err)
		return nil, fmtError("commit tcp open half", err)
	}
	tcpHalf = nil

	setupBytes, err := encodeFlowSetupBytes(attachHeader, wire.Target{})
	if err != nil {
		_ = tcpConn.Close()
		b.emitAsymmetric(ctx, "asymmetric_udp_open", flowID, target, up, down, tcpCarrierID, 0, started, err)
		return nil, fmtError("encode quic attach", err)
	}
	quicConn, err := commitQUICFlow(ctx, quicPrep, setupBytes)
	if err != nil {
		cancel()
		_ = tcpConn.Close()
		b.emitAsymmetric(ctx, "asymmetric_udp_open", flowID, target, up, down, tcpCarrierID, 0, started, err)
		return nil, fmtError("commit quic attach half", err)
	}
	quicHandle, err := newQUICDatagramHandle(quicPrep, flowID)
	if err != nil {
		cancel()
		_ = quicConn.Close()
		_ = tcpConn.Close()
		b.emitAsymmetric(ctx, "asymmetric_udp_open", flowID, target, up, down, tcpCarrierID, 0, started, err)
		return nil, fmtError("register quic udp flow", err)
	}
	quicPrep = nil

	uplink := &uotLaneUplink{raw: tcpConn}
	downlink := &quicLaneDownlink{prep: quicHandle}
	b.emitAsymmetric(ctx, "asymmetric_udp_open", flowID, target, up, down, tcpCarrierID, 0, started, nil)
	return &asymmetricPacketConn{
		dest:     target,
		uplink:   uplink,
		downlink: downlink,
		dnCloser: quicConn,
	}, nil
}

// openUDPTCP: QUIC uplink (OPEN) + TCP downlink (UoT Attach).
func (b *CarrierBundle) openUDPTCP(
	ctx context.Context,
	cancel context.CancelFunc,
	target wire.Target,
	flowID wire.FlowID,
	up, down wire.Carrier,
	started time.Time,
) (net.PacketConn, error) {
	openHeader := wire.FlowHeader{Role: wire.FlowRoleOpen, FlowID: flowID, Kind: wire.FlowKindUDP, Uplink: up, Downlink: down}
	attachHeader := wire.FlowHeader{Role: wire.FlowRoleAttach, FlowID: flowID, Kind: wire.FlowKindUDP, Uplink: up, Downlink: down}

	quicPrep, err := b.prepareQUICStream(ctx, openHeader.FlowID)
	if err != nil {
		b.emitAsymmetric(ctx, "asymmetric_udp_open", flowID, target, up, down, 0, 0, started, err)
		return nil, fmtError("prepare quic open half", err)
	}
	defer func() {
		if quicPrep != nil {
			_ = quicPrep.Close()
		}
	}()

	pool, err := b.tcpPool()
	if err != nil {
		cancel()
		b.emitAsymmetric(ctx, "asymmetric_udp_open", flowID, target, up, down, 0, 0, started, err)
		return nil, fmtError("prepare tcp pool", err)
	}
	if pool == nil {
		cancel()
		return nil, errors.New("nowhere: tcp downlink carrier unavailable")
	}
	tcpHalf, err := pool.PrepareAuthenticatedFlowHalf(ctx, wire.Target{}, attachHeader)
	if err != nil {
		cancel()
		b.emitAsymmetric(ctx, "asymmetric_udp_open", flowID, target, up, down, 0, 0, started, err)
		return nil, fmtError("prepare tcp attach half", err)
	}
	tcpCarrierID := tcpHalf.CarrierID()
	defer func() {
		if tcpHalf != nil {
			_ = tcpHalf.Close()
		}
	}()

	setupBytes, err := encodeFlowSetupBytes(openHeader, target)
	if err != nil {
		_ = tcpHalf.Close()
		b.emitAsymmetric(ctx, "asymmetric_udp_open", flowID, target, up, down, tcpCarrierID, 0, started, err)
		return nil, fmtError("encode quic open", err)
	}
	quicConn, err := commitQUICHalf(ctx, quicPrep, setupBytes, true)
	if err != nil {
		cancel()
		_ = tcpHalf.Close()
		b.emitAsymmetric(ctx, "asymmetric_udp_open", flowID, target, up, down, tcpCarrierID, 0, started, err)
		return nil, fmtError("commit quic open half", err)
	}
	quicHandle := newQUICSendHandle(quicPrep, flowID)
	quicPrep = nil

	tcpConn, err := tcpHalf.Commit()
	if err != nil {
		cancel()
		_ = quicConn.Close()
		b.emitAsymmetric(ctx, "asymmetric_udp_open", flowID, target, up, down, tcpCarrierID, 0, started, err)
		return nil, fmtError("commit tcp attach half", err)
	}
	tcpHalf = nil
	// 1.5 collapses the former UoT setup-result into a single SetupResult byte.
	if err := readSetupResult(tcpConn); err != nil {
		cancel()
		_ = quicConn.Close()
		_ = tcpConn.Close()
		b.emitAsymmetric(ctx, "asymmetric_udp_open", flowID, target, up, down, 0, tcpCarrierID, started, err)
		return nil, fmtError("read tcp downlink setup result", err)
	}

	uplink := &quicLaneUplink{prep: quicHandle}
	downlink := &uotLaneDownlink{raw: tcpConn}
	b.emitAsymmetric(ctx, "asymmetric_udp_open", flowID, target, up, down, 0, tcpCarrierID, started, nil)
	return &asymmetricPacketConn{
		dest:     target,
		uplink:   uplink,
		downlink: downlink,
		upCloser: quicConn,
	}, nil
}

// --- asymmetric UDP packet conn ---

type asymmetricPacketConn struct {
	dest     wire.Target
	uplink   udpUplink
	downlink udpDownlink
	upCloser io.Closer
	dnCloser io.Closer
}

func (a *asymmetricPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := a.downlink.ReadPacket(p)
	if err != nil {
		return n, nil, err
	}
	return n, targetToAddr(a.dest), nil
}

func (a *asymmetricPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return a.uplink.WritePacket(p)
}

func (a *asymmetricPacketConn) Close() error {
	var errs []error
	errs = append(errs, a.uplink.ClosePacket())
	if a.upCloser != nil {
		errs = append(errs, a.upCloser.Close())
	}
	errs = append(errs, a.downlink.ClosePacket())
	if a.dnCloser != nil {
		errs = append(errs, a.dnCloser.Close())
	}
	return errors.Join(errs...)
}

func (a *asymmetricPacketConn) LocalAddr() net.Addr { return &net.UDPAddr{} }

func (a *asymmetricPacketConn) SetDeadline(t time.Time) error {
	if err := a.SetReadDeadline(t); err != nil {
		return err
	}
	return a.SetWriteDeadline(t)
}
func (a *asymmetricPacketConn) SetReadDeadline(t time.Time) error {
	if d, ok := a.downlink.(interface{ SetReadDeadline(time.Time) error }); ok {
		return d.SetReadDeadline(t)
	}
	return nil
}
func (a *asymmetricPacketConn) SetWriteDeadline(t time.Time) error {
	if d, ok := a.uplink.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return d.SetWriteDeadline(t)
	}
	return nil
}

var _ net.PacketConn = (*asymmetricPacketConn)(nil)

// --- UoT lanes ---

type uotLaneUplink struct {
	raw        net.Conn
	writerOnce sync.Once
	writer     *uotStreamWriter
}

func (u *uotLaneUplink) streamWriter() *uotStreamWriter {
	u.writerOnce.Do(func() {
		u.writer = &uotStreamWriter{conn: u.raw}
	})
	return u.writer
}

func (u *uotLaneUplink) WritePacket(p []byte) (int, error) {
	return u.streamWriter().WritePacket(p)
}

func (u *uotLaneUplink) ClosePacket() error { return u.streamWriter().Close() }

func (u *uotLaneUplink) SetWriteDeadline(t time.Time) error {
	return u.raw.SetWriteDeadline(t)
}

type uotLaneDownlink struct {
	raw net.Conn
	mu  sync.Mutex
}

func (d *uotLaneDownlink) ReadPacket(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	payload, err := wire.ReadUDPPacket(d.raw)
	if err != nil {
		return 0, err
	}
	if payload == nil {
		// clean EOF: peer half-closed.
		return 0, io.EOF
	}
	return copy(p, payload), nil
}

func (d *uotLaneDownlink) ClosePacket() error { return d.raw.Close() }

func (d *uotLaneDownlink) SetReadDeadline(t time.Time) error {
	return d.raw.SetReadDeadline(t)
}

// --- QUIC datagram lanes ---

type quicLaneUplink struct {
	prep   *qSessionHandle
	nextID atomic.Uint32
}

func (u *quicLaneUplink) WritePacket(p []byte) (int, error) {
	return writeQUICUDPPacket(u.prep, u.prep.flowID, &u.nextID, p)
}

func (u *quicLaneUplink) ClosePacket() error {
	return u.prep.closePacket()
}

func (u *quicLaneUplink) SetWriteDeadline(t time.Time) error {
	return u.prep.setWriteDeadline(t)
}

type quicLaneDownlink struct {
	prep *qSessionHandle
}

func (d *quicLaneDownlink) ReadPacket(p []byte) (int, error) {
	payload, err := d.prep.readPacket(context.Background())
	if err != nil {
		return 0, err
	}
	return copy(p, payload), nil
}

func (d *quicLaneDownlink) ClosePacket() error {
	return d.prep.closePacket()
}

func (d *quicLaneDownlink) SetReadDeadline(t time.Time) error {
	return d.prep.setReadDeadline(t)
}
