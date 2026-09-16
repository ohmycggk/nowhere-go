package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
)

type acceptResult struct {
	c   net.Conn
	err error
}

type fanListener struct {
	listeners []net.Listener
	ch        chan acceptResult
	addr      net.Addr
	once      sync.Once
}

func listenAll(network string, hosts []string, port int, log *logger) (net.Listener, []string, error) {
	var listeners []net.Listener
	var bound []string
	for _, host := range hosts {
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		ln, err := net.Listen(networkFor(network, host), addr)
		if err != nil {
			if log != nil {
				log.warn("listen %s: %v", addr, err)
			}
			continue
		}
		listeners = append(listeners, ln)
		bound = append(bound, ln.Addr().String())
		if log != nil {
			log.info("listening %s %s", network, ln.Addr())
		}
	}
	if len(listeners) == 0 {
		return nil, nil, fmt.Errorf("failed to bind any %s address on port %d", network, port)
	}
	if len(listeners) == 1 {
		return listeners[0], bound, nil
	}
	f := &fanListener{listeners: listeners, ch: make(chan acceptResult), addr: listeners[0].Addr()}
	for _, ln := range listeners {
		go func(ln net.Listener) {
			for {
				c, err := ln.Accept()
				f.ch <- acceptResult{c, err}
				if err != nil {
					return
				}
			}
		}(ln)
	}
	return f, bound, nil
}

func networkFor(base, host string) string {
	ip := net.ParseIP(host)
	if ip == nil {
		return base
	}
	if ip.To4() != nil {
		if base == "udp" {
			return "udp4"
		}
		return "tcp4"
	}
	if base == "udp" {
		return "udp6"
	}
	return "tcp6"
}

func (f *fanListener) Accept() (net.Conn, error) {
	res := <-f.ch
	return res.c, res.err
}

func (f *fanListener) Close() error {
	var err error
	f.once.Do(func() {
		for _, ln := range f.listeners {
			if e := ln.Close(); e != nil && err == nil {
				err = e
			}
		}
	})
	return err
}

func (f *fanListener) Addr() net.Addr { return f.addr }

func listenUDPPacket(host string, port int, family addressFamily, log *logger) ([]net.PacketConn, []string, error) {
	var pcs []net.PacketConn
	var bound []string
	for _, h := range listenHosts(host, family) {
		addr := net.JoinHostPort(h, strconv.Itoa(port))
		pc, err := net.ListenPacket(networkFor("udp", h), addr)
		if err != nil {
			if log != nil {
				log.warn("listen udp %s: %v", addr, err)
			}
			continue
		}
		pcs = append(pcs, pc)
		bound = append(bound, pc.LocalAddr().String())
		if log != nil {
			log.info("listening udp %s", pc.LocalAddr())
		}
	}
	if len(pcs) == 0 {
		return nil, nil, fmt.Errorf("failed to bind any UDP address on port %d", port)
	}
	return pcs, bound, nil
}

func waitDone(ctx context.Context, errCh <-chan error) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}
