package main

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type addressFamily uint8

const (
	familyAny addressFamily = iota
	familyV4
	familyV6
)

type carrierEndpoint struct {
	port   int
	family addressFamily
}

type serviceEndpoint struct {
	host string
	tcp  *carrierEndpoint
	udp  *carrierEndpoint
}

func parseServiceEndpoint(u *url.URL, allowWildcard bool, context string) (serviceEndpoint, error) {
	host := strings.Trim(u.Hostname(), "[]")
	if host == "" {
		if u.Path != "" && u.Path != "/" {
			return serviceEndpoint{}, fmt.Errorf("%s: missing host", context)
		}
		if !allowWildcard {
			return serviceEndpoint{}, fmt.Errorf("%s: missing host", context)
		}
		host = "*"
	}
	if host == "*" && !allowWildcard {
		return serviceEndpoint{}, fmt.Errorf("%s: wildcard host is only valid for Portal listeners", context)
	}

	var tcp, udp *carrierEndpoint
	if u.Path == "" || u.Path == "/" {
		if u.Port() == "" {
			return serviceEndpoint{}, fmt.Errorf("%s: missing port", context)
		}
		port, err := strconv.Atoi(u.Port())
		if err != nil || port <= 0 || port > 65535 {
			return serviceEndpoint{}, fmt.Errorf("%s: invalid port", context)
		}
		ep := carrierEndpoint{port: port, family: familyAny}
		tcp, udp = &ep, &ep
	} else {
		if u.Port() != "" {
			return serviceEndpoint{}, fmt.Errorf("%s: choose either HOST:PORT or HOST/CARRIER:PORT", context)
		}
		var err error
		tcp, udp, err = parseCarrierPath(u.Path, context)
		if err != nil {
			return nilEndpoint(), err
		}
	}
	ep := serviceEndpoint{host: host, tcp: tcp, udp: udp}
	if err := ep.validateLiteralFamilies(context); err != nil {
		return serviceEndpoint{}, err
	}
	return ep, nil
}

func nilEndpoint() serviceEndpoint { return serviceEndpoint{} }

func parseCarrierPath(path, context string) (*carrierEndpoint, *carrierEndpoint, error) {
	path = strings.TrimPrefix(path, "/")
	if path == "" || strings.HasSuffix(path, "/") {
		return nil, nil, fmt.Errorf("%s: empty or trailing carrier path", context)
	}
	var tcp, udp *carrierEndpoint
	for _, seg := range strings.Split(path, "/") {
		if seg == "" {
			return nil, nil, fmt.Errorf("%s: empty carrier path segment", context)
		}
		name, portStr, ok := strings.Cut(seg, ":")
		if !ok || portStr == "" {
			return nil, nil, fmt.Errorf("%s: invalid carrier segment %q", context, seg)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			return nil, nil, fmt.Errorf("%s: invalid port in %q", context, seg)
		}
		switch name {
		case "tcp", "tcp4", "tcp6":
			if tcp != nil {
				return nil, nil, fmt.Errorf("%s: duplicate TCP carrier", context)
			}
			tcp = &carrierEndpoint{port: port, family: familyFromName(name)}
		case "udp", "udp4", "udp6":
			if udp != nil {
				return nil, nil, fmt.Errorf("%s: duplicate UDP carrier", context)
			}
			udp = &carrierEndpoint{port: port, family: familyFromName(name)}
		default:
			return nil, nil, fmt.Errorf("%s: unknown carrier %q", context, name)
		}
	}
	if tcp == nil && udp == nil {
		return nil, nil, fmt.Errorf("%s: no carriers declared", context)
	}
	return tcp, udp, nil
}

func familyFromName(name string) addressFamily {
	switch name {
	case "tcp4", "udp4":
		return familyV4
	case "tcp6", "udp6":
		return familyV6
	default:
		return familyAny
	}
}

func (e serviceEndpoint) validateLiteralFamilies(context string) error {
	ip := net.ParseIP(e.host)
	if ip == nil {
		return nil
	}
	for _, ep := range []*carrierEndpoint{e.tcp, e.udp} {
		if ep == nil {
			continue
		}
		if ep.family == familyV4 && ip.To4() == nil {
			return fmt.Errorf("%s: address family does not match host %s", context, ip)
		}
		if ep.family == familyV6 && ip.To4() != nil {
			return fmt.Errorf("%s: address family does not match host %s", context, ip)
		}
	}
	return nil
}

func (e serviceEndpoint) hasTCP() bool { return e.tcp != nil }
func (e serviceEndpoint) hasUDP() bool { return e.udp != nil }

func (e serviceEndpoint) tcpAddr() string {
	if e.tcp == nil {
		return ""
	}
	return net.JoinHostPort(displayHost(e.host), strconv.Itoa(e.tcp.port))
}

func (e serviceEndpoint) udpAddr() string {
	if e.udp == nil {
		return ""
	}
	return net.JoinHostPort(displayHost(e.host), strconv.Itoa(e.udp.port))
}

func displayHost(host string) string {
	if host == "*" {
		return ""
	}
	return host
}

func listenHosts(host string, family addressFamily) []string {
	switch host {
	case "*", "":
		switch family {
		case familyV4:
			return []string{"0.0.0.0"}
		case familyV6:
			return []string{"::"}
		default:
			return []string{"0.0.0.0", "::"}
		}
	default:
		return []string{host}
	}
}
