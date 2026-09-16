package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"github.com/ohmycggk/nowhere-go/wire"
)

func loadServerTLS(cfg appConfig) (*tls.Config, error) {
	var cert tls.Certificate
	var err error
	if cfg.tlsMode == 2 {
		cert, err = tls.LoadX509KeyPair(cfg.certPath, cfg.keyPath)
	} else {
		cert, err = selfSignedCert()
	}
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{wire.DefaultALPN},
	}, nil
}

func selfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "nowhere"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"nowhere"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func clientTLSConfig(sni, pin string) (*tls.Config, error) {
	normalized, err := wire.ParseCertificatePin(pin)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{wire.DefaultALPN},
		InsecureSkipVerify: sni == "" && normalized == "",
		ServerName:         sni,
	}
	if normalized != "" {
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return wire.VerifyLeafCertSHA256(rawCerts, normalized)
		}
	}
	return cfg, nil
}

type stdTLSDialer struct{ cfg *tls.Config }

func (d stdTLSDialer) DialTLSConn(ctx context.Context, conn net.Conn) (wire.HandshakedConn, error) {
	c := tls.Client(conn, d.cfg.Clone())
	if err := c.HandshakeContext(ctx); err != nil {
		return wire.HandshakedConn{}, err
	}
	state := c.ConnectionState()
	exported, err := state.ExportKeyingMaterial(wire.TLSExporterLabel, wire.EmptyTLSExporterContext(), wire.TLSExporterLen)
	if err != nil {
		_ = c.Close()
		return wire.HandshakedConn{}, err
	}
	var exporter wire.TLSExporter
	copy(exporter[:], exported)
	return wire.HandshakedConn{
		Conn: c,
		TLSHandshakeInfo: wire.TLSHandshakeInfo{
			TLSVersion:     state.Version,
			NegotiatedALPN: state.NegotiatedProtocol,
			Exporter:       exporter,
		},
	}, nil
}

type netDialer struct{ d net.Dialer }

func (n netDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return n.d.DialContext(ctx, network, address)
}
