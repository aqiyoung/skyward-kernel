package proxy

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/aqiyoung/skyward-kernel/internal/config"
)

// trojan is TLS carrying a password hash and a SOCKS-style destination: no
// separate cipher, because the transport is the encryption.
type trojan struct {
	name         string
	serverAddr   string
	sni          string
	passwordHash string
	skipVerify   bool
	dialer       net.Dialer
}

func newTrojan(p config.Proxy) (Dialer, error) {
	sni := p.SNI
	if sni == "" {
		sni = p.Server
	}
	// Trojan's "password" is the hex SHA-224 of the passphrase, sent in the clear
	// inside the TLS stream so the server can look it up without knowing the
	// passphrase itself.
	sum := sha256.Sum224([]byte(p.Password))
	return &trojan{
		name:         p.Name,
		serverAddr:   p.Address(),
		sni:          sni,
		passwordHash: hex.EncodeToString(sum[:]),
		skipVerify:   p.SkipCertVerify,
		dialer:       net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second},
	}, nil
}

func (t *trojan) Name() string { return t.name }
func (t *trojan) Type() string { return "trojan" }

func (t *trojan) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("trojan: %s is not implemented", network)
	}
	host, port, err := splitHostPort(addr)
	if err != nil {
		return nil, err
	}
	destination, err := socksAddress(host, port)
	if err != nil {
		return nil, err
	}

	raw, err := t.dialer.DialContext(ctx, "tcp", t.serverAddr)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, &tls.Config{
		ServerName:         t.sni,
		InsecureSkipVerify: t.skipVerify,
		MinVersion:         tls.VersionTLS12,
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("trojan: tls handshake with %s: %w", t.serverAddr, err)
	}

	// password hash, CRLF, CONNECT, address, CRLF.
	request := make([]byte, 0, 56+2+1+len(destination)+2)
	request = append(request, t.passwordHash...)
	request = append(request, '\r', '\n', 0x01)
	request = append(request, destination...)
	request = append(request, '\r', '\n')
	if _, err := conn.Write(request); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}
