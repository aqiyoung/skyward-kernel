// Package proxy holds the outbounds: one type per protocol, behind a single
// interface, so the router never learns a protocol's name.
package proxy

import (
	"context"
	"fmt"
	"net"

	"github.com/aqiyoung/skyward-kernel/internal/config"
)

// Dialer is one outbound. The kernel asks for a connection to a destination;
// whether that is a plain socket, an encrypted stream, or a chain of both is
// the implementation's business.
type Dialer interface {
	// Name is the profile's name for this outbound, which is what the rules
	// and the UI speak in.
	Name() string
	// Type is the protocol, for logs and for the UI to group by.
	Type() string
	// DialContext opens the stream. The address is "host:port"; a hostname is
	// resolved by the outbound itself, because a proxy dials names, not
	// addresses.
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// New builds the outbound a profile entry describes.
func New(p config.Proxy) (Dialer, error) {
	switch p.Type {
	case "direct":
		return NewDirect(p.Name), nil
	case "ss":
		return newShadowsocks(p)
	case "trojan":
		return newTrojan(p)
	}
	return nil, fmt.Errorf("proxy %q: type %q is not implemented", p.Name, p.Type)
}

// splitHostPort keeps the resolution duty on the outbound's side: net.SplitHostPort
// rejects a bare host, and every caller here has one.
func splitHostPort(addr string) (string, string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", "", fmt.Errorf("destination %q is not host:port: %w", addr, err)
	}
	return host, port, nil
}
