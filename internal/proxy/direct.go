package proxy

import (
	"context"
	"net"
	"time"
)

// direct talks to the destination itself. It is the outbound behind the built-in
// DIRECT target and the whole kernel in direct mode.
type direct struct {
	name   string
	dialer net.Dialer
}

// NewDirect builds the DIRECT outbound under a name the profile gave it.
func NewDirect(name string) Dialer {
	if name == "" {
		name = "DIRECT"
	}
	return &direct{
		name: name,
		// A dial that hangs is worse than one that fails: the app has a timeout
		// of its own and a stuck socket outlives it.
		dialer: net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second},
	}
}

func (d *direct) Name() string { return d.name }
func (d *direct) Type() string { return "direct" }

func (d *direct) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.dialer.DialContext(ctx, network, addr)
}
