// Package route decides which outbound a connection leaves through: the rules
// in the profile, the mode, and the proxy groups in between.
package route

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/aqiyoung/skyward-kernel/internal/config"
	"github.com/aqiyoung/skyward-kernel/internal/logx"
	"github.com/aqiyoung/skyward-kernel/internal/proxy"
	"github.com/aqiyoung/skyward-kernel/internal/rule"
)

// maxGroupDepth bounds a profile that names groups in a cycle.
const maxGroupDepth = 8

// ErrRejected is what REJECT returns; the inbound closes the stream as a failed
// connection, which is what a rejected request is.
var ErrRejected = errors.New("rejected by rule")

// Router answers one question: who dials this destination?
type Router struct {
	mode    string
	log     *logx.Logger
	direct  proxy.Dialer
	proxies map[string]proxy.Dialer
	// groups maps a group to the member it currently sends traffic to. v0.1 has
	// no health checks, so every kind starts on its first member; the map is
	// what a selection will rewrite.
	groups map[string]string
	rules  []rule.Rule
	global string
}

// New builds the router a profile describes.
func New(cfg *config.Config, log *logx.Logger) (*Router, error) {
	r := &Router{
		mode:    cfg.Mode,
		log:     log,
		direct:  proxy.NewDirect(config.TargetDirect),
		proxies: make(map[string]proxy.Dialer, len(cfg.Proxies)),
		groups:  make(map[string]string, len(cfg.ProxyGroups)),
	}

	for _, p := range cfg.Proxies {
		dialer, err := proxy.New(p)
		if err != nil {
			return nil, err
		}
		r.proxies[p.Name] = dialer
	}

	for _, g := range cfg.ProxyGroups {
		r.groups[g.Name] = g.Proxies[0]
	}

	// Global mode has no rules to read, so it needs one target: the first group
	// when there is one, otherwise the first proxy, otherwise DIRECT.
	switch {
	case len(cfg.ProxyGroups) > 0:
		r.global = cfg.ProxyGroups[0].Name
	case len(cfg.Proxies) > 0:
		r.global = cfg.Proxies[0].Name
	default:
		r.global = config.TargetDirect
	}

	rules, skipped, err := rule.ParseAll(cfg.Rules)
	if err != nil {
		return nil, err
	}
	for _, s := range skipped {
		log.Warnf("rule not evaluated: %s", s)
	}
	r.rules = rules
	return r, nil
}

// Mode is the profile's mode, for logging.
func (r *Router) Mode() string { return r.mode }

// Resolve says which proxy handles a destination, without dialling. The app uses
// it to show the decision it is about to make.
func (r *Router) Resolve(ctx context.Context, addr string) (string, error) {
	dest, err := destination(addr, nil)
	if err != nil {
		return "", err
	}
	return r.target(ctx, dest), nil
}

// DialContext opens the connection through whichever outbound the rules chose.
func (r *Router) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dest, err := destination(addr, nil)
	if err != nil {
		return nil, err
	}
	target := r.target(ctx, dest)

	dialer, err := r.outbound(target, 0)
	if err != nil {
		return nil, err
	}
	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	if r.log.Enabled(logx.LevelDebug) {
		r.log.Debugf("%s %s -> %s (%s)", network, addr, target, dialer.Type())
	}
	return conn, nil
}

// target runs the rules for one destination.
func (r *Router) target(ctx context.Context, dest rule.Destination) string {
	switch r.mode {
	case config.ModeDirect:
		return config.TargetDirect
	case config.ModeGlobal:
		return r.global
	}

	resolved := dest.IP != nil
	for _, ru := range r.rules {
		// Only a rule that cannot decide on the name costs a lookup, and only the
		// first such rule pays for it.
		if !resolved && ru.NeedsIP() {
			resolved = true
			if ips, err := net.DefaultResolver.LookupIP(ctx, "ip", dest.Host); err == nil && len(ips) > 0 {
				dest.IP = ips[0]
			}
		}
		if ru.Match(dest) {
			return ru.Target()
		}
	}
	// No rule matched and the profile has no MATCH: direct is the safe default,
	// because it keeps the connection working rather than silently proxying
	// everything.
	return config.TargetDirect
}

// outbound resolves a rule target into a dialer, following groups.
func (r *Router) outbound(target string, depth int) (proxy.Dialer, error) {
	if depth > maxGroupDepth {
		return nil, fmt.Errorf("proxy groups nest more than %d deep at %q", maxGroupDepth, target)
	}
	switch strings.ToUpper(target) {
	case config.TargetDirect:
		return r.direct, nil
	case config.TargetReject:
		return nil, ErrRejected
	}
	if d, ok := r.proxies[target]; ok {
		return d, nil
	}
	if member, ok := r.groups[target]; ok {
		return r.outbound(member, depth+1)
	}
	return nil, fmt.Errorf("no proxy or group named %q", target)
}

func destination(addr string, ip net.IP) (rule.Destination, error) {
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return rule.Destination{}, fmt.Errorf("destination %q is not host:port: %w", addr, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return rule.Destination{}, fmt.Errorf("destination %q has port %q", addr, portText)
	}
	if ip == nil {
		ip = net.ParseIP(host)
	}
	return rule.Destination{Host: host, IP: ip, Port: port}, nil
}
