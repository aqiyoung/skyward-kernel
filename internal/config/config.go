// Package config reads the Clash-family YAML a Skyward profile carries.
//
// It is deliberately a reader, not a schema: a subscription is written by
// somebody else and may carry keys this kernel does not implement yet. Unknown
// top-level keys and unknown proxy fields are reported as warnings instead of
// failures, so a profile that mostly fits still runs and says what it ignored.
package config

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Modes the kernel knows.
const (
	ModeRule   = "rule"
	ModeGlobal = "global"
	ModeDirect = "direct"
)

// Built-in targets every profile may name.
const (
	TargetDirect = "DIRECT"
	TargetReject = "REJECT"
)

// Config is one profile.
type Config struct {
	Mode        string   `yaml:"mode"`
	LogLevel    string   `yaml:"log-level"`
	Proxies     []Proxy  `yaml:"proxies"`
	ProxyGroups []Group  `yaml:"proxy-groups"`
	Rules       []string `yaml:"rules"`
}

// Proxy is every field the kernel reads from a proxy entry. One struct rather
// than one per type keeps the reader honest: a key that appears here is a key
// some type uses.
type Proxy struct {
	Name     string `yaml:"name"`
	Type     string `yaml:"type"`
	Server   string `yaml:"server"`
	Port     int    `yaml:"port"`
	Cipher   string `yaml:"cipher"`
	Password string `yaml:"password"`
	Username string `yaml:"username"`
	SNI      string `yaml:"sni"`
	Network  string `yaml:"network"`
	TLS      bool   `yaml:"tls"`

	// SkipCertVerify is `skip-cert-verify` in a profile. It exists because
	// plenty of subscriptions ship a certificate no client can verify; it is
	// never the default.
	SkipCertVerify bool `yaml:"skip-cert-verify"`

	UDP bool `yaml:"udp"`
}

// Group is a proxy group. The kernel reads the members and the kind; the timing
// knobs are kept so a profile round-trips, and are used once health checks land.
type Group struct {
	Name      string   `yaml:"name"`
	Type      string   `yaml:"type"`
	Proxies   []string `yaml:"proxies"`
	URL       string   `yaml:"url"`
	Interval  int      `yaml:"interval"`
	Tolerance int      `yaml:"tolerance"`
}

// Address is the proxy's dial target, "host:port".
func (p Proxy) Address() string {
	return net.JoinHostPort(p.Server, fmt.Sprint(p.Port))
}

// Load reads and checks one profile. The warnings it returns are the parts of
// the file this kernel does not implement yet; they are not errors.
func Load(path string) (*Config, []string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	return Parse(raw)
}

// Parse is Load for bytes already in memory, which is how the app hands a
// profile over.
func Parse(raw []byte) (*Config, []string, error) {
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, nil, fmt.Errorf("read profile: %w", err)
	}
	cfg.applyDefaults()

	var warnings []string
	warnings = append(warnings, unknownTopLevel(raw)...)
	if err := cfg.check(); err != nil {
		return nil, warnings, err
	}
	warnings = append(warnings, cfg.unsupported()...)
	return &cfg, warnings, nil
}

func (c *Config) applyDefaults() {
	if c.Mode == "" {
		c.Mode = ModeRule
	}
	c.Mode = strings.ToLower(c.Mode)
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
}

func (c *Config) check() error {
	switch c.Mode {
	case ModeRule, ModeGlobal, ModeDirect:
	default:
		return fmt.Errorf("unknown mode %q (want rule, global or direct)", c.Mode)
	}

	seen := make(map[string]bool, len(c.Proxies))
	for i, p := range c.Proxies {
		if p.Name == "" {
			return fmt.Errorf("proxies[%d]: no name", i)
		}
		if seen[p.Name] {
			return fmt.Errorf("proxy %q is defined twice", p.Name)
		}
		seen[p.Name] = true
		switch p.Type {
		case "direct":
			continue
		case "ss", "trojan":
		default:
			return fmt.Errorf("proxy %q: type %q is not implemented yet (ss, trojan and direct are)", p.Name, p.Type)
		}
		if p.Server == "" || p.Port <= 0 || p.Port > 65535 {
			return fmt.Errorf("proxy %q: needs a server and a port", p.Name)
		}
		if p.Password == "" {
			return fmt.Errorf("proxy %q: needs a password", p.Name)
		}
	}

	for i, g := range c.ProxyGroups {
		if g.Name == "" {
			return fmt.Errorf("proxy-groups[%d]: no name", i)
		}
		if seen[g.Name] {
			return fmt.Errorf("group %q shares its name with a proxy", g.Name)
		}
		seen[g.Name] = true
	}

	// Groups may name each other, so membership is checked once every name is
	// known.
	for _, g := range c.ProxyGroups {
		if len(g.Proxies) == 0 {
			return fmt.Errorf("group %q has no proxies", g.Name)
		}
		for _, member := range g.Proxies {
			if !seen[member] && member != TargetDirect && member != TargetReject {
				return fmt.Errorf("group %q names %q, which is not a proxy or group", g.Name, member)
			}
		}
	}
	return nil
}

func (c *Config) unsupported() []string {
	var out []string
	for _, g := range c.ProxyGroups {
		switch strings.ToLower(g.Type) {
		case "select", "fallback", "url-test", "load-balance":
		default:
			out = append(out, fmt.Sprintf("group %q: type %q is treated as select", g.Name, g.Type))
		}
	}
	return out
}

// unknownTopLevel lists keys the profile carries that this kernel does not read.
// It works on the raw node rather than a map so a profile with duplicate keys
// still reports something useful.
func unknownTopLevel(raw []byte) []string {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil || len(doc.Content) == 0 {
		return nil
	}
	known := map[string]bool{
		"mode": true, "log-level": true, "proxies": true,
		"proxy-groups": true, "rules": true,
	}
	var unknown []string
	root := doc.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		key := root.Content[i].Value
		if !known[key] {
			unknown = append(unknown, key)
		}
	}
	sort.Strings(unknown)
	return unknown
}
