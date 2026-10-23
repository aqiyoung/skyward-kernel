package config

import (
	"strings"
	"testing"
)

const sampleProfile = `
mode: rule
log-level: debug
proxies:
  - {name: a, type: ss, server: 1.2.3.4, port: 8388, cipher: aes-256-gcm, password: x}
  - {name: b, type: trojan, server: t.example.com, port: 443, password: y}
proxy-groups:
  - {name: Proxy, type: select, proxies: [a, b, DIRECT]}
rules:
  - DOMAIN-SUFFIX,example.com,Proxy
  - MATCH,Proxy
dns:
  enable: true
`

func TestParseReadsWhatItKnows(t *testing.T) {
	cfg, warnings, err := Parse([]byte(sampleProfile))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Mode != ModeRule || cfg.LogLevel != "debug" {
		t.Fatalf("mode/log-level = %q/%q", cfg.Mode, cfg.LogLevel)
	}
	if len(cfg.Proxies) != 2 || len(cfg.ProxyGroups) != 1 || len(cfg.Rules) != 2 {
		t.Fatalf("counts = %d/%d/%d", len(cfg.Proxies), len(cfg.ProxyGroups), len(cfg.Rules))
	}
	if got := cfg.Proxies[0].Address(); got != "1.2.3.4:8388" {
		t.Fatalf("address = %q", got)
	}

	// `dns` is a key this kernel does not read yet; it must be reported, not
	// swallowed, and not fail the profile.
	if len(warnings) != 1 || warnings[0] != "dns" {
		t.Fatalf("warnings = %v, want [dns]", warnings)
	}
}

func TestParseDefaults(t *testing.T) {
	cfg, _, err := Parse([]byte("proxies: []\nrules: []\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Mode != ModeRule {
		t.Fatalf("mode default = %q, want rule", cfg.Mode)
	}
	if cfg.LogLevel != "info" {
		t.Fatalf("log-level default = %q, want info", cfg.LogLevel)
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"unknown mode":       "mode: turbo\n",
		"unnamed proxy":      "proxies:\n  - {type: ss, server: a, port: 1, cipher: aes-256-gcm, password: p}\n",
		"duplicate name":     "proxies:\n  - {name: a, type: ss, server: a, port: 1, cipher: aes-256-gcm, password: p}\n  - {name: a, type: ss, server: b, port: 2, cipher: aes-256-gcm, password: p}\n",
		"unimplemented type": "proxies:\n  - {name: a, type: vless, server: a, port: 1, password: p}\n",
		"missing port":       "proxies:\n  - {name: a, type: ss, server: a, cipher: aes-256-gcm, password: p}\n",
		"missing password":   "proxies:\n  - {name: a, type: ss, server: a, port: 1, cipher: aes-256-gcm}\n",
		"group member gone":  "proxy-groups:\n  - {name: Proxy, type: select, proxies: [nope]}\n",
	}
	for name, profile := range cases {
		if _, _, err := Parse([]byte(profile)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestParseKeepsBuiltinsAsGroupMembers(t *testing.T) {
	profile := "proxy-groups:\n  - {name: Proxy, type: select, proxies: [DIRECT, REJECT]}\n"
	if _, _, err := Parse([]byte(profile)); err != nil {
		t.Fatalf("DIRECT and REJECT must be legal members: %v", err)
	}
}

func TestParseReportsUnknownGroupKind(t *testing.T) {
	profile := "proxy-groups:\n  - {name: Proxy, type: magic, proxies: [DIRECT]}\n"
	_, warnings, err := Parse([]byte(profile))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "treated as select") {
		t.Fatalf("warnings = %v", warnings)
	}
}
