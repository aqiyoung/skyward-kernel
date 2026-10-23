package route

import (
	"context"
	"io"
	"testing"

	"github.com/aqiyoung/skyward-kernel/internal/config"
	"github.com/aqiyoung/skyward-kernel/internal/logx"
)

func testRouter(t *testing.T, profile string) *Router {
	t.Helper()
	cfg, _, err := config.Parse([]byte(profile))
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	r, err := New(cfg, logx.New(logx.LevelError, io.Discard))
	if err != nil {
		t.Fatalf("router: %v", err)
	}
	return r
}

const routingProfile = `
mode: rule
proxies:
  - {name: hk, type: ss, server: 192.0.2.1, port: 8388, cipher: aes-256-gcm, password: p}
  - {name: us, type: ss, server: 192.0.2.2, port: 8388, cipher: aes-256-gcm, password: p}
proxy-groups:
  - {name: Proxy, type: select, proxies: [hk, us]}
rules:
  - DOMAIN-SUFFIX,lan,DIRECT
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - DOMAIN-SUFFIX,blocked.example,REJECT
  - DOMAIN-KEYWORD,google,Proxy
  - MATCH,us
`

func TestResolve(t *testing.T) {
	r := testRouter(t, routingProfile)
	ctx := context.Background()

	cases := []struct{ addr, want string }{
		{"printer.lan:80", config.TargetDirect},
		{"10.1.2.3:443", config.TargetDirect},
		{"ads.blocked.example:443", config.TargetReject},
		{"www.google.com:443", "Proxy"},
		{"anything.example:443", "us"},
	}
	for _, c := range cases {
		got, err := r.Resolve(ctx, c.addr)
		if err != nil {
			t.Fatalf("%s: %v", c.addr, err)
		}
		if got != c.want {
			t.Errorf("%s -> %q, want %q", c.addr, got, c.want)
		}
	}
}

func TestModeOverridesRules(t *testing.T) {
	direct := testRouter(t, "mode: direct\n")
	if got, _ := direct.Resolve(context.Background(), "www.google.com:443"); got != config.TargetDirect {
		t.Fatalf("direct mode -> %q", got)
	}

	global := testRouter(t, routingProfile+"\n")
	global.mode = config.ModeGlobal
	if got, _ := global.Resolve(context.Background(), "printer.lan:80"); got != "Proxy" {
		t.Fatalf("global mode -> %q, want the first group", got)
	}
}

func TestGroupFollowsItsMember(t *testing.T) {
	r := testRouter(t, routingProfile)

	// v0.1 picks the first member; when a selection lands it rewrites this map,
	// and the target stays the group's name either way.
	if got := r.groups["Proxy"]; got != "hk" {
		t.Fatalf("Proxy starts on %q, want hk", got)
	}
	r.groups["Proxy"] = "us"
	dialer, err := r.outbound("Proxy", 0)
	if err != nil {
		t.Fatalf("outbound: %v", err)
	}
	if dialer.Name() != "us" {
		t.Fatalf("group resolved to %q", dialer.Name())
	}
}

func TestUnknownTargetIsAnError(t *testing.T) {
	r := testRouter(t, routingProfile)
	if _, err := r.outbound("nope", 0); err == nil {
		t.Fatal("a rule naming a missing proxy must fail at dial time")
	}
}

func TestGroupCycleStops(t *testing.T) {
	// A profile can name a group inside itself; the depth bound is what keeps the
	// kernel answering instead of recursing.
	r := testRouter(t, "proxy-groups:\n  - {name: A, type: select, proxies: [A]}\n")
	if _, err := r.outbound("A", 0); err == nil {
		t.Fatal("a self-referencing group must not resolve")
	}
}
