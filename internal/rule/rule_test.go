package rule

import (
	"net"
	"testing"
)

func mustParse(t *testing.T, line string) Rule {
	t.Helper()
	r, err := Parse(line)
	if err != nil {
		t.Fatalf("parse %q: %v", line, err)
	}
	return r
}

func TestMatch(t *testing.T) {
	cases := []struct {
		line string
		dest Destination
		want bool
	}{
		{"DOMAIN,ads.example.com,DIRECT", Destination{Host: "ads.example.com"}, true},
		{"DOMAIN,ads.example.com,DIRECT", Destination{Host: "ADS.Example.com"}, true},
		{"DOMAIN,ads.example.com,DIRECT", Destination{Host: "x.ads.example.com"}, false},
		{"DOMAIN-SUFFIX,example.com,P", Destination{Host: "example.com"}, true},
		{"DOMAIN-SUFFIX,example.com,P", Destination{Host: "a.b.example.com"}, true},
		{"DOMAIN-SUFFIX,example.com,P", Destination{Host: "notexample.com"}, false},
		{"DOMAIN-KEYWORD,double,REJECT", Destination{Host: "adoubleclick.net"}, true},
		{"DOMAIN-KEYWORD,double,REJECT", Destination{Host: "click.net"}, false},
		{"IP-CIDR,10.0.0.0/8,DIRECT", Destination{Host: "x", IP: net.ParseIP("10.1.2.3")}, true},
		{"IP-CIDR,10.0.0.0/8,DIRECT", Destination{Host: "x", IP: net.ParseIP("11.1.2.3")}, false},
		{"IP-CIDR,10.0.0.0/8,DIRECT", Destination{Host: "x"}, false},
		{"IP-CIDR6,2001:db8::/32,DIRECT", Destination{Host: "x", IP: net.ParseIP("2001:db8::1")}, true},
		{"MATCH,Proxy", Destination{Host: "anything"}, true},
	}
	for _, c := range cases {
		if got := mustParse(t, c.line).Match(c.dest); got != c.want {
			t.Errorf("%s against %+v = %v, want %v", c.line, c.dest, got, c.want)
		}
	}
}

func TestTargetAndNoResolve(t *testing.T) {
	r := mustParse(t, "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve")
	if r.Target() != "DIRECT" {
		t.Fatalf("target = %q", r.Target())
	}
	if !r.NeedsIP() {
		t.Fatal("an IP rule needs the address")
	}
	if !mustParse(t, "IP-CIDR,10.0.0.0/8,DIRECT").NeedsIP() {
		t.Fatal("an IP rule needs the address with or without no-resolve")
	}
	if mustParse(t, "DOMAIN,example.com,P").NeedsIP() {
		t.Fatal("a domain rule must not need a lookup")
	}

	// no-resolve reads as a flag in either place, and never as the target.
	if got := mustParse(t, "IP-CIDR,10.0.0.0/8,no-resolve,DIRECT").Target(); got != "DIRECT" {
		t.Fatalf("target = %q, want DIRECT", got)
	}
}

func TestUnsupportedRuleStays(t *testing.T) {
	r := mustParse(t, "RULE-SET,ads,REJECT")
	if r.Unsupported() == "" {
		t.Fatal("RULE-SET should report itself as unsupported")
	}
	if r.Match(Destination{Host: "ads.example.com"}) {
		t.Fatal("an unsupported rule must never match")
	}
	if r.Target() != "REJECT" {
		t.Fatalf("target = %q", r.Target())
	}
}

func TestParseAllCollectsSkips(t *testing.T) {
	rules, skipped, err := ParseAll([]string{
		"DOMAIN,a.com,P",
		"GEOIP,CN,DIRECT",
		"MATCH,P",
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("kept %d rules, want 3", len(rules))
	}
	if len(skipped) != 1 {
		t.Fatalf("skipped = %v", skipped)
	}
}

func TestParseErrors(t *testing.T) {
	for _, line := range []string{
		"",
		"DOMAIN",
		"IP-CIDR,not-a-cidr,DIRECT",
		"MATCH,extra,target",
		"DOMAIN-SUFFIX,,DIRECT",
	} {
		if _, err := Parse(line); err == nil {
			t.Errorf("%q: expected an error", line)
		}
	}
}
