// Package rule turns a profile's rule strings into matchers.
//
// A rule the kernel cannot evaluate is kept, not dropped: it never matches, and
// it reports itself so the caller can say which line was skipped. That keeps a
// subscription written for a bigger client running instead of refusing to load.
package rule

import (
	"fmt"
	"net"
	"strings"
)

// Kind is the part before the first comma.
type Kind string

// The kinds this kernel evaluates.
const (
	Domain        Kind = "DOMAIN"
	DomainSuffix  Kind = "DOMAIN-SUFFIX"
	DomainKeyword Kind = "DOMAIN-KEYWORD"
	IPCIDR        Kind = "IP-CIDR"
	IPCIDR6       Kind = "IP-CIDR6"
	Match         Kind = "MATCH"
)

// Destination is what a rule sees: the name the client asked for, the address it
// resolved to when one is known, and the port.
type Destination struct {
	Host string
	IP   net.IP
	Port int
}

// Rule is one parsed line.
type Rule struct {
	kind      Kind
	payload   string
	target    string
	noResolve bool

	// unsupported holds the reason when this kind is not implemented; the rule
	// then never matches.
	unsupported string

	network *net.IPNet
}

// Target is the proxy, group or built-in this rule sends traffic to.
func (r Rule) Target() string { return r.target }

// Kind is the rule's type, as written.
func (r Rule) Kind() string { return string(r.kind) }

// Unsupported is empty for a rule this kernel evaluates.
func (r Rule) Unsupported() string { return r.unsupported }

// String rebuilds the line closely enough for a log.
func (r Rule) String() string {
	if r.payload == "" {
		return fmt.Sprintf("%s,%s", r.kind, r.target)
	}
	return fmt.Sprintf("%s,%s,%s", r.kind, r.payload, r.target)
}

// Match reports whether the destination belongs to this rule.
func (r Rule) Match(d Destination) bool {
	if r.unsupported != "" {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(d.Host, "."))
	switch r.kind {
	case Match:
		return true
	case Domain:
		return host == strings.ToLower(r.payload)
	case DomainSuffix:
		suffix := strings.ToLower(r.payload)
		return host == suffix || strings.HasSuffix(host, "."+suffix)
	case DomainKeyword:
		return strings.Contains(host, strings.ToLower(r.payload))
	case IPCIDR, IPCIDR6:
		if d.IP == nil || r.network == nil {
			return false
		}
		return r.network.Contains(d.IP)
	}
	return false
}

// NeedsIP reports whether the rule can only decide once the host has been
// resolved. The router uses it to avoid a lookup for a rule that will match on
// the name alone.
func (r Rule) NeedsIP() bool {
	return (r.kind == IPCIDR || r.kind == IPCIDR6) && r.unsupported == ""
}

// Parse reads one rule line. A line this kernel cannot evaluate still parses;
// the caller learns about it from Unsupported.
func Parse(line string) (Rule, error) {
	text := strings.TrimSpace(line)
	if text == "" {
		return Rule{}, fmt.Errorf("empty rule")
	}
	fields := strings.Split(text, ",")
	for i := range fields {
		fields[i] = strings.TrimSpace(fields[i])
	}
	if len(fields) < 2 {
		return Rule{}, fmt.Errorf("rule %q needs a type, a payload and a target", line)
	}

	r := Rule{kind: Kind(strings.ToUpper(fields[0]))}

	// `no-resolve` is a flag, not a field with a place: a profile puts it after
	// the payload or after the target, so it is dropped before either is read.
	rest := make([]string, 0, len(fields)-1)
	for _, f := range fields[1:] {
		if strings.EqualFold(f, "no-resolve") {
			r.noResolve = true
			continue
		}
		rest = append(rest, f)
	}
	if len(rest) == 0 {
		return Rule{}, fmt.Errorf("rule %q has no target", line)
	}
	// MATCH carries a target and nothing else; every other kind carries a
	// payload too, which the switch below holds it to.
	r.target = rest[len(rest)-1]
	if len(rest) > 1 {
		r.payload = strings.Join(rest[:len(rest)-1], ",")
	}
	if r.target == "" {
		return Rule{}, fmt.Errorf("rule %q has no target", line)
	}

	switch r.kind {
	case Match:
		if r.payload != "" {
			return Rule{}, fmt.Errorf("MATCH takes only a target, got %q", line)
		}
	case Domain, DomainSuffix, DomainKeyword:
		if r.payload == "" {
			return Rule{}, fmt.Errorf("rule %q needs a domain", line)
		}
	case IPCIDR, IPCIDR6:
		_, network, err := net.ParseCIDR(r.payload)
		if err != nil {
			return Rule{}, fmt.Errorf("rule %q: %w", line, err)
		}
		r.network = network
	default:
		r.unsupported = fmt.Sprintf("%s is not implemented yet", r.kind)
	}
	return r, nil
}

// ParseAll reads every line and collects the ones this kernel skips, so the
// caller can report them once instead of per connection.
func ParseAll(lines []string) ([]Rule, []string, error) {
	rules := make([]Rule, 0, len(lines))
	var skipped []string
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		r, err := Parse(line)
		if err != nil {
			return nil, skipped, fmt.Errorf("rules[%d]: %w", i, err)
		}
		if why := r.Unsupported(); why != "" {
			skipped = append(skipped, fmt.Sprintf("%s: %s", r.String(), why))
		}
		rules = append(rules, r)
	}
	return rules, skipped, nil
}
