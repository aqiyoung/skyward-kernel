# Architecture

The kernel has one job: take a connection request, decide which outbound it
leaves through, and hand back a stream. Everything here follows from keeping that
path short and keeping the policy out of the protocols.

## The one interface

```go
type Dialer interface {
	Name() string
	Type() string
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}
```

Every outbound is a `Dialer`. A protocol implementation knows nothing about
rules, groups or modes; the router knows nothing about protocols. A new protocol
is one file in `internal/proxy` plus a case in `New`, and nothing else changes.

`addr` is always `host:port`, and a hostname stays a hostname: a proxy dials
names, because the name is what the rule matched and what the server should see.
Resolution happens either inside the outbound (the usual case) or in the router,
and only when an IP rule needs it.

## Per connection, in order

```
inbound (SOCKS5)
  └─ route.Router.DialContext
       ├─ destination: parse host/port, take the IP if the caller already has one
       ├─ mode: direct -> DIRECT, global -> one target, rule -> walk the rules
       ├─ rules: first match wins; an IP rule triggers one lazy lookup
       ├─ target: DIRECT / REJECT / proxy name / group name
       ├─ group: follow the current member, bounded to 8 levels
       └─ outbound.DialContext
```

Two decisions worth naming:

- **A rule the kernel cannot evaluate never matches.** It is kept, reported once
  at load, and skipped per connection. This is why a mihomo profile loads here
  instead of failing: the parts we do not implement degrade to "no opinion".
- **No match means DIRECT.** Proxying traffic nobody asked to proxy is the
  failure users notice last and hate most.

## What is not here yet, and where it goes

DNS, TUN, health checks, the REST controller and the remaining protocols are
absent by design, not by omission. The roadmap puts them in the order that keeps
the app usable at every step; until a step lands, the app falls back to mihomo
for the profiles that need it.

## Rules that keep this small

- Standard library first. The whole kernel depends on YAML and one crypto
  package (`x/crypto` for ChaCha20-Poly1305); a third dependency has to earn its
  place.
- One file per protocol, one file per concern. If a file needs a table of
  contents, the concern is two concerns.
- No global state. The router owns its outbounds; nothing reaches for a package
  level singleton, which is what makes two profiles in one process possible.
- Errors carry the profile's name for the thing that failed. "proxy "hk-01":
  cipher "rc4-md5" is not implemented" is worth ten lines of stack trace.
