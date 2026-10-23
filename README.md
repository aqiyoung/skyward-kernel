# skyward-kernel

Skyward's own proxy core. It replaces the `mihomo` submodule the app carried
until now: same profile format, no upstream core, and a dependency list that fits
on one screen.

**Status: v0.1, a working skeleton.** Direct, Shadowsocks (AEAD) and Trojan
outbounds; rule routing with domain and CIDR rules; a SOCKS5 inbound. Everything
else a subscription may carry — the other protocols, DNS, TUN, providers,
health checks, the REST controller — is listed in [docs/roadmap.md](docs/roadmap.md)
with what it would take.

## Why

The core the app shipped was 871 Go files and 135 modules, none of them ours. A
single rule change, a protocol fix or a size cut meant asking upstream. This
kernel is written here, so the answer to "can we change this?" is yes.

The trade is deliberate: at v0.1 a subscription written for mihomo mostly will
not work yet. The roadmap closes that gap protocol by protocol, and until it
does the app keeps mihomo as a fallback.

## Run it

```bash
go run ./cmd/skyward -c configs/example.yaml -log debug
curl --socks5-hostname 127.0.0.1:7890 https://example.com
```

`-explain` prints what the profile resolved to and exits, which is the quickest
way to see which rule catches what:

```bash
go run ./cmd/skyward -c configs/example.yaml -explain
```

## What the profile reader understands

| Key | Reads | Notes |
| --- | --- | --- |
| `mode` | `rule`, `global`, `direct` | anything else is an error |
| `log-level` | `error`, `warn`, `info`, `debug` | |
| `proxies` | `ss`, `trojan`, `direct` | other types fail the load, by name |
| `proxy-groups` | `select`, `fallback`, `url-test`, `load-balance` | every kind starts on its first member; no health checks yet |
| `rules` | `DOMAIN`, `DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`, `IP-CIDR`, `IP-CIDR6`, `MATCH` | other kinds are kept, never match, and are reported at load |

Unknown top-level keys are reported as warnings rather than failing the profile.

## Layout

```
cmd/skyward          the CLI: a profile in, a SOCKS5 listener out
internal/config      the profile reader
internal/proxy       one file per outbound, behind a single Dialer
internal/rule        a rule line and what it matches
internal/route       rules + mode + groups -> one outbound per connection
internal/inbound     SOCKS5 (v0.1's only way in)
internal/logx        levelled logging
docs/                architecture and roadmap
```

[docs/architecture.md](docs/architecture.md) explains why it is split this way;
[docs/roadmap.md](docs/roadmap.md) is the order things get added and what each
step buys.

## License

GPL-3.0, the same as the app it serves.
