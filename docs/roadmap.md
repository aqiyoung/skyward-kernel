# Roadmap

Ordered by what the app needs to stop depending on mihomo, not by what is
interesting to write. Each step ends with something the app can ship and a
profile that works.

## v0.1 — the skeleton (done)

Direct, Shadowsocks (AEAD: AES-GCM, ChaCha20-Poly1305), Trojan. Rules on domain,
CIDR and MATCH. SOCKS5 in. A profile that only uses these runs today.

## v0.2 — the transports that cover most subscriptions

| Step | Why it is next |
| --- | --- |
| VMess + VLESS over TCP and WebSocket | Together they are most of the links in circulation; the transport layer they share is the same TLS/WS dialer |
| TLS options: `sni`, `alpn`, `fingerprint`, `skip-cert-verify` | Already read by the profile and needed by every TLS protocol |
| Shadowsocks 2022 (`2022-blake3-*`) | Newer subscriptions ship it; the AEAD framing is done, the key schedule is the work |
| Rule kinds: `GEOSITE`, `GEOIP`, `RULE-SET`, `DST-PORT`, `PROCESS-NAME` | A real profile rarely stays inside domain and CIDR |
| Rule providers and `mrs` rule sets | Without these, most published subscriptions load with half their rules skipped |

## v0.3 — what makes it a desktop client

| Step | Why |
| --- | --- |
| DNS module: fake-ip, hosts, DoH/DoT upstreams | Rules and TUN both need it; fake-ip is what makes TUN fast |
| TUN inbound (`with_gvisor`-class stack) | The app's "TUN mode" is a headline feature |
| UDP relay for SOCKS5 and the proxies that carry it | QUIC and games do not work over TCP-only |
| Health checks: `url-test`, `fallback`, `load-balance` | The group kinds are read today and always pick their first member |
| Selection API (in-process, not REST) | The UI changes a group's member; the kernel needs a way to accept that |

## v0.4 — the long tail

Hysteria2, TUIC, AnyTLS, Snell, SSR, ShadowTLS, mieru, WireGuard. Each is one
file plus a case in `New`; none of them change the router.

## v0.5 — replacing mihomo

- The REST/controller surface mihomo exposes, only as far as the app actually
  calls it.
- Profile pre-processing: `rule-providers`, `proxy-providers`, `script`,
  `overrides` — whatever the app's own editor writes today.
- A compatibility test corpus: real subscriptions, loaded by both kernels, whose
  routing decisions are compared connection by connection. This is the gate that
  decides when the app can drop the fallback.

## Not planned

Anything that exists to serve a client other than this app: the full REST API
surface, Clash's dashboard, remote provider caching policies nobody sets, and
protocol modes that need dedicated hardware. The kernel is small on purpose.
