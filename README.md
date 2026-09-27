# Warren — a censorship-resistant network transport

**The network layer for the CRODE no-log line: Crovi, Thump, and Lumra.**

> **Status: pre-alpha.** Two layers work today — multi-channel bridge discovery and
> a camouflaged TLS transport proof of concept (~1,100 lines of Go). Everything
> else in this README is design, not shipped code. The honest breakdown is in
> [`DESIGN.md` §0](DESIGN.md#0-implementation-status); the ordered plan with
> falsifiable gates is in [`docs/ROADMAP.md`](docs/ROADMAP.md).

---

## What Warren is for

When a network is actively trying to stop you from connecting at all, Warren is
what still gets a connection through. It has one job: **reachability under a
state-scale adversary.**

| Problem | Warren's answer |
|---------|-----------------|
| Exit IPs get blocklisted within days | Relay pool of ordinary residential nodes, churning, non-enumerable — blocking cost scales with households, not with VPN companies |
| DPI signature matching and active probing | Camouflaged transport: an unauthenticated connection gets a genuine response from a real site, because a real site actually answered it |
| Statistical flow classification | Current browser fingerprint (incl. hybrid post-quantum key share) + costed traffic-shaping regimes |
| Discovery endpoints get blocked | Multi-channel bootstrap (DoH/DNS TXT, out-of-band bridge lists, compiled-in fallback), no central bridge API |
| Allowlist regimes and shutdowns | An explicit degradation ladder down to mesh-only and offline — and a plain statement of where it ends |

What Warren is **not**: an anonymity network (no protection against an adversary
who watches both ends), identity protection (it carries bytes; it cannot unlink a
logged-in account), or a coin (the core protocol works with settlement disabled).
See [`DESIGN.md` §2](DESIGN.md#2-scope--non-goals).

---

## What works today

```bash
git clone https://github.com/croc100/warren.git
cd warren
go test ./internal/... -race
```

Run the camouflage demo — a relay that borrows a real site's identity, a genuine
client, and a probe that gets the real site instead:

```bash
export WARREN_PSK_HEX=$(openssl rand -hex 32)   # both sides share this

# 1. a stand-in "real site" the relay borrows an identity from
python3 -m http.server 9443

# 2. the relay
go run ./cmd/node -listen=127.0.0.1:8443 \
  -fallback-addr=127.0.0.1:9443 -fallback-sni=www.example.com

# 3. a genuine Warren client
go run ./cmd/cli -addr=127.0.0.1:8443 -fallback-sni=www.example.com \
  -message="hello from behind the firewall"
```

Then act like a censor's probe: `curl -v --http1.0 http://127.0.0.1:8443/` gets a
real response from whatever is on `-fallback-addr`, with nothing to flag.
Details and known gaps: [`docs/protocol/reality-transport.md`](docs/protocol/reality-transport.md).

| Component | Path | State |
|-----------|------|-------|
| Bridge discovery (DNS TXT / file / static, partial-failure tolerant) | `internal/discovery/bootstrap` | Implemented + tested |
| Camouflaged transport (tagged ClientHello, real-site fallback, AEAD framing) | `internal/network/transport` | PoC, tested, documented gaps |
| Relay pool, routing, reputation, exit policy | — | Not started |
| Accounting / settlement | `contracts/` (sketches, never deployed) | Not started |
| Measurement | — | Not started |
| Satellite / mesh, Crovi/Thump integration | — | Not started |

There is no installer, no package, and no binary release. The directory tree is
mostly placeholders.

---

## Architecture

```
L4  Measurement   private aggregate telemetry (opt-in, k-anonymous)   [planned]
L3  Accounting    off-chain credits; optional L2 net settlement       [planned]
L2  Relay pool    path selection, reputation, exit/abuse policy       [planned]
L1  Transport     camouflaged, post-quantum hybrid, pluggable         [PoC]
L0  Discovery     multi-channel bridges + client distribution         [working]
```

Three roles, and a process may hold several: **client**, **relay**, and **exit**.
Relay and exit are deliberately separate — a default install relays but does not
egress, because running an exit carries real legal exposure that the operator has
to opt into knowingly ([`DESIGN.md` §7.4](DESIGN.md#74-abuse-containment-and-operator-liability-new-blocking)).

---

## CRODE ecosystem

- **Crovi (secure VDI)** — hands Warren a policy-set identifier at session start;
  Warren applies local shaping/path policy to that desktop's traffic without ever
  learning the user's identity.
- **Thump (infrastructure protection)** — Warren reports the link class it is on so
  Thump can hold a workload migration instead of attempting it over a mesh-grade link.
- **Lumra (censorship-interference analysis)** — consumes Warren's opt-in aggregate
  measurements, including the blocked-vs-degraded signal.

---

## Design documents

- [`DESIGN.md`](DESIGN.md) — threat environment, layer specs, crypto inventory,
  retired decisions and why
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — slices and their gates
- [`docs/protocol/reality-transport.md`](docs/protocol/reality-transport.md) — L0/L1
  implementation notes, bugs found, known gaps

---

## Contributing

Early-stage, and the useful contributions right now are adversarial: try to
distinguish the transport from the site it borrows, break the bootstrap logic, or
poke holes in the threat model. See [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md)
and the open problems in [`DESIGN.md` §15](DESIGN.md#15-open-problems).

## License

AGPL-3.0 (commercial licensing available) — see [LICENSE](LICENSE).

## Citation

```bibtex
@software{warren2026,
  title={Warren: a censorship-resistant network transport},
  author={croc100},
  year={2026},
  url={https://github.com/croc100/warren}
}
```
