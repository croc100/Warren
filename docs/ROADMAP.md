# Warren Roadmap

**A censorship-resistant network transport for the CRODE line (Crovi, Thump, Lumra).**

This file tracks *what ships in what order*. Architecture and rationale live in
[`DESIGN.md`](../DESIGN.md).

Status legend: ✅ done · 🚧 in progress · ⬜ planned

> **Read this first.** Warren is pre-alpha. Two layers exist (bootstrap discovery
> and a camouflaged, post-quantum transport, ~1,700 lines of Go); everything
> else is specification. See [`DESIGN.md` §0](../DESIGN.md#0-implementation-status).

---

## Why there are no dates

The previous version of this file promised a marketplace MVP in "Months 1–3" and
mainnet in "Months 10–12". Those numbers were not derived from anything, and they
ordered the work backwards: the bandwidth market was scheduled before the
transport it would sell access to was known to survive a censor.

Slices are now ordered by *what makes everything above it moot if it fails*, and
each one ships with a falsifiable gate. A slice is done when its gate passes, not
when a month ends.

---

## Slices at a glance

| # | Slice | Gate | Status |
|---|-------|------|--------|
| 1 | L1 transport hardening | Active-probe harness can't distinguish a relay from the site it borrows; ClientHello not distinguishable from the parroted browser's current profile | 🚧 (handshake + signed descriptors done; borrowed handshake decision left) |
| 2 | L1 breadth + L0 distribution | Fresh client still connects with UDP/443 blocked, primary transport blocked, and bridge list expired | ⬜ |
| 3 | L2 relay pool | 20+ node testbed usable for interactive browsing while a 24h discovery-harvesting adversary recovers < stated fraction of the pool | ⬜ |
| 4 | L3 accounting | A week of paid relay traffic with zero on-chain transactions; separately, net settlement on an L2 testnet with no per-session data on chain | ⬜ |
| 5 | L4 measurement | Regional report emits no sub-threshold bucket and no recoverable individual report | ⬜ |
| 6 | Resilience + ecosystem | Link severed → data plane stops, control plane flows over mesh within real duty-cycle budget, Thump holds migration | ⬜ |

---

## Slice 1 — L1 transport hardening 🚧

The layer everything else depends on. If a connection can be detected or probed,
no amount of marketplace or analytics matters.

- ✅ Tagged TLS ClientHello + byte-for-byte fallback splice to a real site
  (`internal/network/transport`), verified end-to-end against a real HTTP server
- ✅ Multi-channel bridge resolution with per-channel failure reporting
  (`internal/discovery/bootstrap`)
- ✅ Camouflage profile tracks a current browser (hybrid post-quantum key share),
  with a CI staleness guard on the profile's key-share groups
- ✅ Segmented-ClientHello handling validated — the relay peeks the whole record,
  and a test delivers a ~1.5 KB hello in 137-byte chunks through a fragmenting proxy
- ✅ Hybrid X25519 + ML-KEM-768 session handshake: ML-KEM for post-quantum
  confidentiality, ephemeral X25519 for forward secrecy, and an exchange with the
  relay's long-term identity key for authentication
- ✅ Static pre-shared key removed. Clients hold only a relay's public key, which
  travels in the bridge descriptor (`addr|sni|pubkey`), so a compromised client
  reveals nothing about other sessions and a hostile discovery channel cannot
  steer a client onto a relay it can authenticate to
- ✅ Replay cache: a captured hello re-sent verbatim is spliced to the real site,
  so it can't be used to confirm a relay
- ✅ Application data framed as TLS `application_data` records (the bespoke 4-byte
  length prefix is gone), with the record header authenticated as AEAD associated data
- ✅ Signed, expiring bridge descriptors (`warren-bridges/1`, Ed25519 over the
  literal wire bytes), with `bootstrap -genkey/-sign/-verify`. File and DNS
  channels fail closed without a trust anchor; expiry surfaces as *stale
  discovery* rather than *no bridges*, so blocking every channel for a week does
  not strand clients that already hold working addresses
- ⬜ Complete the borrowed TLS handshake, or migrate to an audited REALITY
  implementation — upstream REALITY is X25519-only, so adopting it as-is would
  trade the post-quantum property for the mimicry property

**Gate:** an isolated active-probe harness — connect, replay, resume — cannot
distinguish a Warren relay from the borrowed site, and the client's hello is not
separable by key-share, size, or version features from the profile it parrots.
A passive signature tool (nDPI-class) is not sufficient evidence.

---

## Slice 2 — L1 breadth + client distribution ⬜

One transport and two app stores are both single points of failure.

- ⬜ `masque` transport (RFC 9298 CONNECT-UDP / RFC 9484 CONNECT-IP)
- ⬜ `websocket-tunnel` transport (Tor WebTunnel pattern, behind a fronted site)
- ⬜ Transport selection policy + degradation ladder rungs 1–4
- ⬜ Reproducible builds, signed artifacts, ≥3 non-app-store distribution channels
- ⬜ Shaping regimes `bucket` and `cover`, each with measured overhead published

**Gate:** with UDP/443 blocked, the primary transport blocked, and the newest
signed bridge list expired, a fresh install still reaches the network and reports
which rung of the ladder it is on.

---

## Slice 3 — L2 relay pool ⬜

The structural anti-blocklisting bet: many ordinary residential endpoints,
churning, non-enumerable.

- ⬜ Relay / exit role separation — a default install is **relay only**
- ⬜ Declared, locally enforced exit policy + abuse-handling documentation
- ⬜ Goodput- and completion-based health (throttling detection, not just reachability)
- ⬜ Local-first reputation; `mode=resilience` diversity-weighted path selection
- ⬜ Rotating per-requester discovery subsets, rate-limited by Privacy Pass tokens

**Gate:** a 20+ node testbed sustains usable interactive browsing while an
adversary process harvesting discovery responses for 24 hours recovers less than a
pre-stated fraction of the pool.

---

## Slice 4 — L3 accounting ⬜

Reachability must never depend on a chain being live or a token having value.

- ⬜ `none` backend (volunteer pool, fully functional) and `credits` backend
- ⬜ Off-chain signed receipts, settlement on 10 MB or 5 s, whichever first
- ⬜ Optional L2 `onchain` adapter (Sepolia/Hoodi first), net balances only
- ⬜ No public listing surface — capacity offers never become a browsable directory

**Gate:** relays are paid for a week of real traffic with zero on-chain
transactions; separately, net settlement reconciles on an L2 testnet with
per-session data appearing nowhere on chain.

---

## Slice 5 — L4 private measurement ⬜

Replaces the on-chain Independence Logger, which is retired
([why](../DESIGN.md#91-why-the-old-design-is-retired)).

- ⬜ Threshold-aggregated telemetry (Prio/STAR-class) over Oblivious HTTP
- ⬜ Opt-in, per-region, with a k-anonymity floor below which nothing is emitted
- ⬜ Blocked-vs-degraded classification — the signal the analytics market lacks
- ⬜ OONI-compatible publication path for Lumra and external researchers

**Gate:** a regional report is produced in which no sub-threshold bucket is
emitted and no individual report is recoverable by the collector.

---

## Slice 6 — Resilience transports + ecosystem ⬜

- ⬜ Link-type abstraction (terrestrial / mobile / satellite VSAT / direct-to-cell / mesh)
  with per-traffic-class policy
- ⬜ Mesh control-plane store-and-forward on a Meshtastic-class stack, inside real
  duty-cycle limits (single-digit messages per minute, not the 500/s an earlier
  draft claimed)
- ⬜ Crovi policy injection; Thump link-class reporting and migration holds
- ⬜ Degradation ladder rungs 6–7 (mesh-only, then offline cache)

**Gate:** live demo — terrestrial link severed, data plane stops, control plane
keeps flowing over mesh within its duty-cycle budget, and Thump holds a migration
instead of attempting it over a kilobit link.

---

## Later — horizontal expansion

Warren DNS, Warren Email, Warren Storage. Not scoped until Slice 3's gate passes;
a name service over an unproven transport is a demo, not a product.

---

## Non-goals

Warren is a network transport, not an application suite, not an anonymity network,
and not a coin. The core must work with settlement disabled. See
[`DESIGN.md` §2](../DESIGN.md#2-scope--non-goals).

---

## Ecosystem alignment

Warren is the network substrate for the CRODE no-log line — Crovi (secure VDI),
Thump (infrastructure protection), and Lumra (censorship-interference analysis).
Lumra consumes Slice 5's opt-in aggregate measurements.
