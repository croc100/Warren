# Warren Technical Architecture & Design

> **Revision note (2026-09):** This revision re-bases the design on the 2026
> censorship, cryptography, and regulatory environment, and on the honest state of
> the repository (see [§0](#0-implementation-status)). The substantive changes:
>
> 1. **Post-quantum TLS is now the baseline**, which changes L1 camouflage from
>    "look like a browser" to "look like a *current* browser, including its hybrid
>    ML-KEM key share" — a 2023-era ClientHello is now itself a fingerprint.
> 2. **Application whitelisting and full shutdowns are no longer forward-looking
>    risks**; they are deployed. The design adds an explicit degradation ladder
>    instead of assuming "generic HTTPS" always suffices.
> 3. **Transport is re-specified as pluggable**, with QUIC/MASQUE (RFC 9298/9484)
>    as a first-class path rather than a custom framing over TCP only.
> 4. **The on-chain per-event Independence Logger is retired** and replaced with
>    private aggregate telemetry (Prio/STAR-class), which preserves the analytics
>    revenue line while removing an unnecessary privacy liability and a dead
>    dependency (libsnark).
> 5. **Settlement moves off L1 mainnet and out of the critical path.** The core
>    protocol works with no token at all; value transfer is an optional adapter.
> 6. **Abuse containment and operator liability are now first-class**, because
>    "residential nodes relay strangers' traffic" is the same shape as the
>    residential-proxy abuse problem that drew law-enforcement action in 2024–2025.
> 7. **Satellite/mesh is re-specified as a link type**, not an API integration.
>    The old failover pseudocode assumed a Starlink tunnel API that does not exist
>    and a LoRa control-plane capacity ~1–2 orders of magnitude too optimistic.
>
> Superseded decisions and the reason each was dropped are listed in
> [§14](#14-deprecated-decisions).

## Table of Contents

0. [Implementation Status](#0-implementation-status)
1. [Threat Environment (2026)](#1-threat-environment-2026)
2. [Scope & Non-Goals](#2-scope--non-goals)
3. [Design Principles](#3-design-principles)
4. [Layered Architecture](#4-layered-architecture)
5. [L0 — Discovery & Client Distribution](#5-l0--discovery--client-distribution)
6. [L1 — Transport & Camouflage](#6-l1--transport--camouflage)
7. [L2 — Relay Pool, Routing & Abuse Containment](#7-l2--relay-pool-routing--abuse-containment)
8. [L3 — Accounting & Settlement](#8-l3--accounting--settlement)
9. [L4 — Private Measurement](#9-l4--private-measurement)
10. [Resilience Transports (Satellite / Mesh)](#10-resilience-transports-satellite--mesh)
11. [Cryptographic Inventory](#11-cryptographic-inventory)
12. [Integration Layer (Crovi / Thump)](#12-integration-layer-crovi--thump)
13. [Security Model](#13-security-model)
14. [Deprecated Decisions](#14-deprecated-decisions)
15. [Open Problems](#15-open-problems)
16. [Roadmap](#16-roadmap)

---

## 0. Implementation Status

This document describes a design, not a shipped system. As of this revision the
repository contains roughly 1,700 lines of Go, and exactly two things work:

| Layer | Component | Status |
|-------|-----------|--------|
| L0 | `internal/discovery/bootstrap` — multi-channel bridge resolution (DNS TXT / file / static), signed and expiring descriptors, partial-failure tolerant | **Implemented + tested** |
| L1 | `internal/network/transport` — tagged ClientHello with real-site fallback splice, hybrid post-quantum session handshake (X25519 + ML-KEM-768), TLS-record framing, replay cache | **Implemented + tested (known gaps)** |
| L2 | Relay pool, routing, reputation | Not started |
| L3 | Payment channels, contracts | Solidity sketches only, never compiled or deployed |
| L4 | Measurement / analytics | Not started |
| — | Satellite, LoRa, Crovi/Thump integration | Not started |

Everything else in this document is specification. Where a section describes
something unbuilt, it says so. Treating the rest of this file as a description of
existing capability would be a misrepresentation — the directory tree is mostly
`.gitkeep` files.

Two consequences for how to read the roadmap in [§16](#16-roadmap):

- The repository is close enough to a blank canvas that **no design decision here
  is load-bearing for legacy compatibility.** Choices are made on technical merit
  in the 2026 environment, not to preserve earlier drafts.
- The original month-numbered plan ("Months 1–3", "Months 4–6") is replaced with
  **falsifiable gates**. A calendar has no opinion about whether a censorship
  transport survives a probe; a test harness does.

---

## 1. Threat Environment (2026)

The original design targeted a censor that does signature-based DPI and IP
blocklisting. That censor still exists, but it is no longer the hard case. Five
shifts matter for Warren's design:

### 1.1 Blocking has moved from "detect the bad protocol" to "permit only the good app"

Detection-and-block is losing ground to allowlisting and to wholesale shutdown:

- **Regional mobile allowlists.** Russian authorities have repeatedly restricted
  mobile internet in specific regions to a published whitelist of domestic
  services during shutdown periods (reported from 2025 onward), rather than
  attempting to enumerate and block circumvention protocols.
- **National intranets.** Iran's National Information Network is built to keep
  domestic services reachable while foreign connectivity is severed, and was
  exercised during the near-total shutdown of June 2025.
- **Whole-country shutdowns as routine policy.** Afghanistan's nationwide
  fiber cut (September 2025) is the clearest recent case: nothing at the
  protocol layer helps when the physical layer is administratively off.
- **National firewall build-outs** outside the traditional set (e.g. Pakistan's
  centralized web-management deployment, 2024–2025).

**Design consequence:** "indistinguishable from generic HTTPS" is necessary but
bounded. Warren needs an explicit **degradation ladder** (§6.5) whose lower rungs
do not assume foreign HTTPS is reachable at all, and it must state plainly where
the ladder ends — against an enforced allowlist with no permitted foreign
endpoint, no network-layer trick wins.

### 1.2 Throttling has partly replaced blocking

Blocking is visible and politically expensive; degrading a service until users
abandon it is neither. Russia's TSPU-based throttling of specific platforms is
the reference case. A circumvention transport that treats "connected" as success
will report itself healthy while being unusable.

**Design consequence:** health signals must be goodput- and
completion-based, not reachability-based (§7.3), and the measurement layer must
distinguish *blocked* from *degraded* (§9).

### 1.3 Classification is statistical, and cheap

Flow classification using packet-size distributions, inter-arrival timing, and
handshake-shape features is commodity work now, and entropy-based detection of
"fully encrypted" protocols has been deployed in production by at least one
state-scale censor. Payload-signature evasion is no longer the frontier.

**Design consequence:** L1 must mimic a *live* browser profile (§6.2), and
traffic-shape defenses must be specified with an honest cost model — the earlier
"constant-rate cover traffic" line was both unbudgeted and, in a marketplace
where bandwidth is billed per GB, self-contradictory (§6.4).

### 1.4 Post-quantum handshakes are the common case

NIST standardized ML-KEM (FIPS 203), ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) in
August 2024, and draft NIST IR 8547 puts classical public-key crypto on a path to
deprecation around 2030 and disallowance by 2035. Independently of policy, the
hybrid group **X25519MLKEM768** now ships by default in mainstream browsers and is
supported across major CDNs, so a large and growing share of real TLS 1.3
handshakes carry a hybrid PQ key share — and a correspondingly large ClientHello
(~1.5–2 KB, frequently spanning multiple TCP segments).

**Design consequence, and the single most actionable item in this revision:** a
ClientHello that mimics a 2023 browser (no `key_share` for a hybrid group, ~500
bytes, one segment) is *anomalous in 2026*. Warren's current PoC pins uTLS's
Chrome-120 profile, which has exactly this problem (§6.2). Camouflage profiles are
now perishable goods and need a refresh process, not a constant.

The same standardization wave applies to Warren's own data plane: traffic recorded
today is decryptable later under a harvest-now-decrypt-later assumption, so the
Warren session handshake itself must be hybrid PQ (§11).

### 1.5 The client is a chokepoint, and so is the operator

Two non-network attack surfaces have proven more effective than DPI:

- **Distribution.** VPN applications have been removed from national app-store
  fronts on government demand (Russia, 2024, and similar pressure elsewhere).
  A circumvention tool that can only be installed from two app stores is
  blockable by email.
- **Operator liability.** Selling residential bandwidth to strangers is
  structurally identical to the residential-proxy market, whose abuse history
  brought law-enforcement action (e.g. the 911 S5 takedown, 2024) and continued
  criminal monetization of residential IPs through 2025. A Warren seller whose
  home IP is used for fraud, intrusion, or CSAM distribution faces real legal and
  ISP-contractual exposure. The original design had *nothing* to say about this;
  it is now §7.4, and it is a precondition for anyone sane to run a node.

---

## 2. Scope & Non-Goals

Warren operates at the **network layer**. Its purpose is **censorship
resistance**: making it structurally hard for a state-level adversary to *block*
a connection, and making an individual connection *indistinguishable from
ordinary current-generation HTTPS traffic* to passive DPI, statistical
classifiers, and active probing.

Anonymity is not a single property — it splits into three layers, and Warren only
addresses one of them. Being explicit about this boundary is a security property
in itself: a system that implies protections it does not provide gets users hurt.

| Layer | What it hides | Warren's coverage |
|-------|---------------|-------------------|
| **Network reachability** | Your IP/location from blocklists; the fact that a connection is a circumvention tunnel | **In scope** — this is Warren's core (residential relay pool + camouflaged transport) |
| **Traffic metadata / timing correlation** | *That* you communicated with a given endpoint, inferable from packet timing and volume | **Partial / best-effort, opt-in cost** — bucketed sizing and padding regimes raise the bar; Warren is a relay network, **not** a mixnet, and end-to-end timing correlation by an adversary who sees both ends is out of scope |
| **Identity** | *Who you are*: browser fingerprint, logged-in accounts, payment trail, writing style | **Out of scope** — Warren carries bytes; it cannot unlink an account you log into or a browser that is uniquely fingerprintable |

### Explicit non-goals

- **Not an anonymity network in the Tor sense.** No sender–receiver unlinkability
  against an adversary observing both ends. If your threat model includes global
  traffic correlation, compose Warren with a mixnet (Nym/Loopix-class), not Warren
  alone.
- **Not identity protection above the network layer.** Fingerprinting, cookies,
  logged-in sessions, payment identifiers, and stylometry are outside its reach.
  Run a fingerprint-resistant client *over* Warren.
- **Not a "trust us" VPN.** Warren avoids concentrating trust in one
  operator-controlled exit set, and therefore cannot make the latency or
  simplicity guarantees a centralized VPN can.
- **Not a defense against physical-layer shutdown.** When connectivity is
  administratively severed, Warren degrades to local/mesh operation (§10) and says
  so; it does not pretend to route around a cut fiber.
- **Not a coin.** The core protocol must be fully functional with settlement
  disabled (§8). No part of reachability may depend on a token's existence, price,
  or a chain's liveness.

### The intended composition

```
[Fingerprint-resistant client: Tor Browser / hardened app]   <- identity layer (NOT Warren)
                        |
[Optional: mixnet for timing defense]                        <- metadata layer (NOT Warren)
                        |
[Warren: unblockable, camouflaged network transport]          <- reachability layer (THIS project)
                        |
[Hostile network / censored ISP]
```

Warren's contribution is the bottom layer: **when the network itself is trying to
stop you from connecting at all, Warren is what still gets a connection through.**

---

## 3. Design Principles

These are the rules the rest of the document is accountable to.

1. **Reuse audited implementations for anything cryptographically deep.** The
   REALITY authentication path, ZK circuits, and PQ KEMs are not places to
   innovate. Where Warren has a hand-rolled version (the current static-PSK
   transport), the migration target is a maintained upstream implementation, and
   that is recorded as a gap, not a feature.
2. **Every layer must fail independently.** Discovery failing must not break
   established sessions; settlement failing must not break routing; measurement
   failing must not break anything.
3. **No privacy liability without a revenue or safety justification that survives
   a hostile reading.** Applied here, it retired per-event on-chain evasion logs
   (§14): the analytics product needs regional aggregates, and aggregates do not
   require publishing "someone in region X evaded censorship at time T" to an
   immutable public ledger.
4. **Perishable defenses need refresh machinery, not constants.** Camouflage
   profiles, fallback site pairings, and bridge distribution channels all expire.
   Anything with a shelf life gets an update path and a staleness alarm.
5. **Gates, not dates.** Each roadmap slice states a falsifiable pass condition
   (§16). "Survives the active-probe harness" is a gate; "Month 6" is not.
6. **State costs in the units users pay.** Latency, gigabytes, battery, dollars.
   A defense whose overhead is not written down is a defense that will be turned
   off in production.

---

## 4. Layered Architecture

```
L4  Measurement        private aggregate telemetry (opt-in)         [not started]
L3  Accounting         offline credits; optional on-chain settle    [sketch only]
L2  Relay pool         path selection, reputation, abuse policy     [not started]
L1  Transport          camouflaged, PQ-hybrid, pluggable            [PoC]
L0  Discovery          multi-channel bridge + client distribution   [implemented]
```

Control plane and data plane are separate: L0/L4 are control, L1/L2 are data, L3
is out-of-band with respect to both. Node types collapse from the original five
to three **roles** (a process may hold several):

| Role | Responsibility |
|------|----------------|
| **Client** | Originates traffic, resolves bridges, selects paths, enforces local policy |
| **Relay** | Accepts camouflaged connections, forwards, optionally sells capacity; borrows a TLS identity from a real site it can actually reach |
| **Exit** | Egresses to the open internet under a declared exit policy (§7.4). **Explicitly a distinct role** — running a relay must not implicitly make a home connection an exit |

The earlier "Privacy Node / Logger Node / Satellite Node" taxonomy is folded in:
policy enforcement is a client concern, measurement is a control-plane service,
and satellite/mesh is a link type available to any role (§10).

---

## 5. L0 — Discovery & Client Distribution

**Status: implemented** (`internal/discovery/bootstrap`) for bridge resolution;
distribution hardening not started.

The implemented design is unchanged in principle and remains correct: `Multi`
queries every configured resolver concurrently, merges all successes, and returns
a per-channel report so a client survives channels being blocked one at a time and
operators can see *which* channel is blocked in which region. Resolvers today:
DNS TXT (injectable lookup), local bridge file (the landing point for
out-of-band distribution), and a compiled-in static list of last resort.

### 5.1 Additions required by the 2026 environment

- **Encrypted-transport resolvers.** Plain DNS TXT is trivially tampered with at
  the resolver. Add DoH/DoQ resolvers. (Every DNS answer is already treated as
  untrusted input requiring signature verification, which is the part that
  matters for integrity; encryption is about not advertising the query.)
- ✅ **Signed bridge lists.** Every descriptor carries an Ed25519 signature over
  `(version, issued, expires, bridges)` — including each relay's identity key —
  verified against an anchor shipped in the client. The signature covers the
  literal wire bytes rather than a re-serialization of parsed fields. Channels a
  censor can influence (file, DNS) fail closed without an anchor; only the
  compiled-in static list needs none. A hostile channel is now a
  denial-of-service problem, not an attack that can steer clients onto
  censor-run relays.
- **Client distribution as an L0 concern.** Bridges are useless without a client.
  Required: reproducible builds, verifiable release artifacts, and at least three
  distribution channels that are not the two mainstream app stores (direct
  download with signature, F-Droid-style repository, and a peer-to-peer/sideload
  path). A blocked update channel must degrade to "old client keeps working with
  stale bridges", never to "client cannot start".
- ✅ **Staleness is a first-class state.** An expired descriptor still yields
  bridges, marked stale; `Multi` prefers fresh copies for the same relay and
  reports which channels serve only stale data. Treating expiry as fatal would
  let a censor strand clients by blocking every channel for a week. Jittered
  retry across channels is still to do.

### 5.2 Explicit non-mechanism

Warren does **not** operate a central bridge-distribution API, nor publish a
global relay list. Enumerability is the failure mode that kills relay pools
(§7.2); discovery deliberately returns small, per-requester, rotating subsets.

---

## 6. L1 — Transport & Camouflage

**Status: proof of concept implemented** (`internal/network/transport`), with the
gaps below. This is the layer where this revision changes the most.

### 6.1 What exists

A Warren client's first packet is a syntactically valid TLS 1.3 ClientHello built
with [uTLS](https://github.com/refraction-networking/utls). Two things ride inside
it: a 16-byte authentication tag in the `session_id` field, and the client's own
ephemeral **X25519MLKEM768** key share in the exact wire layout a real browser
sends for that group (ML-KEM-768 encapsulation key ‖ X25519 public key).

The tag is `HMAC-SHA256(ss_auth, "warren-tag-v1" ‖ client_random ‖ client_share)`
where `ss_auth = X25519(client_ephemeral, relay_identity_public)`. The relay peeks
the first record:

- **Tag valid, random unseen** → the relay answers with a real-shaped TLS 1.3
  ServerHello carrying the ML-KEM ciphertext plus its own ephemeral X25519 key,
  then a ChangeCipherSpec; the client answers with its own ChangeCipherSpec.
  Both sides derive the session key from three secrets — ML-KEM (post-quantum),
  ephemeral X25519 (forward secrecy), and the identity exchange (authentication)
  — and application data flows in records framed as TLS `application_data`.
- **Tag invalid, absent, malformed, or replayed** → the raw bytes are spliced
  byte-for-byte to a real fallback site, so a probe gets a genuine response from
  a genuine service, because that is literally what answered.

Three properties this buys over the first proof of concept, which authenticated
with a static pre-shared key and derived its session key from that PSK alone:

1. **No shared secret exists.** Clients hold only the relay's public key, so a
   compromised client reveals nothing about any other session.
2. **Forward secrecy.** Seizing a relay's identity key does not decrypt sessions
   recorded earlier; the ephemeral halves are gone.
3. **Post-quantum confidentiality** for recorded traffic, which matters because
   circumvention traffic is exactly what gets recorded for later analysis.

Replay is handled explicitly: the tag is a function of the hello, so a captured
hello re-sent verbatim would validate. The relay keeps a bounded replay cache of
recent `client_random` values and treats a repeat like any unauthenticated
connection — spliced to the real site — so a censor cannot confirm a relay by
replaying one recording.

Remaining gaps are documented in `docs/protocol/reality-transport.md`; the
blocking one is now the state machine after the ServerHello, not the key
schedule.

### 6.2 Camouflage profiles are perishable (new, blocking)

The PoC pins `utls.HelloChrome_120` — a late-2023 profile with **no hybrid PQ key
share**. In an environment where a large share of genuine browser handshakes offer
`X25519MLKEM768`, that profile is a distinguisher rather than a disguise: it is
both stale relative to the claimed browser version and small relative to the real
size distribution.

Status: **done**, except per-region selection.

- ✅ Track a **current** profile: `DefaultFingerprint` is `utls.HelloChrome_Auto`,
  and `Config.Fingerprint` overrides it per bridge. The resulting hello is
  ~1.5 KB and carries `X25519MLKEM768`, which Warren's own handshake now hides
  inside rather than merely parroting.
- ✅ **Multi-segment ClientHello.** The relay peeks the whole record rather than a
  fixed-offset prefix, so a segmented arrival blocks until the record is complete
  or the sniff deadline fires. Exercised by a test that delivers the hello in
  137-byte chunks through a fragmenting proxy.
- ✅ **Profile-refresh test.** CI asserts the active profile's key-share groups
  include a hybrid PQ group, so the disguise can't silently rot.
- **Per-region profile choice.** The right parrot is "what the local population
  actually runs", which is not globally uniform. The profile is a configuration
  input resolved alongside bridges (§5), not a compile-time constant.

### 6.3 Pluggable transports (new)

A single transport is a single point of failure. L1 is re-specified as an
interface with several concrete implementations, selected per-bridge and
per-region by the degradation ladder (§6.5):

| Transport | Shape on the wire | Notes |
|-----------|-------------------|-------|
| `tls-borrow` (current) | TLS 1.3 to a real site, tagged hello, real-site fallback | Strongest against active probing; TCP only |
| `masque` | HTTP/3 over QUIC; `CONNECT-UDP` (RFC 9298) / `CONNECT-IP` (RFC 9484) | Standards-based proxying, indistinguishable from the growing volume of real MASQUE traffic (Apple iCloud Private Relay, Cloudflare WARP). Dies wherever UDP/443 is blocked — which is common |
| `websocket-tunnel` | Long-lived WSS inside an ordinary HTTPS site | The Tor WebTunnel pattern: cheap to host behind a real CDN-fronted site |
| `rendezvous` | Browser-sourced WebRTC (Snowflake pattern) | Last-resort reachability when all fixed relays are blocked; low throughput |

Selection is a policy, and policies are local. The client never receives "use
transport X" as an instruction from the network without verifying it against a
signed bridge descriptor.

### 6.4 Traffic shaping, with a cost model (revised)

The prior design specified "fixed-bucket packet sizing plus constant-rate cover
traffic during idle periods". The mechanism is right; the specification was
unusable for two reasons: no overhead budget, and — in a network where relays bill
per gigabyte (§8) — constant-rate cover traffic means **paying a relay to carry
noise**, continuously, on a residential uplink.

Revised: three named regimes, client-selectable, each with a stated cost.

| Regime | Mechanism | Overhead | When |
|--------|-----------|----------|------|
| `off` | No shaping beyond the transport's own record sizes | 0% | Default for throughput-bound use (VDI, bulk) |
| `bucket` | Payload padded to a small set of fixed sizes; no injected idle traffic | Bounded, typically <15% of carried bytes | Default for interactive browsing |
| `cover` | `bucket` plus constant-rate cover during idle, rate-capped and duty-cycled | Explicit: a configured bytes/hour ceiling the user opts into and pays for | Only where a named local threat justifies it |

Honesty requirement: `cover` raises the cost of website-fingerprinting attacks; it
does not defeat a determined classifier, and published padding-defense results
(Tor's padding machines onward) are a record of partial mitigation, not solution.
The doc must not claim otherwise, and the default must not be a regime whose bill
the user did not agree to.

### 6.5 Degradation ladder (new)

The client walks down this ladder and reports which rung it is on. Each rung is a
weaker but more survivable posture:

```
1. tls-borrow to a nearby residential relay            (normal operation)
2. tls-borrow / websocket-tunnel behind a real CDN-fronted site
3. masque to a large shared provider endpoint          (blends with real MASQUE)
4. rendezvous (WebRTC/Snowflake pattern)               (throughput collapses)
5. domestic-permitted-endpoint carriage                (where any allowlisted
   endpoint can carry bytes; regionally specific, high risk, opt-in only)
6. mesh / store-and-forward                            (no foreign reachability;
   local control plane only, see §10)
7. offline: local cache serving only
```

Rungs 5 and 6 are where an allowlist regime (§1.1) puts users, and both are honest
about what they cannot do. The ladder's existence is the design's answer to
§1.1 — not a claim that rung 1 always works.

---

## 7. L2 — Relay Pool, Routing & Abuse Containment

**Status: not started.** This layer carries the design's central bet.

### 7.1 The two-layer anti-blocklisting model (retained)

State-scale censors block by IP/ASN reputation and by active probing, not
primarily by decoding protocols. Commercial VPNs are blocked within days because
their exits sit on small, enumerable datacenter ranges; domain fronting died when
major CDNs disabled cross-domain SNI/Host mismatch. So:

```
Layer 1 (structural):  a large pool of ordinary residential relays, churning as
                       sellers join and leave
                       -> the censor's blocking cost scales with the number of
                          households, not the number of VPN companies

Layer 2 (protocol):    per-connection camouflage (§6)
                       -> each connection looks like a real visit to a real site,
                          to passive DPI, statistical classifiers, and probes
```

This composes two independently proven patterns — large ephemeral proxy pools
(Psiphon/Snowflake) and probe-resistant TLS borrowing (REALITY) — rather than
inventing one. Module 1 is therefore **primary censorship infrastructure**, not
just a revenue mechanism.

### 7.2 Enumerability is the real adversary

A pool's value is entirely in the censor's inability to enumerate it. Therefore:

- **No global relay list exists anywhere**, including on any relay, and including
  on-chain. This is the decisive argument against the original design's on-chain
  bandwidth listings: a public contract that enumerates sellers, their capacity,
  and their addresses is a censor's blocklist with a REST API and a permanent
  archive. Listings must be private and query-scoped (§8.2).
- **Discovery returns rotating per-requester subsets** (§5.2), rate-limited by
  unlinkable tokens (§8.3) so enumeration costs the censor real resources.
- **Selection prefers diversity and churn over quality.** For a resilience
  session the router wants many small, short-lived residential endpoints — the
  opposite of a throughput optimizer's choice. This is the `mode=resilience`
  weighting: an explicit, measurable trade of throughput for endpoint diversity.

### 7.3 Path selection and health

Health is **goodput- and completion-based**, not reachability-based, because
throttling is now a primary tactic (§1.2). Per-path signals: achieved goodput
versus advertised, request-completion rate, latency distribution (not just mean),
and handshake-failure rate. A path that connects and then delivers 40 kbit/s is
*unhealthy*, and the router must say so rather than reporting success.

Reputation is local-first: each client maintains its own scores, optionally
seeded by signed aggregate hints. A globally shared reputation score is both an
enumeration oracle and a sybil target.

### 7.4 Abuse containment and operator liability (new, blocking)

Nobody should run an exit without this, and the original design shipped no answer
at all. Requirements:

- **Relay ≠ exit.** Default installation makes a node a *relay only*. Becoming an
  exit is a separate, explicit, informed action with jurisdiction-aware warnings.
- **Declared exit policy, enforced locally.** Exits publish a machine-readable
  policy (permitted ports/protocols, rate caps) in their signed descriptor, and
  enforce it. Sensible default: no SMTP, no scanning-shaped traffic, aggressive
  per-source rate limits.
- **Abuse response path.** A documented complaint-handling procedure, per-exit
  contact metadata, and templated ISP-response documentation — the operational
  asset Tor exit operators rely on, which is what makes exit operation survivable.
- **No logs that identify users, and that must be a design property, not a
  promise.** An exit cannot answer "who sent this" if it never had the
  information; the accounting design (§8) must therefore not require exits to
  retain per-session user identifiers.
- **Stated residual risk.** Selling residential bandwidth resembles the
  residential-proxy market whose abuse invited law-enforcement action (§1.5).
  Warren's countermeasures reduce but do not eliminate operator exposure, and the
  onboarding flow must say that in plain language, before a user enables an exit.

---

## 8. L3 — Accounting & Settlement

**Status: Solidity sketches only.** Re-specified here; the old sketches
(`contracts/`) are superseded.

### 8.1 The core must work with settlement off

Reachability may not depend on a chain being live, a token having value, or a
user holding one. Warren therefore defines an **accounting interface** with
pluggable backends:

| Backend | Use |
|---------|-----|
| `none` | Volunteer relays, altruistic pool. Fully functional. Default. |
| `credits` | Signed off-chain receipts; redeemable, or never redeemed |
| `onchain` | Optional adapter that settles net balances on a low-cost L2 |

### 8.2 If on-chain, then L2-only and privately

- **Never L1 mainnet for micro-settlement.** Post-EIP-4844 (Dencun, 2024) rollup
  data costs made L2 settlement the only defensible choice; the original design's
  "Ethereum mainnet" target is obsolete on cost grounds alone.
- **Testnet names updated:** Goerli and Holesky are retired. Current targets are
  **Sepolia** and **Hoodi**.
- **Sponsored transactions are standard now.** ERC-4337 paymasters and EIP-7702
  delegation (Pectra, 2025) provide sponsored/abstracted transactions off the
  shelf. Warren's bespoke "bonded relayer pays gas" scheme (§14) is a
  reimplementation of a solved problem and is dropped.
- **No public listings.** Capacity offers are exchanged over the Warren control
  plane and settled on-chain only as net balances between counterparties, never as
  a browsable directory of residential relays (§7.2).
- **Net settlement, hybrid trigger.** Off-chain signed receipts, with settlement
  on the earlier of a volume or time threshold (starting point: 10 MB or 5 s of
  open exposure, tuned against real receipt sizes). This part of the original
  design was sound and is retained.

### 8.3 Access rights without identity (revised)

The original design authenticated relay access with a bespoke ZK "passport"
circuit. The 2026 answer is an off-the-shelf standard: **Privacy Pass** (RFCs
9576–9578, 2024) issues unlinkable, single-use tokens. A client redeems a token to
open a session or to fetch a discovery subset; the relay learns *that* the client
holds a valid entitlement, not which client, and cannot link two redemptions.

This replaces the hand-rolled nullifier scheme for the authorization use case and
covers the property that actually mattered — non-linkability across sessions —
with an implemented, reviewed protocol. A ZK circuit remains justified only if
Warren later needs attribute proofs (e.g. "holder of a real e-passport", for which
ICAO-9303-based stacks now exist); in that case the library is **gnark** (Go
native) or Noir/Halo2-class tooling, **not libsnark**, which has been unmaintained
for years.

### 8.4 Regulatory reality (new)

- **EU:** MiCA has been fully applicable since 30 December 2024, and DAC8
  reporting obligations begin in 2026. A freely transferable Warren token with a
  public issuer is a regulated instrument, not a design detail.
- **Consequence:** the `credits` backend is the default commercial path —
  non-transferable, redeemable-for-service accounting. A transferable token, if it
  ever exists, is a separate product decision with separate legal work, and the
  protocol must not assume it.

---

## 9. L4 — Private Measurement

**Status: not started.** This section replaces the Independence Logger's on-chain
per-event design.

### 9.1 Why the old design is retired

The original scheme wrote a ZK proof of "censorship evaded in region R at time T"
to a public chain, via bonded relayers, to support NGO/research data
subscriptions. Three problems:

1. **It publishes a permanent, timestamped, region-tagged record of circumvention
   activity.** Relayer indirection hides the wallet, not the event. In a small
   region and a quiet hour, an event count *is* identifying, and immutability
   means a future adversary inherits the whole archive.
2. **It solves a solved problem worse.** Aggregate censorship measurement has
   mature public infrastructure (OONI, IODA, Cloudflare Radar). Reinventing
   collection adds no research value; contributing measurements does.
3. **Its stack was dead.** libsnark is unmaintained; per-event ZK proof generation
   for telemetry is enormous cost for a statistic.

### 9.2 What replaces it

- **Private aggregation, not published events.** Clients submit measurements
  through a threshold-aggregation protocol (Prio/STAR-class, as deployed by ISRG's
  Divvi Up and Cloudflare) where the collector learns only aggregates above a
  k-anonymity threshold and never an individual report. Reports travel over
  Oblivious HTTP (RFC 9458) so the collector does not learn submitter IPs.
- **Opt-in, per-region, with an explicit k-threshold** below which a bucket is
  simply never reported.
- **Blocked vs. degraded as distinct signals** (§1.2), which is the measurement
  the analytics product genuinely lacks today and can defensibly sell.
- **Interoperate, don't duplicate:** publish in OONI-compatible form where
  possible so Lumra's analytics and external researchers consume one schema.

The revenue line survives: regional censorship analytics with a differentiated
*degradation* signal, sold as aggregates. What's gone is the liability of an
immutable public log of evasion events.

---

## 10. Resilience Transports (Satellite / Mesh)

**Status: not started.** Re-specified as a **link type**, not an API integration.

### 10.1 Corrections to the old design

- **There is no consumer Starlink "establish tunnel" API.** The old pseudocode
  (`StarlinkClient.EstablishTunnel(gateway)`) describes something that does not
  exist. What a satellite link actually provides is an ordinary IP path with
  distinctive latency, jitter, cost, and CGNAT behavior. Warren models it as a
  link with attributes, and everything above L1 stays unchanged.
- **Naming:** Amazon's Project Kuiper has been commercially branded **Amazon Leo**
  since late 2025. Design text should name the service, not the codename.
- **Direct-to-cell now exists** (e.g. T-Mobile's Starlink-backed T-Satellite,
  commercial since 2025) and is a *messaging-class* link: excellent for control
  plane, useless for data plane. It belongs on the ladder's lower rungs.
- **Satellite terminals are a physical-risk vector, not a circumvention win.**
  Possession is illegal in several censored jurisdictions, and a user terminal
  emits a direction-findable signal. Recommending satellite as a censorship
  workaround without saying this would endanger users; for most users under an
  allowlist regime it is *more* dangerous than the network problem it solves.
- **The old health formula was not a health score.**
  `(1 - loss/100) * (1000/(latency+1)) * (bandwidth/100)` is unbounded and
  compared against `0.6`, which is meaningless. Health is re-specified as
  normalized, weighted goodput/completion/latency-percentile terms in [0, 1],
  with hysteresis so a failover doesn't oscillate.
- **LoRa capacity was overstated by 1–2 orders of magnitude.** The old claim of
  "~500 control messages/second" is impossible: at an optimistic 50 kbit/s, a
  100-byte message is 800 bits, giving ~60/s *theoretically*; at long-range
  spreading factors the link is a few hundred bit/s, and EU sub-GHz duty-cycle
  limits (commonly 1%) cap airtime at tens of seconds per hour. The realistic
  budget is **single-digit messages per minute**, which changes the design: the
  control plane must be built for store-and-forward with prioritized queues, not
  periodic heartbeats.

### 10.2 Revised model

```
Link types, each with {goodput, latency, jitter, cost/GB, legality risk, detectability}:
  terrestrial-broadband | mobile | satellite-vsat | satellite-d2c | lora-mesh

Policy picks a link per traffic class:
  data-plane (VDI, bulk, browsing)  -> terrestrial | mobile | satellite-vsat
  control-plane (heartbeat, DHT, checkpoint signals)
                                    -> any, including satellite-d2c and lora-mesh
  nothing                           -> lora-mesh gets data-plane traffic, ever
```

Strict tiering is retained and remains correct: routing VDI or workload migration
over a kilobit mesh collapses the mesh. The enforcement mechanism is a policy-level
drop on data-plane classes when the active link is mesh-grade, plus a user-visible
"resilience mode (control only)" state.

For the mesh itself, prefer the existing ecosystem (**Meshtastic**-class LoRa
firmware and its addressing/routing) over a bespoke controller. Incentive payouts
per relayed byte are dropped for mesh: with single-digit messages per minute there
is no meaningful byte-volume market, and a payout scheme creates a spam incentive
on the scarcest link in the system.

---

## 11. Cryptographic Inventory

Every primitive, its status, and why. Hybrid PQ is the default for anything whose
recording today could be decrypted later.

| Purpose | Choice | Rationale |
|---------|--------|-----------|
| Session key exchange (Warren data plane) | **Hybrid X25519 + ML-KEM-768** — *implemented* (`crypto/mlkem`, `crypto/ecdh`) | FIPS 203 standardized 2024; harvest-now-decrypt-later applies to long-lived recordings of circumvention traffic |
| Camouflage handshake shape | uTLS profile whose `key_share` includes `X25519MLKEM768` — *implemented* | Must match what real browsers send *now* (§6.2), and it is where Warren's own key exchange hides |
| AEAD | ChaCha20-Poly1305 default; AES-256-GCM where hardware AES is present | ChaCha for CPU-only/mobile; AES-NI/ARMv8-crypto devices are faster with GCM |
| Hash / KDF | SHA-256 (interop), BLAKE3 (bulk), HKDF-SHA256 | Unchanged, still correct |
| Signatures (descriptors, releases) | Ed25519 now; **ML-DSA-65 hybrid planned** | FIPS 204; signature agility must exist before it is needed |
| Access tokens | Privacy Pass (RFC 9576–9578) | Unlinkable entitlement without identity (§8.3) |
| Telemetry aggregation | Prio/STAR-class threshold aggregation over OHTTP (RFC 9458) | Aggregates without individual reports (§9.2) |
| ZK (only if attribute proofs are needed) | **gnark** (Go) or Noir/Halo2-class | libsnark is unmaintained and is removed from the stack |
| RNG | OS CSPRNG (`getrandom`, `BCryptGenRandom`) | Unchanged |

Retired from the earlier design: **the static PSK is gone** — authentication is now
an X25519 exchange with the relay's long-term identity key, whose public half
travels in the bridge descriptor; libsnark; and the Kyber draft groups superseded
by ML-KEM.

---

## 12. Integration Layer (Crovi / Thump)

Unchanged in intent, tightened in contract. Both integrations are **consumers of
L1/L2**, and neither may become a required dependency of the transport.

**Crovi (VDI).** On session start, Crovi hands Warren a policy-set identifier;
Warren applies the corresponding local policy (shaping regime, path mode, exit
constraints) to that desktop's traffic. Warren never receives the user's identity,
and Crovi never receives path details that would let it correlate a user to a
relay. VDI traffic is throughput-bound, so its default shaping regime is `off`
with `bucket` available (§6.4) — the earlier "auto-apply cover traffic to VDI"
assumption is removed as unaffordable.

**Thump (infrastructure protection).** Thump signals workload relocation; Warren
re-provisions the network path and reports the link class it landed on, so Thump
can decide whether to proceed. In mesh-grade resilience mode Warren reports
control-plane-only, and Thump holds migrations rather than attempting them over a
kilobit link.

---

## 13. Security Model

| Threat | Adversary | Mitigation | Status |
|--------|-----------|-----------|--------|
| Payload signature DPI | ISP, state | Camouflaged transport, real-site fallback, TLS-record framing (§6.1) | Implemented |
| Active probing | State probe infrastructure | Untagged, wrong-key, and replayed connections all receive a genuine response from the real fallback site | Implemented |
| Stale-parrot fingerprinting | State classifier | Current uTLS profile incl. hybrid PQ key share, CI staleness check (§6.2) | Implemented (per-region selection: gap) |
| TLS state-machine mimicry after ServerHello | Censor who holds a valid tag and watches a full session | Real-shaped ServerHello + ChangeCipherSpec + `application_data` records; a complete borrowed handshake still missing | Partial (documented) |
| Statistical flow classification | State classifier | Shaping regimes with stated cost (§6.4) | Not started |
| IP/ASN blocklisting | Bulk range blocking | Residential pool scale + churn (§7.1) | Not started |
| Relay pool enumeration | Censor harvesting the pool | No global list; rotating per-requester subsets; token-rate-limited discovery (§7.2) | Design changed, not started |
| Discovery takedown | Blocking the bridge source | Multi-channel resolvers, signed expiring descriptors, no central API (§5) | Implemented |
| Hostile discovery channel steering clients to a censor-run relay | Censor operating or tampering with a bridge channel | Signed descriptors covering each relay's identity key; resolvers fail closed without a trust anchor | Implemented |
| Captured-hello replay | Probe re-sending a recorded hello | Bounded replay cache on `client_random`; a repeat is spliced to the real site (§6.1) | Implemented |
| Client distribution takedown | App-store removal orders | Reproducible builds, ≥3 non-app-store channels (§5.1) | Not started |
| Throttling instead of blocking | State traffic management | Goodput-based health, degraded-vs-blocked signal (§7.3, §9) | Not started |
| Sybil relays / malicious sellers | Profit-motivated or state-run nodes | Local-first reputation, collateral where settlement is on, path diversity | Not started |
| Session linkability | Correlating observer | Privacy Pass unlinkable tokens (§8.3) | Design changed, not started |
| Wallet-graph deanonymization | Chain analyst | Net-balance L2 settlement, sponsored transactions, no public listings (§8.2) | Design changed |
| Evasion-log exposure | Future adversary reading an immutable ledger | On-chain per-event logging removed; threshold aggregation only (§9) | Design changed |
| Exit-node abuse → operator liability | Criminal users; police; ISP | Relay≠exit default, declared exit policy, abuse handling, no identifying logs (§7.4) | **New requirement, not started** |
| Mesh flooding | Attacker on LoRa | Control-plane-only classes, prioritized store-and-forward, no per-byte payouts (§10.2) | Design changed |
| Harvest-now-decrypt-later | Well-resourced recorder | Hybrid X25519+ML-KEM-768 session handshake (§11) | Implemented |
| Slowloris on the sniff path | Cheap resource exhaustion | 5-second sniff deadline | Implemented |
| Allowlist regime / shutdown | State, physical + policy layer | Degradation ladder rungs 5–7, stated honestly as partial (§6.5, §10) | Not started |

### Privacy guarantees (as designed)

1. **Data privacy.** No relay can read payloads; no Warren-operated component holds
   plaintext.
2. **Reachability privacy.** Camouflaged transport makes a Warren connection look
   like a real visit to a real site, against passive DPI and active probes.
3. **No identity requirement.** Access rights are unlinkable tokens; Warren never
   needs a user identifier, so no component can be compelled to produce one.
4. **Financial privacy.** Default accounting is off-chain and non-transferable;
   on-chain settlement, if enabled, publishes net counterparty balances, not
   sessions.
5. **Measurement privacy.** Telemetry is opt-in, threshold-aggregated, and
   IP-blinded; no per-event circumvention record is ever published.
6. **Stated limits.** No metadata-correlation guarantee against an adversary who
   sees both ends; no protection against a fingerprintable client; no defense
   against physical shutdown.

---

## 14. Deprecated Decisions

Recorded so the reasoning isn't re-litigated, and so anyone reading an older draft
knows what changed.

| Earlier decision | Status | Why |
|------------------|--------|-----|
| Naive SNI spoofing | Removed (already in the prior revision) | SNI-to-IP ownership correlation flags it instantly |
| `HelloChrome_120` pinned profile | **Superseded** | No hybrid PQ key share; a 2023 parrot is a 2026 distinguisher (§6.2) |
| TCP-only custom framing as the sole transport | Superseded | Single point of failure; MASQUE/WebSocket/WebRTC paths added (§6.3) |
| Constant-rate cover traffic, always on | Superseded | Unbudgeted, and contradicts per-GB billing; replaced with three costed regimes (§6.4) |
| On-chain per-event evasion logging | **Removed** | Publishes a permanent region-tagged record of circumvention; replaced by threshold aggregation (§9) |
| Bespoke bonded-relayer gas payment | Removed | ERC-4337 / EIP-7702 solve sponsored transactions as a standard (§8.2) |
| Ethereum mainnet for settlement; Goerli for test | Superseded | L2 settlement post-4844; Goerli/Holesky retired, use Sepolia/Hoodi (§8.2) |
| Public on-chain bandwidth listings | **Removed** | A public, permanent directory of residential relays is a censor's blocklist (§7.2) |
| libsnark for ZK | Removed | Unmaintained; gnark/Noir-class tooling if ZK is needed at all (§8.3, §11) |
| Bespoke ZK-Passport nullifier for access control | Superseded | Privacy Pass provides unlinkable tokens as a published standard (§8.3) |
| Static PSK as authentication root | Retained only as PoC | Migration target is an audited REALITY implementation with ECDH-in-`key_share` |
| `Starlink.EstablishTunnel` API integration | Removed | No such consumer API; satellite is a link type (§10.1) |
| "Amazon Kuiper" | Renamed | Commercially **Amazon Leo** since late 2025 |
| "~500 LoRa control messages/second" | **Corrected** | Off by 1–2 orders of magnitude; duty cycle limits imply single-digit messages/minute (§10.1) |
| Unbounded "health" formula compared to 0.6 | Corrected | Re-specified as normalized [0,1] with hysteresis (§10.1) |
| Five node types | Simplified | Three roles: client / relay / exit — and relay≠exit is a safety property (§4, §7.4) |
| Month-numbered roadmap | Replaced | Falsifiable gates (§16) |

---

## 15. Open Problems

Honest list of things this design does not yet answer.

1. **Fallback-site sourcing at scale.** Every relay needs a real, currently-popular
   HTTPS site it can legitimately proxy to, per region, refreshed as sites change.
   Who curates that list, how it is distributed without becoming enumerable, and
   what happens when a borrowed site starts rejecting the relay, are unsolved.
2. **Residential relay supply.** The structural defense assumes thousands of
   households relay traffic. Given §7.4's liability discussion, the acquisition
   story is unproven, and altruistic supply (Snowflake's model) may be the only
   honest starting point — which changes the business model, not just the roadmap.
3. **Sybil resistance without identity or a token.** Local-first reputation delays
   the problem; it doesn't solve a state-funded adversary running 10,000 relays.
4. **Shaping's real effectiveness.** Bucketing and cover traffic have published
   partial results. Warren needs its own measurements against a current classifier
   before claiming anything.
5. **Rung 5 of the ladder** (carriage over allowlisted domestic endpoints) is the
   most valuable and the most dangerous rung. It needs a per-region threat
   assessment before any implementation.
6. **Analytics product-market fit** for a "degradation" signal, now that the
   on-chain evasion log is gone, is an assumption and not yet validated with the
   NGO/research buyers the business plan names.

---

## 16. Roadmap

Gated slices, ordered by "what makes everything above it moot if it fails".
Each slice ships with its own falsifiable gate; no slice starts before its
predecessor's gate is met.

### Slice 1 — L1 hardening (in progress)

- [x] Tagged ClientHello + real-site fallback splice, tested end-to-end
- [x] Multi-channel bridge resolution with partial-failure reporting
- [x] Current camouflage profile with hybrid PQ key share; segmented-hello handling
- [x] CI staleness assertion on the active profile's key-share groups
- [x] Hybrid X25519+ML-KEM-768 session handshake; static PSK removed; per-relay
      identity keys carried in the bridge descriptor
- [x] Replay cache, so a captured hello can't be used to confirm a relay
- [x] TLS-record framing for application data (no bespoke length prefix)
- [x] Signed, expiring bridge descriptors, with staleness as a reported state
- [ ] Complete borrowed TLS handshake, or migration to an audited REALITY
      implementation — note upstream REALITY is X25519-only, so adopting it
      as-is trades the post-quantum property for the mimicry property

**Gate:** an isolated active-probe harness — a probe that connects, replays, and
resumes against a Warren relay — cannot distinguish it from the borrowed site, and
the client's ClientHello is not distinguishable by key-share/size/version features
from the current profile of the browser it parrots.

### Slice 2 — L1 breadth + L0 distribution

- [ ] `masque` transport (RFC 9298/9484) and `websocket-tunnel`
- [ ] Transport selection policy + degradation ladder rungs 1–4
- [ ] Reproducible builds and ≥3 non-app-store distribution channels
- [ ] Shaping regimes `bucket` / `cover` with measured overhead

**Gate:** with UDP/443 blocked, with the primary transport blocked, and with the
newest bridge list expired, a fresh client still reaches the network, and reports
the rung it is on.

### Slice 3 — L2 relay pool

- [ ] Relay/exit role separation with exit policy enforcement
- [ ] Abuse-handling documentation and per-exit contact metadata
- [ ] Goodput-based health and local-first reputation
- [ ] `mode=resilience` diversity-weighted selection; rotating discovery subsets
- [ ] Privacy Pass token issuance/redemption for discovery and session admission

**Gate:** a 20+ node testbed sustains usable interactive browsing while an
adversary process that harvests discovery responses for 24 hours recovers less
than a stated fraction of the pool.

### Slice 4 — L3 accounting

- [ ] `none` and `credits` backends (core works with settlement off)
- [ ] Off-chain signed receipts, hybrid volume/time settlement trigger
- [ ] Optional L2 `onchain` adapter (Sepolia/Hoodi first), net balances only
- [ ] No public listing surface anywhere in the design

**Gate:** relays are paid for a week of real traffic with zero on-chain
transactions, and separately, net settlement reconciles on an L2 testnet with
per-session data appearing nowhere on chain.

### Slice 5 — L4 measurement

- [ ] Threshold-aggregated telemetry over OHTTP, opt-in, k-anonymity floor
- [ ] Blocked-vs-degraded classification
- [ ] OONI-compatible publication path for Lumra and external researchers

**Gate:** a regional report is produced where no bucket below the k-threshold is
emitted and no individual report is recoverable by the collector.

### Slice 6 — Resilience + ecosystem

- [ ] Link-type abstraction with per-class policy (satellite / mobile / mesh)
- [ ] Mesh control-plane store-and-forward on a Meshtastic-class stack
- [ ] Crovi policy injection; Thump link-class reporting and migration holds
- [ ] Degradation ladder rungs 6–7

**Gate:** a live demo where the terrestrial link is severed, data plane stops,
control plane keeps flowing over a mesh link within its real duty-cycle budget,
and Thump correctly holds a migration instead of attempting it.

### Later — horizontal expansion

Warren DNS, Warren Email, Warren Storage. Not scoped until Slice 3's gate is met;
a name service over an unproven transport is a demo, not a product.

---

## References

**Standards**
- TLS 1.3 — RFC 8446; ChaCha20-Poly1305 — RFC 8439
- ML-KEM — FIPS 203; ML-DSA — FIPS 204; SLH-DSA — FIPS 205; PQC transition — NIST IR 8547 (draft)
- MASQUE — RFC 9298 (CONNECT-UDP), RFC 9484 (CONNECT-IP)
- Oblivious HTTP — RFC 9458; Privacy Pass — RFC 9576–9578
- QUIC — RFC 9000; HTTP/3 — RFC 9114

**Prior art Warren composes**
- REALITY (xtls/xray-core) — probe-resistant TLS borrowing
- uTLS — browser ClientHello fingerprint parroting
- Snowflake, Psiphon, Tor WebTunnel, Conjure/refraction networking — pool-scale and fronted transports
- Prio / STAR / Divvi Up — threshold aggregation for private telemetry
- OONI, IODA, Cloudflare Radar — censorship measurement infrastructure
- Meshtastic — LoRa mesh firmware and routing

**Internal**
- `docs/protocol/reality-transport.md` — L0/L1 implementation notes and known gaps
- `docs/ROADMAP.md` — public-facing slice status
