# Warren Roadmap

**A censorship-resistant network transport for the CRODE line (Crovi, Thump, Lumra).**

This file tracks *what ships in what order*. Architecture and rationale live in
[`DESIGN.md`](../DESIGN.md).

Status legend: ✅ done · 🚧 in progress · ⬜ planned

> **Read this first.** Warren is pre-alpha. Three things exist — bridge discovery
> with signed descriptors, a camouflaged post-quantum transport that imitates its
> borrowed site's handshake shape, and the harness that gates both (~5,500 lines of
> Go, about half of it tests). Everything else is specification. Slice 1's gate
> passing is **not** deployability: see the note under Slice 1.
> Full status: [`DESIGN.md` §0](../DESIGN.md#0-implementation-status).

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
| 1 | L1 transport hardening | Active-probe harness can't distinguish a relay from the site it borrows; ClientHello not distinguishable from the parroted browser's current profile | ✅ gate passes (Stage B of ADR 0001 remains conditional) |
| 2 | L1 breadth + L0 distribution | Fresh client still connects with UDP/443 blocked, primary transport blocked, and bridge list expired | ⬜ |
| 3 | L2 relay pool | 20+ node testbed usable for interactive browsing while a 24h discovery-harvesting adversary recovers < stated fraction of the pool | ⬜ |
| 4 | L3 accounting | A week of paid relay traffic with zero on-chain transactions; separately, net settlement on an L2 testnet with no per-session data on chain | ⬜ |
| 5 | L4 measurement | Regional report emits no sub-threshold bucket and no recoverable individual report | ⬜ |
| 6 | Resilience + ecosystem | Link severed → data plane stops, control plane flows over mesh within real duty-cycle budget, Thump holds migration | ⬜ |

---

## Slice 1 — L1 transport hardening ✅ (gate passing)

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
- ✅ Active-probe and record-shape harness ([ADR 0001](adr/0001-borrowed-tls-handshake.md),
  Stage 0): `internal/network/probe` + `cmd/probe`, which exits non-zero on any
  distinguisher. It found two defects on first run — a parroted ClientHello ~250 B
  short of its own profile (dropped GREASE ECH extension) and a TCP teardown that
  used FIN where the real site sends RST — both now fixed
- ✅ Shape-accurate server flight (Stage A): the relay measures the site it borrows
  from — `ProfileSite` does a genuine handshake and records sizes, order, pacing,
  session tickets and a real client's Finished size — and replays that shape, with
  Warren's key confirmation riding in the largest record. Verified byte-exact
  against a real session by `cmd/probe`. A relay with no usable profile refuses to
  serve, and a site that doesn't negotiate `X25519MLKEM768` is rejected as cover
  because its real ServerHello is hundreds of bytes smaller than Warren's
- ✅ Answer timing equalised: `ProfileSite` measures how long the borrowed site
  takes to answer a ClientHello, and the relay waits that out before its own
  ServerHello. Without it a relay answered in 510 µs where its site took 150 ms,
  so one relay address showed two latency modes — the cheapest distinguisher
  there is, needing only a clock. **Partial:** the splice still pays one extra
  round trip, which `cmd/probe` now measures and reports rather than hides
- ✅ Replay defence no longer bounded by memory: the tag covers a coarse time
  window, so a captured hello expires on its own instead of becoming valid again
  once the cache forgets it. The cache is generational, so filling it retires the
  oldest entries rather than all of them
- ✅ Canaries on the gate (`internal/network/probe/canary_test.go`, plus a
  failure-path step in `hack/smoke.sh`). Every other test asserts the harness
  finds nothing, which is also what a broken harness reports; these require it to
  fail against relays that are deliberately wrong. The first run found the
  post-handshake tolerance wide enough to accept a relay sending no session
  tickets at all
- ⬜ Relayed real handshake nested inside the hybrid session (Stage B), only if
  the harness shows Stage A is still separable. The mimicry-versus-post-quantum
  trade-off was a false choice: the outer borrowed handshake carries shape, the
  inner hybrid handshake carries confidentiality

**Gate: passing.** `cmd/probe` runs six active probes (browser-shaped handshake
with certificate inspection, two sequential handshakes, plaintext HTTP,
record-shaped junk, a truncated hello, and a replay of a captured genuine
ClientHello) and five shape measurements against both a relay and the site it
borrows, and exits non-zero on any distinguisher. It currently reports none, with
the flight byte-exact.

What the gate does **not** cover, and why Slice 1 passing is not deployability:
the shape of application traffic after the handshake (Slice 2) and relay-pool
enumeration (Slice 3).

---

## Hardening backlog

Work that does not gate a slice but is owed. Ordered by what an adversary gets
from it, not by effort. Items marked **found** came out of the hardening pass on
2026-10-01 and are defects in shipped code rather than unbuilt features.

### Distinguishers still on the table

| # | Item | Why it matters |
|---|------|----------------|
| H1 | **Traffic shape after the handshake** (`bucket`/`cover`, DESIGN §6.4) | The largest measured gap. The machinery exists — every record carries a kind byte and filler is already discarded by the peer — so this is a policy layer over tested code, not a new wire format. Slice 2 |
| H2 | **The gate stops measuring where the handshake ends** | `cmd/probe` compares handshake shape and now answer timing; it does not compare the data phase against the borrowed site's real responses. Slice 1's PASS is routinely misread as deployability because of this |
| H3 | **One round trip still separates the relay's two answer paths** — *found* | The ServerHello wait equalises the site's answer time but not the TCP connect the splice additionally pays. Fix is warm upstream connections (better: keeps Warren fast) or measuring from dial (simpler: makes Warren slower). Measured and reported by `cmd/probe` today |
| H6 | **No session rekey** | One ChaCha20-Poly1305 key for the whole connection, no record-count limit, no KeyUpdate equivalent. TLS 1.3 rekeys; a long-lived tunnel should too |

### Resource and failure behaviour

| # | Item | Why it matters |
|---|------|----------------|
| H7 | **No connection limits anywhere** — *found* | One goroutine per accept, and every unauthenticated connection opens a fresh TCP connection to the borrowed site. That makes the relay an amplifier pointed at a site it does not own, and it is the direct cause of DESIGN §15's first open problem, "what happens when a borrowed site starts rejecting the relay". Any limit has to degrade the way an overloaded real site does, or the limit is itself the distinguisher |
| H8 | **Silent failure when the borrowed site is unreachable** — *found* | The splice returns and closes with a FIN, so a relay whose cover site is down behaves visibly unlike that site. Refusing to serve is the consistent answer |
| H9 | **Replay protection does not survive a restart** | Accepted, and worth stating; the exposure is bounded by the tag's window now rather than open-ended |

### Discovery and descriptors (while the format is still v1)

| # | Item | Why it matters |
|---|------|----------------|
| H10 | **No revocation** | A relay whose identity key is compromised cannot be withdrawn before its descriptor expires |
| H11 | **No `not-before` check; duplicate fields silently take the last value** | Parsing happens after signature verification so neither is exploitable today, but both are the kind of thing that becomes exploitable the moment anything around them changes |
| H12 | **No transport field** | §6.3's `masque` / `websocket-tunnel` / `rendezvous` cannot be expressed in `addr|sni|pubkey`. Slice 2 needs this, and a v1 format cannot carry it |
| H13 | **Signature agility** | Ed25519 only, while the crypto inventory already plans an ML-DSA-65 hybrid. The version prefix is currently the only escape hatch |
| H14 | **Anchor rotation is undocumented** | Multiple anchors are supported in code with no story for how one is retired |
| H15 | **DNS discovery uses the OS resolver in the clear** | The signature protects integrity, not the fact that this client looked up the bridge domain. The query itself is a tell; DoH/DoT is the answer |

### Client

| # | Item | Why it matters |
|---|------|----------------|
| H16 | **No failover across bridges, no ladder reporting** | Slice 2's gate requires a client to report which rung of the degradation ladder it is on. Nothing reports anything today |
| H17 | **Clock dependence is now a reachability risk** | The tag's freshness window means a badly-skewed device is silently unreachable. `ErrRelayRejected` names the clock as a cause; nothing yet helps a client establish the time safely (DESIGN §15) |

### Testing and CI

| # | Item | Why it matters |
|---|------|----------------|
| H18 | **CI runs Linux only** — *found the hard way* | TCP teardown mirroring was dead on Windows for as long as this was true: a peer reset arrives as `WSAECONNRESET`, while `syscall.ECONNRESET` on Windows is a synthetic value no socket returns, so a Windows relay closed every spliced connection with a FIN against a site sending RST. Windows is what most of the residential pool this design bets on would run. A build matrix is not a nicety here |
| H19 | **The gate's stand-in site is Go-backed, and a Go-backed site once hid a real defect** | `hack/smoke.sh` says so in its own comments: the RST distinguisher was invisible against Go and visible against OpenSSL. CI therefore runs the weaker of the two. Add an OpenSSL/BoringSSL-backed site, skipped where the local build lacks ML-KEM |
| H20 | **No fuzz targets** | Every attacker-facing parser is unfuzzed: `peekClientHello`, `parseServerHelloParts`, `parseConfirmPayload`, `parseDescriptorPayload`, `ParseBridge`. Go's native fuzzing with a CI seed corpus is the cheapest high-value item on this list |
| H21 | **No `staticcheck`, no `govulncheck`, no reproducible-build target** | Slice 2 explicitly requires reproducible builds and signed artifacts; none of the scaffolding exists |
| H22 | **`make fmt` cannot run on Windows** — *found* | `gofmt -l` reports every file on a CRLF checkout, which is every Windows clone, so a Windows contributor gets a wall of false positives and learns to ignore the check |

### Documentation and process

| # | Item | Why it matters |
|---|------|----------------|
| H23 | **No `SECURITY.md`** | `CONTRIBUTING` has a section, but without the top-level file GitHub shows no reporting path — on a project whose stated most-wanted contribution is adversarial |
| H24 | **No relay operator guide** | How to choose a site to borrow, what that site's operator sees (a handshake every 30 minutes, plus a connection per probe), and what abuse handling is expected. §7.4 is logged as a requirement with nothing written against it |
| H25 | **"~5,500 lines" is hardcoded in four documents** | A drift magnet. Say it once, or derive it |

### Resolved

Closed since the 2026-10-01 pass, kept here so the numbering stays stable and
the history is legible.

| # | Item | How it was closed |
|---|------|-------------------|
| H4 | **The relay hardcoded its ServerHello cipher suite** — *found* | ✅ `ProfileSite` now records the suite the borrowed site negotiates (`FlightProfile.CipherSuite`) and the relay echoes it rather than a pinned `TLS_AES_128_GCM_SHA256`, so a tagged client and a spliced probe see the same suite. `cmd/probe` compares the two ServerHellos' suites, guarded by a canary. It still names nothing about how Warren encrypts (ChaCha20-Poly1305 under the derived key); the echoed value only has to agree with the site |
| H5 | **The splice ignored the ClientHello's SNI** — *found* | ✅ Claim corrected rather than behaviour changed: a relay fronts **one** site and splices every unauthenticated connection to `FallbackAddr` regardless of the SNI, exactly as a real single-site server answers an unexpected SNI with its own default certificate. Routing by SNI was rejected on purpose — it would make the relay an open proxy to arbitrary hosts (see H7). The package comment is fixed and a `unexpected-sni` probe asserts the relay still matches the borrowed site |

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
([why](../DESIGN.md#91-why-on-chain-event-logging-is-out)).

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
