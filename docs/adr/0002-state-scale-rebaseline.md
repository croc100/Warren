# ADR 0002 — Re-baseline L1 against a state-scale censor

- **Status:** Proposed (2026-10-07)
- **Scope:** L1 as a whole, the relay-placement bet in [`DESIGN.md` §7.1](../../DESIGN.md),
  the degradation ladder (§6.5), and how every slice's gate is measured
- **Amends:** [ADR 0001](0001-borrowed-tls-handshake.md). Its stages stand as
  engineering, but its gate measures the wrong adversary, and this ADR replaces
  the claim that Slice 1 is passing
- **Reopens:** Slice 1 in [`docs/ROADMAP.md`](../ROADMAP.md)

## Summary

Slice 1's gate asks one question: **can a prober tell this relay apart from the
site it borrows?** After H3, H4, H5, H7 and H8 the answer is no. A national
censor asks a different question: **is this flow plausible for this client,
this destination address, this name, at this time, given everything else on the
network?** It answers that at line rate, by joining the flow against DNS, IP
ownership, address-space type and the other flows the same address takes part
in. It does not need to win any single comparison.

Measured against that question, today's default posture fails before any byte
of Warren's protocol matters. The relay is a residential address presenting a
foreign site's name it does not host, and it serves long TLS sessions to many
unrelated domestic clients. Nothing we built hides that, and our gate cannot
see it, because the gate only compares a relay with its own cover.

This ADR:

- states the adversary as a set of capabilities;
- lists the distinguishers that follow from them, ranked by what they cost a
  censor;
- proposes a rework of L1 and of the relay-placement bet;
- replaces Slice 1's gate with measurements a censor would recognise.

It is deliberately harsh. Where it overstates a risk, the measurements in
§Gates are how to show that and win the point back.

## Adversary model

Earlier documents described the censor by technique: DPI, probing, blocklists.
Here it is described by capability, because a technique is just a capability
someone has chosen to use, and a state can choose any of them on the day it
matters.

| # | Capability | What it means concretely | Cost to the censor |
|---|-----------|--------------------------|--------------------|
| C1 | **Line-rate per-flow features** | SNI and ClientHello fingerprint. Sizes and timing of the first N packets in each direction. Payload entropy. TCP/IP header fields (TTL, window, options, their order). Flow duration and byte counts | Already deployed. Per-flow and stateless, so it scales |
| C2 | **Cross-source joins** | Did this client resolve the SNI, and to which address? Does the destination address belong to the SNI's operator? Is the address residential, hosting or CDN? How many distinct domestic clients reach this address on 443, and for how long? | Cheap. The ISP has DNS logs, passive DNS and IP-ownership data. Batch, not inline: a flow flagged at 14:00 is blocked by 14:30 |
| C3 | **Active interaction** | Probing and replay; we handle both. Also *inducing* faults: dropping, delaying, injecting RSTs, clamping MSS, skewing NTP. Then watching how a suspected client or server reacts | Cheap per target. Already used against proxies (Ensafi et al., IMC 2015; Wu et al., USENIX Security 2023) |
| C4 | **Running clients** | Holding as many valid Warren clients as it likes, through every distribution channel we offer | Unlimited. Treat it as given, not as a corner case |
| C5 | **Policy-scale action** | Accepting collateral (blocking a residential /24, an ASN or a CDN range for a week). Allowlisting. Throttling. Shutdowns. App-store takedowns | Political, not technical. Spent during crises, which are exactly when users need Warren |
| C6 | **Coercion and infiltration** | Seizing relays. Compelling in-country operators. Running sybil relays and distribution channels | Slow, but permanent once done |

Two properties of a state censor follow, and the rest of this document leans on
them.

**It works at a low false-positive rate, but not zero.** A detector that flags
one benign flow in 10,000 is affordable. Reporting AUC therefore misleads. The
number that matters is the true-positive rate at a false-positive rate of about
10⁻⁴, and a detector can be useless by AUC and devastating at that operating
point.

**It joins.** A distinguisher that is weak in one flow becomes decisive when the
same address shows it in a thousand flows from three hundred clients.
Per-connection indistinguishability, which is all our gate measures, does not
add up to per-address indistinguishability.

## Findings

Ranked by what each one costs the censor to exploit, cheapest first. "Gate sees
it" means today's `cmd/probe`.

### F1 — The name does not belong to the address · C1 + C2 · **critical** · gate: no

A relay presents `SNI = www.<popular-site>` from a residential address. That
site's operator does not own the address, and the client never resolved the name
to it. Passive DNS answers the first point and the client's own DNS log answers
the second. Both are batch joins, needing no probe and no inline state.

[`DESIGN.md` §14](../../DESIGN.md) already rejects "naive SNI spoofing" because
*"SNI-to-IP ownership correlation flags it instantly."* `tls-borrow` on a
residential relay is SNI spoofing with a better handshake. The handshake work in
ADR 0001 is correct and does not reach this, because this distinguisher is
decided before the handshake by facts outside the flow.

REALITY deployments survive this only partly, and only by co-location: a
datacenter relay borrows a site hosted in the same provider's address space, so
ownership data is ambiguous. A residential relay has no such neighbour.

### F2 — A home address acting as a server · C2 · **critical** · gate: no

Even with a name it legitimately owns, a residential address accepting inbound
443 from hundreds of unrelated domestic clients, for sessions lasting minutes to
hours, has no benign population to hide in. Inbound 443 to residential space is
rare to begin with, and much of it is unreachable behind CGNAT. Fan-in (distinct
clients per address) and session duration are aggregate features. No
per-connection camouflage changes them.

This undercuts the structural bet in DESIGN §7.1. The claim that blocking cost
"scales with the number of households" holds only if detecting a household relay
costs something. Under F1 and F2 it costs one SQL query over flow logs, re-run
daily, and blocking is per-address, so churn helps less than assumed.

### F3 — The server's TCP/IP stack is the relay's, not the site's · C1 · **high** · gate: no

The SYN-ACK and every segment after it come from the relay's operating system:
initial TTL (64 for Linux, 128 for Windows), window size and scaling, the set and
order of TCP options, ECN, initial congestion window and retransmission timing.
The borrowed site is typically Linux behind a load balancer or CDN edge. A
residential Windows relay differs in its first packet, before TLS. JA4T-style
fingerprinting of this is commodity.

The path disagrees too. Remaining TTL and RTT put the relay a few hops into a
consumer ISP, while a big site usually answers from a nearby edge with a short
RTT. And the address answers on other ports (RDP, SMB, a router admin page) where
a real front end answers on 80 and 443 only. One SYN to port 3389 settles it.

### F4 — Tunnelled TLS shows through · C1 · **critical once flows are long** · gate: no

When a user opens an HTTPS site through the tunnel, the inner ClientHello, server
flight and Finished cross the outer session as records whose sizes and
inter-arrival times keep the inner handshake's pattern. Xue et al. (USENIX
Security 2024, *Fingerprinting Obfuscated Proxy Traffic with Encapsulated TLS
Handshakes*) detect exactly this across encrypted proxies at a low false-positive
rate. Warren forwards caller writes as records one for one, so it is in that
class.

The same holds a layer up. A browser that has just finished a handshake with
`<site>` sends an HTTP/2 preface, SETTINGS and a HEADERS frame of a
characteristic size, then receives responses shaped by that site's pages. A
Warren session's first client flight is whatever the user's application writes.

### F5 — Flow shape is not a visit · C1 · **high** · gate: no

Real visits to a site follow a distribution: mostly short, download-heavy,
bursty, closed or idle within seconds to minutes, spread over several parallel
connections. A tunnel is one long connection with the user's whole traffic mix:
symmetric during calls, bulk during downloads, keepalives while idle. Duration,
byte ratio and idle structure are cheap per-flow features. DESIGN §6.4 makes
shaping opt-in, which leaves the default flow unshaped.

### F6 — Reactions to induced faults · C3 · **high** · gate: no

The censor can perturb a suspected flow and watch the reaction:

- **Inject an RST.** A browser gives up on that tab or retries with its own
  backoff. A tunnel client reconnects immediately to the same address with a
  fresh hello, and in Warren's case with a fresh tag, so the reconnect is
  well-formed but its timing is not a browser's.
- **Skew NTP for the client population.** The tag's 10-minute window (DESIGN §11)
  becomes a censor-operated off switch. Every Warren client in the region fails
  authentication and gets spliced, while everything else keeps working. This
  needs no detection at all, and DESIGN §15 item 6 lists it only as a
  reliability problem.
- **Throttle and watch.** A client that switches transports, or rotates
  relays, in response to throttling announces that it has alternatives, and
  where they are.

### F7 — The relay's own traffic to its cover · C2 · **medium** · gate: no

When the observer also sees the relay's uplink (a relay inside the censored
network), it sees a residential address holding a few idle TCP connections to
`<site>:443`, re-dialled every few seconds and never carrying a ClientHello (the
warm pool, H3). It also sees a full handshake to the same site every 30 minutes
(profiling) and one fresh connection per probe. None of that is what a household
does. For relays outside the censored network this does not apply, and the
choice of where relays sit therefore matters more than the design admits.

### F8 — The view from inside the country · C1 · **medium** · gate: no

The flight is measured from the relay's vantage point. A geo-distributed site
serves in-country clients from a different edge, sometimes with a different
certificate chain, ticket policy or even TLS stack. The censor compares against
what the site looks like *from inside the country*, and that is the measurement
we never take.

### F9 — The accepted gap is not acceptable · C4 · **critical in combination** · gate: no

ADR 0001 accepts that a censor holding a Warren client can tell a relay from its
site, on the grounds that such a censor could enumerate bridges anyway. Under C4
that censor is the default, not an edge case. Then every relay a channel hands
out is confirmed by connecting to it, and F1 to F3 turn that list into address
blocks with no false positives. The defence is not at L1. It is making
enumeration expensive and *attributable*: what a channel hands out must be
traceable to which credential leaked it (Lox, Tulloch & Goldberg, PETS 2023; Tor's
rdsys). Today L1's tag has no slot for a client credential, so it cannot
participate.

### F10 — The gate verifies self-consistency, not survival · methodology · **critical** · —

`cmd/probe` compares a relay to the site it chose, from one vantage point, using
probes we wrote, against reference stacks we run. It has found real defects and
should stay. But nothing in it:

- is a trained classifier;
- joins across flows;
- observes from inside a censored network;
- was written by someone trying to break Warren.

A PASS from it is evidence that the implementation does what we intended. It is
not evidence that what we intended survives.

## Decision

Six changes. The first two are the "overhaul": they change what a relay *is*,
not how well it imitates.

### D1 — Stop borrowing names. A relay presents a name it owns, or none.

`tls-borrow` is retired as the default posture. A relay's TLS identity must
survive F1, so it has to be one of these:

1. **Self-hosted cover.** The relay serves a real website under a domain the
   operator controls, with a publicly trusted certificate for it. Unauthenticated
   connections get that site, from the relay's own TLS stack. There is no splice,
   no remote cover to measure, and no warm pool. The name resolves to the
   address, so F1 is closed by construction.
2. **Shared front.** The relay sits behind infrastructure that legitimately
   answers for many names on shared addresses: a CDN, or a hosting front end.
   The client-facing name is the front's, sent via ECH where the front supports
   it. F1 is closed because ownership is genuinely ambiguous.
3. **Co-located borrow.** `tls-borrow` as built today, only on a datacenter relay
   in the same provider and prefix as the site it borrows. Kept as an
   implementation behind the transport interface. It is not a default and never
   runs on residential relays.

What this costs, stated plainly:

- **Domains become the unit of blocking.** SNI blocklists are cheap, so names
  must be cheap, numerous and rotated, and that is a supply problem for L0/L2.
- **ECH is itself blockable.** China blocked ESNI in 2020, and Russia has been
  reported blocking ECH to a major CDN since late 2024. A front without ECH
  exposes whatever name the relay uses.
- **CDNs comply with takedown requests,** and can end option 2 unilaterally.
  That was the history of domain fronting (DESIGN §7.1).

### D2 — Residential relays stop being TLS servers for strangers

F2 cannot be answered at the protocol layer, so the relay-placement bet changes:

- **Server-shaped roles** (inbound TLS from many clients) run on addresses where
  serving is normal: hosting, CDN-fronted, or the operator's own domain on a
  hosting address.
- **Residential capacity is reached in shapes residential addresses really
  have:**
  - *Peer-to-peer media.* WebRTC between households is ordinary video-call
    traffic. This is Snowflake's model (Bocovich et al., USENIX Security 2024),
    promoted from rung 4 to the primary residential path.
  - *Outbound-only inner hops.* A residential relay dials out to a fronted
    rendezvous and carries traffic over that connection. It never accepts
    inbound 443 from strangers.
- **DESIGN §7.1 is rewritten to match.** The structural claim becomes "blocking
  cost scales with households *as long as they look like households*", and the
  transports are chosen to keep that true.

This is the most expensive decision in the document. WebRTC throughput is lower,
and rendezvous is a new centralisation point that has to be hardened in its own
right. It is still the honest one: a residential pool that is detectable by flow
logs is a list of addresses the censor will build for us.

### D3 — Data-phase shaping is on by default, at least in the handshake phase

F4 is cheap for the censor, and its signal sits in the first few kilobytes of
each inner connection, where shaping is cheapest for us. So:

- **Inner handshakes are not forwarded record for record.** For the first
  *k* KB of each inner stream (initially 16 KB), writes are coalesced and split
  into the bucket sizes of DESIGN §6.4. Records carry jittered send times inside a
  bounded window. Short filler pads the client direction so request/response
  pairs lose their shape.
- **Streams are multiplexed** over one session, so a page load's parallel inner
  handshakes interleave rather than appear one after another.
- **The cost gets stated in DESIGN §6.4's units.** That covers the bytes and the
  added latency per new inner stream, measured and published. The
  regime table gains a non-optional floor, renamed from `off` to `minimal`.
  `minimal` shapes the handshake phase only.

### D4 — Flows are budgeted to look like visits

Against F5, a session is no longer "one connection for as long as it is useful":

- **Rotation.** Connections are rotated on a duration and volume budget drawn
  from the cover's own distribution, so no single flow outlives what the cover
  produces.
- **Parallelism.** Load is spread over a browser-like number of parallel
  connections.
- **Idle.** Idle periods close connections rather than hold keepalives.

The budget is a per-cover profile, measured from the cover the way the flight is
today, and per-region where F8 says the cover looks different in-country.

### D5 — Client behaviour under faults is specified, not emergent

Against F6:

- **Reconnects.** Reconnection follows a browser-like backoff, with jitter and
  a cap. Relay rotation never fires in immediate reaction to an RST or a
  stall.
- **Authentication and time.** Authentication stops depending on absolute
  time. The replay window moves to state the relay can check: a relay-issued,
  expiring ticket obtained on the previous successful session. Where no ticket
  exists, a wider window is backed by a replay cache that survives restarts (H9).
  A censor skewing NTP then breaks only first contact, not every session.
- **Credentials.** The tag gains space for a client credential (F9), so a relay
  can tell which distribution bucket a connecting client came from. This is
  what attributable enumeration needs at L2. The ClientHello `session_id` is
  32 bytes and the tag uses 16, so there is room without changing the hello's
  shape. The credential has to be encrypted under the authentication secret
  rather than carried in the clear, because those 16 bytes must stay
  indistinguishable from random.

### D6 — The gate measures what a censor measures

Slice 1's gate is replaced by five gates. Each states a number that a release can
fail.

| Gate | What it runs | Pass condition |
|------|-------------|----------------|
| **G1 — Join test** | A censor pipeline over a testbed's flow and DNS logs. It checks SNI-to-address ownership, resolution history, address-space type and per-address fan-in and duration. Real hosts of the same class form the baseline | Relays flagged at a rate statistically indistinguishable from baseline hosts of the same class |
| **G2 — Classifier test** | A classifier trained on real browser traffic to the cover against Warren traffic to the relay. Its features are first-N packet sizes and timings plus flow statistics. A reimplementation of the encapsulated-handshake detector from Xue et al. runs alongside | At a 10⁻⁴ false-positive rate, true positives ≤ 1 %, per shaping regime, with the training sets published |
| **G3 — Stack parity** | SYN-ACK and TCP behaviour compared against the server class the relay claims, plus a port scan of the relay address | No field outside the claimed class's observed range. Nothing open that the class would not have open |
| **G4 — Fault response** | RST injection, loss, MSS clamping and ±1 h clock skew, applied to clients | Reconnect timing within the browser envelope. No reconnect storms. Ticketed clients survive the clock skew |
| **G5 — Outside eyes** | Measurement from at least one in-country vantage point. A review by people outside the project trying to break it | Findings triaged in public before any "deployable" claim |

The thresholds are a starting proposal. They are meant to be argued with, but
only by changing the numbers, never by dropping the gate. `cmd/probe` stays as a
regression suite under G2/G3.

## What happens to the current code

Nothing is deleted on this ADR's acceptance. It re-labels.

| Component | Fate |
|-----------|------|
| Tag in ClientHello, hybrid X25519 + ML-KEM handshake, AEAD record framing, kind byte and filler records | **Kept.** These are the base for D1 options 1–2 and for D3's shaping. The tag gains a credential field (D5) |
| Signed, expiring descriptors | **Kept.** The format still needs a transport field (H12), and now also a cover-type field |
| Borrowed-site splice, `ProfileSite` flight imitation, answer-time equalisation, warm pool (H3), refuse-when-down (H8) | **Demoted** to `tls-borrow`, D1 option 3: datacenter, co-located only. Correct as engineering and no longer the default path |
| Connection cap (H7) | **Kept**, and moves to whatever accepts connections in each transport |
| `cmd/probe` | **Kept** as a regression suite under G2/G3. It is no longer the release gate |
| Slice 1 status | **Reopened.** "Passing" referred to a gate this ADR retires |

## Consequences

- **The roadmap gets longer.** Slice 1 now contains D1 (a self-hosted cover
  transport), D3–D5, and G1–G4 infrastructure. G5 gates deployability claims,
  not merges.
- **The residential-pool story changes** (D2), and with it part of the business
  premise. Selling residential bandwidth through WebRTC and outbound hops is a
  smaller product than selling it as inbound relays. DESIGN §15 item 2 already
  doubts supply, and this adds a throughput limit.
- **Domains and fronts become operational supply,** with costs, takedown exposure
  and their own enumeration problem, which L2 has to own.
- **Some defences now cost bandwidth by default** (D3). This conflicts with DESIGN
  §6.4's "default must not be a regime whose bill the user did not agree to". The
  resolution proposed is that `minimal` is part of the transport's price, stated
  up front, and not a regime the user opts into.
- **Out of reach, still:** allowlist regimes with no permitted foreign endpoint,
  shutdowns, and a censor willing to block whole CDNs for weeks (C5). The ladder
  is the answer to those, and it is a partial one.

## Open questions this ADR does not settle

1. **The per-transport order of D1 options 1 and 2.** It depends on whether ECH
   survives in target regions, which is a measurement, not a choice.
2. **How rendezvous for D2's outbound residential hops avoids becoming the single
   blockable point.** It may need its own fronting and rotation, recursively.
3. **Whether the credential in D5 can be made unlinkable across sessions.** It
   must be, so that a relay cannot track a client while L2 can still attribute a
   leak. That points at Privacy Pass-style tokens (DESIGN §8.3), and the
   construction is not designed.
4. **The G2 threshold.** 1 % at 10⁻⁴ is a guess at what makes blocking
   uneconomical. It should be revised against published censor behaviour, not
   against what Warren happens to achieve.

## References

- Ensafi, Fifield, Winter, Feamster, Weaver, Paxson. *Examining How the Great
  Firewall Discovers Hidden Circumvention Servers.* IMC 2015.
- Wu, Zohaib, Durumeric, Houmansadr, Wustrow. *How the Great Firewall of China
  Detects and Blocks Fully Encrypted Traffic.* USENIX Security 2023.
- Xue, Kallitsis, Houmansadr, Ensafi. *Fingerprinting Obfuscated Proxy Traffic
  with Encapsulated TLS Handshakes.* USENIX Security 2024.
- Bocovich et al. *Snowflake, a censorship circumvention system using temporary
  WebRTC proxies.* USENIX Security 2024.
- Tulloch, Goldberg. *Lox: Protecting the Social Graph in Bridge Distribution.*
  PETS 2023.
- FoxIO. JA4+ network fingerprinting (JA4T for TCP).
