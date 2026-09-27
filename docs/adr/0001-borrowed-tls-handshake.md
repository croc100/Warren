# ADR 0001 — How to close L1's handshake-mimicry gap

- **Status:** Accepted (2026-09-28)
- **Scope:** `internal/network/transport`, Slice 1's gate in [`docs/ROADMAP.md`](../ROADMAP.md)
- **Supersedes:** the note in [`DESIGN.md` §6.1](../../DESIGN.md) that said the choice was
  "complete the borrowed handshake, or migrate to xray-core's `reality`"

## Context

Warren's relay answers an authenticated client with a real-shaped TLS 1.3
ServerHello and ChangeCipherSpec, then switches to its own AEAD records typed
`application_data`. It never sends a certificate flight, because Warren's keys —
not the borrowed site's certificate — protect the session.

**The gap is passively detectable, and that is worse than previously written
down.** A real TLS 1.3 server follows its ServerHello and CCS with
EncryptedExtensions, Certificate, CertificateVerify and Finished, which is
typically 2–6 KB of `application_data` records, and the client answers with a
small Finished record before its first request. Warren sends nothing there. A
classifier does not need to decrypt anything or hold a Warren client to notice
"TLS 1.3 session whose server flight after CCS is under 200 bytes" — it only
needs record sizes and directions. That makes the current transport unsafe
against a live adversary, and it is the highest-priority remaining L1 defect.

The counterweight is what TLS 1.3 *hides*: the certificate flight is encrypted.
A passive observer cannot read or validate the certificate at all; it can only
see sizes and timing. An active prober that connects itself is already handled —
it has no valid tag, so it is spliced to the real site and gets that site's real
certificate chain. This asymmetry is what makes the decision below cheaper than
it first looks.

Two candidate answers were on the table.

### Option A — adopt xray-core's `reality` package

REALITY authenticates with an X25519 exchange embedded in the TLS `key_share`
and, for authenticated clients, relays the *real* site's handshake while
substituting a certificate the client can verify against the relay's key. It is
deployed at scale against the GFW, which is evidence no test harness of ours can
match.

Against it:

- **It is X25519-only.** Adopting it as-is would trade away the hybrid
  post-quantum confidentiality Warren just built, on traffic whose defining
  property is that adversaries record it for later. (Whether current xray-core
  has changed this is listed under Verification below; the decision does not
  depend on it.)
- **Dependency weight and coupling.** xray-core is a large module and its
  `reality` package is entangled with xray's own config and session types.
  Importing it drags that surface into a project whose threat model includes
  supply-chain exposure; forking only the package means the "audited upstream"
  benefit decays as the fork diverges.
- **Licensing needs care.** xray-core is MPL-2.0 and Warren is AGPL-3.0. That
  combination is workable, but only with the MPL files kept identifiable and
  their obligations honoured — not something to discover after vendoring.

### Option B — implement the full borrowed handshake ourselves

Relay the real site's TLS 1.3 handshake and substitute a certificate signed by
the relay's identity key. This keeps post-quantum confidentiality and every
other property Warren already has.

Against it: it is exactly the class of work [`DESIGN.md` §3](../../DESIGN.md)
says not to hand-roll. Certificate substitution inside a relayed handshake is
deep protocol surgery whose bugs are invisible until an adversary finds them.

## Decision

Neither, yet. The gap is closed in stages, cheapest first, and the harness comes
before the cryptography.

### Stage 0 — build the active-probe and classifier harness first — **done**

Implemented as `internal/network/probe` and `cmd/probe`. It taps a Warren session
and a real TLS session to the same borrowed site, compares record shape, and runs
an active probe suite (browser-shaped handshake and certificate inspection, two
sequential handshakes, plaintext HTTP, record-shaped junk, a truncated hello, and
a replay of a captured genuine ClientHello) against both endpoints. `cmd/probe`
exits non-zero on any distinguisher, so it can gate a release rather than be a
report someone reads occasionally.

**It found two defects on first run, which is the argument for having built it
before the cryptography:**

1. **The parroted ClientHello was ~250 bytes short of the profile it claimed to
   be.** `PubClientHelloMsg.Marshal()` only emits extensions it knows about and
   drops everything living solely in `uconn.Extensions` — for a current Chrome
   profile that includes the GREASE ECH block. Fixed by marshaling through
   `UConn.MarshalClientHello()`. A first-packet size distinguisher, and nothing
   in the unit tests could have caught it: they compared Warren against itself.
2. **TCP teardown did not match.** A real HTTPS server handed plaintext HTTP
   aborts with an RST; the relay spliced the site's bytes faithfully and then
   closed cleanly with a FIN. Separable on teardown alone, no TLS analysis
   needed. Fixed by mirroring the upstream's reset (`SetLinger(0)` before close).
   A Go-backed test site hid this — it closes cleanly — and only an OpenSSL-backed
   site exposed it, which is a reminder that the harness's *reference* site has
   to be representative.

Related: comparison thresholds have to tolerate a profile's own variance. A
current Chrome hello is not a fixed size — the GREASE ECH payload moves it in
32-byte steps across a ~100-byte band — and a harness that reports that as a
finding is a harness people stop reading.

### Stage A — make the server flight shape-accurate — **done**

Implemented as `internal/network/transport/flight.go` plus the shaped-record
machinery in `aead_conn.go`. `cmd/probe` now reports no distinguisher, with the
flight byte-exact against a real session to the same site (1196 B in 4 records,
and 500 B in 2 post-handshake records, in the local OpenSSL-backed setup).

What made this more than padding:

- **The shape is measured, not assumed.** `ProfileSite` performs a genuine TLS
  handshake with the borrowed site using the same parroted fingerprint a Warren
  client would, and records record sizes, order, pacing, post-handshake records
  and the size of a real client's Finished. A constant was never viable: Go emits
  one record per handshake message, OpenSSL coalesces several, certificate chains
  differ by kilobytes between sites, ticket counts differ again. A hardcoded pad
  would have made every Warren relay look like the same server that doesn't exist.
- **The records have a job.** The largest one carries an HMAC over the session key
  and the whole transcript, so the client gets key confirmation before it sends
  anything and any rewriting of the ClientHello or ServerHello in transit is
  detected. The client answers in a Finished-sized record. Shape that also does
  work is easier to keep correct than shape that doesn't.
- **Ordering is explicit, not timed.** The confirmation carries how many flight
  records follow it, so the client answers only once the whole flight has arrived.
  A timing heuristic would have put the client's ChangeCipherSpec in the middle of
  the server's flight on a slow link — precisely the ordering this exercise exists
  to get right.
- **Fail closed, and re-measure.** A relay with no usable profile refuses to serve
  rather than emit a shape that advertises itself; profiles are re-measured on a
  schedule because certificates rotate, and a failed or implausible re-measurement
  keeps the last good one.
- **Site selection became machine-checkable.** A site that negotiates classical
  X25519 answers with a ServerHello hundreds of bytes smaller than Warren's
  hybrid one, so pairing with it would make the *first server packet* a
  distinguisher. Profiles that don't negotiate `X25519MLKEM768` are rejected, and
  `node -profile-only` exists so an operator can check a candidate site before
  committing to it.

This is still shape, not substance: it defeats an adversary who measures, which is
the adversary that scales, but it does not produce a certificate anyone can verify.
A censor running its own Warren client can still tell. That remains accepted (see
Consequences), and Stage B remains conditional.

### Stage B — conditional: relay the real handshake, nested

Only if the Stage 0 harness shows Stage A is still separable, or if a target
region deploys TLS-intercepting middleboxes (a censor with its own CA sees a
real session to a real site survive interception while Warren's would break).

If it happens, the layering resolves the apparent conflict between mimicry and
post-quantum, which was a false choice:

```
outer: borrowed TLS 1.3 handshake, relayed from the real site   -> shape and verifiability
inner: Warren's hybrid X25519 + ML-KEM-768 handshake            -> confidentiality of recorded traffic
```

The outer layer only has to look right, so it may be X25519-only because that is
what the real site dictates. The inner layer carries the post-quantum property.
Recorded traffic stays protected by the inner layer regardless of what the outer
one negotiated.

And if Stage B is built, upstream REALITY is used as a **reference
implementation and test oracle** — run our transport and xray's side by side
against the same harness — rather than as a dependency. `tls-borrow` stays one
implementation behind the pluggable-transport interface
([`DESIGN.md` §6.3](../../DESIGN.md)), so a `reality` transport can be added
later as a peer without disturbing anything above L1.

## Consequences

- Stage A has landed, so the handshake no longer carries the passive
  distinguisher. The transport is still not deployable, for reasons that are now
  about traffic shape and pool enumeration rather than the handshake; the README
  says which.
- Slice 1's gate now passes: Stage 0 and Stage A are done, and `cmd/probe` reports
  no distinguisher against a local OpenSSL-backed site across six active probes and
  five shape measurements. What that gate does *not* cover is the shape of
  application traffic after the handshake (DESIGN.md §6.4) or relay-pool
  enumeration (§7.2), so it is not a statement that Warren is deployable.
- Post-quantum confidentiality is not traded away at any stage.
- A censor that runs a Warren client can still tell a relay from the borrowed
  site, because it holds a valid tag and can see the flight is synthetic. That
  is accepted: such an adversary can also enumerate bridges through discovery,
  which is an L2 anti-enumeration problem ([`DESIGN.md` §7.2](../../DESIGN.md)),
  not something protocol mimicry can fix.
- Residual risk, recorded: TLS-intercepting middleboxes (a state CA) break a
  Warren session where they would not break a real one. Stage B is the answer if
  a target region deploys them.

## Verification before Stage B

1. Current xray-core REALITY's post-quantum status and whether its auth survives
   a hybrid `key_share`.
2. MPL-2.0 / AGPL-3.0 obligations for vendoring versus forking.
3. What the borrowed site's real flight looks like per target site, since Stage A
   sizes its synthetic records from it.
