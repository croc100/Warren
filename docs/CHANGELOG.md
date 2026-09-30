# Changelog

Newest first. This file records *why* things changed, since that is the part a diff
does not keep. Structural decisions live in [`DESIGN.md`](../DESIGN.md) §14 and in
[`docs/adr/`](adr/).

## 2026-10-01 — L1 hardening: answer timing, replay freshness, and canaries on the gate

Three weaknesses closed and three defects found on the way, one of which had been
silently disabling a measured defence on the platform most of the intended relay
pool would run.

### The gate can now be shown to fail

Every test in `internal/network/probe` asserted that the harness finds nothing,
which is also what a harness returns once it has quietly stopped working. A
`Compare` that loses a measurement in a refactor, a tolerance widened past
meaning, a suite that stops running its probes — all of them read as PASS,
forever, and the gate keeps certifying that a relay is indistinguishable.

`canary_test.go` points the harness at relays that are deliberately wrong and
requires it to say so, one canary per measurement so none can be satisfied by an
unrelated failure. `hack/smoke.sh` does the same to the binary, running
`cmd/probe` against a site the relay does not borrow from and failing if it does
not exit non-zero. A canary going green is now as much a defect as a gate going
red.

It paid for itself immediately: the post-handshake comparison had a 512-byte
absolute tolerance inherited from the certificate-flight comparison, and the
post-handshake window is only a few hundred bytes in total. A relay sending **no
session tickets at all** against a site sending two was inside tolerance. That
measurement had been inert. It now has its own, far tighter floor, plus a
categorical rule: silence where the site reliably speaks is never within
tolerance, whatever the byte budget says.

### The relay no longer answers faster than the site it claims to be

A relay has two answer paths and they cost structurally different amounts of
time. A client holding a valid tag is answered out of local state in
microseconds. Everyone else is spliced, which costs a fresh TCP connection to
the borrowed site plus that site's own answer time. Connections to one relay
address therefore split into two clearly separated latency modes, and no real
web server does that. It needs no decryption, no key and no active probing —
a passive observer timing ClientHello to ServerHello sees it.

`ProfileSite` now measures how long the borrowed site takes to answer, and the
relay waits that out before its own ServerHello. The wait is measured from the
hello's arrival, so the key exchange comes out of the budget rather than being
added to it, and it is capped so a slow or hostile site cannot turn every
handshake into a stall. Measured: without the wait, a relay answered in 510 µs
where the site it imitates took 150 ms.

**This narrows the gap rather than closing it, and the gate now says so.** The
splice still pays one round trip more than the Warren path, because it has to
open a TCP connection the profile's measurement does not include. `cmd/probe`
captures a third session — unauthenticated, against the relay — and reports the
two paths side by side, so the residual is measured rather than assumed. Closing
it means either warm upstream connections or waiting out the connect as well;
both are tracked in the roadmap's hardening backlog.

### A captured hello now expires on its own

The tag is a function of the hello, so a verbatim replay validates by
construction, and the relay refused repeats from a cache of randoms it had seen.
But a cache is a memory budget and every memory budget expires: a censor holding
one captured hello only had to wait out the TTL, and it would verify again.
Waiting is free, so the cache's TTL was the real lifetime of the defence.

The tag now also covers a coarse clock, and a relay accepts only the windows
adjacent to its own. Nothing changes on the wire — the window is an input to the
HMAC, not a field, so the hello keeps the size and structure a browser's has —
and the cache's job shrinks to covering the window span rather than standing
alone.

The cost is honest and stated: a client whose clock is wrong past the slack
cannot connect, and cannot be told why, because an out-of-window tag has to be
answered exactly like a forged one. `Dial` now fails with `ErrRelayRejected`,
which names the clock along with the other plausible causes, instead of the raw
AEAD failure that being spliced used to surface as.

### The replay cache degrades instead of collapsing

On reaching its ceiling the old cache swept for expired entries and, if that
freed nothing, emptied itself. A relay busy enough to fill it inside one TTL
therefore forgot *every* random it had seen, periodically and silently, with no
replay protection at all until it refilled — a cliff that appears on a relay
that is doing well rather than one under attack. Entries now live in
generations that rotate, so the ceiling costs the oldest generation and nothing
else. What makes that safe is the freshness window above: a random old enough to
be evicted is close to one whose tag no longer verifies anyway.

### Defects found on the way

- **TCP teardown mirroring never worked on Windows.** The splice mirrors an
  upstream reset so a connection tears down the way the borrowed site's would —
  a distinguisher `cmd/probe` found and fixed once already. The check was
  `errors.Is(err, syscall.ECONNRESET)`, and on Windows a peer reset arrives as
  `WSAECONNRESET` (10054) while `syscall.ECONNRESET` is a synthetic value
  (0x20000017) no socket returns. It matched nothing, so a Windows relay closed
  every spliced connection with a FIN against a site sending RST. CI ran only
  Linux, so nothing caught it, and Windows is the operating system most of the
  residential pool this design bets on would run. Detection is now per-platform
  and has its own test.
- **The splice truncated the site's answer under load.** Teardown waited for
  whichever direction finished first and then allowed a fixed 200 ms. When the
  site closed straight after answering, the client-to-site copy could finish
  first and start a grace the response then had to beat — usually it did, and
  under load sometimes it did not, so the relay answered a probe with nothing
  where the site answered with an alert. It now waits on the site's direction by
  name, bounded, because a truncated answer is itself a difference from a site
  that always finishes what it started.
- **A `gofmt` check that cannot run on Windows.** `make fmt` reports every file
  as unformatted on a CRLF checkout, which is every Windows clone. Tracked in
  the backlog rather than fixed here.

## 2026-09-28 — L0 and L1 brought up to a measurable standard

Warren went from a proof of concept that compared favourably against itself to two
layers that hold up against a harness built to break them. The design was re-based
on the 2026 environment first, then the transport and discovery layers were
rebuilt to match, with a measurement gate in between.

### L1 — transport

- **Hybrid post-quantum session handshake; the static PSK is gone.** The client's
  ephemeral X25519MLKEM768 key share rides in the parroted ClientHello in the exact
  layout a real browser uses, and the relay answers with a real-shaped ServerHello
  carrying the ML-KEM ciphertext. Three secrets feed the AEAD key: ML-KEM-768
  (recorded traffic stays unreadable later), ephemeral X25519 (forward secrecy), and
  an exchange with the relay's long-term identity key (authentication). Clients hold
  only a relay's public key, so a compromised client reveals nothing about any other
  session, and seizing a relay key does not decrypt earlier recordings.
- **The server flight is shaped from a live measurement of the borrowed site.** A
  real TLS 1.3 server follows its ServerHello with kilobytes of encrypted
  certificate messages and then session tickets; sending nothing there is separable
  on record sizes alone. A constant could not fix it — Go emits one record per
  handshake message, OpenSSL coalesces several, chains differ by kilobytes, ticket
  counts differ again — so `ProfileSite` measures the site and the relay replays its
  shape, re-measuring on a schedule because certificates rotate. The records carry
  Warren's key confirmation (an HMAC over the session key and the whole transcript)
  rather than padding, and the confirmation states how many records follow it, so
  ordering is explicit instead of timed.
- **Consequences that are now enforced:** a relay with no usable profile refuses to
  serve, and a site that does not negotiate `X25519MLKEM768` is rejected as cover,
  because Warren's ServerHello is hundreds of bytes larger than such a site's would
  be. `node -profile-only` exists so an operator can check a candidate first.
- **Replay cache.** The tag is a function of the hello, so a verbatim replay would
  validate by construction; a repeat is now spliced to the real site, closing the
  "replay one recording to confirm a relay" probe.
- **Framing.** Application data is TLS `application_data` records with the header
  authenticated as associated data, replacing a bespoke 4-byte length prefix. Every
  record's plaintext starts with a kind byte, which is what makes filler invisible
  to callers — the mechanism the traffic-shaping regimes will reuse.
- **Camouflage profile tracks a current browser** (`HelloChrome_Auto`), with a CI
  guard asserting the active profile still offers a hybrid post-quantum key share.
  A 2023 parrot is a distinguisher in 2026, not a disguise.

### L0 — discovery

- **Signed, expiring bridge descriptors** (`warren-bridges/1`), one whitespace-free
  line so any text channel carries them. The Ed25519 signature covers the literal
  wire prefix, never a re-serialization of parsed fields, because verifying a
  re-encoding is a well-worn way to ship a signature bypass; unknown fields are
  rejected. This reduces a hostile channel from a redirection to a denial of
  service, since each relay's identity key is inside the signed payload.
- **File and DNS resolvers fail closed without a trust anchor.** Those are the two
  cheapest places for a censor to put its own list. `StaticResolver` needs none: its
  bridges arrived inside the client binary.
- **Expiry is a reported state, not an error.** An expired descriptor still yields
  bridges, marked stale, and fresh copies win; treating expiry as fatal would let a
  censor strand clients by blocking every channel for a week.
- `cmd/bootstrap` replaces its placeholder with `-genkey`, `-sign`, `-verify`.

### Measurement

- **`internal/network/probe` + `cmd/probe`, the gate.** It taps a Warren session
  and a real TLS session to the same borrowed site, compares record shape, and runs
  six active probes (browser-shaped handshake with certificate inspection, two
  sequential handshakes, plaintext HTTP, record-shaped junk, a truncated hello, and
  a replay of a captured genuine ClientHello) against both endpoints. It exits
  non-zero on any distinguisher.
- Its own self-test first asserted that it *detected* the known missing certificate
  flight — a harness that cannot find a defect you already know about is not
  evidence of anything — and now asserts the shapes match, which was Stage A's
  definition of done.
- `internal/network/tlsrec` holds the record-layer vocabulary both the transport
  and the harness use, so the thing measured and the thing measuring cannot
  disagree about a record boundary.

### Defects the harness found, all fixed

1. **The parroted ClientHello was ~250 bytes short of its own profile.**
   `PubClientHelloMsg.Marshal()` drops extensions that live only in
   `uconn.Extensions`, which for a current Chrome profile includes the GREASE ECH
   block. A first-packet size distinguisher, invisible to unit tests that compare
   Warren against itself.
2. **TCP teardown used FIN where the real site sends RST.** Separable on teardown
   alone, no TLS analysis needed. A Go-backed test site hid it; an OpenSSL-backed
   one exposed it — the reference site has to be representative.
3. **uTLS parses a ClientHello zero-copy**, so the parsed hello pointed into the
   `bufio` buffer the record was peeked from and later reads overwrote those bytes.
   Harmless until the key confirmation started reading the transcript after the
   client's own records had arrived; it presented as an intermittent failure that
   vanished under a debug print.

### Design

Re-based on the 2026 environment: deployed allowlist regimes and national
shutdowns, throttling instead of blocking, statistical classification,
post-quantum TLS as the common case, and client-distribution and operator-liability
chokepoints. Transports became pluggable with an explicit degradation ladder; node
types collapsed to client/relay/exit with relay ≠ exit as a safety property; exit
abuse containment became a blocking requirement; settlement left the critical path.

Retired, with reasons in [`DESIGN.md` §14](../DESIGN.md#14-deprecated-decisions):
the on-chain per-event Independence Logger (replaced by threshold-aggregated
telemetry over Oblivious HTTP), public on-chain bandwidth listings, a bespoke
bonded-relayer gas scheme, libsnark, L1-mainnet settlement, and a
`Starlink.EstablishTunnel` API that does not exist. Factual corrections: LoRa
control-plane capacity was overstated by one to two orders of magnitude, and the
failover "health" formula was unbounded yet compared against 0.6.

[ADR 0001](adr/0001-borrowed-tls-handshake.md) records how L1's mimicry gap is
being closed — measurement first, then shape, and a relayed real handshake only if
measurement demands it — and why xray-core's `reality` stays a reference
implementation rather than a dependency.

### Repository

The aspirational directory skeleton (95 empty placeholder directories, four
`not yet implemented` command stubs, and empty Solidity sketches for a design that
has since changed) was deleted. A tree that implies capability is its own kind of
dishonesty, and `DESIGN.md` already says what will live where.

## Earlier

Initial project structure, and the first L0 bootstrap plus REALITY-lite camouflage
proof of concept.
