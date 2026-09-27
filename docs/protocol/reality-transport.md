# L0 + L1: Discovery and Protocol Camouflage

This document covers the two lowest layers of Warren's stack, described in
[DESIGN.md](../../DESIGN.md#anti-blocklisting-defense-model):

- **L0 — Discovery/bootstrap** (`internal/discovery/bootstrap`): how a client
  finds a working relay without depending on one blockable endpoint.
- **L1 — Protocol camouflage** (`internal/network/transport`): how a single
  connection to that relay survives passive DPI signature matching and active
  probing.

These two are implemented and tested. Everything above them in the stack
(marketplace routing, payment channels, ZK-Passport auth, aggregate logging)
is deliberately not wired in yet — see [DESIGN.md](../../DESIGN.md) for why
that ordering was chosen: a censorship-evasion tool that can't survive L0/L1
against a real adversary makes every other layer moot, so this is the first
thing that needed to be provable, not just specified.

## What's actually implemented

### L1: `internal/network/transport` — a "REALITY-lite" transport

A Warren client's first packet on the wire is a syntactically valid TLS 1.3
ClientHello, built with [uTLS](https://github.com/refraction-networking/utls)
so its extension order, cipher list, key shares, and ALPN match a current
Chrome fingerprint (`transport.DefaultFingerprint`, tracking
`utls.HelloChrome_Auto`). That profile is a perishable value, not a constant:
mainstream browsers now offer the hybrid post-quantum group
`X25519MLKEM768` by default, so a parrot of a pre-PQ browser is a
distinguisher rather than a disguise — smaller than real hellos and missing a
key share real hellos carry. `Config.Fingerprint` overrides it per bridge or
per region, since the right parrot is whatever the local population runs. A 16-byte authentication tag — `HMAC-SHA256(psk, client_random)`
— is embedded in the ClientHello's `session_id` field (padded to the usual
32 bytes so the field length itself isn't a tell).

The server peeks the first TLS record on every inbound connection:

- **Tag valid** → genuine Warren client. Both sides independently derive a
  session key via HKDF from `(psk, client_random)` and switch immediately to
  an AEAD-framed (ChaCha20-Poly1305) channel on the same TCP stream.
- **Tag invalid, absent, or the input isn't a well-formed ClientHello at
  all** → the raw bytes are spliced byte-for-byte to a real fallback site.
  Whoever sent them — a normal non-Warren client, or a censor's active probe
  — gets a completely genuine response from that real site, because that's
  what actually answered.

This was verified against a real HTTP server standing in as the "fallback
site": a plain socket client sending a bare `GET / HTTP/1.0` (not a Warren
client at all) received a real `200 OK` from the fallback, proving the splice
path works end-to-end, not just in the happy path.

**Two real bugs were found and fixed while building this** (worth recording
since they're the kind of thing that looks fine in a design doc and breaks on
first real run):

1. uTLS caches the ClientHello's originally-built wire bytes in `hello.Raw`,
   and `Marshal()` returns that cache verbatim if it's non-nil — it does
   **not** re-encode from the struct fields by default. Mutating
   `hello.SessionId` and calling `Marshal()` silently produced the
   *original*, unpatched bytes. Fix: clear `hello.Raw = nil` before
   marshaling so the tag actually makes it onto the wire.
2. The server only discarded the bytes it had peeked to extract the tag,
   not the full ClientHello record — leaving the record's extensions/cipher
   suite bytes sitting in the stream to be misread as the first AEAD frame's
   length prefix. Fix: parse the record-layer length field and discard the
   *entire* record before switching to AEAD framing.

A third issue was a genuine hardening gap, not just a test artifact: without
a read deadline, a connection that sends a plausible record/handshake header
claiming a large `session_id` but never sends the rest would block its
handler goroutine forever — a cheap Slowloris-style resource exhaustion (one
dangling connection per idle goroutine, no cap). Fixed with a 5-second sniff
deadline, cleared once the ClientHello is fully read or the read fails.

### L0: `internal/discovery/bootstrap` — multi-channel discovery

`Multi` queries every configured `Resolver` concurrently and merges whatever
succeeds, rather than stopping at the first one that answers. Three resolver
types are implemented:

- `DNSResolver` — TXT record lookup, injectable `LookupTXT` function so it's
  testable without a real DNS server and so production code can point
  different instances at different upstream resolvers (the same "don't
  depend on one operator" logic that makes multi-resolver DNS robust against
  a single censored resolver).
- `FileResolver` — reads a local bridge list, one `addr|sni` per line. This
  is the landing point for out-of-band bridge distribution (encrypted
  messaging, email autoresponder — the same pattern Tor bridges use); the
  distribution mechanism itself is out of scope for this package.
- `StaticResolver` — a fixed, compiled-in list. Last resort only: it can't be
  taken down, but also can't be updated without a new build.

`Multi.Resolve` returns success as long as *any* channel works, plus a
per-channel report — so an operator can see which discovery channels are
currently blocked in a given region, and a client keeps working as channels
get blocked one at a time rather than failing outright.

## Known gaps vs. a hardened production transport

- **Static PSK instead of ephemeral ECDH.** Real REALITY (xtls/xray-core's
  `reality` package) derives its authentication key from an X25519 exchange
  embedded in the TLS `key_share` extension — there's no long-lived shared
  secret to leak, rotate, or have seized. This implementation uses a simpler
  static PSK distributed via the same channel as bridge addresses. Easier to
  reason about and test; weaker against key compromise. Migrating to
  xray-core's audited `reality` package (rather than reimplementing X25519-
  in-TLS handshake internals in-house) is the recommended production path —
  reusing an audited implementation for the cryptographically deep part is
  the right call, not a shortcut.
- **No TLS 1.3 state-machine mimicry after the ClientHello.** Genuine
  connections switch straight to Warren's own AEAD framing right after the
  ClientHello; a censor recording and replaying the full byte sequence of a
  session (not just the first packet) would notice it doesn't continue as a
  real TLS 1.3 handshake (ServerHello, Certificate, Finished, ...). Full
  REALITY avoids this because the non-Warren fallback path *is* a real
  handshake all the way through. Out of scope for this proof of concept.
- **Sniff latency on short, non-ClientHello-shaped input.** The server needs
  44 bytes to even check the tag (fixed offset through `session_id`). A
  request shorter than that (e.g. a bare `GET /` under the TLS record
  minimum) waits out the full 5-second sniff timeout before falling back.
  Real TLS ClientHellos are always well over this size, so real HTTPS
  traffic isn't affected — but naive test clients (or an unusually terse
  probe) will see the full delay.
- **Segmented ClientHello not yet exercised in tests.** The current profile's
  hello is ~1.5 KB (see `TestClientHelloSpansMultipleSegments`), which does not
  arrive in a single TCP segment on a real network. The tag sits at a fixed
  offset inside the first record, so extraction is unaffected in principle, and
  the server discards the whole record by its length field — but the tests
  exercise a loopback socket, not realistic segmentation, and the 5-second
  sniff deadline has not been validated against a slow, fragmented arrival of a
  legitimate hello.
- **No cover traffic / packet-size normalization yet.** DESIGN.md's
  "fixed-bucket sizing + constant-rate cover traffic" ML-classifier defense
  isn't implemented at this layer — this PoC proves the tag+fallback
  mechanism, not the full traffic-shape defense.

## Running the demo

```bash
export WARREN_PSK_HEX=$(openssl rand -hex 32)   # both sides must share this

# Terminal 1 — a stand-in "real site" the node borrows an identity from
python3 -m http.server 9443

# Terminal 2 — the relay
go run ./cmd/node -listen=127.0.0.1:8443 \
  -fallback-addr=127.0.0.1:9443 -fallback-sni=www.example.com

# Terminal 3 — the client
go run ./cmd/cli -addr=127.0.0.1:8443 -fallback-sni=www.example.com \
  -message="hello from behind the firewall"
```

A genuine Warren client gets its message echoed back over the AEAD channel.
A plain HTTP client pointed at the same port and given time to clear the
sniff window gets a real response from whatever's running on
`-fallback-addr` — try `curl -v --http1.0 http://127.0.0.1:8443/` and compare
against hitting port 9443 directly.

## Tests

```bash
go test ./internal/network/transport/... ./internal/discovery/bootstrap/... -race
```

Covers: the camouflage profile actually offering a hybrid post-quantum key
share (a staleness guard — it fails the moment `DefaultFingerprint` regresses
to a pre-PQ profile) and the resulting hello size, genuine-client round trip
over AEAD framing, untagged/malformed
input falling through to the real fallback (not reaching the Warren
handler), bridge-file parsing (including skipping malformed lines rather
than failing the whole file), and `Multi` surviving partial discovery-channel
failure while deduplicating bridges returned by more than one channel.
