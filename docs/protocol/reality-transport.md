# L0 + L1: Discovery, Camouflage, and the Session Handshake

This document covers the two lowest layers of Warren's stack, described in
[DESIGN.md](../../DESIGN.md#anti-blocklisting-defense-model):

- **L0 — Discovery/bootstrap** (`internal/discovery/bootstrap`): how a client
  finds a working relay without depending on one blockable endpoint.
- **L1 — Protocol camouflage + session handshake**
  (`internal/network/transport`): how a single connection to that relay
  survives passive DPI, statistical classification, and active probing, and
  how the two sides agree on keys inside that disguise.

These two are implemented and tested. Everything above them (relay pool,
accounting, measurement) is deliberately not wired in yet — see
[DESIGN.md](../../DESIGN.md) for why that ordering was chosen: a
censorship-evasion tool that can't survive L0/L1 against a real adversary
makes every other layer moot.

## L1: what's on the wire

A Warren client's first packet is a syntactically valid TLS 1.3 ClientHello,
built with [uTLS](https://github.com/refraction-networking/utls) so its
extension order, cipher list, key shares, and ALPN match a current Chrome
fingerprint (`transport.DefaultFingerprint`, tracking `utls.HelloChrome_Auto`).

That profile is a perishable value, not a constant: mainstream browsers now
offer the hybrid post-quantum group `X25519MLKEM768` by default, so a parrot of
a pre-PQ browser is a distinguisher rather than a disguise — smaller than real
hellos and missing a key share real hellos carry. `Config.Fingerprint` overrides
it per bridge or per region, since the right parrot is whatever the local
population runs. `TestDefaultFingerprintOffersHybridPQKeyShare` fails the build
if the default regresses to a pre-PQ profile.

Two things ride inside the hello:

1. **A 16-byte authentication tag** in the `session_id` field (padded to the
   usual 32 bytes so the field length isn't a tell), derived as
   `HMAC-SHA256(ss_auth, "warren-tag-v1" || client_random || client_share)`
   where `ss_auth = X25519(client_ephemeral, relay_identity_public)`.
2. **The client's own ephemeral hybrid key share** — an ML-KEM-768
   encapsulation key followed by an X25519 public key (1216 bytes), byte-for-byte
   the layout a real browser sends for that group, so the hello's size and
   structure are unchanged. Only the bytes are Warren's, and only the client
   holds the private halves.

The relay peeks the first record on every inbound connection:

- **Tag valid, random not seen before** → a genuine Warren client. The relay
  answers with a real-shaped TLS 1.3 **ServerHello** carrying the ML-KEM
  ciphertext and its own ephemeral X25519 key in a `key_share` extension, plus
  a `ChangeCipherSpec` record; the client answers with its own
  `ChangeCipherSpec`. Both sides then derive the session key and application
  data flows in records framed as TLS `application_data`.
- **Tag invalid, absent, malformed, or replayed** → the raw bytes are spliced
  byte-for-byte to a real fallback site. Whoever sent them — an ordinary
  non-Warren client or a censor's active probe — gets a genuine response from
  that real site, because that's what actually answered.

So the record-type sequence a client emits is `handshake`,
`change_cipher_spec`, `application_data …` — exactly what a real TLS 1.3 client
in middlebox-compatibility mode emits, which is asserted by
`TestClientWireShapeIsTLSRecords`.

## The session handshake

Three shared secrets go into the AEAD key:

| Secret | Derivation | Property it buys |
|--------|-----------|------------------|
| `ss_mlkem` | ML-KEM-768 encapsulation to the client's ephemeral key | Post-quantum: a recorded session stays unreadable to an adversary who gets a quantum computer later |
| `ss_ecdhe` | X25519 between both sides' ephemeral keys | Forward secrecy: the keys are gone when the connection ends |
| `ss_auth` | X25519 between the client's ephemeral key and the relay's long-term identity key | Authentication: only the intended relay can recognize the tag |

`session_key = HKDF-SHA256(ss_mlkem ‖ ss_ecdhe ‖ ss_auth, salt = client_random ‖
server_random, info = "warren hybrid v1 aead key" ‖ client_share ‖
server_share)`. Every input has a fixed length, so the concatenations are
unambiguous. The ML-KEM-then-ECDHE ordering follows
draft-kwiatkowski-tls-ecdhe-mlkem, the same ordering real TLS uses for the
group.

**This replaces the static pre-shared key the first proof of concept used**,
which was its most serious weakness:

| | Static PSK (before) | Identity key + ephemerals (now) |
|---|---|---|
| Secret held by clients | One shared PSK, same for everyone | The relay's public key only |
| One client compromised | Every session, past and future, readable | Nothing about any other session |
| Relay seized later | Recorded sessions decryptable | Recorded sessions stay unreadable |
| Tag | Function of a shared secret | Function of a per-connection exchange |
| Post-quantum | No | Yes (hybrid ML-KEM-768) |

A relay generates its identity with `node -genkey`; the public half is published
in the bridge descriptor (`addr|sni|pubkey`), the private half never leaves the
relay.

**Replay.** Because the tag is a function of the hello, a captured hello
re-sent verbatim validates by construction. The relay therefore keeps a bounded
replay cache of recently-seen `client_random` values (10-minute TTL) and treats
a repeat exactly like an unauthenticated connection: spliced to the real site.
Without this, a censor could confirm a suspected relay by replaying one
recorded hello and noticing the response differs from the real site's.

## L0: signed descriptors over multiple channels

Bridges travel as **signed, expiring descriptors**, one per line, so any channel
that carries text can carry them — a DNS TXT record, a chat message, a QR code,
a printed page:

```
warren-bridges/1;issued=<RFC3339>;expires=<RFC3339>;bridge=<addr|sni|pubkey>[;bridge=...];sig=<base64url>
```

The Ed25519 signature covers the literal prefix of the line up to and including
the `;` before `sig=` — the exact bytes on the wire, never a re-serialization of
parsed fields, because verifying a re-encoding is a well-worn way to ship a
signature bypass: any field the parser ignores or normalizes becomes a place to
hide content the signature does not cover. Unknown fields are rejected outright;
the version prefix is how a future format announces itself.

This is what reduces a hostile discovery channel from an attack to a denial of
service. A censor who controls a DNS answer or circulates its own "bridge list"
cannot produce a descriptor that verifies, so it cannot steer a client onto a
relay of its choosing — and since the relay's identity key is inside the signed
payload, it cannot swap that either. `TestVerifyRejectsTamperedFields` flips
every byte of the payload in turn and asserts that none of them survives.

**Expiry is a reported state, not a fatal error.** A verified but expired
descriptor still yields bridges, marked `Stale`, and `Multi` prefers fresh
copies and reports which channels are serving only stale data. Treating expiry
as fatal would hand a censor a way to strand clients by blocking every discovery
channel for a week; the addresses a client already holds may well still work.

`bootstrap -genkey` mints the anchor (public half ships with clients, signing key
stays offline), `-sign` produces a descriptor, `-verify` inspects one.

`Multi` queries every configured `Resolver` concurrently and merges whatever
succeeds, rather than stopping at the first one that answers. Three resolver
types are implemented:

- `DNSResolver` — TXT record lookup, injectable `LookupTXT` function so it's
  testable without a real DNS server and so production code can point different
  instances at different upstream resolvers (the same "don't depend on one
  operator" logic that makes multi-resolver DNS robust against a single censored
  resolver).
- `FileResolver` — reads signed descriptors from a local file, one per line. This
  is the landing point for out-of-band bridge distribution (encrypted messaging,
  email autoresponder — the same pattern Tor bridges use); the distribution
  mechanism itself is out of scope for this package.
- `StaticResolver` — a fixed, compiled-in list. Last resort only: it can't be
  taken down, but also can't be updated without a new build. It is the one
  resolver that needs no signature, because its bridges arrived inside the
  client binary and already carry whatever assurance the release artifact has.

`FileResolver` and `DNSResolver` both **fail closed without a trust anchor**: a
file and a DNS answer are the two cheapest places for a censor to put its own
list, so "no anchor configured" is an error rather than a silent downgrade to
trusting the channel.

`Multi.Resolve` returns success as long as *any* channel works, plus a
per-channel report — so an operator can see which discovery channels are
currently blocked (or being tampered with, or serving stale data) in a given
region, and a client keeps working as channels get blocked one at a time rather
than failing outright. A bridge missing its relay public key is rejected as
malformed: a bridge without an identity key is unusable, and accepting it would
push the failure to dial time, where it looks like censorship instead of a bad
descriptor.

## Measuring it

`internal/network/probe` (driven by `cmd/probe`) is the gate. It taps a genuine
Warren session and a real TLS session to the same borrowed site, compares record
shape, and runs an active probe suite against both endpoints: a browser-shaped
handshake with certificate inspection, two sequential handshakes, plaintext HTTP,
record-shaped junk, a truncated hello, and a replay of a captured genuine
ClientHello. It exits non-zero on any distinguisher.

```bash
go run ./cmd/probe -relay=127.0.0.1:8443 -site=127.0.0.1:9443 \
  -sni=www.example.com -relay-key=<relay public key>
```

Two things it found on its first run, neither of which any unit test could have
caught, because unit tests compare Warren against itself:

- The parroted ClientHello was ~250 bytes short of the profile it claimed to be:
  `PubClientHelloMsg.Marshal()` drops extensions that live only in
  `uconn.Extensions`, which for a current Chrome profile includes the GREASE ECH
  block. Fixed by marshaling through `UConn.MarshalClientHello()`.
- TCP teardown didn't match. A real HTTPS server handed plaintext HTTP aborts
  with an RST; the relay spliced the site's bytes and then closed cleanly with a
  FIN, which is separable on teardown alone. Fixed by mirroring the upstream
  reset. A Go-backed test site hid it; an OpenSSL-backed one exposed it.

What it still reports, by design, is the missing certificate flight below.

## Known gaps vs. a hardened production transport

- **No certificate flight after the ServerHello — and it is passively
  detectable.** A real TLS 1.3 server follows its ServerHello and
  ChangeCipherSpec with EncryptedExtensions, Certificate, CertificateVerify and
  Finished: typically 2–6 KB of `application_data` records, answered by a small
  client Finished. Warren sends nothing there. A classifier needs no decryption
  and no Warren client to notice "TLS 1.3 session whose server flight after CCS
  is under 200 bytes"; record sizes and directions are enough. **This is the
  highest-priority remaining defect, and until it is fixed the transport is not
  safe against a live adversary.**

  What works in our favour is that TLS 1.3 *encrypts* the certificate flight, so
  a passive observer can never validate a certificate — only measure the shape —
  and an active prober is already spliced to the real site and gets that site's
  genuine chain. So the fix is staged: shape-accurate synthetic records first, a
  relayed real handshake only if measurement says that is not enough, and never
  at the cost of the post-quantum property. See
  [ADR 0001](../adr/0001-borrowed-tls-handshake.md).
- **Traffic shape is unmodified.** DESIGN.md's `bucket`/`cover` regimes
  (§6.4) aren't implemented; record sizes track payload sizes, so a flow
  classifier still sees Warren's own size and timing distribution.
- **Distribution of the anchor and of the client itself is unsolved.** Signed
  descriptors move the problem one step back: the anchor ships with the client,
  so the remaining question is how the client gets to the user in a region where
  app stores remove it on request. Reproducible builds and several non-app-store
  channels are the next L0 items (DESIGN.md §5.1).
- **No rotating per-requester subsets.** Discovery currently hands out whatever
  a channel holds; anti-enumeration (rotating subsets, token-rate-limited
  requests) is L2 work (DESIGN.md §7.2).
- **Sniff latency on short, non-ClientHello-shaped input.** A connection whose
  record header claims more bytes than it ever sends waits out the 5-second
  sniff deadline before falling through. Real HTTPS clients are unaffected;
  an unusually terse probe sees the delay.

## Running the demo

```bash
# 1. generate the relay identity (private half stays here, public half is published)
eval "$(go run ./cmd/node -genkey | head -1)"   # exports WARREN_RELAY_KEY_HEX
go run ./cmd/node -genkey                        # prints a pair; note the public key

# 2. a stand-in "real site" the relay borrows an identity from
python3 -m http.server 9443

# 3. the relay
go run ./cmd/node -listen=127.0.0.1:8443 \
  -fallback-addr=127.0.0.1:9443 -fallback-sni=www.example.com

# 4. the bridge-distribution trust anchor (signing key stays offline)
eval "$(go run ./cmd/bootstrap -genkey 2>/dev/null)"

# 5. a signed descriptor, as an out-of-band channel would distribute it
go run ./cmd/bootstrap -sign -ttl=168h \
  -bridge="127.0.0.1:8443|www.example.com|<relay public key hex>" > bridges.txt
go run ./cmd/bootstrap -verify -file=bridges.txt

# 6. the client
go run ./cmd/cli -bridge-file=bridges.txt -message="hello from behind the firewall"
```

A genuine Warren client gets its message echoed back over the AEAD channel. Edit
one byte of `bridges.txt` — swap the relay key, as a hostile channel would — and
the client refuses it before dialing anything.
Then act like a censor's probe: `curl -v --http1.0 http://127.0.0.1:8443/`
returns a real response from whatever is on `-fallback-addr`. A client holding
the wrong relay key gets the same treatment as the probe — it is spliced to the
real site and its `Dial` fails, because a Warren relay it cannot authenticate to
is indistinguishable from a web server.

## Tests

```bash
go test ./internal/network/transport/... ./internal/discovery/bootstrap/... -race
```

Covers: the full hybrid handshake round trip; untagged input spliced to the real
site without reaching the Warren handler; a client holding the **wrong relay
key** treated as a probe; a **replayed ClientHello** spliced to the real site;
a **segmented ClientHello** (delivered in 137-byte chunks through a fragmenting
proxy) still authenticating; descriptor signing and verification, including a
byte-by-byte tamper sweep, an unknown-field rejection, a hostile signer, and
expiry surfacing as stale rather than fatal; which is the realistic arrival pattern for a
~1.5 KB hybrid hello; the client's on-wire **record-type sequence** matching a
real TLS 1.3 client; **per-connection ephemerality** of every secret, including
a relay with a different identity key failing the tag check; and the camouflage
profile still offering a hybrid PQ key share.

## Bugs found while building this

Worth recording since they're the kind of thing that looks fine in a design doc
and breaks on first real run.

1. uTLS caches the ClientHello's originally-built wire bytes in `hello.Raw`,
   and `Marshal()` returns that cache verbatim if it's non-nil — it does **not**
   re-encode from the struct fields. Mutating `SessionId`/`KeyShares` and
   calling `Marshal()` silently produced the *original*, unpatched bytes. Fix:
   clear `hello.Raw = nil` before marshaling.
2. The relay originally discarded only the bytes it had peeked to extract the
   tag, not the full ClientHello record — leaving the record's remaining bytes
   in the stream to be misread as the first frame's length prefix. Fix: parse
   the record-layer length and discard the entire record.
3. Without a read deadline, a connection sending a plausible record header and
   then nothing would block its handler goroutine forever — a cheap
   Slowloris-style resource exhaustion. Fixed with a 5-second sniff deadline.
4. When the relay started sending a real-shaped `ChangeCipherSpec` after its
   ServerHello, the client didn't consume it and read it as the first
   application-data record. The record framing is what caught it, since the
   type byte no longer matched — a bespoke length prefix would have desynced
   silently.
