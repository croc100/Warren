# Changelog

All notable changes to Warren. Newest first.

## 2026-09-28 — L0: signed, expiring bridge descriptors

Second Slice 1 item. Bridges no longer travel as bare `addr|sni|pubkey` lines
over channels a censor can influence.

### Added

- `internal/discovery/bootstrap/descriptor.go`: the `warren-bridges/1`
  descriptor — one line, whitespace-free, so any text channel can carry it (DNS
  TXT record, chat message, QR code, printed page):
  `warren-bridges/1;issued=…;expires=…;bridge=addr|sni|pubkey[;bridge=…];sig=…`
  with an Ed25519 signature over the literal wire prefix, not a
  re-serialization of parsed fields. Unknown fields are rejected; the version
  prefix is how a future format announces itself.
- `cmd/bootstrap`: `-genkey` (mint the trust anchor; the anchor ships with
  clients, the signing key stays offline), `-sign`, `-verify`. It replaces the
  "not yet implemented" placeholder.
- Staleness as a first-class state: `Descriptor.Stale`, `Bridge.Stale`,
  `Bridge.Expires`, `Result.Stale`. `Multi` prefers a fresh copy of a relay over
  a stale one and sorts fresh bridges first; `cmd/cli` warns when it is dialing
  a stale bridge.
- Tests: sign/verify round trip, a byte-by-byte tamper sweep over the whole
  signed payload, a descriptor signed by a different key, missing anchor,
  unknown field, expiry surfacing as stale rather than fatal, a tampered DNS
  record costing only itself, and `Multi` refusing to let a stale descriptor
  override a current one.

### Changed

- `FileResolver` and `DNSResolver` now require `Anchors` and **fail closed**
  without one. A file and a DNS answer are the two cheapest places for a censor
  to put its own bridge list, so "no anchor configured" is an error rather than a
  silent downgrade to trusting the channel. `StaticResolver` still needs no
  signature: its bridges arrived inside the client binary.
- `cmd/cli` takes `-trust-anchor` / `WARREN_BRIDGE_ANCHOR_HEX` when reading a
  bridge file. Explicit `-addr`/`-relay-key` still works for local demos, where
  the operator is the trust anchor.

### Why expiry is not fatal

A verified but expired descriptor still yields bridges, marked stale. Treating
expiry as fatal would hand a censor a way to strand clients by blocking every
discovery channel for a week — the addresses a client already holds may well
still work, and "discovery is stale" is a different state from "no bridges".

## 2026-09-28 — L1: hybrid post-quantum session handshake, static PSK removed

Slice 1 work from [`docs/ROADMAP.md`](ROADMAP.md). The transport no longer has a
shared secret, and a recorded session is no longer decryptable by anyone who
later obtains the relay's key or a quantum computer.

### Added

- `internal/network/transport/handshake.go`: the Warren session handshake, hidden
  inside the camouflaged TLS flight. The client's ephemeral X25519MLKEM768 key
  share (ML-KEM-768 encapsulation key ‖ X25519 public key, the real browser
  layout) rides in the ClientHello; the relay answers with a real-shaped TLS 1.3
  ServerHello carrying the ML-KEM ciphertext and its own ephemeral X25519 key.
  Three secrets feed the AEAD key: ML-KEM (post-quantum), ephemeral X25519
  (forward secrecy), and an exchange with the relay's long-term identity key
  (authentication).
- Relay identity keys: `transport.GenerateServerIdentity`, `node -genkey`. The
  private half never leaves the relay; the public half is published in the bridge
  descriptor.
- Bounded replay cache on `client_random`. The tag is a function of the hello, so
  a verbatim replay would otherwise validate; a repeat is now spliced to the real
  site, closing the "replay one recording to confirm a relay" probe.
- `internal/network/transport/record.go`: TLS record-layer framing and helpers.
- Tests: wrong-relay-key treated as a probe, replayed hello spliced to the real
  site, segmented ClientHello (137-byte chunks through a fragmenting proxy) still
  authenticating, client record-type sequence matching a real TLS 1.3 client, and
  per-connection ephemerality of every secret.

### Changed

- **Removed the static pre-shared key.** `Config.PSK` is gone, replaced by
  `ServerPublicKey` (client) and `ServerPrivateKey` (relay). Consequences: a
  compromised client reveals nothing about other sessions; seizing a relay key
  does not decrypt earlier recordings; and a hostile discovery channel cannot
  steer a client onto a censor-run relay, because the client cannot authenticate
  to a relay whose key it was not given.
- Application data is framed as TLS `application_data` records (`0x17 0x03 0x03`
  + length) instead of a bespoke 4-byte length prefix, with the record header
  authenticated as AEAD associated data. The client's wire sequence is now
  ClientHello → ChangeCipherSpec → application_data, matching a real TLS 1.3
  client in middlebox-compatibility mode.
- Bridge descriptors are `addr|sni|pubkey`; a descriptor missing its relay key is
  skipped as malformed rather than failing later at dial time.
- `cmd/node` takes `-identity-file` / `WARREN_RELAY_KEY_HEX` and `-genkey`;
  `cmd/cli` takes `-relay-key` / `WARREN_RELAY_PUBKEY_HEX` or reads the key from
  the bridge file. `WARREN_PSK_HEX` is gone.
- Server-side hello parsing now peeks the complete record and parses it with
  uTLS rather than reading fixed offsets, which is what makes a segmented
  ~1.5 KB hybrid hello a non-issue.

### Known gaps

- The flight after the ServerHello is TLS-*shaped*, not a real TLS handshake:
  no Certificate/Finished. A censor who already holds a valid tag could see that.
  Either completing a borrowed handshake or adopting xray-core's audited
  `reality` package is the next decision — upstream REALITY is X25519-only, so
  adopting it as-is would trade the post-quantum property for the mimicry one.
- Bridge descriptors are still unsigned, and traffic shaping is unimplemented.

## 2026-09-28 — Design re-based on the 2026 environment

Warren is pre-alpha with two working layers, so this revision optimizes for
technical merit in the current environment rather than continuity with earlier
drafts. Full rationale in [`DESIGN.md`](../DESIGN.md); superseded decisions are
tabulated in [`DESIGN.md` §14](../DESIGN.md#14-deprecated-decisions).

### Changed — transport (code)

- `internal/network/transport`: the camouflage profile is now configurable
  (`Config.Fingerprint`) and defaults to `DefaultFingerprint` =
  `utls.HelloChrome_Auto`, instead of a pinned `HelloChrome_120`. A pre-2024
  browser parrot offers no hybrid post-quantum key share, which makes it a
  distinguisher against today's real TLS traffic rather than a disguise.
- Added `TestDefaultFingerprintOffersHybridPQKeyShare` as a staleness guard: it
  fails if the active profile stops offering `X25519MLKEM768`.
- Added `TestClientHelloSpansMultipleSegments`, recording that the current
  profile's hello is ~1.5 KB and therefore will not arrive in one TCP segment on
  a real network.

### Changed — design

- Threat model updated for deployed allowlist regimes, national shutdowns,
  throttling-instead-of-blocking, statistical classification, post-quantum TLS
  as the common case, and client-distribution/operator-liability chokepoints.
- Transport re-specified as pluggable (`tls-borrow`, `masque` per RFC 9298/9484,
  `websocket-tunnel`, `rendezvous`) with an explicit degradation ladder.
- Traffic shaping re-specified as three costed regimes (`off` / `bucket` /
  `cover`); always-on constant-rate cover traffic is removed as unbudgeted and
  self-contradictory under per-GB billing.
- Node taxonomy reduced from five types to three roles (client / relay / exit),
  with relay ≠ exit as a safety property.
- Abuse containment and exit-operator liability added as a blocking requirement.
- Settlement moved off L1 mainnet and out of the critical path: the core works
  with settlement disabled; optional on-chain settlement is L2, net-balance only,
  with no public listing surface.
- Access control moved from a bespoke ZK nullifier scheme to Privacy Pass
  (RFC 9576–9578) unlinkable tokens.
- Satellite/mesh re-specified as a link type with per-traffic-class policy.
- Roadmap replaced month numbers with falsifiable per-slice gates.

### Removed

- On-chain per-event Independence Logger, replaced by opt-in threshold-aggregated
  telemetry (Prio/STAR-class) over Oblivious HTTP. An immutable public record of
  "circumvention happened in region R at time T" is a liability the analytics
  product does not need.
- Public on-chain bandwidth listings — a permanent, browsable directory of
  residential relays is a censor's blocklist.
- Bespoke bonded-relayer gas payment (ERC-4337 / EIP-7702 cover this).
- libsnark (unmaintained); gnark/Noir-class tooling if ZK is needed at all.
- `Starlink.EstablishTunnel`-style API integration — no such consumer API exists.

### Fixed — factual errors in the design

- LoRa control-plane capacity was overstated by 1–2 orders of magnitude
  ("~500 messages/second"); duty-cycle limits put the real budget at single-digit
  messages per minute, which changes the control plane to store-and-forward.
- The failover "health" formula was unbounded yet compared against `0.6`;
  re-specified as normalized [0,1] with hysteresis.
- Retired Ethereum testnets (Goerli/Holesky) replaced with Sepolia/Hoodi.
- "Amazon Kuiper" renamed to its commercial brand, Amazon Leo.
- README no longer advertises installers, packages, binary releases, or a 10 Gbps
  hardware requirement that do not exist.

## Earlier

- L0 bootstrap + L1 REALITY-lite camouflage implemented and tested (`adbf189`).
- Initial project structure and design documents.
