# Changelog

All notable changes to Warren. Newest first.

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
