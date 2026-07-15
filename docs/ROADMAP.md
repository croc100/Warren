# Warren Roadmap

**The decentralized internet layer for Crovi, Thump, and beyond.**

This document is the source of truth for Warren's public roadmap. Detailed
architecture and rationale for each item live in [`DESIGN.md`](../DESIGN.md);
this file tracks *what* ships *when* and in what order.

Status legend: ✅ done · 🚧 in progress · ⬜ planned

---

## Milestones at a Glance

| Phase | Timeline | Theme | Gate to next phase |
|-------|----------|-------|--------------------|
| **Alpha** | Months 1–3 | ISP Marketplace MVP on testnet | 5–10 node testnet trades settle end-to-end |
| **Beta** | Months 4–6 | Privacy Gateway + Independence Logger | Passes active-probing resistance harness |
| **RC** | Months 7–9 | Satellite Fallback + CRODE integrations | Live primary→satellite failover demo |
| **GA** | Months 10–12 | Mainnet + hardening | Production mainnet with paying nodes |
| **Expansion** | Year 2+ | Warren DNS / Email / Storage | — |

Timelines are relative to project start, not calendar-locked. Phases gate on the
"gate to next phase" criterion, not the month count.

---

## Phase 1 — Alpha: ISP Marketplace MVP (Months 1–3)

Prove the core economic loop: a node can sell spare bandwidth and a buyer can
route through it with settlement on chain.

- ⬜ Warren Core Protocol — P2P mesh + DHT (libp2p)
- ⬜ Bandwidth-trading smart contract (Ethereum testnet, Sepolia)
- ⬜ Marketplace node implementation (list / buy / settle)
- ⬜ Encrypted tunnel creation (ChaCha20-Poly1305)
- ⬜ Basic reputation system

**Deliverables**
- CLI: `warren marketplace list`, `warren marketplace buy`
- Local testnet with 5–10 nodes settling trades
- Getting-started documentation

**Stack:** Go · Solidity · libp2p

---

## Phase 2 — Beta: Privacy Gateway + Independence Logger (Months 4–6)

Make traffic uncensorable and prove it, without exposing users.

- ⬜ Privacy-first routing protocol (DPN), intent-based
- ⬜ YAML policy engine (policies stay local, never leave device)
- ⬜ REALITY-style TLS borrowing — protocol camouflage (Module 2)
- ⬜ Decentralized bootstrap/discovery — multi-channel, no single broker
- ⬜ ZK-Passport local handshake auth with session nullifiers (Module 3a)
- ⬜ Independence Logger — aggregate ZKP generation (Module 3b)
- ⬜ On-chain aggregate stats logging (Ethereum mainnet, Module 3b only)

**Deliverables**
- CLI: `warren privacy policy set`
- Active-probing resistance harness — isolated DPI simulator validating against
  real active-probe behavior, not just passive signature tools (nDPI)
- Dashboard: real-time censorship statistics

**Stack:** Go · Ethereum Sepolia · libsnark · Circom/Groth16 (Module 3a)

---

## Phase 3 — RC: Satellite Fallback + CRODE Integrations (Months 7–9)

Survive infrastructure collapse and plug into the rest of CRODE.

- ⬜ Starlink / Kuiper API integration
- ⬜ LoRa mesh controller + incentive model
- ⬜ Crovi VDI integration — auto-apply Warren privacy policies
- ⬜ Thump workload-relocation network sync

**Deliverables**
- Auto-failover demo (primary → satellite)
- Crovi plugin: transparent per-desktop privacy policies

---

## Phase 4 — GA + Horizontal Expansion (Months 10–12+)

- ⬜ Production mainnet deployment + hardening
- ⬜ Warren DNS — name resolution over the Warren network
- ⬜ Warren Email — SMTP/IMAP over Warren
- ⬜ Warren Storage — object storage over Warren

---

## Non-Goals

Warren is a network layer, not an application suite. See
[`DESIGN.md` § Scope & Non-Goals](../DESIGN.md) for the full list — notably it is
not a coin, not a general-purpose blockchain, and does not custody user funds
beyond the bandwidth-settlement contract.

---

## Ecosystem Alignment

Warren is the network substrate for the CRODE no-log line — Crovi (secure VDI),
Thump (infrastructure protection), and Lumra (censorship-interference analysis).
Lumra's analytics consume the Independence Logger's aggregate, opt-in statistics.
