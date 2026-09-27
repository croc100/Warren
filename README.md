# Warren

**A censorship-resistant network transport.** When the network itself is trying to
stop you from connecting at all, Warren is what still gets a connection through.

It is the network layer for the CRODE no-log line — Crovi (secure VDI), Thump
(infrastructure protection), Lumra (censorship-interference analysis) — and is
designed to be useful on its own.

---

## Status: pre-alpha, and honest about it

| | |
|---|---|
| **Works today** | Bridge discovery, signed descriptors, camouflaged transport with a hybrid post-quantum handshake, borrowed-site shape imitation, and a measurement harness that gates all of it |
| **Not started** | Relay pool and routing, exit policy, accounting, measurement analytics, satellite/mesh |
| **Code** | ~5,500 lines of Go, about half of it tests |
| **Safe to point at a censored network?** | **Not yet.** See [Where it stands](#where-it-stands) |

The full breakdown is [`DESIGN.md` §0](DESIGN.md#0-implementation-status). Nothing
in this README describes capability the repository does not have; where something
is planned, it says so.

---

## The problem Warren is built for

A state-scale censor does not mainly decode protocols. It blocks by IP and ASN
reputation, probes suspicious servers to see whether they behave like the site
they claim to be, and increasingly just allows a short list of domestic apps.
Commercial VPNs die within days of launch because their exits sit on a small,
enumerable set of datacenter ranges, however well the tunnel is disguised.

Warren's answer has two layers, and it is the combination that matters:

```
structural   a large pool of ordinary residential relays, churning as operators
             join and leave
             -> the censor's blocking cost scales with the number of households,
                not the number of VPN companies

per-session  each connection is, to a passive classifier and to an active prober,
             a real visit to a real site
             -> nothing to fingerprint, and nothing to confirm by probing
```

Neither half works alone. A perfect disguise on an enumerable set of IPs gets
blocked by address; a huge pool of relays running an obvious protocol gets blocked
by signature.

### What Warren is not

- **Not an anonymity network.** No sender–receiver unlinkability against an
  adversary who watches both ends. Compose it with a mixnet if that is your threat
  model.
- **Not identity protection.** It carries bytes; it cannot unlink an account you
  log into or a browser that is uniquely fingerprintable. Run a
  fingerprint-resistant client *over* Warren.
- **Not a coin.** The core protocol works with settlement disabled, and must
  continue to.
- **Not a defence against a shutdown.** When the fibre is administratively cut,
  Warren degrades to mesh and says so.

Full boundaries: [`DESIGN.md` §2](DESIGN.md#2-scope--non-goals).

---

## How a connection works

```
       client                                               relay            borrowed site
         │                                                    │                    │
         │ ClientHello — a current Chrome fingerprint,         │                    │
         │ hybrid X25519MLKEM768 key share, and a 16-byte      │                    │
         │ tag in session_id only this relay can recognise     │                    │
         ├───────────────────────────────────────────────────►│                    │
         │                                                    │                    │
         │            tag valid?                              │                    │
         │              no ──────────────────────────────────►│ spliced verbatim ──┤
         │                 (probe, or any non-Warren client)  │  real cert, real   │
         │                                                    │  response, real RST│
         │              yes                                   │                    │
         │◄───────────────────────────────────────────────────┤                    │
         │ ServerHello with the ML-KEM ciphertext, CCS, then   │                    │
         │ a flight whose record sizes are this site's own     │                    │
         │ measured certificate flight, carrying Warren's      │                    │
         │ key confirmation                                   │                    │
         │                                                    │                    │
         ├──► CCS + a Finished-sized confirmation             │                    │
         │◄── session-ticket-shaped records                   │                    │
         │                                                    │                    │
         │══════ application data in TLS-shaped records ══════│                    │
```

Three properties fall out of this:

**Probing costs the censor nothing and gains it nothing.** An unauthenticated
connection is spliced byte-for-byte to the real site, so a prober gets that site's
genuine certificate chain, genuine content, and genuine TCP teardown — because
that is literally what answered. A replayed ClientHello gets the same treatment,
so one recording cannot confirm a relay either.

**The handshake is post-quantum and forward secret.** Three secrets feed the
session key: ML-KEM-768 encapsulation (recorded traffic stays unreadable later),
ephemeral X25519 (the keys are gone when the connection ends), and an exchange
with the relay's long-term identity key (only the intended relay can recognise the
tag). There is no shared secret distributed to clients — they hold only a relay's
public key — so a compromised client tells an adversary nothing about any other
session.

**The disguise is measured, not assumed.** A relay profiles the site it borrows
from and replays that site's record shape, because how a TLS server's flight looks
is a property of its certificate chain and its TLS stack: Go emits one record per
handshake message, OpenSSL coalesces several, chains differ by kilobytes. A
hardcoded pad would make every relay look like the same server that doesn't exist.

Details and known gaps: [`docs/protocol/reality-transport.md`](docs/protocol/reality-transport.md).

---

## Try it

Four terminals. There is no installer, no package, and no binary release.

```bash
git clone https://github.com/croc100/warren.git
cd warren
go test ./... -race
./hack/smoke.sh    # or: make smoke — the whole flow below, automated
```

**1. A stand-in "real site" for the relay to borrow.** In production this is an
actual popular HTTPS site; locally, any TLS server will do:

```bash
openssl req -x509 -newkey rsa:2048 -keyout k.pem -out c.pem -days 1 -nodes -subj /CN=www.example.com
python3 -c "
import http.server, ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain('c.pem','k.pem')
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
srv = http.server.HTTPServer(('127.0.0.1',9443), http.server.SimpleHTTPRequestHandler)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True); srv.serve_forever()"
```

**2. Check the site is usable as cover, then run a relay.** The check is a real
operator step, not a formality: a site that does not negotiate a hybrid
post-quantum key exchange answers with a ServerHello hundreds of bytes smaller
than Warren's, which would make the first server packet a giveaway.

```bash
go run ./cmd/node -profile-only -profile-insecure \
  -fallback-addr=127.0.0.1:9443 -fallback-sni=www.example.com

eval "$(go run ./cmd/node -genkey)"   # WARREN_RELAY_KEY_HEX + WARREN_RELAY_PUBKEY_HEX
go run ./cmd/node -listen=127.0.0.1:8443 \
  -profile-insecure -fallback-addr=127.0.0.1:9443 -fallback-sni=www.example.com
```

**3. Publish a signed bridge descriptor and connect.** The signature is what makes
a hostile discovery channel a denial of service rather than a redirection:

```bash
eval "$(go run ./cmd/bootstrap -genkey)"   # anchor + signing key
go run ./cmd/bootstrap -sign -bridge="127.0.0.1:8443|www.example.com|$WARREN_RELAY_PUBKEY_HEX" > bridges.txt
go run ./cmd/bootstrap -verify -file=bridges.txt

go run ./cmd/cli -bridge-file=bridges.txt -message="hello from behind the firewall"
```

**4. Be the censor.** Probe the relay and the site it borrows from, and see
whether anything separates them:

```bash
go run ./cmd/probe -relay=127.0.0.1:8443 -site=127.0.0.1:9443 \
  -sni=www.example.com -relay-key=$WARREN_RELAY_PUBKEY_HEX
```

```
probe                  warren relay                       real site                          verdict
tls-handshake          ok=true ver=1.3 cert=22ed4e978ab9… ok=true ver=1.3 cert=22ed4e978ab9… indistinguishable
plaintext-http         replied=false prefix="" err=reset  replied=false prefix="" err=reset  indistinguishable
replayed-hello         replied=true kind=tls:server_hell… replied=true kind=tls:server_hell… indistinguishable
…
server flight after CCS       1196 B in 4 records   1196 B in 4 records   ok
post-handshake server records  500 B in 2 records    500 B in 2 records   ok
ServerHello size              1210 B                1210 B               ok

PASS: nothing measured here separates the relay from www.example.com
```

Things worth trying: edit one byte of `bridges.txt` (the client refuses it before
dialing anything), pass the wrong `-relay-key` to the client (it gets the real
site, exactly like a probe), or `curl -v --http1.0 http://127.0.0.1:8443/`.

---

## Where it stands

`cmd/probe` is the gate, and it exits non-zero on any distinguisher, so this table
is measured rather than claimed:

| Adversary move | Warren's answer | State |
|---|---|---|
| Payload-signature DPI | Valid TLS 1.3 records throughout, current browser fingerprint | measured |
| Active probing | Unauthenticated, wrong-key and replayed connections are spliced to the real site | measured |
| Certificate inspection by a prober | The prober gets the borrowed site's genuine chain | measured |
| Handshake-shape classification | The relay replays its borrowed site's measured record shape, including session tickets | measured |
| TCP teardown fingerprinting | An upstream reset is mirrored rather than turned into a clean close | measured |
| Recording now to decrypt later | Hybrid X25519 + ML-KEM-768, forward secret per connection | implemented |
| Hostile discovery channel | Signed, expiring descriptors covering each relay's identity key; resolvers fail closed without an anchor | implemented |
| **A censor that runs a Warren client** | Nothing here stops it: it holds a valid tag and can see the flight is synthetic | **accepted gap** — it can enumerate bridges anyway, which is an L2 problem |
| **TLS-intercepting middlebox (a state CA)** | A real session survives interception; Warren's would break | **open** — [ADR 0001](docs/adr/0001-borrowed-tls-handshake.md) Stage B |
| **Statistical flow classification of traffic** | Handshake shape matches; *data* shape does not | **not started** — [`DESIGN.md` §6.4](DESIGN.md#64-traffic-shaping-with-a-cost-model) |
| **Relay-pool enumeration** | No rotating subsets, no rate limiting | **not started** |

So: the handshake stands up to measurement, and everything after it does not yet.
Do not point this at a censored network expecting it to hold — the traffic-shape
work and the relay pool are both unbuilt, and a real deployment needs both.

---

## Design documents

- [`DESIGN.md`](DESIGN.md) — threat environment, layer specs, crypto inventory, and
  a table of decisions that were dropped and why
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — slices, each with a falsifiable gate
  instead of a date
- [`docs/adr/0001-borrowed-tls-handshake.md`](docs/adr/0001-borrowed-tls-handshake.md)
  — how L1's mimicry gap is being closed, and why not by importing xray-core
- [`docs/protocol/reality-transport.md`](docs/protocol/reality-transport.md) —
  L0/L1 implementation notes, bugs found on the way, known gaps
- [`docs/CHANGELOG.md`](docs/CHANGELOG.md)

## Repository map

```
cmd/node        relay: serves camouflaged connections, profiles its borrowed site
cmd/cli         demo client: resolves a bridge, dials it, echoes a message
cmd/bootstrap   bridge descriptors: -genkey, -sign, -verify
cmd/probe       the gate: probes a relay against the site it borrows from
internal/network/transport   camouflage, hybrid handshake, shaped flight
internal/network/probe       active probes and record-shape comparison
internal/network/tlsrec      shared TLS record-layer vocabulary
internal/discovery/bootstrap discovery channels and signed descriptors
```

That is the whole tree. The aspirational directory skeleton this repository used to
carry — placeholders for a marketplace, satellite adapters, contracts, dashboards —
was deleted: `DESIGN.md` says what will live where, and a tree that implies
capability is its own kind of dishonesty.

## Contributing

The useful contributions right now are adversarial: find something that separates
a relay from the site it borrows, break the bootstrap logic, or poke holes in the
threat model. If you find a distinguisher `cmd/probe` misses, that is the most
valuable bug report this project can get.

See [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) and the open problems in
[`DESIGN.md` §15](DESIGN.md#15-open-problems).

## License

AGPL-3.0, commercial licensing available — see [LICENSE](LICENSE).

## Citation

```bibtex
@software{warren2026,
  title={Warren: a censorship-resistant network transport},
  author={croc100},
  year={2026},
  url={https://github.com/croc100/warren}
}
```
