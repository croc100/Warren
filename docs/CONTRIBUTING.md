# Contributing

Warren is pre-alpha and its threat model is a state-scale adversary, so the most
valuable contribution is an attack, not a feature.

## What helps most

1. **A distinguisher `cmd/probe` misses.** Anything that separates a relay from
   the site it borrows — record sizes, timing, TCP behaviour, a probe we don't
   run, a TLS stack whose flight we imitate badly. If you can tell them apart,
   that is the single most useful bug report this project can get.
2. **A break in the bootstrap logic.** Descriptor parsing, signature verification,
   staleness handling, the behaviour when every channel is hostile at once.
3. **A hole in the threat model.** [`DESIGN.md` §15](../DESIGN.md#15-open-problems)
   lists what we know we haven't answered; the interesting reports are the ones
   that aren't on it.

Feature work above L1 is mostly not ready to be parallelised — see
[`docs/ROADMAP.md`](ROADMAP.md) for what is gated on what, and why the order is
what it is.

## Before you send a change

```bash
go test ./... -race
gofmt -l ./cmd ./internal     # must print nothing
go vet ./...
```

If you touched the transport, also run the gate against a real TLS site and paste
the output. The [README](../README.md#try-it) has a four-terminal setup; the short
version is that `cmd/probe` must still exit zero.

## Conventions

- **Tests are the argument.** A shaping or camouflage change is only believable
  with a measurement next to it, and a measurement that compares Warren against
  itself proves nothing. Compare against a real TLS session to the same site.
- **Prefer audited implementations for anything cryptographically deep**, and when
  you hand-roll something, record it as a gap rather than a feature.
- **Write down the cost.** Latency, bytes, battery, dollars. A defence whose
  overhead isn't written down is a defence that gets turned off in production.
- **Commit messages and code comments in English.** Subject in the imperative,
  body explaining *why* — the constraint that forced the change, not a restatement
  of the diff.
- **Document what you decided against.** `DESIGN.md` §14 and `docs/adr/` exist so
  the same option doesn't get re-litigated every quarter.

## Security issues

Do not open a public issue for something that would put users of a running relay
at risk. Mail the maintainer first.
