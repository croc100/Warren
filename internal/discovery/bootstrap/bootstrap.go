// Package bootstrap resolves the initial set of Warren bridge nodes a client
// can connect to. This is the L0 layer: everything else (protocol camouflage,
// routing, payment, auth) is moot if a client can't find a single reachable
// node in the first place, and it's moot twice over if that discovery step
// itself is a single centralized endpoint a censor can block.
//
// The design principle is the same one Tor bridges use: never rely on one
// channel. A Resolver here is one channel; Multi combines several so that
// blocking any single one doesn't take down discovery entirely.
package bootstrap

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// Bridge is a single reachable Warren relay a client can dial through the
// transport package's camouflage layer.
type Bridge struct {
	Addr        string // host:port
	FallbackSNI string // the real site this bridge borrows a TLS identity from

	// PublicKeyHex is the relay's long-term X25519 identity key, hex-encoded
	// (64 characters). A client needs it to authenticate itself to that relay
	// and to derive a session key, and it is per-relay rather than shared, so
	// learning one bridge's key gives an adversary nothing about any other.
	PublicKeyHex string

	// Expires is the expiry of the signed descriptor this bridge came from,
	// and Stale reports that the expiry has passed. Stale bridges are returned
	// rather than dropped — they may still work, and a client with only stale
	// bridges is in a "discovery is stale" state, not a "no bridges" state —
	// but fresh ones are preferred (see Multi.Resolve).
	Expires time.Time
	Stale   bool
}

func (b Bridge) String() string {
	return fmt.Sprintf("%s|%s|%s", b.Addr, b.FallbackSNI, b.PublicKeyHex)
}

// ParseBridge parses the "addr|sni|pubkey" wire format used by both the DNS TXT
// and file-based resolvers below. All three fields are required: a bridge
// without its identity key is unusable, and silently accepting one would push
// the failure to dial time, where it looks like censorship rather than a
// malformed descriptor.
func ParseBridge(s string) (Bridge, error) {
	parts := strings.Split(strings.TrimSpace(s), "|")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return Bridge{}, fmt.Errorf("bootstrap: malformed bridge line %q, want \"addr|sni|pubkey\"", s)
	}
	key, err := hex.DecodeString(parts[2])
	if err != nil || len(key) != publicKeyLen {
		return Bridge{}, fmt.Errorf("bootstrap: bridge %q: public key must be %d hex chars", parts[0], publicKeyLen*2)
	}
	return Bridge{Addr: parts[0], FallbackSNI: parts[1], PublicKeyHex: parts[2]}, nil
}

// publicKeyLen is the length of an X25519 identity key in bytes.
const publicKeyLen = 32

// Resolver is one independent discovery channel.
type Resolver interface {
	// Name identifies the channel for logging/diagnostics.
	Name() string
	Resolve(ctx context.Context) ([]Bridge, error)
}

// StaticResolver returns a fixed, compiled-in bridge list. This is the
// resolver of last resort: it can't be blocked by taking down a server, but
// it also can't be updated without shipping a new client build, so it exists
// only to guarantee bootstrap never fails completely on a fresh install.
//
// It takes no trust anchor because it needs none: these bridges arrived inside
// the client binary, so whatever assurance the release artifact has is exactly
// the assurance they have. Every other resolver reads from a channel a censor
// can influence, and therefore requires signed descriptors.
type StaticResolver struct {
	Bridges []Bridge
}

func (s StaticResolver) Name() string { return "static" }

func (s StaticResolver) Resolve(ctx context.Context) ([]Bridge, error) {
	if len(s.Bridges) == 0 {
		return nil, errors.New("bootstrap: static resolver has no compiled-in bridges")
	}
	return s.Bridges, nil
}

// FileResolver reads signed bridge descriptors from a local file, one per line.
// This is how out-of-band-distributed bridges (shared via encrypted messaging,
// an email autoresponder, a printed page — the same pattern Tor bridges use)
// reach a client: the distribution mechanism is outside this package's concern,
// but once a user has saved a descriptor to disk, this resolver reads it.
//
// Anchors is required. A file is exactly the channel where a censor's copy of a
// "bridge list" is cheapest to circulate, so an unsigned line is not accepted
// at all — failing closed here is what makes a hostile channel a denial of
// service rather than a redirection.
type FileResolver struct {
	Path    string
	Anchors [][]byte
}

func (f FileResolver) Name() string { return "file:" + f.Path }

func (f FileResolver) Resolve(ctx context.Context) ([]Bridge, error) {
	if len(f.Anchors) == 0 {
		return nil, fmt.Errorf("bootstrap: %s: %w", f.Path, ErrNoTrustAnchor)
	}
	data, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: read bridge file: %w", err)
	}

	var bridges []Bridge
	var rejected int
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		d, err := VerifyDescriptor(line, f.Anchors, time.Now())
		if err != nil {
			rejected++ // skip a bad descriptor rather than failing the whole file
			continue
		}
		bridges = append(bridges, d.Bridges...)
	}
	if len(bridges) == 0 {
		return nil, fmt.Errorf("bootstrap: %s contained no verifiable bridge descriptors (%d rejected)", f.Path, rejected)
	}
	return bridges, nil
}

// LookupTXTFunc matches net.Resolver.LookupTXT's signature, injectable so
// DNSResolver is testable without a real DNS server.
type LookupTXTFunc func(ctx context.Context, name string) ([]string, error)

// DNSResolver resolves bridges from TXT records, queried through a specific
// upstream (a specific DoH/DoT endpoint or a specific system resolver). Using
// several DNSResolvers against different upstreams (see Multi) means no
// single DNS operator blocking or lying about one record takes discovery
// down — the same logic that makes DNS-over-multiple-resolvers robust against
// a single censored resolver.
type DNSResolver struct {
	Domain    string // e.g. "_warren-bridges.example.org"
	LookupTXT LookupTXTFunc

	// Anchors verifies the descriptors in the TXT records. Required: DNS is
	// the easiest channel of all to tamper with, on the path or at the
	// resolver, and a signature is the only thing that makes an answer from an
	// untrusted resolver usable.
	Anchors [][]byte
}

func (d DNSResolver) Name() string { return "dns:" + d.Domain }

func (d DNSResolver) Resolve(ctx context.Context) ([]Bridge, error) {
	if d.LookupTXT == nil {
		return nil, errors.New("bootstrap: DNSResolver has no LookupTXT configured")
	}
	if len(d.Anchors) == 0 {
		return nil, fmt.Errorf("bootstrap: %s: %w", d.Domain, ErrNoTrustAnchor)
	}
	records, err := d.LookupTXT(ctx, d.Domain)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: TXT lookup for %s: %w", d.Domain, err)
	}

	var bridges []Bridge
	var rejected int
	for _, r := range records {
		// Each record is a self-contained descriptor, so DNS's lack of
		// ordering guarantees doesn't matter and a single tampered record
		// costs only itself.
		desc, err := VerifyDescriptor(r, d.Anchors, time.Now())
		if err != nil {
			rejected++
			continue
		}
		bridges = append(bridges, desc.Bridges...)
	}
	if len(bridges) == 0 {
		return nil, fmt.Errorf("bootstrap: %s returned no verifiable bridge descriptors (%d rejected)", d.Domain, rejected)
	}
	return bridges, nil
}

// Multi queries every configured Resolver and merges whatever succeeds. It
// deliberately does not stop at the first success: combining results from
// every channel that responds maximizes the bridge pool (more endpoints,
// harder to enumerate and block) rather than depending on the first channel
// tried being both reachable and not itself compromised/monitored.
type Multi struct {
	Resolvers []Resolver
}

// Result reports what each channel returned, so callers/operators can see
// which discovery channels are currently blocked in a given region.
type Result struct {
	Channel string
	Bridges []Bridge
	Err     error

	// Stale is true when the channel answered but every bridge it returned
	// came from an expired descriptor. That is a distinct operational state
	// from a blocked channel: the channel works, its publisher has gone quiet
	// (or the client's clock is wrong), and the addresses may still be good.
	Stale bool
}

// Resolve tries all channels concurrently and returns the deduplicated union
// of every bridge any channel returned, plus a per-channel report. An error
// is returned only if every channel failed — a partial result (some channels
// blocked, others not) is exactly the scenario this design exists for.
func (m Multi) Resolve(ctx context.Context) ([]Bridge, []Result, error) {
	results := make([]Result, len(m.Resolvers))
	done := make(chan int, len(m.Resolvers))

	for i, r := range m.Resolvers {
		go func(i int, r Resolver) {
			bridges, err := r.Resolve(ctx)
			results[i] = Result{Channel: r.Name(), Bridges: bridges, Err: err}
			done <- i
		}(i, r)
	}
	for range m.Resolvers {
		<-done
	}

	seen := make(map[string]int) // addr -> index into merged
	var merged []Bridge
	successCount := 0
	for i, res := range results {
		if res.Err != nil {
			continue
		}
		successCount++

		stale := len(res.Bridges) > 0
		for _, b := range res.Bridges {
			if !b.Stale {
				stale = false
			}
			if at, ok := seen[b.Addr]; ok {
				// The same relay can arrive from several channels. Keep the
				// copy from the freshest descriptor: a stale channel must not
				// be able to downgrade what a current one said.
				if merged[at].Stale && !b.Stale || b.Expires.After(merged[at].Expires) {
					merged[at] = b
				}
				continue
			}
			seen[b.Addr] = len(merged)
			merged = append(merged, b)
		}
		results[i].Stale = stale
	}

	if successCount == 0 {
		return nil, results, errors.New("bootstrap: every discovery channel failed")
	}

	// Fresh bridges first, so a caller that just takes the head of the list
	// gets a current one and only falls back to stale addresses when that is
	// all discovery could produce.
	sort.SliceStable(merged, func(i, j int) bool { return !merged[i].Stale && merged[j].Stale })
	return merged, results, nil
}
