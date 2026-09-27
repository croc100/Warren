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
	"strings"
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

// FileResolver reads a bridge list from a local file, one "addr|sni|pubkey" per
// line. This is how out-of-band-distributed bridges (shared via encrypted
// messaging, email autoresponder, etc. — the same pattern Tor bridges use)
// reach a client: the distribution mechanism is outside this package's
// concern, but once a user has saved a list to disk, this resolver reads it.
type FileResolver struct {
	Path string
}

func (f FileResolver) Name() string { return "file:" + f.Path }

func (f FileResolver) Resolve(ctx context.Context) ([]Bridge, error) {
	data, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: read bridge file: %w", err)
	}
	var bridges []Bridge
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		b, err := ParseBridge(line)
		if err != nil {
			continue // skip malformed lines rather than failing the whole file
		}
		bridges = append(bridges, b)
	}
	if len(bridges) == 0 {
		return nil, fmt.Errorf("bootstrap: %s contained no valid bridge lines", f.Path)
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
}

func (d DNSResolver) Name() string { return "dns:" + d.Domain }

func (d DNSResolver) Resolve(ctx context.Context) ([]Bridge, error) {
	if d.LookupTXT == nil {
		return nil, errors.New("bootstrap: DNSResolver has no LookupTXT configured")
	}
	records, err := d.LookupTXT(ctx, d.Domain)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: TXT lookup for %s: %w", d.Domain, err)
	}
	var bridges []Bridge
	for _, r := range records {
		b, err := ParseBridge(r)
		if err != nil {
			continue
		}
		bridges = append(bridges, b)
	}
	if len(bridges) == 0 {
		return nil, fmt.Errorf("bootstrap: %s returned no valid bridge records", d.Domain)
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

	seen := make(map[string]struct{})
	var merged []Bridge
	successCount := 0
	for _, res := range results {
		if res.Err != nil {
			continue
		}
		successCount++
		for _, b := range res.Bridges {
			if _, ok := seen[b.Addr]; ok {
				continue
			}
			seen[b.Addr] = struct{}{}
			merged = append(merged, b)
		}
	}

	if successCount == 0 {
		return nil, results, errors.New("bootstrap: every discovery channel failed")
	}
	return merged, results, nil
}
