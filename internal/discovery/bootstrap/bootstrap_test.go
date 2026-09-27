package bootstrap

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const (
	relayKeyA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	relayKeyB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// testAnchor returns a signing key plus the trust anchor a client would ship.
func testAnchor(t *testing.T) (ed25519.PrivateKey, [][]byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate anchor: %v", err)
	}
	return priv, [][]byte{pub}
}

func signBridges(t *testing.T, key ed25519.PrivateKey, ttl time.Duration, bridges ...Bridge) string {
	t.Helper()
	now := time.Now()
	line, err := SignDescriptor(key, now.Add(-time.Minute), now.Add(ttl), bridges)
	if err != nil {
		t.Fatalf("sign descriptor: %v", err)
	}
	return line
}

func TestParseBridge(t *testing.T) {
	b, err := ParseBridge("203.0.113.5:443|www.example.com|" + relayKeyA)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if b.Addr != "203.0.113.5:443" || b.FallbackSNI != "www.example.com" || b.PublicKeyHex != relayKeyA {
		t.Fatalf("got %+v", b)
	}
	if _, err := ParseBridge("not-a-valid-line"); err == nil {
		t.Fatal("expected error for malformed line")
	}
	if _, err := ParseBridge("203.0.113.5:443|www.example.com"); err == nil {
		t.Fatal("expected error for a bridge with no relay key")
	}
}

func TestFileResolver_SkipsUnverifiableDescriptorsButKeepsGood(t *testing.T) {
	key, anchors := testAnchor(t)
	other, _ := testAnchor(t)

	good := signBridges(t, key, time.Hour,
		Bridge{Addr: "203.0.113.5:443", FallbackSNI: "www.example.com", PublicKeyHex: relayKeyA},
		Bridge{Addr: "198.51.100.9:8443", FallbackSNI: "cdn.example.net", PublicKeyHex: relayKeyB})
	// A descriptor signed by someone else: exactly what a censor circulating
	// its own "bridge list" through a messaging channel would look like.
	hostile := signBridges(t, other, time.Hour,
		Bridge{Addr: "192.0.2.66:443", FallbackSNI: "trap.example", PublicKeyHex: relayKeyA})

	dir := t.TempDir()
	path := filepath.Join(dir, "bridges.txt")
	content := "# comment\n\n" + good + "\ngarbage-line\n" +
		"203.0.113.9:443|unsigned.example.net|" + relayKeyA + "\n" + hostile + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	bridges, err := FileResolver{Path: path, Anchors: anchors}.Resolve(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(bridges) != 2 {
		t.Fatalf("got %d bridges, want the 2 from the verifiable descriptor: %+v", len(bridges), bridges)
	}
	for _, b := range bridges {
		if b.Addr == "192.0.2.66:443" || b.FallbackSNI == "unsigned.example.net" {
			t.Fatalf("accepted a bridge that was not covered by a trusted signature: %+v", b)
		}
	}
}

// TestFileResolver_FailsClosedWithoutAnchor pins the decision that an unsigned
// channel is not usable at all: a file is the cheapest place for a censor to
// circulate its own list, so "no anchor configured" must be an error rather
// than a silent downgrade to trusting the file.
func TestFileResolver_FailsClosedWithoutAnchor(t *testing.T) {
	key, _ := testAnchor(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "bridges.txt")
	line := signBridges(t, key, time.Hour, Bridge{Addr: "203.0.113.5:443", FallbackSNI: "www.example.com", PublicKeyHex: relayKeyA})
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := FileResolver{Path: path}.Resolve(context.Background())
	if !errors.Is(err, ErrNoTrustAnchor) {
		t.Fatalf("got %v, want ErrNoTrustAnchor", err)
	}
}

func TestFileResolver_MissingFile(t *testing.T) {
	_, anchors := testAnchor(t)
	r := FileResolver{Path: "/nonexistent/path/bridges.txt", Anchors: anchors}
	if _, err := r.Resolve(context.Background()); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestDNSResolver_VerifiesTXTRecords(t *testing.T) {
	key, anchors := testAnchor(t)
	good := signBridges(t, key, time.Hour, Bridge{Addr: "203.0.113.5:443", FallbackSNI: "www.example.com", PublicKeyHex: relayKeyA})
	second := signBridges(t, key, time.Hour, Bridge{Addr: "198.51.100.9:8443", FallbackSNI: "cdn.example.net", PublicKeyHex: relayKeyB})
	// One record tampered with in flight: a single byte flipped inside the
	// signed payload. It must cost only itself, not the whole answer.
	tampered := []byte(good)
	tampered[len(descriptorVersion)+len(";issued=")+1]++

	r := DNSResolver{
		Domain:  "_warren-bridges.example.org",
		Anchors: anchors,
		LookupTXT: func(ctx context.Context, name string) ([]string, error) {
			return []string{good, "not-valid", string(tampered), second}, nil
		},
	}
	bridges, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(bridges) != 2 {
		t.Fatalf("got %d bridges, want 2", len(bridges))
	}
}

func TestDNSResolver_UpstreamFailure(t *testing.T) {
	_, anchors := testAnchor(t)
	r := DNSResolver{
		Domain:  "_warren-bridges.example.org",
		Anchors: anchors,
		LookupTXT: func(ctx context.Context, name string) ([]string, error) {
			return nil, errors.New("simulated: this resolver is blocked in-region")
		},
	}
	if _, err := r.Resolve(context.Background()); err == nil {
		t.Fatal("expected error propagated from upstream")
	}
}

// TestMulti_SurvivesPartialChannelFailure is the core property this package
// exists to provide: if some discovery channels are blocked/down and others
// aren't, the client still gets a usable, merged bridge set — not a hard
// failure — and duplicate bridges returned by multiple channels are merged,
// not doubled.
func TestMulti_SurvivesPartialChannelFailure(t *testing.T) {
	key, anchors := testAnchor(t)

	blockedDNS := DNSResolver{
		Domain:  "_warren-bridges.blocked.example",
		Anchors: anchors,
		LookupTXT: func(ctx context.Context, name string) ([]string, error) {
			return nil, errors.New("simulated: censored in-region")
		},
	}
	workingDNS := DNSResolver{
		Domain:  "_warren-bridges.working.example",
		Anchors: anchors,
		LookupTXT: func(ctx context.Context, name string) ([]string, error) {
			return []string{signBridges(t, key, time.Hour,
				Bridge{Addr: "203.0.113.5:443", FallbackSNI: "www.example.com", PublicKeyHex: relayKeyA})}, nil
		},
	}
	static := StaticResolver{Bridges: []Bridge{
		{Addr: "203.0.113.5:443", FallbackSNI: "www.example.com", PublicKeyHex: relayKeyA}, // duplicate of workingDNS's entry
		{Addr: "192.0.2.77:443", FallbackSNI: "cdn.example.net", PublicKeyHex: relayKeyB},
	}}
	missingFile := FileResolver{Path: "/nonexistent/bridges.txt", Anchors: anchors}

	m := Multi{Resolvers: []Resolver{blockedDNS, workingDNS, static, missingFile}}
	bridges, results, err := m.Resolve(context.Background())
	if err != nil {
		t.Fatalf("expected overall success despite partial failures, got: %v", err)
	}
	if len(bridges) != 2 {
		t.Fatalf("got %d merged bridges, want 2 (deduplicated): %+v", len(bridges), bridges)
	}

	failCount := 0
	for _, r := range results {
		if r.Err != nil {
			failCount++
		}
	}
	if failCount != 2 {
		t.Fatalf("expected exactly 2 failed channels (blockedDNS, missingFile), got %d", failCount)
	}
}

// TestMulti_PrefersFreshOverStale covers the case where discovery has gone
// quiet: an expired descriptor still yields bridges (they may well work, and
// stranding the client is exactly what a censor blocking every channel for a
// week wants), but a current descriptor for the same relay wins, and the
// channel serving only expired data is reported as stale rather than healthy.
func TestMulti_PrefersFreshOverStale(t *testing.T) {
	key, anchors := testAnchor(t)

	expired, err := SignDescriptor(key, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour),
		[]Bridge{
			{Addr: "203.0.113.5:443", FallbackSNI: "old.example.com", PublicKeyHex: relayKeyA},
			{Addr: "192.0.2.99:443", FallbackSNI: "only.here.example", PublicKeyHex: relayKeyB},
		})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	fresh := signBridges(t, key, time.Hour,
		Bridge{Addr: "203.0.113.5:443", FallbackSNI: "current.example.com", PublicKeyHex: relayKeyA})

	staleChannel := DNSResolver{Domain: "stale.example", Anchors: anchors,
		LookupTXT: func(context.Context, string) ([]string, error) { return []string{expired}, nil }}
	freshChannel := DNSResolver{Domain: "fresh.example", Anchors: anchors,
		LookupTXT: func(context.Context, string) ([]string, error) { return []string{fresh}, nil }}

	bridges, results, err := Multi{Resolvers: []Resolver{staleChannel, freshChannel}}.Resolve(context.Background())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(bridges) != 2 {
		t.Fatalf("got %d bridges, want 2 (stale-only bridges are kept): %+v", len(bridges), bridges)
	}
	if bridges[0].Stale {
		t.Fatalf("head of the list is stale: %+v", bridges)
	}
	for _, b := range bridges {
		if b.Addr == "203.0.113.5:443" && b.FallbackSNI != "current.example.com" {
			t.Fatalf("a stale descriptor overrode a current one: %+v", b)
		}
	}
	if !results[0].Stale {
		t.Fatal("channel serving only expired descriptors was not reported stale")
	}
	if results[1].Stale {
		t.Fatal("channel serving a current descriptor was reported stale")
	}
}

func TestMulti_AllChannelsFailing(t *testing.T) {
	_, anchors := testAnchor(t)
	m := Multi{Resolvers: []Resolver{
		FileResolver{Path: "/nonexistent/a.txt", Anchors: anchors},
		FileResolver{Path: "/nonexistent/b.txt", Anchors: anchors},
	}}
	if _, _, err := m.Resolve(context.Background()); err == nil {
		t.Fatal("expected error when every channel fails")
	}
}
