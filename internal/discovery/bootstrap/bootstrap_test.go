package bootstrap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestParseBridge(t *testing.T) {
	b, err := ParseBridge("203.0.113.5:443|www.example.com|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if b.Addr != "203.0.113.5:443" || b.FallbackSNI != "www.example.com" || b.PublicKeyHex != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("got %+v", b)
	}
	if _, err := ParseBridge("not-a-valid-line"); err == nil {
		t.Fatal("expected error for malformed line")
	}
}

func TestFileResolver_SkipsMalformedLinesButKeepsGood(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bridges.txt")
	content := "# comment\n\n203.0.113.5:443|www.example.com|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\ngarbage-line\n203.0.113.9:443|no.key.example.net\n198.51.100.9:8443|cdn.example.net|bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	r := FileResolver{Path: path}
	bridges, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(bridges) != 2 {
		t.Fatalf("got %d bridges, want 2: %+v", len(bridges), bridges)
	}
}

func TestFileResolver_MissingFile(t *testing.T) {
	r := FileResolver{Path: "/nonexistent/path/bridges.txt"}
	if _, err := r.Resolve(context.Background()); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestDNSResolver_ParsesTXTRecords(t *testing.T) {
	r := DNSResolver{
		Domain: "_warren-bridges.example.org",
		LookupTXT: func(ctx context.Context, name string) ([]string, error) {
			return []string{
				"203.0.113.5:443|www.example.com|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"not-valid",
				"198.51.100.9:8443|cdn.example.net|bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			}, nil
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
	r := DNSResolver{
		Domain: "_warren-bridges.example.org",
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
	blockedDNS := DNSResolver{
		Domain: "_warren-bridges.blocked.example",
		LookupTXT: func(ctx context.Context, name string) ([]string, error) {
			return nil, errors.New("simulated: censored in-region")
		},
	}
	workingDNS := DNSResolver{
		Domain: "_warren-bridges.working.example",
		LookupTXT: func(ctx context.Context, name string) ([]string, error) {
			return []string{"203.0.113.5:443|www.example.com|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, nil
		},
	}
	static := StaticResolver{Bridges: []Bridge{
		{Addr: "203.0.113.5:443", FallbackSNI: "www.example.com"}, // duplicate of workingDNS's entry
		{Addr: "192.0.2.77:443", FallbackSNI: "cdn.example.net"},
	}}
	missingFile := FileResolver{Path: "/nonexistent/bridges.txt"}

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

func TestMulti_AllChannelsFailing(t *testing.T) {
	m := Multi{Resolvers: []Resolver{
		FileResolver{Path: "/nonexistent/a.txt"},
		FileResolver{Path: "/nonexistent/b.txt"},
	}}
	if _, _, err := m.Resolve(context.Background()); err == nil {
		t.Fatal("expected error when every channel fails")
	}
}
