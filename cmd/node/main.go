// Command node runs a minimal Warren relay: it listens for camouflaged
// connections (internal/network/transport), echoes application data back to
// authenticated Warren clients, and transparently splices anything else to a
// real fallback site. This is the L0+L1 proof of concept — no marketplace,
// payment, or exit policy wired in yet.
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/croc100/warren/internal/network/transport"
)

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:8443", "address to accept connections on")
	fallbackAddr := flag.String("fallback-addr", "", "real host:port to splice non-Warren connections to (required)")
	fallbackSNI := flag.String("fallback-sni", "", "hostname the disguised ClientHello claims to be (required)")
	keyFile := flag.String("identity-file", "", "path to a file containing this relay's X25519 identity key (64 hex chars); if empty, reads WARREN_RELAY_KEY_HEX")
	genKey := flag.Bool("genkey", false, "generate a relay identity key pair, print it, and exit")
	profileOnly := flag.Bool("profile-only", false, "measure the fallback site's TLS handshake shape, print it, and exit")
	profileRefresh := flag.Duration("profile-refresh", 30*time.Minute, "how often to re-measure the fallback site (its certificate rotates)")
	profileInsecure := flag.Bool("profile-insecure", false, "skip certificate verification while measuring the fallback site (local demos only)")
	flag.Parse()

	if *genKey {
		priv, pub, err := transport.GenerateServerIdentity()
		if err != nil {
			log.Fatalf("node: %v", err)
		}
		fmt.Printf("WARREN_RELAY_KEY_HEX=%s\n", hex.EncodeToString(priv))
		fmt.Printf("relay public key (publish this with the bridge address): %s\n", hex.EncodeToString(pub))
		return
	}

	if *fallbackAddr == "" || *fallbackSNI == "" {
		fmt.Fprintln(os.Stderr, "usage: node -fallback-addr=host:port -fallback-sni=example.com [-identity-file=path]")
		fmt.Fprintln(os.Stderr, "       node -genkey")
		fmt.Fprintln(os.Stderr, "       node -profile-only -fallback-addr=host:port -fallback-sni=example.com")
		os.Exit(2)
	}

	profileOpts := transport.ProfileOptions{SkipVerify: *profileInsecure}

	// Measure the borrowed site before serving anyone. A relay answers its
	// ServerHello with a flight shaped like that site's certificate messages, and
	// it cannot invent those sizes: they are a property of the site's certificate
	// chain and TLS stack. Without a measurement there is nothing to imitate, so
	// this is fatal rather than a warning.
	flight, err := transport.ProfileSite(context.Background(), *fallbackAddr, *fallbackSNI, profileOpts)
	if err != nil {
		log.Fatalf("node: could not measure fallback site %s (%s): %v\n"+
			"       the relay cannot imitate a site it has not seen; check the address, or pass -profile-insecure for a self-signed local site",
			*fallbackAddr, *fallbackSNI, err)
	}
	log.Printf("node: measured %s", flight)

	if err := flight.Validate(); err != nil {
		log.Fatalf("node: this site is not usable as a cover: %v\n"+
			"       Warren's ServerHello carries a hybrid post-quantum key share, so a site that negotiates\n"+
			"       something else answers with a ServerHello hundreds of bytes smaller — pairing with it would\n"+
			"       make the first server packet a giveaway. Pick a site that offers X25519MLKEM768.", err)
	}

	if *profileOnly {
		return
	}

	identity, err := loadIdentity(*keyFile)
	if err != nil {
		log.Fatalf("node: %v", err)
	}

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("node: listen %s: %v", *listenAddr, err)
	}
	log.Printf("node: listening on %s, camouflaged as %s, falling back to %s", *listenAddr, *fallbackSNI, *fallbackAddr)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var current transport.AtomicFlight
	current.Store(flight)
	go refreshProfile(ctx, &current, *fallbackAddr, *fallbackSNI, *profileRefresh, profileOpts)

	cfg := transport.Config{
		ServerPrivateKey: identity,
		FallbackSNI:      *fallbackSNI,
		FallbackAddr:     *fallbackAddr,
		FlightFunc:       current.Load,
	}

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	err = transport.Serve(ctx, ln, cfg, func(conn net.Conn) {
		defer conn.Close()
		log.Println("node: authenticated Warren client connected, echoing")
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if _, werr := conn.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	})
	if err != nil {
		log.Fatalf("node: serve: %v", err)
	}
}

// refreshProfile re-measures the borrowed site on a schedule. Certificates
// rotate every couple of months and TLS stacks get reconfigured, so a profile
// measured once at startup drifts away from the site it is supposed to imitate.
//
// A failed refresh keeps the last good profile rather than clearing it: a
// transient outage at the borrowed site should not take the relay down, and a
// slightly stale shape is far closer to the truth than no shape at all. A
// refresh that measures something unusable is discarded for the same reason.
func refreshProfile(
	ctx context.Context,
	current *transport.AtomicFlight,
	addr, sni string,
	every time.Duration,
	opts transport.ProfileOptions,
) {
	if every <= 0 {
		return
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		next, err := transport.ProfileSite(ctx, addr, sni, opts)
		if err != nil {
			log.Printf("node: re-measuring %s failed, keeping the previous shape: %v", sni, err)
			continue
		}
		if err := next.Validate(); err != nil {
			log.Printf("node: re-measured %s is unusable, keeping the previous shape: %v", sni, err)
			continue
		}
		if previous := current.Load(); previous == nil || previous.TotalServerFlight() != next.TotalServerFlight() {
			log.Printf("node: fallback site shape changed, now %s", next)
		}
		current.Store(next)
	}
}

// loadIdentity reads the relay's long-term X25519 private key. Unlike the
// pre-shared key this replaced, it is never distributed to clients: clients
// only ever see the corresponding public key, so a compromised client cannot
// impersonate the relay or read another client's session.
func loadIdentity(path string) ([]byte, error) {
	encoded := os.Getenv("WARREN_RELAY_KEY_HEX")
	source := "WARREN_RELAY_KEY_HEX"
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read identity file: %w", err)
		}
		encoded, source = string(data), path
	}
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, fmt.Errorf("no relay identity provided: pass -identity-file or set WARREN_RELAY_KEY_HEX (generate one with -genkey)")
	}
	key, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("%s must decode to 32 bytes, got %d", source, len(key))
	}
	return key, nil
}
