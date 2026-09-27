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

	"github.com/croc100/warren/internal/network/transport"
)

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:8443", "address to accept connections on")
	fallbackAddr := flag.String("fallback-addr", "", "real host:port to splice non-Warren connections to (required)")
	fallbackSNI := flag.String("fallback-sni", "", "hostname the disguised ClientHello claims to be (required)")
	keyFile := flag.String("identity-file", "", "path to a file containing this relay's X25519 identity key (64 hex chars); if empty, reads WARREN_RELAY_KEY_HEX")
	genKey := flag.Bool("genkey", false, "generate a relay identity key pair, print it, and exit")
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
		os.Exit(2)
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

	cfg := transport.Config{ServerPrivateKey: identity, FallbackSNI: *fallbackSNI, FallbackAddr: *fallbackAddr}

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
