// Command cli is a minimal Warren client: it resolves a bridge via the L0
// bootstrap package, dials it through the L1 camouflage transport, and
// exercises a simple echo round-trip to prove the connection is genuinely
// authenticated and encrypted end-to-end. This is the demo/PoC client, not
// the eventual VDI-tunneling client.
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/croc100/warren/internal/discovery/bootstrap"
	"github.com/croc100/warren/internal/network/transport"
)

func main() {
	bridgeFile := flag.String("bridge-file", "", "path to a locally-distributed bridge list (out-of-band channel)")
	fallbackSNI := flag.String("fallback-sni", "", "override: hostname to present in the disguised ClientHello (required if not using -bridge-file)")
	addr := flag.String("addr", "", "override: bridge host:port to dial directly (required if not using -bridge-file)")
	relayKey := flag.String("relay-key", "", "override: the bridge's X25519 public key (64 hex chars); defaults to WARREN_RELAY_PUBKEY_HEX")
	anchorHex := flag.String("trust-anchor", "", "Ed25519 public key that bridge descriptors must be signed by (64 hex chars); defaults to WARREN_BRIDGE_ANCHOR_HEX")
	message := flag.String("message", "hello from a censored network", "test message to echo through the bridge")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	bridge, err := resolveBridge(ctx, *bridgeFile, *addr, *fallbackSNI, *relayKey, *anchorHex)
	if err != nil {
		log.Fatalf("cli: %v", err)
	}
	publicKey, err := hex.DecodeString(bridge.PublicKeyHex)
	if err != nil || len(publicKey) != 32 {
		log.Fatalf("cli: bridge public key must be 64 hex chars (got %q)", bridge.PublicKeyHex)
	}
	if bridge.Stale {
		// Worth saying out loud rather than failing: the descriptor's publisher
		// has gone quiet (or every channel is blocked), and these addresses may
		// still work. "Discovery is stale" is a different state from "no bridges".
		log.Printf("cli: warning: bridge came from a descriptor that expired %s — discovery is stale",
			bridge.Expires.UTC().Format(time.RFC3339))
	}
	log.Printf("cli: dialing bridge %s (camouflaged as %s)", bridge.Addr, bridge.FallbackSNI)

	conn, err := transport.Dial(ctx, bridge.Addr, transport.Config{
		ServerPublicKey: publicKey,
		FallbackSNI:     bridge.FallbackSNI,
	})
	if err != nil {
		log.Fatalf("cli: dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte(*message)); err != nil {
		log.Fatalf("cli: write: %v", err)
	}
	buf := make([]byte, len(*message))
	r := bufio.NewReader(conn)
	if _, err := r.Read(buf); err != nil {
		log.Fatalf("cli: read: %v", err)
	}
	fmt.Printf("echoed back: %s\n", buf)
}

func resolveBridge(ctx context.Context, bridgeFile, addr, sni, relayKey, anchorHex string) (bootstrap.Bridge, error) {
	if relayKey == "" {
		relayKey = os.Getenv("WARREN_RELAY_PUBKEY_HEX")
	}
	if addr != "" && sni != "" {
		// Explicit address and key: the operator is the trust anchor here, so
		// no descriptor signature is involved. Useful for a local demo, not
		// how a real client bootstraps.
		return bootstrap.Bridge{Addr: addr, FallbackSNI: sni, PublicKeyHex: relayKey}, nil
	}
	if bridgeFile == "" {
		return bootstrap.Bridge{}, fmt.Errorf("must pass either -bridge-file or both -addr and -fallback-sni")
	}
	if anchorHex == "" {
		anchorHex = os.Getenv("WARREN_BRIDGE_ANCHOR_HEX")
	}
	anchor, err := hex.DecodeString(strings.TrimSpace(anchorHex))
	if err != nil || len(anchor) != ed25519.PublicKeySize {
		return bootstrap.Bridge{}, fmt.Errorf("-trust-anchor must be %d hex chars: descriptors from a file are only usable if they are signed", ed25519.PublicKeySize*2)
	}
	m := bootstrap.Multi{Resolvers: []bootstrap.Resolver{
		bootstrap.FileResolver{Path: bridgeFile, Anchors: [][]byte{anchor}},
	}}
	bridges, results, err := m.Resolve(ctx)
	if err != nil {
		for _, r := range results {
			log.Printf("cli: discovery channel %s failed: %v", r.Channel, r.Err)
		}
		return bootstrap.Bridge{}, err
	}
	return bridges[0], nil
}
