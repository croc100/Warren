// Command bootstrap is the L0 discovery tool: it mints the trust anchor a
// client ships with, signs bridge descriptors for distribution over whatever
// out-of-band channels are available, and verifies a descriptor a user was
// handed.
//
// The signature is what makes a hostile discovery channel a denial of service
// instead of a redirection: a censor who controls a DNS answer or circulates
// its own "bridge list" cannot produce a descriptor that verifies, so it cannot
// steer a client onto a relay of its choosing.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/croc100/warren/internal/discovery/bootstrap"
)

type bridgeList []string

func (b *bridgeList) String() string     { return strings.Join(*b, ",") }
func (b *bridgeList) Set(v string) error { *b = append(*b, v); return nil }

func main() {
	log.SetFlags(0)

	genKey := flag.Bool("genkey", false, "generate a bridge-distribution trust anchor key pair and exit")
	sign := flag.Bool("sign", false, "sign a bridge descriptor")
	verify := flag.Bool("verify", false, "verify a bridge descriptor")

	keyHex := flag.String("key", "", "signing key, hex-encoded (-sign); prefix with @ to read from a file, or set WARREN_BRIDGE_KEY_HEX")
	anchorHex := flag.String("anchor", "", "trust anchor public key, hex-encoded (-verify); or set WARREN_BRIDGE_ANCHOR_HEX")
	ttl := flag.Duration("ttl", 7*24*time.Hour, "how long the descriptor stays fresh (-sign)")
	descriptorFile := flag.String("file", "", "file containing descriptors, one per line (-verify); default reads the remaining argument")

	var bridges bridgeList
	flag.Var(&bridges, "bridge", "bridge to include, as addr|sni|relay-pubkey-hex (-sign; repeatable)")
	flag.Parse()

	switch {
	case *genKey:
		runGenKey()
	case *sign:
		runSign(*keyHex, *ttl, bridges)
	case *verify:
		runVerify(*anchorHex, *descriptorFile, flag.Args())
	default:
		fmt.Fprintln(os.Stderr, "usage:")
		fmt.Fprintln(os.Stderr, "  bootstrap -genkey")
		fmt.Fprintln(os.Stderr, "  bootstrap -sign -key=<hex|@file> [-ttl=168h] -bridge='addr|sni|pubkey' [-bridge=...]")
		fmt.Fprintln(os.Stderr, "  bootstrap -verify -anchor=<hex> [-file=bridges.txt | <descriptor>]")
		os.Exit(2)
	}
}

func runGenKey() {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatalf("bootstrap: %v", err)
	}
	fmt.Printf("WARREN_BRIDGE_KEY_HEX=%s\n", hex.EncodeToString(priv))
	fmt.Printf("WARREN_BRIDGE_ANCHOR_HEX=%s\n", hex.EncodeToString(pub))
	fmt.Fprintln(os.Stderr, "\nThe anchor ships with clients; the signing key stays offline. Rotate by")
	fmt.Fprintln(os.Stderr, "shipping a client that trusts both the old and the new anchor.")
}

func runSign(keyArg string, ttl time.Duration, rawBridges []string) {
	if len(rawBridges) == 0 {
		log.Fatal("bootstrap: -sign needs at least one -bridge")
	}
	key, err := loadSigningKey(keyArg)
	if err != nil {
		log.Fatalf("bootstrap: %v", err)
	}

	parsed := make([]bootstrap.Bridge, 0, len(rawBridges))
	for _, raw := range rawBridges {
		b, err := bootstrap.ParseBridge(raw)
		if err != nil {
			log.Fatalf("bootstrap: %v", err)
		}
		parsed = append(parsed, b)
	}

	now := time.Now()
	line, err := bootstrap.SignDescriptor(key, now, now.Add(ttl), parsed)
	if err != nil {
		log.Fatalf("bootstrap: %v", err)
	}
	fmt.Println(line)
	fmt.Fprintf(os.Stderr, "\n%d bridge(s), fresh until %s. Distribute this line over as many\n", len(parsed), now.Add(ttl).UTC().Format(time.RFC3339))
	fmt.Fprintln(os.Stderr, "independent channels as you have; any one of them being blocked or hostile")
	fmt.Fprintln(os.Stderr, "costs availability, not integrity.")
}

func runVerify(anchorArg, file string, args []string) {
	if anchorArg == "" {
		anchorArg = os.Getenv("WARREN_BRIDGE_ANCHOR_HEX")
	}
	anchor, err := hex.DecodeString(strings.TrimSpace(anchorArg))
	if err != nil || len(anchor) != ed25519.PublicKeySize {
		log.Fatalf("bootstrap: -anchor must be %d hex chars", ed25519.PublicKeySize*2)
	}

	var lines []string
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			log.Fatalf("bootstrap: %v", err)
		}
		lines = strings.Split(string(data), "\n")
	} else {
		lines = args
	}

	verified, rejected := 0, 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		d, err := bootstrap.VerifyDescriptor(line, [][]byte{anchor}, time.Now())
		if err != nil {
			rejected++
			fmt.Printf("REJECTED  %v\n", err)
			continue
		}
		verified++
		state := "fresh"
		if d.Stale {
			state = "STALE (expired " + d.Expires.UTC().Format(time.RFC3339) + ") — still usable, but discovery has gone quiet"
		}
		fmt.Printf("OK        %d bridge(s), issued %s, %s\n", len(d.Bridges), d.Issued.UTC().Format(time.RFC3339), state)
		for _, b := range d.Bridges {
			fmt.Printf("          %s via %s (relay key %s…)\n", b.Addr, b.FallbackSNI, b.PublicKeyHex[:16])
		}
	}
	if verified == 0 {
		log.Fatalf("bootstrap: nothing verified (%d rejected)", rejected)
	}
}

func loadSigningKey(arg string) (ed25519.PrivateKey, error) {
	if arg == "" {
		arg = os.Getenv("WARREN_BRIDGE_KEY_HEX")
	}
	if after, ok := strings.CutPrefix(arg, "@"); ok {
		data, err := os.ReadFile(after)
		if err != nil {
			return nil, fmt.Errorf("read signing key: %w", err)
		}
		arg = string(data)
	}
	key, err := hex.DecodeString(strings.TrimSpace(arg))
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signing key must be %d hex chars (from -genkey), got %d", ed25519.PrivateKeySize*2, len(key)*2)
	}
	return ed25519.PrivateKey(key), nil
}
