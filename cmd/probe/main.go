// Command probe is Warren's L1 gate: it behaves like a censor's active prober
// against a relay and against the site that relay borrows its identity from,
// compares the two, and measures whether a genuine Warren session's record
// shape separates from a real TLS session to the same site.
//
// It exits non-zero when anything distinguishes the relay from the real site, so
// it can be the thing a release is blocked on rather than a report someone reads
// occasionally. See docs/adr/0001-borrowed-tls-handshake.md.
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/croc100/warren/internal/network/probe"
	"github.com/croc100/warren/internal/network/transport"
)

func main() {
	log.SetFlags(0)

	relayAddr := flag.String("relay", "", "Warren relay to probe, host:port (required)")
	siteAddr := flag.String("site", "", "the real site the relay borrows its identity from, host:port (required)")
	sni := flag.String("sni", "", "hostname to present, i.e. the borrowed site's name (required)")
	relayKey := flag.String("relay-key", "", "relay's X25519 public key, hex; enables the record-shape comparison and the replay probe")
	timeout := flag.Duration("timeout", 2*time.Minute, "overall budget")
	flag.Parse()

	if *relayAddr == "" || *siteAddr == "" || *sni == "" {
		fmt.Fprintln(os.Stderr, "usage: probe -relay=host:port -site=host:port -sni=name [-relay-key=hex]")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	var extra []probe.Probe
	var shape *probe.Report

	if *relayKey != "" {
		cfg, err := clientConfig(*relayKey, *sni)
		if err != nil {
			log.Fatalf("probe: %v", err)
		}

		warrenTrace, err := probe.Capture(ctx, "warren", *relayAddr, driveWarren(cfg))
		if err != nil {
			log.Fatalf("probe: capture Warren session: %v", err)
		}
		realTrace, err := probe.Capture(ctx, "real", *siteAddr, driveRealTLS(*sni))
		if err != nil {
			log.Fatalf("probe: capture real session: %v", err)
		}

		// A third capture, against the relay but without a valid tag, so it is
		// spliced. Comparing it with the Warren session isolates what the relay
		// itself adds on each of its two answer paths — the one comparison a
		// censor can make without leaving a single IP address.
		splicedTrace, err := probe.Capture(ctx, "spliced", *relayAddr, driveRealTLS(*sni))
		if err != nil {
			log.Fatalf("probe: capture spliced session: %v", err)
		}

		report := probe.Compare(warrenTrace, realTrace)
		report.Findings = append(report.Findings, probe.CompareAnswerPaths(warrenTrace, splicedTrace))
		shape = &report

		fmt.Println(warrenTrace)
		fmt.Println(realTrace)
		fmt.Println(splicedTrace)

		if hello := warrenTrace.FirstClientRecord(); len(hello) > 0 {
			extra = append(extra, probe.ReplayProbe(hello))
		}
	}

	results := probe.RunSuite(ctx, *relayAddr, *siteAddr, *sni, extra...)
	fmt.Println(probe.FormatResults(results))

	failures := 0
	for _, r := range results {
		if r.Distinguishable {
			failures++
		}
	}

	if shape != nil {
		fmt.Println(shape)
		failures += len(shape.Distinguishers())
	} else {
		fmt.Println("(no -relay-key: skipped the record-shape comparison and the replay probe)")
	}

	if failures > 0 {
		fmt.Printf("FAIL: %d distinguisher(s) — this relay is separable from %s\n", failures, *sni)
		os.Exit(1)
	}
	fmt.Printf("PASS: nothing measured here separates the relay from %s\n", *sni)
}

func clientConfig(keyHex, sni string) (transport.Config, error) {
	key, err := hex.DecodeString(strings.TrimSpace(keyHex))
	if err != nil || len(key) != 32 {
		return transport.Config{}, fmt.Errorf("-relay-key must be 64 hex chars")
	}
	return transport.Config{ServerPublicKey: key, FallbackSNI: sni}, nil
}

// driveWarren runs one genuine Warren session. It writes a request-shaped
// payload and reads whatever comes back, which is enough for the handshake and
// first data records to appear in the trace even if the relay doesn't echo.
func driveWarren(cfg transport.Config) func(context.Context, string) error {
	return func(ctx context.Context, addr string) error {
		conn, err := transport.Dial(ctx, addr, cfg)
		if err != nil {
			return err
		}
		defer conn.Close()
		// Pause before sending the payload. Post-handshake records — session
		// tickets — race the client's first request on a real connection, and
		// without a gap the measurement window for them is empty on both sides,
		// which would report "no tickets" as a match. The pause makes that part
		// of the shape observable.
		time.Sleep(400 * time.Millisecond)
		if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + cfg.FallbackSNI + "\r\n\r\n")); err != nil {
			return err
		}
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		io.ReadFull(conn, make([]byte, 64))
		return nil
	}
}

func driveRealTLS(sni string) func(context.Context, string) error {
	return func(ctx context.Context, addr string) error {
		d := net.Dialer{Timeout: 10 * time.Second}
		raw, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return err
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(15 * time.Second))

		conn := probe.RealTLSClient(raw, sni)
		defer conn.Close()
		if err := conn.Handshake(); err != nil {
			return err
		}
		// Pause before sending the payload. Post-handshake records — session
		// tickets — race the client's first request on a real connection, and
		// without a gap the measurement window for them is empty on both sides,
		// which would report "no tickets" as a match. The pause makes that part
		// of the shape observable.
		time.Sleep(400 * time.Millisecond)
		if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + sni + "\r\nConnection: close\r\n\r\n")); err != nil {
			return err
		}
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		io.ReadFull(conn, make([]byte, 64))
		return nil
	}
}
