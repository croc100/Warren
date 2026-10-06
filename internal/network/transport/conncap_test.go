package transport

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// TestServeHoldsAtMostMaxConns is ROADMAP H7: with the cap reached, the relay
// takes on no further connection — it is not spliced, so nothing reaches the
// borrowed site — until one of the held connections ends, and then it is served
// normally.
//
// It doubles as a canary for the cap: without it the third connection is
// spliced at once and its echo comes straight back.
func TestServeHoldsAtMostMaxConns(t *testing.T) {
	priv, _, err := GenerateServerIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	const maxConns = 2
	go Serve(ctx, ln, Config{
		ServerPrivateKey: priv,
		FallbackSNI:      "www.example.com",
		FallbackAddr:     startFallbackEcho(t),
		Flight:           testFlight(),
		MaxConns:         maxConns,
	}, echoHandler)
	relayAddr := ln.Addr().String()

	// Fill the cap with connections that send nothing, so each sits in the
	// ClientHello sniff and holds its slot.
	held := make([]net.Conn, maxConns)
	for i := range held {
		c, err := net.Dial("tcp", relayAddr)
		if err != nil {
			t.Fatalf("dial held connection %d: %v", i, err)
		}
		t.Cleanup(func() { c.Close() })
		held[i] = c
	}

	// Long enough for the sniff to rule out a ClientHello straight away, so the
	// connection is spliced as soon as it is accepted.
	probeMsg := []byte("GET / HTTP/1.0\r\n\r\n")

	// One more. The TCP connect still completes — the kernel's backlog takes it
	// — but the relay must not pick it up.
	extra, err := net.Dial("tcp", relayAddr)
	if err != nil {
		t.Fatalf("dial extra connection: %v", err)
	}
	defer extra.Close()
	if _, err := extra.Write(probeMsg); err != nil {
		t.Fatalf("write extra: %v", err)
	}
	extra.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if n, err := extra.Read(make([]byte, len(probeMsg))); err == nil || n > 0 {
		t.Fatalf("connection over the cap was served (read %d bytes, err %v); the relay holds more than MaxConns=%d", n, err, maxConns)
	}

	// Free a slot. Closing a held connection ends its sniff and its splice of
	// nothing — after at most spliceDrainGrace, since the echo site never hangs
	// up — and the waiting connection is accepted and spliced.
	held[0].Close()

	extra.SetReadDeadline(time.Now().Add(spliceDrainGrace + 5*time.Second))
	buf := make([]byte, len(probeMsg))
	if _, err := io.ReadFull(extra, buf); err != nil {
		t.Fatalf("waiting connection was not served after a slot freed: %v", err)
	}
	if string(buf) != string(probeMsg) {
		t.Fatalf("echo = %q, want %q", buf, probeMsg)
	}
}

// TestConfigMaxConnsDefault pins that an unset or nonsensical cap falls back to
// the default rather than to no connections at all.
func TestConfigMaxConnsDefault(t *testing.T) {
	for _, n := range []int{0, -1} {
		if got := (Config{MaxConns: n}).maxConns(); got != DefaultMaxConns {
			t.Errorf("MaxConns=%d gives a cap of %d, want DefaultMaxConns (%d)", n, got, DefaultMaxConns)
		}
	}
	if got := (Config{MaxConns: 7}).maxConns(); got != 7 {
		t.Errorf("MaxConns=7 gives a cap of %d", got)
	}
}
