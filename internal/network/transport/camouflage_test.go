package transport

import (
	"context"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func startFallbackEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fallback listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c) // echo
			}(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

// TestGenuineClient_ReachesWarrenProtocol proves that a client presenting the
// correct tag gets switched to the AEAD-framed Warren channel, and that a
// message written by the client is received, decrypted, and echoed back by
// the server-side handler.
func TestGenuineClient_ReachesWarrenProtocol(t *testing.T) {
	psk := make([]byte, 32)
	rand.Read(psk)
	fallbackAddr := startFallbackEcho(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	cfg := Config{PSK: psk, FallbackSNI: "www.example.com", FallbackAddr: fallbackAddr}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go Serve(ctx, ln, cfg, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 5)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		conn.Write(buf)
	})

	conn, err := Dial(ctx, ln.Addr().String(), cfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	out := make([]byte, 5)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, out); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(out) != "hello" {
		t.Fatalf("got %q, want %q", out, "hello")
	}
}

// TestUntaggedClient_FallsBackToRealSite proves that a connection which does
// not present a valid tag (i.e. any non-Warren client, or a censor's probe)
// is transparently spliced through to the fallback address rather than
// reaching the Warren handler at all.
func TestUntaggedClient_FallsBackToRealSite(t *testing.T) {
	psk := make([]byte, 32)
	rand.Read(psk)
	fallbackAddr := startFallbackEcho(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	cfg := Config{PSK: psk, FallbackSNI: "www.example.com", FallbackAddr: fallbackAddr}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handlerReached := make(chan struct{}, 1)
	go Serve(ctx, ln, cfg, func(conn net.Conn) {
		handlerReached <- struct{}{}
		conn.Close()
	})

	// A plain TCP client with no idea about the tag scheme — this stands in
	// for both an ordinary non-Warren connection and a censor's active probe.
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()

	// Send *something* that looks vaguely like a ClientHello record header
	// so peekClientHello doesn't just bail on the magic bytes, proving the
	// splice path is reached even when parsing gets as far as a tag check.
	// 300 bytes comfortably covers the worst case session_id-length claim
	// (up to 44+255=299) so this test exercises the "well-formed but wrong
	// tag" path deterministically, not the sniffTimeout fallback path.
	junk := make([]byte, 300)
	rand.Read(junk)
	junk[0], junk[5] = 0x16, 0x01
	raw.Write(junk)

	echoed := make([]byte, len(junk))
	raw.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(raw, echoed); err != nil {
		t.Fatalf("expected spliced echo from fallback, got: %v", err)
	}
	for i := range junk {
		if junk[i] != echoed[i] {
			t.Fatalf("splice roundtrip mismatch at byte %d", i)
		}
	}

	select {
	case <-handlerReached:
		t.Fatal("Warren handler was reached by an untagged connection")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestDefaultFingerprintOffersHybridPQKeyShare is a staleness guard, not a
// crypto test. Mainstream browsers offer X25519MLKEM768 by default, so a
// parroted ClientHello that only offers classical groups is anomalous against
// the real traffic distribution it's hiding in — the disguise rots quietly as
// the pinned profile ages. This fails as soon as DefaultFingerprint is moved
// back to a pre-PQ profile.
func TestDefaultFingerprintOffersHybridPQKeyShare(t *testing.T) {
	uconn := utls.UClient(nil, &utls.Config{ServerName: "example.com"}, DefaultFingerprint)
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("build handshake state: %v", err)
	}

	for _, ks := range uconn.HandshakeState.Hello.KeyShares {
		if ks.Group == utls.X25519MLKEM768 {
			return
		}
	}
	t.Fatalf("default fingerprint %+v offers no hybrid post-quantum key share; real browsers do", DefaultFingerprint)
}

// TestClientHelloSpansMultipleSegments records the size shift a hybrid PQ key
// share causes: the hello no longer fits the single small segment the rest of
// these tests exercise, so the server's record-boundary handling has to cope
// with a hello that arrives in pieces.
func TestClientHelloSpansMultipleSegments(t *testing.T) {
	uconn := utls.UClient(nil, &utls.Config{ServerName: "example.com"}, DefaultFingerprint)
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("build handshake state: %v", err)
	}
	uconn.HandshakeState.Hello.Raw = nil
	raw, err := uconn.HandshakeState.Hello.Marshal()
	if err != nil {
		t.Fatalf("marshal client hello: %v", err)
	}
	if len(raw) < 1000 {
		t.Fatalf("client hello is %d bytes, expected a post-quantum-sized hello (>1000); profile may have regressed", len(raw))
	}
	t.Logf("default profile client hello: %d bytes", len(raw))
}
