package bootstrap

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	key, anchors := testAnchor(t)
	issued := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	expires := issued.Add(7 * 24 * time.Hour)

	in := []Bridge{
		{Addr: "203.0.113.5:443", FallbackSNI: "www.example.com", PublicKeyHex: relayKeyA},
		{Addr: "198.51.100.9:8443", FallbackSNI: "cdn.example.net", PublicKeyHex: relayKeyB},
	}
	line, err := SignDescriptor(key, issued, expires, in)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if strings.ContainsAny(line, " \n\t") {
		t.Fatalf("descriptor must be a single whitespace-free line so any text channel can carry it: %q", line)
	}

	d, err := VerifyDescriptor(line, anchors, time.Now())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if d.Stale {
		t.Fatal("a descriptor inside its validity window was marked stale")
	}
	if !d.Issued.Equal(issued) || !d.Expires.Equal(expires) {
		t.Fatalf("times round-tripped wrong: issued %v expires %v", d.Issued, d.Expires)
	}
	if len(d.Bridges) != 2 || d.Bridges[0].Addr != in[0].Addr || d.Bridges[1].PublicKeyHex != relayKeyB {
		t.Fatalf("bridges round-tripped wrong: %+v", d.Bridges)
	}
	for _, b := range d.Bridges {
		if !b.Expires.Equal(expires) {
			t.Fatalf("bridge did not inherit the descriptor expiry: %+v", b)
		}
	}
}

// TestVerifyRejectsTamperedFields walks every byte position of the signed
// payload and flips it, asserting that no single-byte edit anywhere in the
// descriptor — address, relay key, expiry, version — survives verification.
// The relay key is the one that matters most: it is what makes a hostile
// discovery channel unable to steer a client onto a censor's relay.
func TestVerifyRejectsTamperedFields(t *testing.T) {
	key, anchors := testAnchor(t)
	line, err := SignDescriptor(key, time.Now(), time.Now().Add(time.Hour),
		[]Bridge{{Addr: "203.0.113.5:443", FallbackSNI: "www.example.com", PublicKeyHex: relayKeyA}})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	payloadLen := strings.LastIndex(line, sigSeparator)
	for i := 0; i < payloadLen; i++ {
		mangled := []byte(line)
		mangled[i]++
		if _, err := VerifyDescriptor(string(mangled), anchors, time.Now()); err == nil {
			t.Fatalf("a descriptor with byte %d altered verified successfully", i)
		}
	}
}

func TestVerifyRejectsOtherSignersAndMissingAnchors(t *testing.T) {
	key, _ := testAnchor(t)
	_, otherAnchors := testAnchor(t)

	line, err := SignDescriptor(key, time.Now(), time.Now().Add(time.Hour),
		[]Bridge{{Addr: "203.0.113.5:443", FallbackSNI: "www.example.com", PublicKeyHex: relayKeyA}})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if _, err := VerifyDescriptor(line, otherAnchors, time.Now()); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature for a descriptor signed by a different key", err)
	}
	if _, err := VerifyDescriptor(line, nil, time.Now()); !errors.Is(err, ErrNoTrustAnchor) {
		t.Fatalf("got %v, want ErrNoTrustAnchor", err)
	}
}

// TestVerifyRejectsUnknownFields pins fail-closed parsing: a field this build
// doesn't understand means a descriptor whose meaning is uncertain, and the
// version prefix is how a future format is supposed to announce itself.
func TestVerifyRejectsUnknownFields(t *testing.T) {
	key, anchors := testAnchor(t)
	now := time.Now().UTC().Truncate(time.Second)

	payload := descriptorVersion +
		";issued=" + now.Format(time.RFC3339) +
		";expires=" + now.Add(time.Hour).Format(time.RFC3339) +
		";bridge=203.0.113.5:443|www.example.com|" + relayKeyA +
		";transport=quic;"
	sig := ed25519.Sign(key, []byte(payload))
	line := payload + "sig=" + rawURL(sig)

	if _, err := VerifyDescriptor(line, anchors, time.Now()); !errors.Is(err, ErrMalformedDescriptor) {
		t.Fatalf("got %v, want ErrMalformedDescriptor for an unknown field", err)
	}
}

// TestVerifyMarksExpiredStaleRatherThanFailing is the availability half of the
// design: expiry is a reported state, not a fatal error, because a censor who
// blocks every discovery channel for a week must not thereby strand clients
// that already hold working addresses.
func TestVerifyMarksExpiredStaleRatherThanFailing(t *testing.T) {
	key, anchors := testAnchor(t)
	line, err := SignDescriptor(key, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour),
		[]Bridge{{Addr: "203.0.113.5:443", FallbackSNI: "www.example.com", PublicKeyHex: relayKeyA}})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	d, err := VerifyDescriptor(line, anchors, time.Now())
	if err != nil {
		t.Fatalf("an expired but validly signed descriptor must still parse: %v", err)
	}
	if !d.Stale || !d.Bridges[0].Stale {
		t.Fatal("expired descriptor was not marked stale")
	}
}

func TestSignDescriptorRejectsBadInput(t *testing.T) {
	key, _ := testAnchor(t)
	now := time.Now()
	good := Bridge{Addr: "203.0.113.5:443", FallbackSNI: "www.example.com", PublicKeyHex: relayKeyA}

	if _, err := SignDescriptor(key, now, now.Add(time.Hour), nil); err == nil {
		t.Fatal("expected an error signing an empty descriptor")
	}
	if _, err := SignDescriptor(key, now, now.Add(-time.Hour), []Bridge{good}); err == nil {
		t.Fatal("expected an error when expiry precedes issue time")
	}
	if _, err := SignDescriptor(key[:16], now, now.Add(time.Hour), []Bridge{good}); err == nil {
		t.Fatal("expected an error for a short signing key")
	}
	noKey := Bridge{Addr: "203.0.113.5:443", FallbackSNI: "www.example.com"}
	if _, err := SignDescriptor(key, now, now.Add(time.Hour), []Bridge{noKey}); err == nil {
		t.Fatal("expected refusal to sign a bridge with no relay identity key")
	}
}

func rawURL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
