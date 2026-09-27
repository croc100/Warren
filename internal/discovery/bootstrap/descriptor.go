package bootstrap

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// A bridge descriptor is a signed, expiring bundle of bridges. Every channel a
// censor can influence — DNS, a file pasted out of a messaging app, an email
// autoresponder — hands the client one of these rather than bare addresses.
//
// The point is to reduce a hostile channel from an attack to a denial of
// service. A channel that lies, injects, or rewrites can only make discovery
// fail; it cannot steer a client onto a relay chosen by the censor, because the
// relay identity keys inside the bundle are covered by the signature.
//
// Wire format is one line, so it survives every channel that carries text —
// a DNS TXT record, a chat message, a QR code, a printed page:
//
//	warren-bridges/1;issued=<RFC3339>;expires=<RFC3339>;bridge=<addr|sni|pubkey>[;bridge=...];sig=<base64url>
//
// The signature covers the literal prefix of the line up to and including the
// ';' before "sig=" — the exact bytes on the wire, never a re-serialization of
// parsed fields. Verifying a re-encoding of parsed data is a well-worn way to
// ship a signature bypass: any field the parser ignores or normalizes becomes a
// place to hide content the signature doesn't actually cover.

const (
	descriptorVersion = "warren-bridges/1"
	sigSeparator      = ";sig="
)

var (
	ErrMalformedDescriptor = errors.New("bootstrap: malformed bridge descriptor")
	ErrBadSignature        = errors.New("bootstrap: bridge descriptor signature does not verify under any trust anchor")
	ErrNoTrustAnchor       = errors.New("bootstrap: no trust anchor configured to verify bridge descriptors against")
)

// Descriptor is a verified bundle of bridges.
type Descriptor struct {
	Issued  time.Time
	Expires time.Time
	Bridges []Bridge

	// Stale is true when the descriptor verified but its expiry has passed.
	// Such a descriptor is still returned, deliberately: a client whose
	// newest list has expired is in a "discovery is stale" state, not a "no
	// bridges" state, and the stale addresses may well still work. Treating
	// expiry as fatal would hand a censor a way to strand clients by simply
	// blocking every discovery channel for a week.
	Stale bool
}

// SignDescriptor builds a signed descriptor line for the given bridges.
func SignDescriptor(key ed25519.PrivateKey, issued, expires time.Time, bridges []Bridge) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("bootstrap: signing key must be %d bytes, got %d", ed25519.PrivateKeySize, len(key))
	}
	if len(bridges) == 0 {
		return "", errors.New("bootstrap: cannot sign a descriptor with no bridges")
	}
	if !expires.After(issued) {
		return "", errors.New("bootstrap: descriptor expiry must be after its issue time")
	}

	var b strings.Builder
	b.WriteString(descriptorVersion)
	b.WriteString(";issued=")
	b.WriteString(issued.UTC().Format(time.RFC3339))
	b.WriteString(";expires=")
	b.WriteString(expires.UTC().Format(time.RFC3339))
	for _, br := range bridges {
		if _, err := ParseBridge(br.String()); err != nil {
			return "", fmt.Errorf("bootstrap: refusing to sign bridge %q: %w", br.Addr, err)
		}
		b.WriteString(";bridge=")
		b.WriteString(br.String())
	}
	b.WriteString(";")

	payload := b.String()
	sig := ed25519.Sign(key, []byte(payload))
	return payload + "sig=" + base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyDescriptor checks a descriptor line against the given trust anchors
// (Ed25519 public keys shipped with the client) and returns its contents.
//
// Expiry is reported through Descriptor.Stale rather than as an error; a
// signature failure, an unknown anchor, or any parse problem is fatal.
func VerifyDescriptor(line string, anchors [][]byte, now time.Time) (*Descriptor, error) {
	line = strings.TrimSpace(line)
	if len(anchors) == 0 {
		return nil, ErrNoTrustAnchor
	}

	cut := strings.LastIndex(line, sigSeparator)
	if cut < 0 {
		return nil, fmt.Errorf("%w: no signature field", ErrMalformedDescriptor)
	}
	// The signed bytes include the ';' that precedes "sig=", so the boundary
	// itself is authenticated and a field cannot be smuggled across it.
	payload := line[:cut+1]
	sig, err := base64.RawURLEncoding.DecodeString(line[cut+len(sigSeparator):])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: signature is not %d base64url-encoded bytes", ErrMalformedDescriptor, ed25519.SignatureSize)
	}

	verified := false
	for _, anchor := range anchors {
		if len(anchor) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(ed25519.PublicKey(anchor), []byte(payload), sig) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, ErrBadSignature
	}

	// Only parse after the signature verifies: everything below this line is
	// authenticated data, so a malformed field is an operator's mistake rather
	// than attacker-controlled input.
	return parseDescriptorPayload(payload, now)
}

func parseDescriptorPayload(payload string, now time.Time) (*Descriptor, error) {
	fields := strings.Split(strings.TrimSuffix(payload, ";"), ";")
	if len(fields) < 4 || fields[0] != descriptorVersion {
		return nil, fmt.Errorf("%w: want %s with issued, expires and at least one bridge", ErrMalformedDescriptor, descriptorVersion)
	}

	d := &Descriptor{}
	for _, f := range fields[1:] {
		name, value, ok := strings.Cut(f, "=")
		if !ok {
			return nil, fmt.Errorf("%w: field %q is not name=value", ErrMalformedDescriptor, f)
		}
		switch name {
		case "issued", "expires":
			t, err := time.Parse(time.RFC3339, value)
			if err != nil {
				return nil, fmt.Errorf("%w: %s: %v", ErrMalformedDescriptor, name, err)
			}
			if name == "issued" {
				d.Issued = t
			} else {
				d.Expires = t
			}
		case "bridge":
			b, err := ParseBridge(value)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedDescriptor, err)
			}
			d.Bridges = append(d.Bridges, b)
		default:
			// Fail closed on anything we don't understand. A descriptor
			// carrying a field this build ignores is a descriptor whose
			// meaning we can't be sure of; the version prefix is how a
			// future format announces itself.
			return nil, fmt.Errorf("%w: unknown field %q", ErrMalformedDescriptor, name)
		}
	}
	if d.Issued.IsZero() || d.Expires.IsZero() || len(d.Bridges) == 0 {
		return nil, fmt.Errorf("%w: missing issued, expires or bridge", ErrMalformedDescriptor)
	}

	d.Stale = now.After(d.Expires)
	for i := range d.Bridges {
		d.Bridges[i].Expires = d.Expires
		d.Bridges[i].Stale = d.Stale
	}
	return d, nil
}
