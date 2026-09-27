// Package transport implements Warren's L1 protocol camouflage layer.
//
// This is a "REALITY-lite" scheme: a Warren client's first packet is a
// syntactically valid TLS 1.3 ClientHello (built with uTLS so it carries a
// current browser's fingerprint, including the hybrid post-quantum key share
// mainstream browsers now offer by default) addressed to a real,
// currently-reachable HTTPS site. A 16-byte authentication tag is embedded in the ClientHello's
// session_id field, derived from a pre-shared key (PSK) and the ClientHello's
// own random field.
//
// The server peeks the first TLS record on every inbound connection:
//   - tag valid  -> this is a genuine Warren client. Both sides independently
//     derive a session key from (PSK, client_random) and switch immediately
//     to Warren's own AEAD-framed protocol on the same TCP stream.
//   - tag invalid/absent -> the connection is spliced byte-for-byte to the
//     real site the ClientHello's SNI names. A censor's active probe (or any
//     passive DPI classifier) sees a completely genuine handshake with the
//     real site's real certificate, because it *is* one.
//
// Known gap vs. full REALITY (xtls/xray-core's `reality` package): real
// REALITY derives its authentication key from an X25519 exchange embedded in
// the TLS key_share extension, so there is no long-lived shared secret to
// leak or rotate, and post-ClientHello bytes remain valid TLS 1.3 handshake
// records throughout. This package uses a simpler static PSK and switches to
// Warren's own framing immediately after the ClientHello, which is easier to
// reason about and test, but weaker against key compromise and against a
// censor that verifies TLS 1.3 state machine ordering off the first
// connection, not just the first packet. Treat this as the buildable proof
// of concept for the tag+fallback mechanism, not the hardened production
// transport — see docs/protocol/reality-transport.md for the migration path.
package transport

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"
)

const (
	tagLen                 = 16
	sessionIDLen           = 32                                                                               // matches typical Chrome TLS 1.3 ClientHello session_id length
	clientHelloFixedPrefix = 5 /*record header*/ + 4 /*handshake header*/ + 2 /*version*/ + 32 /*random*/ + 1 /*session_id len byte*/
)

var (
	ErrNotClientHello = errors.New("transport: first record is not a TLS ClientHello")
	ErrShortRead      = errors.New("transport: connection closed before ClientHello was fully read")
)

// Config holds the parameters both a camouflage client and server need.
type Config struct {
	// PSK is the pre-shared key used to derive per-connection tags and
	// session keys. In production this should be rotated and distributed
	// over the same out-of-band bootstrap channel as bridge addresses.
	PSK []byte

	// FallbackSNI is the hostname the disguised ClientHello claims to be
	// visiting. The server dials this host for real when a connection's
	// tag doesn't validate.
	FallbackSNI string

	// FallbackAddr is host:port for FallbackSNI (server-side only).
	FallbackAddr string

	// Fingerprint selects which browser ClientHello uTLS parrots. Zero value
	// means DefaultFingerprint.
	//
	// This is a perishable value, not a constant: browsers now offer a hybrid
	// post-quantum key share (X25519MLKEM768) by default, which makes a real
	// 2026 ClientHello both larger and structurally different from a 2023 one.
	// Parroting a profile that predates that shift is itself a distinguisher,
	// so the pinned profile has to keep moving. Per-region overrides matter too
	// — the right parrot is whatever the local population actually runs.
	Fingerprint utls.ClientHelloID
}

// DefaultFingerprint is the profile used when Config.Fingerprint is unset.
// HelloChrome_Auto tracks the newest Chrome profile uTLS ships, which is what
// keeps the hello's size and key_share groups inside the distribution of real
// browser traffic. TestDefaultFingerprintOffersHybridPQKeyShare guards the
// property that actually matters if this is ever pinned to a fixed version.
var DefaultFingerprint = utls.HelloChrome_Auto

func deriveTag(psk, clientRandom []byte) []byte {
	mac := hmac.New(sha256.New, psk)
	mac.Write(clientRandom)
	return mac.Sum(nil)[:tagLen]
}

func deriveSessionKey(psk, clientRandom []byte) ([]byte, error) {
	h := hkdf.New(sha256.New, psk, clientRandom, []byte("warren-lite-v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, err
	}
	return key, nil
}

// clientHello is the subset of a parsed TLS 1.3 ClientHello we need.
type clientHello struct {
	raw          []byte // prefix through session_id only — enough to read the tag
	recordLen    int    // full on-wire length of the TLS record (header + body)
	clientRandom []byte
	sessionIDOff int // offset of the session_id bytes within raw
}

// peekClientHello reads (without consuming beyond what's needed) a single
// TLS record containing a ClientHello from r, returning the raw bytes and
// the offsets of the fields we care about. Offsets are fixed by the TLS 1.2+
// wire format up through session_id, so no general ASN.1/TLS parser is
// needed for this subset.
func peekClientHello(r *bufio.Reader) (*clientHello, error) {
	head, err := r.Peek(clientHelloFixedPrefix)
	if err != nil {
		return nil, ErrShortRead
	}
	if head[0] != 0x16 /* handshake */ || head[5] != 0x01 /* client_hello */ {
		return nil, ErrNotClientHello
	}
	// TLS record length (bytes 3-4 of the record header) covers everything
	// after the 5-byte record header — this is the full on-wire size we
	// must eventually discard, not just the prefix we peek here.
	recordBodyLen := int(head[3])<<8 | int(head[4])
	recordLen := 5 + recordBodyLen

	sessionIDLenByte := int(head[clientHelloFixedPrefix-1])
	total := clientHelloFixedPrefix + sessionIDLenByte
	if total > recordLen {
		return nil, ErrNotClientHello
	}
	full, err := r.Peek(total)
	if err != nil {
		return nil, ErrShortRead
	}
	raw := make([]byte, len(full))
	copy(raw, full)

	const randomOff = 5 /*record*/ + 4 /*handshake*/ + 2 /*client_version*/
	return &clientHello{
		raw:          raw,
		recordLen:    recordLen,
		clientRandom: raw[randomOff : randomOff+32],
		sessionIDOff: clientHelloFixedPrefix,
	}, nil
}

// Dial opens a camouflaged connection to addr. On success the returned
// net.Conn transparently encrypts/decrypts application data with a session
// key both sides derive from cfg.PSK; the caller does not need to know this
// happened.
func Dial(ctx context.Context, addr string, cfg Config) (net.Conn, error) {
	d := net.Dialer{}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("transport: dial %s: %w", addr, err)
	}

	fingerprint := cfg.Fingerprint
	if fingerprint.Client == "" {
		fingerprint = DefaultFingerprint
	}

	uconn := utls.UClient(raw, &utls.Config{ServerName: cfg.FallbackSNI}, fingerprint)
	if err := uconn.BuildHandshakeState(); err != nil {
		raw.Close()
		return nil, fmt.Errorf("transport: build client hello: %w", err)
	}

	hello := uconn.HandshakeState.Hello
	clientRandom := append([]byte(nil), hello.Random...)

	tag := deriveTag(cfg.PSK, clientRandom)
	sessionID := make([]byte, sessionIDLen)
	copy(sessionID, tag)
	if _, err := rand.Read(sessionID[tagLen:]); err != nil {
		raw.Close()
		return nil, fmt.Errorf("transport: fill session id padding: %w", err)
	}
	hello.SessionId = sessionID
	// uTLS caches the originally-built wire bytes in hello.Raw and Marshal
	// returns that cache verbatim whenever it's non-nil — it does NOT
	// re-encode from the struct fields by default. Since we just mutated
	// SessionId, the cache is stale; clearing Raw forces Marshal to
	// actually re-serialize, picking up our patched SessionId while
	// everything else (extension order, cipher list, key shares, ALPN — the
	// fingerprint proper) still matches what uTLS built for the parroted
	// browser profile.
	hello.Raw = nil
	rawHello, err := hello.Marshal()
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("transport: marshal client hello: %w", err)
	}
	record := append([]byte{0x16, 0x03, 0x01, byte(len(rawHello) >> 8), byte(len(rawHello))}, rawHello...)

	if _, err := raw.Write(record); err != nil {
		raw.Close()
		return nil, fmt.Errorf("transport: send client hello: %w", err)
	}

	sessionKey, err := deriveSessionKey(cfg.PSK, clientRandom)
	if err != nil {
		raw.Close()
		return nil, err
	}

	return newAEADConn(raw, sessionKey, true /* isClient */)
}

// Handler processes an authenticated Warren connection. Implementations own
// the lifetime of conn and must close it when done.
type Handler func(conn net.Conn)

// Serve accepts connections on ln, validating each one's embedded tag. Valid
// connections are handed to handle over an AEAD-framed net.Conn; invalid or
// absent tags cause the raw bytes to be spliced to cfg.FallbackAddr so the
// connection completes as a genuine visit to the real site.
func Serve(ctx context.Context, ln net.Listener, cfg Config, handle Handler) error {
	for {
		raw, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go serveConn(ctx, raw, cfg, handle)
	}
}

// sniffTimeout bounds how long we'll wait for a complete ClientHello before
// giving up. Without this, a connection that sends a plausible record/
// handshake header claiming a large session_id but never sends the rest
// would block its serveConn goroutine forever (a cheap Slowloris-style
// resource exhaustion — one dangling TCP connection per idle goroutine).
const sniffTimeout = 5 * time.Second

func serveConn(ctx context.Context, raw net.Conn, cfg Config, handle Handler) {
	br := bufio.NewReaderSize(raw, 4096)

	raw.SetReadDeadline(time.Now().Add(sniffTimeout))

	// Any failure below — malformed record, short read, tag mismatch — is
	// treated identically: fall through to the fallback splice. Closing the
	// connection instead on a parse failure would itself be a distinguishing
	// signal (a real HTTPS server doesn't instantly RST on odd input), so we
	// deliberately don't special-case parse errors from tag mismatches.
	hello, err := peekClientHello(br)
	raw.SetReadDeadline(time.Time{}) // clear the sniff deadline either way
	if err == nil {
		expected := deriveTag(cfg.PSK, hello.clientRandom)
		got := hello.raw[hello.sessionIDOff : hello.sessionIDOff+tagLen]

		if hmac.Equal(expected, got) {
			// Genuine Warren client. Consume the *entire* ClientHello
			// record (not just the prefix we peeked to read the tag —
			// extensions/cipher suites/etc. still follow it on the wire),
			// then switch to AEAD framing for everything after.
			if _, err := br.Discard(hello.recordLen); err != nil {
				raw.Close()
				return
			}
			sessionKey, err := deriveSessionKey(cfg.PSK, hello.clientRandom)
			if err != nil {
				raw.Close()
				return
			}
			wrapped := &bufferedConn{Conn: raw, r: br}
			conn, err := newAEADConn(wrapped, sessionKey, false /* isClient */)
			if err != nil {
				raw.Close()
				return
			}
			handle(conn)
			return
		}
	}

	// Not a Warren client (or a censor's probe) — splice to the real site
	// so whatever they see is indistinguishable from a normal visit.
	spliceToFallback(ctx, raw, br, cfg.FallbackAddr)
}

func spliceToFallback(ctx context.Context, raw net.Conn, br *bufio.Reader, fallbackAddr string) {
	defer raw.Close()
	d := net.Dialer{Timeout: 5 * time.Second}
	upstream, err := d.DialContext(ctx, "tcp", fallbackAddr)
	if err != nil {
		return
	}
	defer upstream.Close()

	done := make(chan struct{}, 2)
	go func() { io.Copy(upstream, br); done <- struct{}{} }()
	go func() { io.Copy(raw, upstream); done <- struct{}{} }()
	<-done
}

// bufferedConn lets us keep using a bufio.Reader (which may already hold
// buffered bytes past the ClientHello) as a net.Conn for the AEAD layer.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }
