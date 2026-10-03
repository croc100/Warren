package transport

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Warren's session handshake rides inside the camouflaged TLS 1.3 flight: the
// client's real X25519MLKEM768 key_share carries Warren's own ephemeral keys,
// and the relay answers with a real-shaped ServerHello carrying the ML-KEM
// ciphertext. Three secrets go into the session key:
//
//	ss_mlkem  ML-KEM-768 encapsulation to the client's ephemeral key  (post-quantum)
//	ss_ecdhe  X25519 between both sides' ephemeral keys               (forward secrecy)
//	ss_auth   X25519 between the client's ephemeral key and the       (authentication)
//	          relay's long-term identity key
//
// ss_auth replaces the static PSK the first proof of concept used. That matters
// for three reasons: the authentication tag is now per-connection rather than a
// function of a shared secret every client holds; a leaked client can't decrypt
// anyone else's traffic; and recorded sessions stay unreadable even if the
// relay's identity key is later seized, because the ephemeral halves are gone.
// ss_mlkem is what keeps that true against an adversary who records now and
// gets a quantum computer later.
//
// Group and layout follow draft-kwiatkowski-tls-ecdhe-mlkem, the same wire
// format real browsers use for X25519MLKEM768, so the bytes Warren puts in the
// key_share are indistinguishable in size and structure from a genuine hybrid
// share: client sends ek||x25519_pub, server answers ciphertext||x25519_pub,
// and the hybrid secret concatenates ML-KEM first.

const (
	tagLen       = 16
	sessionIDLen = 32 // matches a typical Chrome TLS 1.3 ClientHello session_id
	x25519KeyLen = 32

	hybridClientShareLen = mlkem.EncapsulationKeySize768 + x25519KeyLen // 1216
	hybridServerShareLen = mlkem.CiphertextSize768 + x25519KeyLen       // 1120

	// tls13CipherSuite is the ServerHello fallback when the borrowed site's
	// negotiated suite has not been measured (FlightProfile.CipherSuite == 0).
	// Every Chrome profile offers TLS_AES_128_GCM_SHA256, so selecting it is
	// always consistent with the ClientHello we just parroted. It names nothing
	// about how Warren actually encrypts the session (that's ChaCha20-Poly1305
	// under the derived key); it only has to be a suite the client offered. When
	// the profile carries the site's real choice, that is echoed instead, so a
	// site preferring AES-256 or ChaCha20 does not split the relay's two answer
	// paths onto different suites.
	tls13CipherSuite = 0x1301

	extSupportedVersions = 0x002b
	extKeyShare          = 0x0033
)

var (
	ErrNotClientHello  = errors.New("transport: first record is not a TLS ClientHello")
	ErrShortRead       = errors.New("transport: connection closed before the TLS record was fully read")
	ErrNoHybridShare   = errors.New("transport: ClientHello carries no X25519MLKEM768 key share")
	ErrBadServerHello  = errors.New("transport: relay did not answer with a usable ServerHello")
	ErrIdentityMissing = errors.New("transport: relay identity key missing from Config")

	// ErrRelayRejected is what being treated as an ordinary visitor looks like
	// from the client's side. The relay did not accept the tag, so it spliced
	// the connection to the site it borrows and everything after the
	// ServerHello belongs to that site's real TLS session.
	//
	// The relay cannot say why, and deliberately: an unrecognised tag has to be
	// answered exactly like a censor's probe, or the difference between the two
	// answers becomes the distinguisher. So the plausible causes are named here
	// rather than reported from the other end — the relay key in the bridge
	// descriptor is wrong or has been rotated, the address is not a Warren
	// relay at all, or this device's clock is outside the tag's freshness
	// window (see tagWindow).
	ErrRelayRejected = errors.New(
		"transport: the relay did not accept this connection and spliced it to the site it borrows; " +
			"check the relay key in the bridge descriptor, and this device's clock")
)

// GenerateServerIdentity returns a new relay identity: a long-term X25519 key
// pair whose public half is published with the bridge address (in the bridge
// descriptor) and whose private half never leaves the relay.
func GenerateServerIdentity() (privateKey, publicKey []byte, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("transport: generate relay identity: %w", err)
	}
	return k.Bytes(), k.PublicKey().Bytes(), nil
}

// clientKeys holds the ephemeral material a client generates per connection.
type clientKeys struct {
	ecdhe    *ecdh.PrivateKey
	mlkemDK  *mlkem.DecapsulationKey768
	share    []byte // ek || x25519_pub, exactly as a real hybrid client share
	authSS   []byte // X25519(ephemeral, relay identity)
	relayPub *ecdh.PublicKey
}

func newClientKeys(relayPublicKey []byte) (*clientKeys, error) {
	if len(relayPublicKey) != x25519KeyLen {
		return nil, fmt.Errorf("%w: want %d-byte public key, got %d", ErrIdentityMissing, x25519KeyLen, len(relayPublicKey))
	}
	relayPub, err := ecdh.X25519().NewPublicKey(relayPublicKey)
	if err != nil {
		return nil, fmt.Errorf("transport: relay public key: %w", err)
	}
	ecdheKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	authSS, err := ecdheKey.ECDH(relayPub)
	if err != nil {
		return nil, fmt.Errorf("transport: derive auth secret: %w", err)
	}

	share := make([]byte, 0, hybridClientShareLen)
	share = append(share, dk.EncapsulationKey().Bytes()...)
	share = append(share, ecdheKey.PublicKey().Bytes()...)

	return &clientKeys{ecdhe: ecdheKey, mlkemDK: dk, share: share, authSS: authSS, relayPub: relayPub}, nil
}

// Freshness binding for the tag.
//
// The tag is a function of the hello, so a hello re-sent verbatim validates by
// construction and the relay needs some other way to refuse it. A cache of
// randoms already seen is the obvious answer and it is what the relay keeps,
// but a cache is a memory budget, and any memory budget expires: a censor that
// captures one genuine hello and simply waits out the cache gets a Warren
// answer, which is the exact move the cache exists to stop.
//
// So the tag also covers a coarse clock, and the relay accepts only the
// windows near its own. A hello then stops being replayable on its own terms,
// bounded by arithmetic rather than by how much the relay can afford to
// remember, and the cache's job shrinks to covering the window span.
//
// The cost is that a client whose clock is wrong past the slack cannot
// connect, and cannot be told why by the relay: an out-of-window tag is
// indistinguishable from a forged one, so it is spliced like any other
// unauthenticated connection. That failure looks exactly like censorship from
// the client's side, which is why Dial names the clock as a candidate cause
// (see ErrRelayRejected).
const (
	// tagWindow is the granularity of the freshness binding.
	tagWindow = 10 * time.Minute

	// tagWindowSlack is how many windows either side of its own the relay will
	// accept, and so how much clock skew a client may carry. One window either
	// way gives at least tagWindow of tolerance in each direction.
	tagWindowSlack = 1

	// tagAcceptanceSpan is how long a given hello stays replayable at all: the
	// whole range of windows a relay will accept. The replay cache has to
	// remember at least this far back, and beyond it nothing needs remembering
	// because the tag no longer verifies.
	tagAcceptanceSpan = (2*tagWindowSlack + 1) * tagWindow
)

// tagWindowIndex is the coarse clock both sides bind into the tag.
func tagWindowIndex(t time.Time) int64 {
	return t.Unix() / int64(tagWindow/time.Second)
}

// deriveTag computes the authentication tag embedded in the ClientHello's
// session_id. It binds the client's random *and* its key share, so a censor
// who replays a captured hello with a substituted key share (hoping to have
// the relay answer it) fails the check instead, and the coarse time window, so
// a captured hello stops verifying once the window has passed.
//
// Nothing about this is visible on the wire: the window is an input to the
// HMAC, not a field, so the hello is byte-for-byte the shape it was before.
func deriveTag(authSS, clientRandom, clientShare []byte, window int64) []byte {
	var w [8]byte
	binary.BigEndian.PutUint64(w[:], uint64(window))

	mac := hmac.New(sha256.New, authSS)
	mac.Write([]byte("warren-tag-v2"))
	mac.Write(clientRandom)
	mac.Write(clientShare)
	mac.Write(w[:])
	return mac.Sum(nil)[:tagLen]
}

// tagMatchesAnyWindow reports whether the tag verifies under the relay's own
// window or either neighbour.
//
// Every window is always checked — no early exit — so the time this takes says
// nothing about which window matched or whether any did.
func tagMatchesAnyWindow(authSS, clientRandom, clientShare, tag []byte, now time.Time) bool {
	center := tagWindowIndex(now)
	match := 0
	for d := int64(-tagWindowSlack); d <= tagWindowSlack; d++ {
		want := deriveTag(authSS, clientRandom, clientShare, center+d)
		match |= subtle.ConstantTimeCompare(want, tag)
	}
	return match == 1
}

// deriveSessionKey mixes the three shared secrets into the AEAD key. Every
// input has a fixed length, so plain concatenation is unambiguous: ML-KEM
// secret, then ECDHE secret (the draft's hybrid ordering), then the
// authentication secret. The handshake transcript goes into salt and info so
// two connections can never derive the same key even if a secret repeats.
func deriveSessionKey(mlkemSS, ecdheSS, authSS, clientRandom, serverRandom, clientShare, serverShare []byte) ([]byte, error) {
	secret := make([]byte, 0, len(mlkemSS)+len(ecdheSS)+len(authSS))
	secret = append(secret, mlkemSS...)
	secret = append(secret, ecdheSS...)
	secret = append(secret, authSS...)

	salt := make([]byte, 0, len(clientRandom)+len(serverRandom))
	salt = append(salt, clientRandom...)
	salt = append(salt, serverRandom...)

	info := make([]byte, 0, 32+len(clientShare)+len(serverShare))
	info = append(info, []byte("warren hybrid v1 aead key")...)
	info = append(info, clientShare...)
	info = append(info, serverShare...)

	key, err := hkdf.Key(sha256.New, secret, salt, string(info), 32)
	if err != nil {
		return nil, fmt.Errorf("transport: derive session key: %w", err)
	}
	return key, nil
}

// confirmation is the key-confirmation tag carried inside the shaped flight
// (see flight.go). It proves the peer derived the same session key and binds the
// handshake transcript, so a middlebox that rewrote the ClientHello or the
// ServerHello on the way cannot go unnoticed.
//
// This is not what protects application data — the AEAD does that — which is why
// it can safely be truncated to fit a small record.
func confirmation(sessionKey []byte, label string, clientRandom, clientShare, serverRandom, serverShare []byte) []byte {
	mac := hmac.New(sha256.New, sessionKey)
	mac.Write([]byte(label))
	mac.Write(clientRandom)
	mac.Write(clientShare)
	mac.Write(serverRandom)
	mac.Write(serverShare)
	return mac.Sum(nil)
}

const (
	serverConfirmLabel = "warren server finished v1"
	clientConfirmLabel = "warren client finished v1"
)

// hybridShare extracts the X25519MLKEM768 entry from a parsed ClientHello.
func hybridShare(shares []utls.KeyShare) ([]byte, error) {
	for _, ks := range shares {
		if ks.Group == utls.X25519MLKEM768 {
			if len(ks.Data) != hybridClientShareLen {
				return nil, ErrNoHybridShare
			}
			return ks.Data, nil
		}
	}
	return nil, ErrNoHybridShare
}

func splitClientShare(share []byte) (encapKey, ecdhePub []byte) {
	return share[:mlkem.EncapsulationKeySize768], share[mlkem.EncapsulationKeySize768:]
}

// acceptResult is everything the relay needs after validating a client: the
// ServerHello bytes to send, the session key, and the server-side halves of the
// transcript that the key confirmation in the shaped flight binds.
type acceptResult struct {
	serverHello  []byte
	sessionKey   []byte
	serverRandom []byte
	serverShare  []byte
}

// serverAccept validates a client's tag and produces everything the relay needs
// to answer. cipherSuite is the suite the borrowed site negotiated (from its
// FlightProfile), echoed in the ServerHello so the relay's two answer paths —
// local for a tagged client, spliced for everyone else — agree on it; zero
// falls back to a suite every parroted ClientHello offers.
func serverAccept(identityKey, clientRandom, sessionID, clientShare []byte, now time.Time, cipherSuite uint16) (*acceptResult, error) {
	if len(identityKey) != x25519KeyLen {
		return nil, ErrIdentityMissing
	}
	identity, err := ecdh.X25519().NewPrivateKey(identityKey)
	if err != nil {
		return nil, fmt.Errorf("transport: relay identity key: %w", err)
	}

	encapKeyBytes, clientECDHEBytes := splitClientShare(clientShare)
	clientECDHE, err := ecdh.X25519().NewPublicKey(clientECDHEBytes)
	if err != nil {
		return nil, fmt.Errorf("transport: client ephemeral key: %w", err)
	}
	authSS, err := identity.ECDH(clientECDHE)
	if err != nil {
		return nil, fmt.Errorf("transport: derive auth secret: %w", err)
	}

	if !tagMatchesAnyWindow(authSS, clientRandom, clientShare, sessionID[:tagLen], now) {
		return nil, errTagMismatch
	}

	encapKey, err := mlkem.NewEncapsulationKey768(encapKeyBytes)
	if err != nil {
		// A well-formed hybrid share whose ML-KEM half doesn't decode is not
		// something a real browser sends; treat it like any other non-Warren
		// input and let the caller splice to the real site.
		return nil, ErrNoHybridShare
	}
	mlkemSS, ciphertext := encapKey.Encapsulate()

	serverECDHE, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ecdheSS, err := serverECDHE.ECDH(clientECDHE)
	if err != nil {
		return nil, err
	}

	serverShare := make([]byte, 0, hybridServerShareLen)
	serverShare = append(serverShare, ciphertext...)
	serverShare = append(serverShare, serverECDHE.PublicKey().Bytes()...)

	serverRandom := make([]byte, 32)
	if _, err := rand.Read(serverRandom); err != nil {
		return nil, err
	}

	key, err := deriveSessionKey(mlkemSS, ecdheSS, authSS, clientRandom, serverRandom, clientShare, serverShare)
	if err != nil {
		return nil, err
	}
	return &acceptResult{
		serverHello:  buildServerHello(sessionID, serverRandom, serverShare, cipherSuite),
		sessionKey:   key,
		serverRandom: serverRandom,
		serverShare:  serverShare,
	}, nil
}

var errTagMismatch = errors.New("transport: client hello tag mismatch")

// buildServerHello emits a TLS 1.3 ServerHello record carrying the hybrid
// key_share. Everything about its shape — legacy version 0x0303, the echoed
// session_id, supported_versions announcing TLS 1.3, key_share carrying
// ciphertext||x25519 for group X25519MLKEM768 — is what a real TLS 1.3 server
// answering our parroted ClientHello would send. cipherSuite is the suite the
// borrowed site negotiated; zero falls back to TLS_AES_128_GCM_SHA256, which
// every parroted Chrome profile offers.
func buildServerHello(sessionIDEcho, serverRandom, serverShare []byte, cipherSuite uint16) []byte {
	if cipherSuite == 0 {
		cipherSuite = tls13CipherSuite
	}
	ext := make([]byte, 0, 16+len(serverShare))
	ext = appendUint16(ext, extSupportedVersions)
	ext = appendUint16(ext, 2)
	ext = appendUint16(ext, 0x0304) // TLS 1.3

	ext = appendUint16(ext, extKeyShare)
	ext = appendUint16(ext, uint16(4+len(serverShare)))
	ext = appendUint16(ext, uint16(utls.X25519MLKEM768))
	ext = appendUint16(ext, uint16(len(serverShare)))
	ext = append(ext, serverShare...)

	body := make([]byte, 0, 64+len(sessionIDEcho)+len(ext))
	body = appendUint16(body, 0x0303) // legacy_version
	body = append(body, serverRandom...)
	body = append(body, byte(len(sessionIDEcho)))
	body = append(body, sessionIDEcho...)
	body = appendUint16(body, cipherSuite)
	body = append(body, 0x00) // legacy_compression_method
	body = appendUint16(body, uint16(len(ext)))
	body = append(body, ext...)

	handshake := make([]byte, 0, 4+len(body))
	handshake = append(handshake, 0x02) // server_hello
	handshake = append(handshake, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	handshake = append(handshake, body...)

	record := make([]byte, 0, 5+len(handshake))
	record = append(record, recordTypeHandshake, 0x03, 0x03)
	record = appendUint16(record, uint16(len(handshake)))
	return append(record, handshake...)
}

// parseServerHello pulls the server random and hybrid key_share out of a
// ServerHello handshake body, rejecting anything that isn't the group Warren
// hides its handshake in.
func parseServerHello(body []byte) (serverRandom, serverShare []byte, err error) {
	serverRandom, group, _, share, err := parseServerHelloParts(body)
	if err != nil {
		return nil, nil, err
	}
	if group != uint16(utls.X25519MLKEM768) || len(share) != hybridServerShareLen {
		return nil, nil, ErrBadServerHello
	}
	return serverRandom, share, nil
}

// parseServerHelloParts is the group-agnostic version, used when profiling a
// borrowed site: there we need to know *which* group the site actually
// negotiated, because a site that doesn't offer the hybrid group cannot
// plausibly be the one answering a hybrid ClientHello.
func parseServerHelloParts(body []byte) (serverRandom []byte, group, cipherSuite uint16, share []byte, err error) {
	// server_hello(1) + length(3) + legacy_version(2) + random(32) + session_id_len(1)
	if len(body) < 39 || body[0] != 0x02 {
		return nil, 0, 0, nil, ErrBadServerHello
	}
	p := body[4:]
	if len(p) < 35 {
		return nil, 0, 0, nil, ErrBadServerHello
	}
	serverRandom = append([]byte(nil), p[2:34]...)
	sidLen := int(p[34])
	p = p[35:]
	if len(p) < sidLen+2+1+2 {
		return nil, 0, 0, nil, ErrBadServerHello
	}
	cipherSuite = uint16(p[sidLen])<<8 | uint16(p[sidLen+1])
	p = p[sidLen+3:] // session_id + cipher_suite(2) + compression(1)

	extLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) < extLen {
		return nil, 0, 0, nil, ErrBadServerHello
	}
	for ext := p[:extLen]; len(ext) >= 4; {
		extType := uint16(ext[0])<<8 | uint16(ext[1])
		bodyLen := int(ext[2])<<8 | int(ext[3])
		if len(ext) < 4+bodyLen {
			return nil, 0, 0, nil, ErrBadServerHello
		}
		payload := ext[4 : 4+bodyLen]
		ext = ext[4+bodyLen:]

		if extType != extKeyShare || len(payload) < 4 {
			continue
		}
		group = uint16(payload[0])<<8 | uint16(payload[1])
		shareLen := int(payload[2])<<8 | int(payload[3])
		if len(payload) < 4+shareLen {
			return nil, 0, 0, nil, ErrBadServerHello
		}
		return serverRandom, group, cipherSuite, append([]byte(nil), payload[4:4+shareLen]...), nil
	}
	return nil, 0, 0, nil, ErrBadServerHello
}

func appendUint16(b []byte, v uint16) []byte { return append(b, byte(v>>8), byte(v)) }

// replayCache remembers recently-seen ClientHello randoms. A replayed hello
// carries a valid tag by construction (the tag is a function of the hello), so
// without this a censor could capture one genuine hello and replay it to
// confirm the relay answers differently than the real site does. A replay is
// treated exactly like an unauthenticated connection: spliced to the real site.
//
// Entries are kept in generations that rotate, rather than in one map with a
// per-entry timestamp, for two reasons.
//
// Expiry becomes free. Dropping a whole generation retires every random in it
// at once, so there is no scan and no per-entry time.Time to store.
//
// More importantly, running out of room degrades instead of collapsing. The
// previous version swept for expired entries when it hit its ceiling and, if
// that freed nothing, emptied the map — so a relay busy enough to fill it
// inside one TTL periodically forgot *everything* and had no replay protection
// at all until it refilled. That is a cliff on a relay that is doing well, and
// it is also silent. Here the ceiling retires the oldest generation only.
//
// What makes that safe is the freshness window in the tag: a random old enough
// to fall out of the cache under pressure is close to being a random whose tag
// no longer verifies anyway. The cache covers tagAcceptanceSpan and no more.
type replayCache struct {
	mu sync.Mutex

	// generations holds sets of randoms, oldest first. Only membership
	// matters, so the values are empty.
	generations []map[string]struct{}
	rotatedAt   time.Time

	span       time.Duration // how long one generation collects for
	keep       int           // how many generations to retain
	maxEntries int           // ceiling across all generations
	entries    int
}

// replayCacheMaxEntries bounds the cache's memory. At roughly 80 bytes per
// entry this is about 10 MB fully loaded, which a relay on domestic hardware
// can afford; reaching it means sustaining a few hundred authenticated
// handshakes a minute for the whole acceptance span, and the consequence is
// that the oldest generation retires early rather than that anything fails.
const replayCacheMaxEntries = 1 << 17

func newReplayCache() *replayCache {
	// Four generations of one window each: retention lands between three and
	// four windows, so it always covers tagAcceptanceSpan (three windows) no
	// matter where in a generation a hello arrives.
	return newReplayCacheWith(tagWindow, 4, replayCacheMaxEntries, time.Now())
}

func newReplayCacheWith(span time.Duration, keep, maxEntries int, now time.Time) *replayCache {
	return &replayCache{
		generations: []map[string]struct{}{make(map[string]struct{})},
		rotatedAt:   now,
		span:        span,
		keep:        keep,
		maxEntries:  maxEntries,
	}
}

// admit records the random and reports whether this is the first time we have
// seen it inside the retention window.
func (c *replayCache) admit(clientRandom []byte, now time.Time) bool {
	key := string(clientRandom)

	c.mu.Lock()
	defer c.mu.Unlock()

	c.rotate(now)

	for _, gen := range c.generations {
		if _, seen := gen[key]; seen {
			return false
		}
	}

	// At the ceiling, retire the oldest generation rather than everything.
	// Replay protection is lost for the randoms in it and for nothing else.
	for c.entries >= c.maxEntries {
		if len(c.generations) == 1 {
			// One generation has filled the entire budget on its own, which
			// means arrivals outran the rotation interval. Start a new
			// generation first, so the full one becomes the oldest and is
			// retired in order — rather than clearing the set that holds the
			// most recent randoms, which is the cliff this design removed.
			c.generations = append(c.generations, make(map[string]struct{}))
		}
		c.dropOldest()
	}

	c.generations[len(c.generations)-1][key] = struct{}{}
	c.entries++
	return true
}

// rotate starts new generations for however many spans have elapsed, retiring
// the oldest as it goes.
func (c *replayCache) rotate(now time.Time) {
	if c.span <= 0 {
		return
	}
	for now.Sub(c.rotatedAt) >= c.span {
		c.rotatedAt = c.rotatedAt.Add(c.span)
		c.generations = append(c.generations, make(map[string]struct{}))
		for len(c.generations) > c.keep {
			c.dropOldest()
		}
		// A relay that was idle for a long time would otherwise spin through
		// every elapsed span; once everything is retired there is nothing left
		// to retire.
		if c.entries == 0 && len(c.generations) >= c.keep {
			c.rotatedAt = now
			return
		}
	}
}

func (c *replayCache) dropOldest() {
	c.entries -= len(c.generations[0])
	c.generations = c.generations[1:]
	if len(c.generations) == 0 {
		c.generations = []map[string]struct{}{make(map[string]struct{})}
	}
}
