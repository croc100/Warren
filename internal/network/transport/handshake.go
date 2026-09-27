package transport

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
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

	// tls13CipherSuite is echoed in the ServerHello. Every Chrome profile
	// offers TLS_AES_128_GCM_SHA256, so selecting it is always consistent
	// with the ClientHello we just parroted. It names nothing about how
	// Warren actually encrypts the session (that's ChaCha20-Poly1305 under
	// the derived key); it only has to be a suite the client offered.
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

// deriveTag computes the authentication tag embedded in the ClientHello's
// session_id. It binds the client's random *and* its key share, so a censor
// who replays a captured hello with a substituted key share (hoping to have
// the relay answer it) fails the check instead.
func deriveTag(authSS, clientRandom, clientShare []byte) []byte {
	mac := hmac.New(sha256.New, authSS)
	mac.Write([]byte("warren-tag-v1"))
	mac.Write(clientRandom)
	mac.Write(clientShare)
	return mac.Sum(nil)[:tagLen]
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

// serverAccept validates a client's tag and produces everything the relay
// needs to answer: the ServerHello bytes and the derived session key.
func serverAccept(identityKey, clientRandom, sessionID, clientShare []byte) (serverHello, sessionKey []byte, err error) {
	if len(identityKey) != x25519KeyLen {
		return nil, nil, ErrIdentityMissing
	}
	identity, err := ecdh.X25519().NewPrivateKey(identityKey)
	if err != nil {
		return nil, nil, fmt.Errorf("transport: relay identity key: %w", err)
	}

	encapKeyBytes, clientECDHEBytes := splitClientShare(clientShare)
	clientECDHE, err := ecdh.X25519().NewPublicKey(clientECDHEBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("transport: client ephemeral key: %w", err)
	}
	authSS, err := identity.ECDH(clientECDHE)
	if err != nil {
		return nil, nil, fmt.Errorf("transport: derive auth secret: %w", err)
	}

	if !hmac.Equal(deriveTag(authSS, clientRandom, clientShare), sessionID[:tagLen]) {
		return nil, nil, errTagMismatch
	}

	encapKey, err := mlkem.NewEncapsulationKey768(encapKeyBytes)
	if err != nil {
		// A well-formed hybrid share whose ML-KEM half doesn't decode is
		// not something a real browser sends; treat it like any other
		// non-Warren input and let the caller splice to the real site.
		return nil, nil, ErrNoHybridShare
	}
	mlkemSS, ciphertext := encapKey.Encapsulate()

	serverECDHE, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ecdheSS, err := serverECDHE.ECDH(clientECDHE)
	if err != nil {
		return nil, nil, err
	}

	serverShare := make([]byte, 0, hybridServerShareLen)
	serverShare = append(serverShare, ciphertext...)
	serverShare = append(serverShare, serverECDHE.PublicKey().Bytes()...)

	serverRandom := make([]byte, 32)
	if _, err := rand.Read(serverRandom); err != nil {
		return nil, nil, err
	}

	key, err := deriveSessionKey(mlkemSS, ecdheSS, authSS, clientRandom, serverRandom, clientShare, serverShare)
	if err != nil {
		return nil, nil, err
	}
	return buildServerHello(sessionID, serverRandom, serverShare), key, nil
}

var errTagMismatch = errors.New("transport: client hello tag mismatch")

// buildServerHello emits a TLS 1.3 ServerHello record carrying the hybrid
// key_share. Everything about its shape — legacy version 0x0303, the echoed
// session_id, supported_versions announcing TLS 1.3, key_share carrying
// ciphertext||x25519 for group X25519MLKEM768 — is what a real TLS 1.3 server
// answering our parroted ClientHello would send.
func buildServerHello(sessionIDEcho, serverRandom, serverShare []byte) []byte {
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
	body = appendUint16(body, tls13CipherSuite)
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
// ServerHello handshake body.
func parseServerHello(body []byte) (serverRandom, serverShare []byte, err error) {
	// server_hello(1) + length(3) + legacy_version(2) + random(32) + session_id_len(1)
	if len(body) < 39 || body[0] != 0x02 {
		return nil, nil, ErrBadServerHello
	}
	p := body[4:]
	if len(p) < 35 {
		return nil, nil, ErrBadServerHello
	}
	serverRandom = append([]byte(nil), p[2:34]...)
	sidLen := int(p[34])
	p = p[35:]
	if len(p) < sidLen+2+1+2 {
		return nil, nil, ErrBadServerHello
	}
	p = p[sidLen+3:] // session_id + cipher_suite(2) + compression(1)

	extLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) < extLen {
		return nil, nil, ErrBadServerHello
	}
	for ext := p[:extLen]; len(ext) >= 4; {
		extType := uint16(ext[0])<<8 | uint16(ext[1])
		bodyLen := int(ext[2])<<8 | int(ext[3])
		if len(ext) < 4+bodyLen {
			return nil, nil, ErrBadServerHello
		}
		payload := ext[4 : 4+bodyLen]
		ext = ext[4+bodyLen:]

		if extType != extKeyShare || len(payload) < 4 {
			continue
		}
		group := uint16(payload[0])<<8 | uint16(payload[1])
		shareLen := int(payload[2])<<8 | int(payload[3])
		if group != uint16(utls.X25519MLKEM768) || len(payload) < 4+shareLen || shareLen != hybridServerShareLen {
			return nil, nil, ErrBadServerHello
		}
		return serverRandom, append([]byte(nil), payload[4:4+shareLen]...), nil
	}
	return nil, nil, ErrBadServerHello
}

func appendUint16(b []byte, v uint16) []byte { return append(b, byte(v>>8), byte(v)) }

// replayCache remembers recently-seen ClientHello randoms. A replayed hello
// carries a valid tag by construction (the tag is a function of the hello), so
// without this a censor could capture one genuine hello and replay it to
// confirm the relay answers differently than the real site does. A replay is
// treated exactly like an unauthenticated connection: spliced to the real site.
type replayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
	ttl  time.Duration
	max  int
}

func newReplayCache() *replayCache {
	return &replayCache{seen: make(map[string]time.Time), ttl: 10 * time.Minute, max: 1 << 16}
}

// admit records the random and reports whether this is the first time we've
// seen it.
func (c *replayCache) admit(clientRandom []byte) bool {
	key := string(clientRandom)
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	if seenAt, ok := c.seen[key]; ok && now.Sub(seenAt) < c.ttl {
		return false
	}
	if len(c.seen) >= c.max {
		for k, t := range c.seen {
			if now.Sub(t) >= c.ttl {
				delete(c.seen, k)
			}
		}
		// Still full of live entries: drop the whole set rather than grow
		// without bound. Forgetting is the safe direction — it costs replay
		// protection for old randoms, not confidentiality.
		if len(c.seen) >= c.max {
			c.seen = make(map[string]time.Time, c.max)
		}
	}
	c.seen[key] = now
	return true
}
