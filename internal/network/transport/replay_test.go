package transport

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

// TestTagStopsVerifyingOnceItsWindowPasses is the property the replay cache
// could never give on its own.
//
// A cache of randoms already seen is a memory budget, and every memory budget
// expires. Before the tag carried a clock, a censor holding one captured hello
// only had to wait out the cache: the tag is a function of the hello, so it
// would verify again and the relay would answer as Warren where the borrowed
// site would have answered as itself. Waiting is free, which made the cache's
// TTL the real lifetime of the defence.
func TestTagStopsVerifyingOnceItsWindowPasses(t *testing.T) {
	priv, pub, err := GenerateServerIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	keys, err := newClientKeys(pub)
	if err != nil {
		t.Fatalf("client keys: %v", err)
	}

	clientRandom := randomBytes(t, 32)
	sessionID := make([]byte, sessionIDLen)

	minted := time.Now()
	copy(sessionID, deriveTag(keys.authSS, clientRandom, keys.share, tagWindowIndex(minted)))

	if _, err := serverAccept(priv, clientRandom, sessionID, keys.share, minted, 0); err != nil {
		t.Fatalf("a freshly minted tag was rejected: %v", err)
	}

	// Well past every window the relay will accept. A captured hello is now
	// inert on its own terms, with no cache lookup involved.
	late := minted.Add(tagAcceptanceSpan + 2*tagWindow)
	if _, err := serverAccept(priv, clientRandom, sessionID, keys.share, late, 0); err == nil {
		t.Fatalf("a tag minted %s earlier still verified; a captured hello stays replayable forever once the cache forgets it",
			late.Sub(minted))
	}
}

// TestTagToleratesClockSkewWithinTheSlack is the other side of that trade. The
// freshness binding costs reachability for anyone whose clock is wrong, and the
// relay cannot tell a skewed client from a forged tag — it splices both — so
// the tolerance has to be real rather than nominal.
func TestTagToleratesClockSkewWithinTheSlack(t *testing.T) {
	priv, pub, err := GenerateServerIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	keys, err := newClientKeys(pub)
	if err != nil {
		t.Fatalf("client keys: %v", err)
	}
	clientRandom := randomBytes(t, 32)

	// Pin the client to the middle of a window so the test measures the slack
	// rather than where the boundary happens to fall.
	base := time.Unix(tagWindowIndex(time.Now())*int64(tagWindow/time.Second), 0).Add(tagWindow / 2)

	sessionID := make([]byte, sessionIDLen)
	copy(sessionID, deriveTag(keys.authSS, clientRandom, keys.share, tagWindowIndex(base)))

	for _, skew := range []time.Duration{
		-tagWindow + time.Minute,
		-tagWindow / 2,
		0,
		tagWindow / 2,
		tagWindow - time.Minute,
	} {
		relayNow := base.Add(skew)
		if _, err := serverAccept(priv, clientRandom, sessionID, keys.share, relayNow, 0); err != nil {
			t.Errorf("a client %s out of step with the relay was refused: %v", skew, err)
		}
	}
}

// TestTagIsUnchangedOnTheWire guards the reason this binding was acceptable at
// all: the window is an input to the HMAC, never a field, so the hello keeps
// the size and structure it had. A freshness field would have been a Warren
// marker in a packet whose whole job is to look like a browser's.
func TestTagIsUnchangedOnTheWire(t *testing.T) {
	_, pub, err := GenerateServerIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	keys, err := newClientKeys(pub)
	if err != nil {
		t.Fatalf("client keys: %v", err)
	}
	clientRandom := randomBytes(t, 32)

	a := deriveTag(keys.authSS, clientRandom, keys.share, 100)
	b := deriveTag(keys.authSS, clientRandom, keys.share, 101)

	if len(a) != tagLen || len(b) != tagLen {
		t.Fatalf("tag lengths %d and %d, want %d", len(a), len(b), tagLen)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two different windows produced the same tag; the window is not actually bound in")
	}
}

// --- the cache itself ------------------------------------------------------

func TestReplayCacheRejectsARepeat(t *testing.T) {
	now := time.Now()
	c := newReplayCacheWith(tagWindow, 4, replayCacheMaxEntries, now)

	r := randomBytes(t, 32)
	if !c.admit(r, now) {
		t.Fatal("first sighting was rejected")
	}
	if c.admit(r, now) {
		t.Fatal("a repeat was admitted")
	}
	if c.admit(r, now.Add(tagWindow)) {
		t.Fatal("a repeat one window later was admitted, inside the retention span")
	}
}

// TestReplayCacheUnderPressureRetiresOldestOnly is the regression that matters
// on a relay that is doing well rather than one under attack.
//
// The previous cache swept for expired entries when it hit its ceiling and, if
// that freed nothing, threw the whole map away. A relay busy enough to fill it
// inside one TTL therefore forgot *every* random it had seen, periodically and
// silently, leaving no replay protection at all until it refilled. Here the
// ceiling costs the oldest generation and nothing else, so what was seen most
// recently — the part a replay is most likely to target — survives.
func TestReplayCacheUnderPressureRetiresOldestOnly(t *testing.T) {
	const maxEntries = 64
	now := time.Now()
	c := newReplayCacheWith(tagWindow, 4, maxEntries, now)

	// Fill the first generation, then move into a second and fill past the
	// ceiling so eviction has to happen.
	oldest := make([][]byte, 0, maxEntries/2)
	for i := 0; i < maxEntries/2; i++ {
		r := randomBytes(t, 32)
		oldest = append(oldest, r)
		c.admit(r, now)
	}

	now = now.Add(tagWindow)
	recent := make([][]byte, 0, maxEntries)
	for i := 0; i < maxEntries; i++ {
		r := randomBytes(t, 32)
		recent = append(recent, r)
		c.admit(r, now)
	}

	// Everything recent must still be remembered: this is the set a censor
	// replaying a freshly captured hello would be drawing from.
	forgotten := 0
	for _, r := range recent {
		if c.admit(r, now) {
			forgotten++
		}
	}
	if forgotten > 0 {
		t.Errorf("%d of %d recent randoms were forgotten under pressure; eviction is not oldest-first", forgotten, len(recent))
	}
	if c.entries > maxEntries+len(recent) {
		t.Errorf("cache holds %d entries against a ceiling of %d; it is not bounded", c.entries, maxEntries)
	}

	// And the eviction path has to have actually run, or the assertion above
	// proves nothing: the oldest generation is the one that should have paid.
	evicted := 0
	for _, r := range oldest {
		if c.admit(r, now) {
			evicted++
		}
	}
	if evicted == 0 {
		t.Fatalf("nothing was evicted, so this test never exercised the ceiling: %d entries, ceiling %d", c.entries, maxEntries)
	}
}

// TestReplayCacheForgetsPastTheAcceptanceSpan pins that retention is sized to
// the tag's acceptance span and not to an arbitrary number: remembering longer
// costs memory for randoms whose tags no longer verify anyway, and remembering
// less would leave a gap inside the span where a replay works.
func TestReplayCacheForgetsPastTheAcceptanceSpan(t *testing.T) {
	now := time.Now()
	c := newReplayCache()
	// newReplayCache bases its rotation on time.Now(); align the test's clock
	// with it rather than assuming they agree.
	c.rotatedAt = now

	r := randomBytes(t, 32)
	if !c.admit(r, now) {
		t.Fatal("first sighting was rejected")
	}

	// Anywhere inside the span the cache still has to be the thing refusing it,
	// because the tag is still valid there.
	if c.admit(r, now.Add(tagAcceptanceSpan-time.Minute)) {
		t.Errorf("random was forgotten after %s, inside the %s acceptance span",
			tagAcceptanceSpan-time.Minute, tagAcceptanceSpan)
	}

	// Past the span the tag no longer verifies, so the cache is free to forget
	// and bounded memory follows from that rather than from a guess.
	if !c.admit(r, now.Add(2*tagAcceptanceSpan)) {
		t.Errorf("cache still holds randoms %s old, well past the %s the tag stays valid for",
			2*tagAcceptanceSpan, tagAcceptanceSpan)
	}
}

// TestReplayCacheRotationIsBoundedWhenIdle covers a long-idle relay: rotation
// walks forward one span at a time, so a relay that saw nothing for a week must
// not spend that walk on its next connection.
func TestReplayCacheRotationIsBoundedWhenIdle(t *testing.T) {
	now := time.Now()
	c := newReplayCacheWith(tagWindow, 4, replayCacheMaxEntries, now)

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.admit(randomBytes(t, 32), now.Add(365*24*time.Hour))
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("admit after a year of idleness did not return; rotation is walking every elapsed span")
	}
	if len(c.generations) > 4 {
		t.Errorf("cache holds %d generations after an idle year, want at most 4", len(c.generations))
	}
}

// TestReplayCacheCeilingHoldsWithinOneGeneration covers the case where
// arrivals outrun the rotation interval, so the whole budget is consumed by a
// single generation. Retiring "the oldest generation" is not defined when
// there is only one, and the answer must not be to clear it: that is the set
// holding the most recent randoms, which is exactly what a replay targets.
func TestReplayCacheCeilingHoldsWithinOneGeneration(t *testing.T) {
	const maxEntries = 32
	now := time.Now()
	c := newReplayCacheWith(time.Hour, 4, maxEntries, now) // rotation will not fire

	var last [][]byte
	for i := 0; i < maxEntries*4; i++ {
		r := randomBytes(t, 32)
		last = append(last, r)
		if !c.admit(r, now) {
			t.Fatalf("a fresh random was refused at insert %d", i)
		}
	}

	if c.entries > 2*maxEntries {
		t.Errorf("cache holds %d entries against a ceiling of %d without rotating; memory is not bounded",
			c.entries, maxEntries)
	}

	// The most recent arrivals must still be remembered.
	recent := last[len(last)-maxEntries/2:]
	forgotten := 0
	for _, r := range recent {
		if c.admit(r, now) {
			forgotten++
		}
	}
	if forgotten > 0 {
		t.Errorf("%d of the %d most recent randoms were forgotten; the ceiling cleared the newest set rather than the oldest",
			forgotten, len(recent))
	}
}
