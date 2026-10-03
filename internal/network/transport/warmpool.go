package transport

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// Warm upstream connections (ROADMAP H3).
//
// A relay has two answer paths and a censor can time both from one address: a
// tagged client is answered out of local state, while everyone else is spliced
// to the borrowed site. The ServerHello wait (flight.go) already equalises the
// site's *answer* time between the two, but the splice additionally pays a fresh
// TCP connect to the site that the tagged path does not — one round trip the
// tagged client never spends. Unclosed, connections to one relay IP still split
// into two latency modes, just by a smaller margin, and that split is the
// cheapest distinguisher there is: it needs no decryption, no key, and no probe
// beyond one ordinary handshake, only a clock and enough samples.
//
// Making the tagged path *wait* that extra round trip would close the split
// between the relay's two paths, but only by opening one against the borrowed
// site itself: a tagged client would then answer a round trip slower than the
// real site does over the same comparison. So instead the splice stops paying
// the connect on the hot path. A small pool of connections to the borrowed site
// is kept dialed in the background; the splice takes one when a connection
// arrives rather than dialing then, so the censor's ClientHello is forwarded
// without a connect in front of it. All three latencies — tagged, spliced, and
// a direct visit to the site — then converge on the site's own answer time.
//
// This is best-effort by design. An idle TCP connection to the site can be
// closed under it at any time (keep-alive timeouts, the site shedding load, the
// site starting to reject this relay — DESIGN §15), so every connection is
// health-checked at hand-out and a pool that is empty or stale falls straight
// back to dialing fresh, which is exactly the behaviour before this existed.
// The cost is a footprint the borrowed site's operator can see: up to warmPool
// idle connections held open continuously, which is part of what a relay
// operator owes that site (ROADMAP H7, H24).
const (
	// warmPoolSize is how many connections to the borrowed site the relay keeps
	// ready. Small on purpose: it only has to cover the connect latency of the
	// probes and stray clients arriving between refills, not every connection,
	// and each one is a connection the site's operator sees held open.
	warmPoolSize = 4

	// warmConnTTL is how long a pooled connection may sit before it is retired
	// unused. It is shorter than a typical server's idle keep-alive timeout so
	// the relay discards a connection before the site would, rather than handing
	// the splice one the site has already half-closed; the hand-out health check
	// is the backstop for when it does not.
	warmConnTTL = 10 * time.Second

	// warmRefillInterval is how often the background filler tops the pool back
	// up to warmPoolSize and prunes stale entries.
	warmRefillInterval = 2 * time.Second

	// warmDialTimeout bounds a single background dial to the site.
	warmDialTimeout = 5 * time.Second

	// warmHealthProbe is how long the hand-out check waits for the connection to
	// prove it is still idle (see connStillIdle).
	warmHealthProbe = 2 * time.Millisecond
)

type warmConn struct {
	conn     net.Conn
	dialedAt time.Time
}

// warmPool keeps a bounded set of pre-dialed connections to one borrowed site.
// The zero value is not usable; call newWarmPool.
type warmPool struct {
	addr   string
	size   int
	ttl    time.Duration
	dialer net.Dialer

	mu    sync.Mutex
	conns []warmConn
}

func newWarmPool(addr string, size int, ttl time.Duration) *warmPool {
	return &warmPool{
		addr:   addr,
		size:   size,
		ttl:    ttl,
		dialer: net.Dialer{Timeout: warmDialTimeout},
	}
}

// run keeps the pool topped up until ctx is cancelled, then closes every
// connection it is holding. A pool with no address does nothing, so a relay
// configured without a fallback neither dials nor leaks goroutines.
func (p *warmPool) run(ctx context.Context) {
	if p == nil || p.addr == "" {
		return
	}
	t := time.NewTicker(warmRefillInterval)
	defer t.Stop()

	p.topUp(ctx)
	for {
		select {
		case <-ctx.Done():
			p.drain()
			return
		case <-t.C:
			p.topUp(ctx)
		}
	}
}

// get returns a healthy, non-stale connection to the site, or nil if the pool
// cannot supply one — in which case the caller dials fresh. Stale or dead
// connections are closed and skipped. The health check runs outside the lock so
// one slow connection does not stall the others.
func (p *warmPool) get() net.Conn {
	if p == nil {
		return nil
	}
	for {
		p.mu.Lock()
		if len(p.conns) == 0 {
			p.mu.Unlock()
			return nil
		}
		wc := p.conns[len(p.conns)-1]
		p.conns = p.conns[:len(p.conns)-1]
		p.mu.Unlock()

		if time.Since(wc.dialedAt) > p.ttl || !connStillIdle(wc.conn) {
			wc.conn.Close()
			continue
		}
		return wc.conn
	}
}

// topUp dials until the pool is full, pruning stale entries first. A failed dial
// means the site is unreachable right now; it stops and tries again next tick
// rather than spinning, so a down site does not become a busy loop.
func (p *warmPool) topUp(ctx context.Context) {
	p.pruneStale()
	for {
		p.mu.Lock()
		need := p.size - len(p.conns)
		p.mu.Unlock()
		if need <= 0 {
			return
		}

		c, err := p.dialer.DialContext(ctx, "tcp", p.addr)
		if err != nil {
			return
		}

		p.mu.Lock()
		if len(p.conns) < p.size {
			p.conns = append(p.conns, warmConn{conn: c, dialedAt: time.Now()})
			p.mu.Unlock()
		} else {
			// Lost a race with another topUp; keep the pool at its ceiling.
			p.mu.Unlock()
			c.Close()
		}
	}
}

// pruneStale drops connections older than the TTL. The hand-out check in get
// catches a connection the site closed early; this bounds how long an unused one
// lingers even if it never gets handed out.
func (p *warmPool) pruneStale() {
	p.mu.Lock()
	defer p.mu.Unlock()
	kept := p.conns[:0]
	for _, wc := range p.conns {
		if time.Since(wc.dialedAt) > p.ttl {
			wc.conn.Close()
			continue
		}
		kept = append(kept, wc)
	}
	p.conns = kept
}

// count reports how many connections the pool is currently holding. It is used
// by the tests to confirm a top-up actually dialed; the splice path uses get,
// which validates before handing one out.
func (p *warmPool) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.conns)
}

func (p *warmPool) drain() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, wc := range p.conns {
		wc.conn.Close()
	}
	p.conns = nil
}

// connStillIdle reports whether a pooled connection is still a clean splice
// target. A borrowed TLS site never speaks before the ClientHello, so a healthy
// idle connection has nothing for us to read and the probe read times out —
// which is the only outcome that keeps it. Anything else means it is no longer
// usable: an EOF or reset is the site having closed it, and actual data would be
// a byte we cannot un-read and hand the splice cleanly.
func connStillIdle(c net.Conn) bool {
	if err := c.SetReadDeadline(time.Now().Add(warmHealthProbe)); err != nil {
		return false
	}
	var b [1]byte
	_, err := c.Read(b[:])
	if clearErr := c.SetReadDeadline(time.Time{}); clearErr != nil {
		return false
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
