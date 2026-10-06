package transport

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// Tests for ROADMAP H8: what the relay does when its borrowed site stops
// answering.

// deadAddr returns a loopback address nothing is listening on, so a dial to it
// is refused.
func deadAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// TestWarmPoolTracksSiteReachability pins the verdict the relay refuses on: one
// failed dial is tolerated, siteDownAfter in a row marks the site down, and a
// single success brings it back.
func TestWarmPoolTracksSiteReachability(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool := newWarmPool(deadAddr(t), 2, warmConnTTL)
	defer pool.drain()

	if !pool.siteReachable() {
		t.Fatal("a pool that has not dialed yet reports the site down")
	}
	pool.topUp(ctx)
	if !pool.siteReachable() {
		t.Fatal("one failed dial marked the site down; a dropped SYN would take the relay offline")
	}
	for i := 1; i < siteDownAfter; i++ {
		pool.topUp(ctx)
	}
	if pool.siteReachable() {
		t.Fatalf("site still reported reachable after %d consecutive failed dials", siteDownAfter)
	}

	pool.addr = echoOnceSite(t).Addr().String()
	pool.topUp(ctx)
	if !pool.siteReachable() {
		t.Fatal("a successful dial did not bring the site back")
	}
}

// TestWarmPoolIgnoresDialsAbandonedOnShutdown guards against a relay talking
// itself into "site down" while it is stopping: a dial cut short by the relay's
// own context says nothing about the site.
func TestWarmPoolIgnoresDialsAbandonedOnShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	pool := newWarmPool(deadAddr(t), 2, warmConnTTL)
	for i := 0; i < siteDownAfter+1; i++ {
		pool.topUp(ctx)
	}
	if !pool.siteReachable() {
		t.Fatal("dials abandoned on shutdown were counted against the site")
	}
}

// TestSpliceResetsWhenSiteUnreachable covers the connection that is already in
// flight when the site goes away: it has handed over a ClientHello, and the
// relay must not answer that with a clean FIN.
func TestSpliceResetsWhenSiteUnreachable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool := newWarmPool("", 0, warmConnTTL)
	client, raw, br := clientRelayPair(t)

	msg := []byte("GET / HTTP/1.0\r\n\r\n")
	dead := deadAddr(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Pull the request into br first, as serveConn's peek does. Closing a
		// socket with unread data in its receive buffer makes the kernel send an
		// RST on its own, which would let this test pass against a splice that
		// closes with a FIN.
		raw.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := br.Peek(len(msg)); err != nil {
			raw.Close()
			return
		}
		raw.SetReadDeadline(time.Time{})
		spliceToFallback(ctx, raw, br, dead, pool)
	}()

	if _, err := client.Write(msg); err != nil {
		t.Fatalf("write to relay: %v", err)
	}
	client.SetReadDeadline(time.Now().Add(8 * time.Second))
	_, err := io.ReadFull(client, make([]byte, 1))
	if !isConnReset(err) {
		t.Fatalf("got %v, want a reset when the borrowed site cannot be reached", err)
	}

	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("splice did not finish")
	}
}

// TestRelayRefusesEveryoneWhileSiteIsDown is H8 end to end: once the borrowed
// site stops answering, a genuine Warren client is refused exactly as a probe
// is — both reset — and when the site comes back the relay serves again without
// a restart. The genuine client is the half that matters: a relay that went on
// serving it while probes got nothing would be one address with two behaviours.
func TestRelayRefusesEveryoneWhileSiteIsDown(t *testing.T) {
	// Reserve an address for the site, then leave it unbound: the site starts
	// out down.
	siteAddr := deadAddr(t)

	priv, pub, err := GenerateServerIdentity()
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
	go Serve(ctx, ln, Config{
		ServerPrivateKey: priv,
		FallbackSNI:      "www.example.com",
		FallbackAddr:     siteAddr,
		Flight:           testFlight(),
	}, echoHandler)

	relayAddr := ln.Addr().String()
	clientCfg := Config{ServerPublicKey: pub, FallbackSNI: "www.example.com"}

	// The background filler needs siteDownAfter failed dials, one per refill
	// tick, before the relay starts refusing.
	refuseBy := time.Now().Add(time.Duration(siteDownAfter+2) * warmRefillInterval)

	// A probe is reset without being read.
	for {
		probe, err := net.Dial("tcp", relayAddr)
		if err != nil {
			t.Fatalf("dial relay: %v", err)
		}
		probe.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err = probe.Read(make([]byte, 1))
		probe.Close()
		if isConnReset(err) {
			break
		}
		if time.Now().After(refuseBy) {
			t.Fatalf("relay never started refusing with its site down; last probe got %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// A genuine client is refused too.
	dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := Dial(dctx, relayAddr, clientCfg)
	dcancel()
	if err == nil {
		conn.Close()
		t.Fatal("a Warren client was served while the borrowed site was down")
	}

	// Bring the site up at the address the relay was configured with.
	site, err := net.Listen("tcp", siteAddr)
	if err != nil {
		t.Skipf("could not rebind the site's address to test recovery: %v", err)
	}
	t.Cleanup(func() { site.Close() })
	go func() {
		for {
			c, err := site.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()

	recoverBy := time.Now().Add(3 * warmRefillInterval)
	for {
		dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := Dial(dctx, relayAddr, clientCfg)
		dcancel()
		if err == nil {
			roundTrip(t, conn, "back")
			conn.Close()
			return
		}
		if time.Now().After(recoverBy) {
			t.Fatalf("relay did not serve again after its site came back: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
