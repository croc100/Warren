package transport

import (
	"bufio"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// echoOnceSite stands up a loopback TCP server that, per connection, reads one
// chunk, writes it back, and closes. It stands in for the borrowed site on the
// splice path without the cost of a full TLS server — the splice relays bytes
// and does not care that they are TLS.
func echoOnceSite(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				b := make([]byte, 64)
				n, err := c.Read(b)
				if err != nil {
					return
				}
				c.Write(b[:n])
			}(c)
		}
	}()
	return ln
}

// clientRelayPair returns a connected client end and the relay-side raw
// connection plus its buffered reader, the way serveConn holds them before
// splicing.
func clientRelayPair(t *testing.T) (client net.Conn, raw net.Conn, br *bufio.Reader) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	select {
	case raw = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("relay side never accepted")
	}
	return client, raw, bufio.NewReaderSize(raw, maxRecordLen+recordHeaderLen)
}

// TestWarmPoolReusesDialedConnection is the mechanism in the small: after a
// top-up against a reachable site, the pool hands out a live connection.
func TestWarmPoolReusesDialedConnection(t *testing.T) {
	site := echoOnceSite(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool := newWarmPool(site.Addr().String(), 2, warmConnTTL)
	defer pool.drain()
	pool.topUp(ctx)

	if n := pool.count(); n == 0 {
		t.Fatal("pool did not fill against a reachable site")
	}

	c := pool.get()
	if c == nil {
		t.Fatal("pool handed out nothing after a successful top-up")
	}
	defer c.Close()

	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatalf("write to pooled connection: %v", err)
	}
	b := make([]byte, 1)
	if _, err := io.ReadFull(c, b); err != nil || b[0] != 'x' {
		t.Fatalf("pooled connection did not reach the site: got %q err %v", b, err)
	}
}

// TestWarmPoolDiscardsStaleConnections guards the TTL: a connection older than
// the TTL is never handed out, so the splice does not inherit one the site is
// about to close under it.
func TestWarmPoolDiscardsStaleConnections(t *testing.T) {
	site := echoOnceSite(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool := newWarmPool(site.Addr().String(), 2, 20*time.Millisecond)
	defer pool.drain()
	pool.topUp(ctx)
	if pool.count() == 0 {
		t.Fatal("pool did not fill")
	}

	time.Sleep(60 * time.Millisecond) // past the TTL

	if c := pool.get(); c != nil {
		c.Close()
		t.Fatal("pool handed out a connection older than its TTL")
	}
}

// TestWarmPoolDiscardsConnectionsTheSiteClosed guards the hand-out health check,
// which is what keeps the pool from handing the splice a connection the site has
// already reset — the case the TTL alone would miss (DESIGN §15: a borrowed site
// that starts dropping the relay).
func TestWarmPoolDiscardsConnectionsTheSiteClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	// A site that accepts and immediately hangs up: every pooled connection is
	// dead on arrival.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool := newWarmPool(ln.Addr().String(), 2, warmConnTTL)
	defer pool.drain()
	pool.topUp(ctx)

	time.Sleep(100 * time.Millisecond) // let the site's FINs arrive

	if c := pool.get(); c != nil {
		c.Close()
		t.Fatal("pool handed out a connection the site had already closed")
	}
}

// TestSpliceUsesWarmConnectionWhenFreshDialWouldFail is the load-bearing test
// for H3, and a canary for it: it points the splice's fresh-dial fallback at an
// address that refuses connections, so the only way a byte reaches the borrowed
// site is through a connection the pool dialed ahead of time. If the splice ever
// stops consulting the pool, the echo never comes back and this fails — which is
// what proves the warm path is doing the work, not sitting dead beside a splice
// that dials fresh every time anyway.
func TestSpliceUsesWarmConnectionWhenFreshDialWouldFail(t *testing.T) {
	site := echoOnceSite(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool := newWarmPool(site.Addr().String(), 2, warmConnTTL)
	defer pool.drain()
	pool.topUp(ctx)
	if pool.count() == 0 {
		t.Fatal("warm pool did not fill against a reachable site")
	}

	// An address nothing listens on, so a fresh dial from the splice fails.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := dead.Addr().String()
	dead.Close()

	client, raw, br := clientRelayPair(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		spliceToFallback(ctx, raw, br, deadAddr, pool)
	}()

	client.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("write to relay: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("no echo came back: the splice did not use a warm connection, and a fresh dial to %s refuses: %v", deadAddr, err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo via warm connection = %q, want %q", buf, "ping")
	}
	client.Close()

	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("splice did not finish")
	}
}

// TestSpliceDialsFreshWhenPoolIsEmpty is the other half: with no warm connection
// available the splice must still reach the borrowed site by dialing it. Without
// this, the test above could pass for the wrong reason — a splice that only ever
// worked via the pool would be a regression for every real deployment, where the
// pool is best-effort and often empty.
func TestSpliceDialsFreshWhenPoolIsEmpty(t *testing.T) {
	site := echoOnceSite(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// An empty pool with no address: it never fills, so get always returns nil.
	pool := newWarmPool("", 0, warmConnTTL)

	client, raw, br := clientRelayPair(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		spliceToFallback(ctx, raw, br, site.Addr().String(), pool)
	}()

	client.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("write to relay: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("no echo via fresh dial: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo via fresh dial = %q, want %q", buf, "ping")
	}
	client.Close()

	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("splice did not finish")
	}
}
