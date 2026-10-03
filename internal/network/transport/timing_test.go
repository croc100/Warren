package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/croc100/warren/internal/network/tlsrec"
)

// The relay has two ways of answering a connection and they cost different
// amounts of time. A genuine Warren client is answered out of local state: an
// X25519 exchange and an ML-KEM encapsulation, microseconds. An unauthenticated
// connection is spliced, which costs a fresh TCP dial to the borrowed site plus
// whatever that site takes to produce its own ServerHello — a round trip, so
// tens of milliseconds for any site worth borrowing from.
//
// Left alone, that makes connections to one relay IP fall into two clearly
// separated latency modes, and a real web server does not answer some
// handshakes in a microsecond and the rest in 80 ms. The separation needs no
// decryption, no Warren client and no active probing: a passive observer timing
// ClientHello to ServerHello sees it.
//
// So the relay waits out the borrowed site's measured answer latency before its
// own ServerHello. These tests pin that it does, that the wait is measured from
// the arrival of the hello rather than added on top of the key exchange, and
// that a profile cannot use it to hold connections open indefinitely.

// clientHelloToServerHello returns the gap an on-path observer would measure
// between the client's first handshake record and the server's.
func clientHelloToServerHello(t *testing.T, server, client []tlsrec.Record) time.Duration {
	t.Helper()
	first := func(recs []tlsrec.Record) (time.Duration, bool) {
		for _, r := range recs {
			if r.Type == tlsrec.Handshake {
				return r.At, true
			}
		}
		return 0, false
	}
	clientAt, ok := first(client)
	if !ok {
		t.Fatal("tap saw no ClientHello")
	}
	serverAt, ok := first(server)
	if !ok {
		t.Fatal("tap saw no ServerHello")
	}
	return serverAt - clientAt
}

// measureAnswerLatency runs one Warren handshake through a record tap and
// reports what an observer in front of the relay would have timed.
func measureAnswerLatency(t *testing.T, flight *FlightProfile) time.Duration {
	t.Helper()
	relay, clientCfg := startRelayWithFlight(t, echoHandler, flight)
	tap := newRecordTap(t, relay)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := Dial(ctx, tap.addr, clientCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	roundTrip(t, conn, "hello")

	server, client := tap.records()
	return clientHelloToServerHello(t, server, client)
}

// TestRelayWaitsOutTheBorrowedSiteAnswerLatency is the property itself: a relay
// whose profile says the site takes 150 ms to answer must not answer in 2 ms.
func TestRelayWaitsOutTheBorrowedSiteAnswerLatency(t *testing.T) {
	const siteLatency = 150 * time.Millisecond

	flight := testFlight()
	flight.ServerHelloDelay = siteLatency
	slow := measureAnswerLatency(t, flight)

	// A little slack below the target: the tap timestamps a record when it sees
	// the bytes, and scheduling can shave a millisecond off either end.
	if floor := siteLatency - 20*time.Millisecond; slow < floor {
		t.Errorf("relay answered in %s; the site it claims to be takes %s, so anything under %s is a distinguisher",
			slow, siteLatency, floor)
	}

	// And the control: with nothing measured, nothing is waited for. Without
	// this the test would still pass if the relay simply became slow for some
	// unrelated reason.
	fast := measureAnswerLatency(t, testFlight())
	if fast > siteLatency/2 {
		t.Errorf("relay with no measured latency answered in %s, which is too slow for the comparison to mean anything", fast)
	}
	if slow-fast < siteLatency/2 {
		t.Errorf("answer latency barely moved with the profile: %s measured vs %s unmeasured", slow, fast)
	}
}

// TestServerHelloDelayIsMeasuredFromTheHelloNotAddedToIt covers the part that is
// easy to get subtly wrong. The relay does real work — an X25519 exchange and an
// ML-KEM encapsulation — between reading the hello and answering it. If the wait
// started after that work instead of from the hello's arrival, the relay would
// answer consistently *later* than the site it imitates, which is a
// distinguisher in the other direction and one that grows under CPU load.
func TestServerHelloDelayIsMeasuredFromTheHelloNotAddedToIt(t *testing.T) {
	const siteLatency = 200 * time.Millisecond

	flight := testFlight()
	flight.ServerHelloDelay = siteLatency
	got := measureAnswerLatency(t, flight)

	// The budget is generous because it has to absorb the tap, the loopback and
	// a loaded CI machine; what it will not absorb is the key exchange being
	// added to the wait rather than taken out of it on a slow machine.
	if ceiling := siteLatency + 120*time.Millisecond; got > ceiling {
		t.Errorf("relay answered in %s, over the %s ceiling: the wait looks additive rather than measured from the hello",
			got, ceiling)
	}
}

// TestServerHelloDelayIsCapped keeps a profile from becoming a way to hold
// connections open. The borrowed site is not under the relay's control, and a
// measurement taken across a bad moment — or against a site being deliberately
// slowed by someone who noticed it is being borrowed — must not turn every
// Warren handshake into a stall.
func TestServerHelloDelayIsCapped(t *testing.T) {
	flight := testFlight()
	flight.ServerHelloDelay = 30 * time.Second

	started := time.Now()
	got := measureAnswerLatency(t, flight)
	elapsed := time.Since(started)

	if got > maxServerHelloDelay+150*time.Millisecond {
		t.Errorf("relay waited %s; the cap is %s", got, maxServerHelloDelay)
	}
	if elapsed > 10*time.Second {
		t.Errorf("handshake took %s overall, so the cap is not being applied", elapsed)
	}
}

// TestProfileSiteMeasuresAnswerLatency covers the measurement rather than the
// replay: the number the relay waits out has to come from the site, so a site
// that is deliberately slow to answer must produce a profile that says so.
func TestProfileSiteMeasuresAnswerLatency(t *testing.T) {
	const siteLatency = 120 * time.Millisecond

	site := startSlowTLSSite(t, siteLatency)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	profile, err := ProfileSite(ctx, site, "www.example.com", ProfileOptions{SkipVerify: true})
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	t.Logf("measured %s", profile)

	if floor := siteLatency - 20*time.Millisecond; profile.ServerHelloDelay < floor {
		t.Errorf("measured answer latency %s for a site that stalls %s before answering",
			profile.ServerHelloDelay, siteLatency)
	}
	if profile.ServerHelloDelay > maxServerHelloDelay {
		t.Errorf("measured answer latency %s exceeds the cap %s, so the clamp is not applied at measurement time",
			profile.ServerHelloDelay, maxServerHelloDelay)
	}
}

// --- a borrowed site that is slow to answer ---------------------------------

// startSlowTLSSite runs a real TLS 1.3 server that stalls for `answerIn` before
// its ServerHello. A site on the far side of an ocean behaves like this, and
// the loopback does not, so a measurement test needs one that does it on
// purpose.
func startSlowTLSSite(t *testing.T, answerIn time.Duration) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "www.example.com"},
		DNSNames:     []string{"www.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS13,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func(raw net.Conn) {
				defer raw.Close()
				conn := tls.Server(&delayFirstWrite{Conn: raw, delay: answerIn}, cfg)
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(20 * time.Second))
				if err := conn.Handshake(); err != nil {
					return
				}
				buf := make([]byte, 512)
				if _, err := conn.Read(buf); err != nil {
					return
				}
				conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"))
			}(raw)
		}
	}()
	return ln.Addr().String()
}

// delayFirstWrite holds back a server's first flight, which for a TLS server is
// its ServerHello. Delaying at the socket rather than inside the TLS stack is
// what makes this measure the thing the profile measures: time on the wire.
type delayFirstWrite struct {
	net.Conn
	delay time.Duration
	once  sync.Once
}

func (d *delayFirstWrite) Write(p []byte) (int, error) {
	d.once.Do(func() { time.Sleep(d.delay) })
	return d.Conn.Write(p)
}
