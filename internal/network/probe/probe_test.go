package probe

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/croc100/warren/internal/network/transport"
)

const testSNI = "www.example.com"

// startBorrowedSite runs a real TLS 1.3 server standing in for the site a relay
// borrows its identity from. It has to be a real TLS server, not an echo socket:
// the whole point of the harness is comparing against a genuine handshake,
// including the certificate flight whose absence we are trying to measure. The
// certificate is RSA so the flight is a realistic couple of kilobytes rather
// than the unusually small one a compact ECDSA cert would produce.
func startBorrowedSite(t *testing.T) string {
	t.Helper()
	return startBorrowedSiteWith(t, false)
}

// startBorrowedSiteWithPostHandshakeRecords is the same site, but one that
// sends the client something once the handshake finishes and before any
// request arrives — the window session tickets land in. The measurement of that
// window is only testable against a site that puts something in it.
func startBorrowedSiteWithPostHandshakeRecords(t *testing.T) string {
	t.Helper()
	return startBorrowedSiteWith(t, true)
}

func startBorrowedSiteWith(t *testing.T, postHandshake bool) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: testSNI},
		DNSNames:     []string{testSNI},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
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
				c.SetDeadline(time.Now().Add(5 * time.Second))
				if postHandshake {
					if tc, ok := c.(*tls.Conn); ok {
						if err := tc.Handshake(); err != nil {
							return
						}
					}
					c.Write(make([]byte, 180))
					c.Write(make([]byte, 180))
				}
				buf := make([]byte, 1024)
				if _, err := c.Read(buf); err != nil {
					return
				}
				c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"))
			}(c)
		}
	}()
	return ln.Addr().String()
}

// startRelay brings up a relay that has measured the site it borrows from. The
// measurement is not optional: transport.Serve refuses to run without a usable
// profile, because a relay that answers its ServerHello with silence where a real
// server sends a certificate flight is separable on record sizes alone.
func startRelay(t *testing.T, fallbackAddr string) (addr string, clientCfg transport.Config) {
	t.Helper()
	return startRelayShaped(t, fallbackAddr, nil)
}

// startRelayShaped is startRelay with a hook to damage the measured profile
// before the relay serves from it. It exists for the canary tests: a harness
// that cannot be shown to fail is not evidence that anything passed.
func startRelayShaped(t *testing.T, fallbackAddr string, damage func(*transport.FlightProfile)) (addr string, clientCfg transport.Config) {
	t.Helper()
	priv, pub, err := transport.GenerateServerIdentity()
	if err != nil {
		t.Fatalf("relay identity: %v", err)
	}

	ctxProfile, cancelProfile := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelProfile()
	flight, err := transport.ProfileSite(ctxProfile, fallbackAddr, testSNI, transport.ProfileOptions{
		SkipVerify: true, // the test site is self-signed
	})
	if err != nil {
		t.Fatalf("profile borrowed site: %v", err)
	}
	if err := flight.Validate(); err != nil {
		t.Fatalf("measured profile is unusable: %v", err)
	}
	if damage != nil {
		damage(flight)
		if err := flight.Validate(); err != nil {
			t.Fatalf("damaged profile no longer passes Validate, so the relay would refuse to serve and the canary would test nothing: %v", err)
		}
	}
	t.Logf("measured %s", flight)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go transport.Serve(ctx, ln, transport.Config{
		ServerPrivateKey: priv,
		FallbackSNI:      testSNI,
		FallbackAddr:     fallbackAddr,
		Flight:           flight,
	}, func(conn net.Conn) {
		defer conn.Close()
		io.Copy(conn, conn)
	})
	return ln.Addr().String(), transport.Config{ServerPublicKey: pub, FallbackSNI: testSNI}
}

// driveWarren runs one complete Warren session, for Capture.
func driveWarren(cfg transport.Config) func(context.Context, string) error {
	return func(ctx context.Context, addr string) error {
		conn, err := transport.Dial(ctx, addr, cfg)
		if err != nil {
			return err
		}
		defer conn.Close()
		// Pause before sending the payload. Post-handshake records — session
		// tickets — race the client's first request on a real connection, and
		// without a gap the measurement window for them is empty on both sides,
		// which would report "no tickets" as a match. The pause makes that part
		// of the shape observable.
		time.Sleep(400 * time.Millisecond)
		if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + testSNI + "\r\n\r\n")); err != nil {
			return err
		}
		buf := make([]byte, 64)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		io.ReadFull(conn, buf)
		return nil
	}
}

// driveRealTLS runs one complete browser-shaped TLS session, for Capture.
func driveRealTLS(ctx context.Context, addr string) error {
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(8 * time.Second))

	conn := utls.UClient(raw, &utls.Config{ServerName: testSNI, InsecureSkipVerify: true}, transport.DefaultFingerprint)
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		return err
	}
	// Pause before sending the payload. Post-handshake records — session
	// tickets — race the client's first request on a real connection, and
	// without a gap the measurement window for them is empty on both sides,
	// which would report "no tickets" as a match. The pause makes that part
	// of the shape observable.
	time.Sleep(400 * time.Millisecond)
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + testSNI + "\r\n\r\n")); err != nil {
		return err
	}
	buf := make([]byte, 64)
	io.ReadFull(conn, buf)
	return nil
}

// TestProbeSuite_RelayIsIndistinguishable is the active half of Slice 1's gate:
// every probe a censor can run without holding a Warren key must produce the
// same observation against the relay as against the site it borrows.
func TestProbeSuite_RelayIsIndistinguishable(t *testing.T) {
	site := startBorrowedSite(t)
	relay, clientCfg := startRelay(t, site)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// A genuine session first, so the replay probe has real bytes to replay.
	warrenTrace, err := Capture(ctx, "warren", relay, driveWarren(clientCfg))
	if err != nil {
		t.Fatalf("capture warren session: %v", err)
	}
	hello := warrenTrace.FirstClientRecord()
	if len(hello) < 1000 {
		t.Fatalf("captured ClientHello is %d bytes, expected a hybrid-sized hello", len(hello))
	}

	results := RunSuite(ctx, relay, site, testSNI, ReplayProbe(hello))
	t.Log("\n" + FormatResults(results))

	for _, r := range results {
		if r.Distinguishable {
			t.Errorf("probe %q separates the relay from the real site:\n  relay: %s\n  site:  %s", r.Name, r.RelaySig, r.SiteSig)
		}
	}
}

// TestProbeSuite_TLSHandshakeSeesBorrowedCertificate pins the specific property
// that makes active probing survivable: the certificate a prober gets from the
// relay is the borrowed site's own, because the connection was spliced there.
func TestProbeSuite_TLSHandshakeSeesBorrowedCertificate(t *testing.T) {
	site := startBorrowedSite(t)
	relay, _ := startRelay(t, site)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	viaRelay := runTLSHandshake(ctx, relay, testSNI)
	direct := runTLSHandshake(ctx, site, testSNI)

	if !viaRelay.HandshakeOK || !direct.HandshakeOK {
		t.Fatalf("handshake failed: relay=%+v direct=%+v", viaRelay, direct)
	}
	if viaRelay.CertSHA256 == "" || viaRelay.CertSHA256 != direct.CertSHA256 {
		t.Fatalf("relay presented certificate %q, real site %q", viaRelay.CertSHA256, direct.CertSHA256)
	}
	if viaRelay.TLSVersion != "1.3" {
		t.Fatalf("relay handshake negotiated %s", viaRelay.TLSVersion)
	}
}

// TestCompare_FlightMatchesRealSite is Stage A's verdict, measured rather than
// asserted: a Warren session's record shape no longer separates from a real TLS
// session to the same site.
//
// This test used to assert the opposite — that the harness *detected* a missing
// certificate flight — which was the right thing to assert while the gap existed
// and is the reason the harness was built before the fix. Flipping it is Stage A's
// definition of done.
func TestCompare_FlightMatchesRealSite(t *testing.T) {
	site := startBorrowedSite(t)
	relay, clientCfg := startRelay(t, site)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	warren, err := Capture(ctx, "warren", relay, driveWarren(clientCfg))
	if err != nil {
		t.Fatalf("capture warren: %v", err)
	}
	real, err := Capture(ctx, "real", site, driveRealTLS)
	if err != nil {
		t.Fatalf("capture real: %v", err)
	}

	report := Compare(warren, real)
	t.Log("\n" + warren.String() + "\n" + real.String() + "\n" + report.String())

	for _, f := range report.Distinguishers() {
		t.Errorf("%s still separates Warren from the real site: warren %s, real %s", f.Name, f.Warren, f.Real)
	}

	// Belt and braces on the headline number, in case a tolerance is ever
	// loosened past the point of meaning anything.
	wBytes, wRecords := serverFlightAfterCCS(warren)
	rBytes, rRecords := serverFlightAfterCCS(real)
	if rBytes < 1000 {
		t.Fatalf("real site's certificate flight is only %d bytes; the test site is not representative", rBytes)
	}
	if wRecords != rRecords {
		t.Errorf("Warren sent %d flight records, the real site %d", wRecords, rRecords)
	}
	if wBytes != rBytes {
		t.Logf("flight bytes: warren %d, real %d (within tolerance, but exact reproduction is the goal)", wBytes, rBytes)
	}
}

// TestCompare_HelloAndServerHelloSizesMatch covers the half Warren already gets
// right: the parroted ClientHello and the ServerHello answering it sit in the
// same size class as the real thing, because both carry a hybrid post-quantum
// key share. If this ever regresses it is a distinguisher on the very first
// packet, which is the cheapest one for a censor to use.
func TestCompare_HelloAndServerHelloSizesMatch(t *testing.T) {
	site := startBorrowedSite(t)
	relay, clientCfg := startRelay(t, site)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	warren, err := Capture(ctx, "warren", relay, driveWarren(clientCfg))
	if err != nil {
		t.Fatalf("capture warren: %v", err)
	}
	real, err := Capture(ctx, "real", site, driveRealTLS)
	if err != nil {
		t.Fatalf("capture real: %v", err)
	}

	report := Compare(warren, real)
	for _, name := range []string{"ClientHello size", "ServerHello size"} {
		if f := findingByName(t, report, name); f.Distinguisher {
			t.Errorf("%s differs: warren %s, real %s", name, f.Warren, f.Real)
		}
	}
}

// TestCapture_RecordsBothDirections is a harness self-check: a measurement tool
// that silently observes nothing would make every gate pass.
func TestCapture_RecordsBothDirections(t *testing.T) {
	site := startBorrowedSite(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	trace, err := Capture(ctx, "real", site, driveRealTLS)
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	var fromClient, fromServer int
	for _, r := range trace.Records {
		switch r.Dir {
		case FromClient:
			fromClient++
		case FromServer:
			fromServer++
		}
	}
	if fromClient == 0 || fromServer == 0 {
		t.Fatalf("capture saw %d client and %d server records", fromClient, fromServer)
	}
	if seq := handshakeSequence(trace); !strings.HasPrefix(seq, "C:hs S:hs") {
		t.Fatalf("unexpected record sequence for a real TLS session: %q", seq)
	}
}

func findingByName(t *testing.T, r Report, name string) Finding {
	t.Helper()
	for _, f := range r.Findings {
		if f.Name == name {
			return f
		}
	}
	t.Fatalf("report has no finding named %q", name)
	return Finding{}
}

// TestProfileSite_MeasuresBorrowedSite covers the measurement itself: what the
// relay learns about a site has to be the site's real shape, since everything
// Stage A does is replay it.
func TestProfileSite_MeasuresBorrowedSite(t *testing.T) {
	site := startBorrowedSite(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	profile, err := transport.ProfileSite(ctx, site, testSNI, transport.ProfileOptions{SkipVerify: true})
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	t.Logf("measured %s", profile)

	if err := profile.Validate(); err != nil {
		t.Fatalf("measured profile rejected: %v", err)
	}
	if profile.TotalServerFlight() < 1000 {
		t.Errorf("measured flight is %d bytes; a real certificate flight is kilobytes", profile.TotalServerFlight())
	}
	if len(profile.ServerFlight) == 0 {
		t.Error("measured no flight records")
	}
	if profile.ServerHelloLen < 1000 {
		t.Errorf("measured ServerHello is %d bytes; a hybrid one is ~1.2 KB", profile.ServerHelloLen)
	}
	if profile.ClientFinishedLen < 40 || profile.ClientFinishedLen > 200 {
		t.Errorf("measured client Finished record is %d bytes, which is not a plausible Finished", profile.ClientFinishedLen)
	}

	// The comparison against a real session only means something if the profile
	// describes *this* site, so a second measurement must agree on the parts that
	// are properties of the site rather than of the moment.
	second, err := transport.ProfileSite(ctx, site, testSNI, transport.ProfileOptions{SkipVerify: true})
	if err != nil {
		t.Fatalf("second profile: %v", err)
	}
	if second.TotalServerFlight() != profile.TotalServerFlight() || len(second.ServerFlight) != len(profile.ServerFlight) {
		t.Errorf("two measurements of the same site disagree: %d B in %d records vs %d B in %d records",
			profile.TotalServerFlight(), len(profile.ServerFlight),
			second.TotalServerFlight(), len(second.ServerFlight))
	}
}
