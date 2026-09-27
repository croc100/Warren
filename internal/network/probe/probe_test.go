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
				buf := make([]byte, 1024)
				c.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err := c.Read(buf); err != nil {
					return
				}
				c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"))
			}(c)
		}
	}()
	return ln.Addr().String()
}

func startRelay(t *testing.T, fallbackAddr string) (addr string, clientCfg transport.Config) {
	t.Helper()
	priv, pub, err := transport.GenerateServerIdentity()
	if err != nil {
		t.Fatalf("relay identity: %v", err)
	}
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

// TestCompare_DetectsMissingCertificateFlight is the harness proving itself. We
// already know the current transport omits the server's encrypted certificate
// flight (ADR 0001), so a harness that reports everything is fine would be
// worthless. When Stage A lands, this test's expectation flips — that is the
// definition of done for it.
func TestCompare_DetectsMissingCertificateFlight(t *testing.T) {
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

	flight := findingByName(t, report, "server flight after CCS")
	if !flight.Distinguisher {
		t.Errorf("the harness did not flag the missing certificate flight (warren %s, real %s); "+
			"either Stage A of ADR 0001 has landed — in which case update this test — or the harness is broken",
			flight.Warren, flight.Real)
	}

	wBytes, _ := serverFlightAfterCCS(warren)
	rBytes, _ := serverFlightAfterCCS(real)
	if rBytes < 1000 {
		t.Fatalf("real site's certificate flight is only %d bytes; the test site is not representative", rBytes)
	}
	if wBytes > rBytes/4 {
		t.Fatalf("expected Warren's flight (%d B) to be far smaller than the real one (%d B)", wBytes, rBytes)
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
