package probe

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/croc100/warren/internal/network/transport"
)

// Observation is what a prober learns from one connection attempt.
type Observation struct {
	HandshakeOK bool
	TLSVersion  string
	CertSHA256  string // first 16 hex chars of the leaf certificate's digest
	ALPN        string
	BytesRead   int
	Prefix      string // first bytes returned, printable, for eyeballing
	ErrClass    string
	Elapsed     time.Duration
}

// Probe is one thing a censor's prober might try. It is run twice — against the
// Warren relay and against the site the relay borrows its identity from — and
// the relay passes only when Signature returns the same string for both.
//
// Comparing a signature rather than the whole Observation is deliberate: a real
// site's byte counts and timings move between requests, so an equality test on
// everything would report noise as evidence. The signature names the fields a
// censor could actually act on.
type Probe struct {
	Name      string
	Desc      string
	Run       func(ctx context.Context, addr, sni string) Observation
	Signature func(Observation) string
}

// ProbeResult pairs the two observations with the verdict.
type ProbeResult struct {
	Name            string
	Desc            string
	Relay, Site     Observation
	RelaySig        string
	SiteSig         string
	Distinguishable bool
}

// Suite returns the standard probe set.
func Suite() []Probe {
	return []Probe{
		tlsHandshakeProbe(),
		repeatHandshakeProbe(),
		unexpectedSNIProbe(),
		plaintextHTTPProbe(),
		randomJunkProbe(),
		truncatedHelloProbe(),
	}
}

// RunSuite runs every probe against both endpoints. extra probes (e.g. a replay
// of a captured Warren ClientHello) run after the standard set.
func RunSuite(ctx context.Context, relayAddr, siteAddr, sni string, extra ...Probe) []ProbeResult {
	var out []ProbeResult
	for _, p := range append(Suite(), extra...) {
		relay := p.Run(ctx, relayAddr, sni)
		site := p.Run(ctx, siteAddr, sni)
		relaySig, siteSig := p.Signature(relay), p.Signature(site)
		out = append(out, ProbeResult{
			Name:            p.Name,
			Desc:            p.Desc,
			Relay:           relay,
			Site:            site,
			RelaySig:        relaySig,
			SiteSig:         siteSig,
			Distinguishable: relaySig != siteSig,
		})
	}
	return out
}

// FormatResults renders a probe table.
func FormatResults(results []ProbeResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%-22s %-34s %-34s %s\n", "probe", "warren relay", "real site", "verdict")
	fmt.Fprintln(&b, strings.Repeat("-", 110))
	for _, r := range results {
		verdict := "indistinguishable"
		if r.Distinguishable {
			verdict = "DISTINGUISHABLE"
		}
		fmt.Fprintf(&b, "%-22s %-34s %-34s %s\n", r.Name, truncate(r.RelaySig, 34), truncate(r.SiteSig, 34), verdict)
	}
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// --- the probes ------------------------------------------------------------

// tlsHandshakeProbe is the probe that killed naive SNI spoofing: connect like a
// browser and look at what certificate comes back. A Warren relay must answer
// with the borrowed site's genuine chain, because the connection is spliced to
// that site — the relay never has a certificate of its own to get caught with.
func tlsHandshakeProbe() Probe {
	return Probe{
		Name: "tls-handshake",
		Desc: "complete a browser-shaped TLS handshake and inspect the certificate",
		Run:  runTLSHandshake,
		Signature: func(o Observation) string {
			return fmt.Sprintf("ok=%t ver=%s cert=%s alpn=%s err=%s", o.HandshakeOK, o.TLSVersion, o.CertSHA256, o.ALPN, o.ErrClass)
		},
	}
}

// repeatHandshakeProbe checks the relay doesn't change its behaviour once it has
// seen a probe: a peer that answers the first handshake like the real site and
// the second one differently is trivially fingerprinted by probing twice.
func repeatHandshakeProbe() Probe {
	return Probe{
		Name: "handshake-twice",
		Desc: "two sequential handshakes must be answered identically",
		Run: func(ctx context.Context, addr, sni string) Observation {
			first := runTLSHandshake(ctx, addr, sni)
			second := runTLSHandshake(ctx, addr, sni)
			same := first.HandshakeOK == second.HandshakeOK && first.CertSHA256 == second.CertSHA256
			return Observation{
				HandshakeOK: first.HandshakeOK && second.HandshakeOK,
				CertSHA256:  first.CertSHA256,
				ErrClass:    fmt.Sprintf("stable=%t", same),
			}
		},
		Signature: func(o Observation) string {
			return fmt.Sprintf("ok=%t cert=%s %s", o.HandshakeOK, o.CertSHA256, o.ErrClass)
		},
	}
}

// unexpectedSNIProbe connects with an SNI the relay does not front (H5). A
// Warren relay borrows one site and splices every unauthenticated connection to
// it regardless of the SNI presented — it does not route by SNI — so it must
// answer an unexpected SNI exactly as the borrowed site does: with that site's
// own default certificate. A relay that instead dialed the SNI-named host would
// return a certificate for a different name and separate itself from the site on
// the leaf digest alone. The SNI argument from the suite is deliberately ignored
// in favour of a fixed name neither endpoint is configured for.
func unexpectedSNIProbe() Probe {
	const unexpected = "nonexistent.example"
	return Probe{
		Name: "unexpected-sni",
		Desc: "handshake with an SNI the relay does not front; it must still answer like the borrowed site",
		Run: func(ctx context.Context, addr, _ string) Observation {
			return runTLSHandshake(ctx, addr, unexpected)
		},
		Signature: func(o Observation) string {
			return fmt.Sprintf("ok=%t cert=%s err=%s", o.HandshakeOK, o.CertSHA256, o.ErrClass)
		},
	}
}

func runTLSHandshake(ctx context.Context, addr, sni string) Observation {
	start := time.Now()
	raw, err := dial(ctx, addr)
	if err != nil {
		return Observation{ErrClass: classify(err), Elapsed: time.Since(start)}
	}
	defer raw.Close()

	// Same parroted profile Warren itself uses, so the probe's own hello is not
	// the thing that makes the two endpoints differ.
	uconn := utls.UClient(raw, &utls.Config{ServerName: sni, InsecureSkipVerify: true}, transport.DefaultFingerprint)
	defer uconn.Close()

	raw.SetDeadline(time.Now().Add(8 * time.Second))
	if err := uconn.Handshake(); err != nil {
		return Observation{ErrClass: classify(err), Elapsed: time.Since(start)}
	}

	state := uconn.ConnectionState()
	o := Observation{
		HandshakeOK: true,
		TLSVersion:  versionName(state.Version),
		ALPN:        state.NegotiatedProtocol,
		ErrClass:    "none",
		Elapsed:     time.Since(start),
	}
	if len(state.PeerCertificates) > 0 {
		sum := sha256.Sum256(state.PeerCertificates[0].Raw)
		o.CertSHA256 = hex.EncodeToString(sum[:])[:16]
	}
	return o
}

// plaintextHTTPProbe is the cheapest probe there is: speak HTTP at a port that
// claims to be HTTPS and see what comes back.
func plaintextHTTPProbe() Probe {
	return Probe{
		Name: "plaintext-http",
		Desc: "send a bare HTTP/1.0 request to the TLS port",
		Run: func(ctx context.Context, addr, sni string) Observation {
			return sendAndRead(ctx, addr, []byte("GET / HTTP/1.0\r\nHost: "+sni+"\r\n\r\n"), 6*time.Second)
		},
		Signature: func(o Observation) string {
			return fmt.Sprintf("replied=%t prefix=%q err=%s", o.BytesRead > 0, o.Prefix, o.ErrClass)
		},
	}
}

// randomJunkProbe sends a record-shaped blob of noise. The interesting property
// is that a Warren relay must not answer it any differently than the real site
// does — in particular it must not close instantly, which a bespoke parser
// rejecting bad input would.
func randomJunkProbe() Probe {
	return Probe{
		Name: "record-shaped-junk",
		Desc: "a well-formed TLS record header wrapping random bytes",
		Run: func(ctx context.Context, addr, sni string) Observation {
			junk := make([]byte, 300)
			rand.Read(junk)
			junk[0], junk[1], junk[2] = TypeHandshake, 0x03, 0x01
			body := len(junk) - 5
			junk[3], junk[4] = byte(body>>8), byte(body)
			junk[5] = 0x01 // client_hello
			return sendAndRead(ctx, addr, junk, 6*time.Second)
		},
		Signature: func(o Observation) string {
			return fmt.Sprintf("replied=%t err=%s", o.BytesRead > 0, o.ErrClass)
		},
	}
}

// truncatedHelloProbe claims a large record and then stops talking. This is the
// Slowloris shape, and also a distinguisher if the two endpoints time out
// differently.
func truncatedHelloProbe() Probe {
	return Probe{
		Name: "truncated-hello",
		Desc: "announce a 2000-byte record, send 100 bytes, then stall",
		Run: func(ctx context.Context, addr, sni string) Observation {
			head := []byte{TypeHandshake, 0x03, 0x01, 0x07, 0xd0, 0x01}
			body := make([]byte, 94)
			rand.Read(body)
			return sendAndRead(ctx, addr, append(head, body...), 3*time.Second)
		},
		Signature: func(o Observation) string {
			// Only the coarse outcome is comparable here: a stalled connection's
			// exact timing is a property of the network, not of the peer.
			return fmt.Sprintf("replied=%t err=%s", o.BytesRead > 0, o.ErrClass)
		},
	}
}

// ReplayProbe replays bytes captured from a genuine Warren session. A relay that
// answers a replayed ClientHello differently than the real site would lets a
// censor confirm it with one recording.
func ReplayProbe(hello []byte) Probe {
	return Probe{
		Name: "replayed-hello",
		Desc: "replay a captured genuine Warren ClientHello",
		Run: func(ctx context.Context, addr, sni string) Observation {
			return sendAndRead(ctx, addr, hello, 6*time.Second)
		},
		Signature: func(o Observation) string {
			// A real site answers a valid hello with a ServerHello; so must the
			// relay, by splicing. Compare the record type and rough size class
			// rather than exact bytes, since a ServerHello carries fresh
			// randomness every time.
			return fmt.Sprintf("replied=%t kind=%s err=%s", o.BytesRead > 0, o.Prefix, o.ErrClass)
		},
	}
}

// --- plumbing --------------------------------------------------------------

func dial(ctx context.Context, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 8 * time.Second}
	return d.DialContext(ctx, "tcp", addr)
}

func sendAndRead(ctx context.Context, addr string, payload []byte, wait time.Duration) Observation {
	start := time.Now()
	conn, err := dial(ctx, addr)
	if err != nil {
		return Observation{ErrClass: classify(err), Elapsed: time.Since(start)}
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(wait))
	if _, err := conn.Write(payload); err != nil {
		return Observation{ErrClass: classify(err), Elapsed: time.Since(start)}
	}

	buf := make([]byte, 4096)
	n, err := io.ReadFull(conn, buf[:64])
	if n == 0 && err != nil {
		return Observation{ErrClass: classify(err), Elapsed: time.Since(start)}
	}
	return Observation{
		BytesRead: n,
		Prefix:    describe(buf[:n]),
		ErrClass:  classify(err),
		Elapsed:   time.Since(start),
	}
}

// describe summarizes a response without pinning bytes that legitimately vary.
func describe(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	switch b[0] {
	case TypeHandshake:
		if len(b) > 5 && b[5] == 0x02 {
			return "tls:server_hello"
		}
		return "tls:handshake"
	case TypeAlert:
		return "tls:alert"
	case TypeApplicationData:
		return "tls:application_data"
	}
	if printableASCII(b) {
		line := strings.SplitN(string(b), "\r\n", 2)[0]
		return truncate(line, 24)
	}
	return fmt.Sprintf("binary:0x%02x", b[0])
}

func printableASCII(b []byte) bool {
	for _, c := range b {
		if c < 0x20 && c != '\r' && c != '\n' && c != '\t' || c > 0x7e {
			return false
		}
	}
	return true
}

// classify reduces an error to something two endpoints can be compared on.
// Exact error text leaks Go's own wording and the peer's timing; the class is
// what a censor can actually key on.
func classify(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "eof"
	case errors.Is(err, os.ErrDeadlineExceeded):
		return "timeout"
	case isTimeout(err):
		return "timeout"
	case strings.Contains(err.Error(), "reset by peer"):
		return "reset"
	case strings.Contains(err.Error(), "connection refused"):
		return "refused"
	case strings.Contains(strings.ToLower(err.Error()), "alert"),
		strings.Contains(strings.ToLower(err.Error()), "tls:"),
		strings.Contains(strings.ToLower(err.Error()), "handshake failure"):
		return "tls-error"
	default:
		return "other"
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func versionName(v uint16) string {
	switch v {
	case 0x0304:
		return "1.3"
	case 0x0303:
		return "1.2"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// RealTLSClient returns a TLS client over conn that parrots the same browser
// profile Warren does, so a comparison between a Warren session and a real one
// isn't confounded by the probe's own fingerprint.
func RealTLSClient(conn net.Conn, sni string) *utls.UConn {
	return utls.UClient(conn, &utls.Config{ServerName: sni, InsecureSkipVerify: true}, transport.DefaultFingerprint)
}
