package probe

import (
	"context"
	"testing"
	"time"

	"github.com/croc100/warren/internal/network/transport"
)

// Canaries.
//
// Every other test in this package asserts that the harness finds nothing. That
// is the result we want and it is also the result a harness returns when it has
// quietly stopped working — a Compare that lost a measurement in a refactor, a
// tolerance widened past the point of meaning anything, a suite that silently
// stops running its probes. All of those read as PASS, forever, and the gate
// they feed keeps reporting that a relay is indistinguishable.
//
// So the harness is pointed at relays that are deliberately wrong, and required
// to say so. A canary that stops failing is as much a defect as a gate that
// stops passing: if one of these ever goes green, the measurement it guards has
// stopped measuring and everything downstream of it is unsupported.
//
// Each canary damages one property, and asserts on the specific finding that
// property belongs to rather than on "some distinguisher somewhere", so that it
// cannot be satisfied by an unrelated failure.

// TestCanary_MissingCertificateFlightIsDetected is the original defect, kept
// alive on purpose. Before ADR 0001 Stage A the relay answered its ServerHello
// with silence where a real server sends kilobytes of encrypted certificate
// messages, and this harness was built to measure exactly that. The fix flipped
// TestCompare_FlightMatchesRealSite from "the gap is detected" to "there is no
// gap", which left nothing asserting that the detection still works.
func TestCanary_MissingCertificateFlightIsDetected(t *testing.T) {
	site := startBorrowedSite(t)

	// A relay that sends one small record where the site sends a full
	// certificate flight. It still has to carry the key confirmation, so the
	// record cannot be arbitrarily small — this is the smallest shape that is
	// still a working relay and an obviously wrong one.
	relay, clientCfg := startRelayShaped(t, site, func(p *transport.FlightProfile) {
		p.ServerFlight = []transport.ShapedRecord{{Len: 128}}
		p.PostClientFlight = nil
	})

	report := captureAndCompare(t, relay, clientCfg, site)

	f := findingByName(t, report, "server flight after CCS")
	if !f.Distinguisher {
		t.Errorf("a relay sending 128 B where the site sends a certificate flight was reported as indistinguishable: warren %s, real %s\n%s",
			f.Warren, f.Real, report)
	}
}

// TestCanary_AnswerLatencySplitIsDetected guards the timing measurement. A
// relay that answers a tagged client out of local state while answering
// everyone else through a splice shows two latency modes at one address, and
// that is visible to an observer holding nothing but a clock. The measurement
// is new, so it gets a canary before it gets trusted.
func TestCanary_AnswerLatencySplitIsDetected(t *testing.T) {
	site := startBorrowedSite(t)

	// The site is on loopback and answers instantly. A relay claiming that site
	// while taking 200 ms to answer a tagged client is the same split in the
	// opposite direction, and is what the measurement has to catch.
	relay, clientCfg := startRelayShaped(t, site, func(p *transport.FlightProfile) {
		p.ServerHelloDelay = 200 * time.Millisecond
	})

	report := captureAndCompare(t, relay, clientCfg, site)

	latency := findingByName(t, report, "ServerHello latency")
	if !latency.Distinguisher {
		t.Errorf("a relay answering %s slower than the site it claims to be was reported as indistinguishable: warren %s, real %s",
			200*time.Millisecond, latency.Warren, latency.Real)
	}

	split := findingByName(t, report, "answer latency, both paths")
	if !split.Distinguisher {
		t.Errorf("the relay's two answer paths differ by ~%s and the split was not reported: tagged %s, spliced %s",
			200*time.Millisecond, split.Warren, split.Real)
	}
}

// TestCanary_CipherSuiteMismatchIsDetected guards the cipher-suite measurement
// (H4). The borrowed site negotiates one TLS 1.3 suite; a relay that answers a
// tagged client with a different one splits its two answer paths onto suites a
// censor can read in cleartext from the ServerHello. The measurement is new, so
// it gets a canary: force the relay to echo a suite the loopback site does not
// negotiate and require the comparison to say so.
func TestCanary_CipherSuiteMismatchIsDetected(t *testing.T) {
	site := startBorrowedSite(t)

	relay, clientCfg := startRelayShaped(t, site, func(p *transport.FlightProfile) {
		// The Go test site negotiates AES-128 (0x1301) on loopback hardware;
		// force the relay to answer AES-256 so the two disagree. This does not
		// touch Warren's own encryption, which is ChaCha20-Poly1305 under the
		// derived key regardless of the suite named here.
		p.CipherSuite = 0x1302
	})

	report := captureAndCompare(t, relay, clientCfg, site)

	f := findingByName(t, report, "ServerHello cipher suite")
	if f.Warren == "unparsed" || f.Real == "unparsed" {
		t.Fatalf("a ServerHello did not parse, so this canary measured nothing: warren %s, real %s", f.Warren, f.Real)
	}
	if !f.Distinguisher {
		t.Errorf("a relay answering 0x1302 where the site negotiates %s was reported as indistinguishable: warren %s, real %s",
			f.Real, f.Warren, f.Real)
	}
}

// TestCanary_MissingSessionTicketsAreDetected guards the post-handshake
// measurement, which is the one a relay would fail a few records later than the
// certificate flight if it stopped replaying what the site sends after the
// client's Finished.
func TestCanary_MissingSessionTicketsAreDetected(t *testing.T) {
	site := startBorrowedSiteWithPostHandshakeRecords(t)

	relay, clientCfg := startRelayShaped(t, site, func(p *transport.FlightProfile) {
		p.PostClientFlight = nil
	})

	report := captureAndCompare(t, relay, clientCfg, site)

	f := findingByName(t, report, "post-handshake server records")
	if f.Real == "0 B in 0 records" {
		t.Fatalf("the test site sent nothing in the post-handshake window, so this canary removed nothing: %s", f.Real)
	}
	if !f.Distinguisher {
		t.Errorf("a relay sending nothing where the site sends %s was reported as indistinguishable; the tolerance is swallowing the measurement",
			f.Real)
	}
}

// TestCanary_ProbeSuiteSeparatesUnrelatedEndpoints guards the active half. The
// suite's job is to report when two endpoints answer differently, and a suite
// that has stopped comparing — or stopped running its probes at all — returns
// "indistinguishable" for everything. Two unrelated TLS sites, with different
// certificates, must not come back as a match.
func TestCanary_ProbeSuiteSeparatesUnrelatedEndpoints(t *testing.T) {
	site := startBorrowedSite(t)
	unrelated := startBorrowedSite(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	results := RunSuite(ctx, site, unrelated, testSNI)
	t.Log("\n" + FormatResults(results))

	found := false
	for _, r := range results {
		if r.Distinguishable {
			found = true
			break
		}
	}
	if !found {
		t.Error("the probe suite reported two unrelated TLS servers with different certificates as indistinguishable; it is not comparing anything")
	}
}

// TestCanary_CaptureRejectsAnEmptyTrace guards the layer under all of it. Every
// shape measurement is computed from a Trace, and a Trace with no records
// compares equal to another Trace with no records, so a tap that silently
// observed nothing would make every gate pass.
func TestCanary_CaptureRejectsAnEmptyTrace(t *testing.T) {
	empty := Trace{Label: "empty"}
	report := Compare(empty, empty)

	if len(report.Distinguishers()) != 0 {
		t.Fatal("two empty traces compared unequal, which is not what this canary is about")
	}

	// Two empty traces matching is arithmetic, not evidence. What the harness
	// has to guarantee is that a real capture is never empty, which is what
	// TestCapture_RecordsBothDirections covers; this pins the reason that test
	// is load-bearing rather than incidental.
	site := startBorrowedSite(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	trace, err := Capture(ctx, "real", site, driveRealTLS)
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	if len(trace.Records) == 0 {
		t.Fatal("a real TLS session produced an empty trace; every shape measurement downstream of this is meaningless")
	}
}

// captureAndCompare runs one Warren session against the relay, one real TLS
// session against the site, and one unauthenticated session against the relay,
// and returns the full report the gate would produce.
func captureAndCompare(t *testing.T, relay string, clientCfg transport.Config, site string) Report {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	warren, err := Capture(ctx, "warren", relay, driveWarren(clientCfg))
	if err != nil {
		t.Fatalf("capture warren: %v", err)
	}
	real, err := Capture(ctx, "real", site, driveRealTLS)
	if err != nil {
		t.Fatalf("capture real: %v", err)
	}
	spliced, err := Capture(ctx, "spliced", relay, driveRealTLS)
	if err != nil {
		t.Fatalf("capture spliced: %v", err)
	}

	report := Compare(warren, real)
	report.Findings = append(report.Findings, CompareAnswerPaths(warren, spliced))
	return report
}
