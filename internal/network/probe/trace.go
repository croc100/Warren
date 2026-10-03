// Package probe is Warren's L1 measurement harness: it records what a
// connection looks like on the wire and compares a Warren session against a
// real TLS session to the same borrowed site, and it behaves like a censor's
// active prober to check that an unauthenticated connection is answered exactly
// as the real site would answer it.
//
// It exists because Slice 1's gate is a measurement, not an assertion
// (docs/adr/0001-borrowed-tls-handshake.md): a passive signature tool proves
// nothing useful, since Warren's disguise is already a valid TLS ClientHello.
// What matters is whether the *shape* of a session — record types, directions,
// sizes, order — separates from the real thing, and whether a prober that
// connects itself can tell the difference.
//
// The harness is deliberately adversarial towards Warren. A harness that cannot
// find a defect we already know about is not evidence of anything, so its own
// tests assert that it does find the missing certificate flight.
package probe

import (
	"context"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Direction says who sent a record.
type Direction string

const (
	FromClient Direction = "client"
	FromServer Direction = "server"
)

// TLS record types, named so a report reads like a transcript.
const (
	TypeChangeCipherSpec = 0x14
	TypeAlert            = 0x15
	TypeHandshake        = 0x16
	TypeApplicationData  = 0x17
)

func TypeName(t byte) string {
	switch t {
	case TypeChangeCipherSpec:
		return "change_cipher_spec"
	case TypeAlert:
		return "alert"
	case TypeHandshake:
		return "handshake"
	case TypeApplicationData:
		return "application_data"
	default:
		return fmt.Sprintf("unknown(0x%02x)", t)
	}
}

// Record is one observed TLS record header plus when it appeared.
type Record struct {
	Dir  Direction
	Type byte
	Len  int           // record body length, excluding the 5-byte header
	At   time.Duration // since the connection opened
}

// Trace is an ordered observation of one connection.
type Trace struct {
	Label   string
	Records []Record

	// ClientBytes is the head of the client->server stream, kept so a captured
	// ClientHello can be replayed back at the relay (ReplayProbe) — which is
	// exactly the move a censor makes with one recording.
	ClientBytes []byte
}

// maxCapturedClientBytes bounds ClientBytes; a ClientHello record is ~1.5 KB
// and nothing beyond the first record is replayable anyway.
const maxCapturedClientBytes = 16 << 10

// FirstClientRecord returns the first complete TLS record the client sent, or
// nil if the capture did not contain one.
func (t Trace) FirstClientRecord() []byte {
	if len(t.ClientBytes) < 5 {
		return nil
	}
	end := 5 + int(t.ClientBytes[3])<<8 + int(t.ClientBytes[4])
	if end > len(t.ClientBytes) {
		return nil
	}
	return t.ClientBytes[:end]
}

func (t Trace) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s (%d records)\n", t.Label, len(t.Records))
	for _, r := range t.Records {
		fmt.Fprintf(&b, "  %6.1fms %-6s %-18s %5d B\n", float64(r.At.Microseconds())/1000, r.Dir, TypeName(r.Type), r.Len)
	}
	return b.String()
}

// scanner extracts record headers from one direction of a stream. Records can
// span reads, and several can arrive in one read, so it buffers rather than
// assuming a read boundary is a record boundary — the same mistake that makes
// naive DPI miss a segmented ClientHello.
type scanner struct {
	dir     Direction
	started time.Time
	buf     []byte
	pending int // bytes still owed to the record currently being consumed
	out     *Trace
	mu      *sync.Mutex
}

func (s *scanner) Write(p []byte) (int, error) {
	at := time.Since(s.started)
	s.buf = append(s.buf, p...)

	if s.dir == FromClient {
		s.mu.Lock()
		if room := maxCapturedClientBytes - len(s.out.ClientBytes); room > 0 {
			s.out.ClientBytes = append(s.out.ClientBytes, p[:min(room, len(p))]...)
		}
		s.mu.Unlock()
	}

	for {
		if s.pending > 0 {
			n := min(s.pending, len(s.buf))
			s.buf = s.buf[n:]
			s.pending -= n
			if s.pending > 0 {
				break
			}
		}
		if len(s.buf) < 5 {
			break
		}
		length := int(s.buf[3])<<8 | int(s.buf[4])
		rec := Record{Dir: s.dir, Type: s.buf[0], Len: length, At: at}
		s.buf = s.buf[5:]
		s.pending = length

		s.mu.Lock()
		s.out.Records = append(s.out.Records, rec)
		s.mu.Unlock()
	}
	return len(p), nil
}

// Capture runs drive against a tapping proxy in front of target and returns the
// record-level transcript of what crossed it. drive receives the proxy's
// address and should perform one complete session.
func Capture(ctx context.Context, label, target string, drive func(ctx context.Context, addr string) error) (Trace, error) {
	trace := Trace{Label: label}
	var mu sync.Mutex

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return trace, fmt.Errorf("probe: tap listen: %w", err)
	}
	defer ln.Close()

	accepted := make(chan struct{})
	go func() {
		client, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		close(accepted)
		defer client.Close()

		upstream, err := net.Dial("tcp", target)
		if err != nil {
			return
		}
		defer upstream.Close()

		started := time.Now()
		toServer := &scanner{dir: FromClient, started: started, out: &trace, mu: &mu}
		toClient := &scanner{dir: FromServer, started: started, out: &trace, mu: &mu}

		done := make(chan struct{}, 2)
		go func() { io.Copy(io.MultiWriter(upstream, toServer), client); done <- struct{}{} }()
		go func() { io.Copy(io.MultiWriter(client, toClient), upstream); done <- struct{}{} }()
		<-done
	}()

	driveErr := drive(ctx, ln.Addr().String())

	// Give the tap a moment to observe the tail of the session (the server's
	// last records may still be in flight when drive returns).
	select {
	case <-accepted:
	case <-time.After(time.Second):
	}
	time.Sleep(150 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	trace.Records = append([]Record(nil), trace.Records...)
	trace.ClientBytes = append([]byte(nil), trace.ClientBytes...)
	sort.SliceStable(trace.Records, func(i, j int) bool { return trace.Records[i].At < trace.Records[j].At })
	return trace, driveErr
}

// Finding is one measured comparison between a Warren session and a real one.
type Finding struct {
	Name          string
	Warren        string
	Real          string
	Distinguisher bool
	Note          string
}

// Report is the result of comparing two traces.
type Report struct {
	Warren   Trace
	Real     Trace
	Findings []Finding
}

func (r Report) Distinguishers() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Distinguisher {
			out = append(out, f)
		}
	}
	return out
}

func (r Report) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%-28s %-26s %-26s %s\n", "measurement", "warren", "real site", "verdict")
	fmt.Fprintln(&b, strings.Repeat("-", 100))
	for _, f := range r.Findings {
		verdict := "ok"
		if f.Distinguisher {
			verdict = "DISTINGUISHER"
		}
		fmt.Fprintf(&b, "%-28s %-26s %-26s %s\n", f.Name, f.Warren, f.Real, verdict)
		if f.Note != "" {
			fmt.Fprintf(&b, "%-28s %s\n", "", f.Note)
		}
	}
	return b.String()
}

// Comparison thresholds. These are deliberately generous: the point is to catch
// order-of-magnitude shape differences that a cheap classifier would catch, not
// to chase byte-exact equality with a site whose content changes between
// requests.
const (
	flightAbsoluteTolerance = 512 // bytes
	flightRelativeTolerance = 0.5 // fraction of the real site's flight

	// postHandshakeAbsoluteTolerance is deliberately far tighter than
	// flightAbsoluteTolerance, because the two windows are not the same size.
	// A certificate flight is kilobytes, so 512 B of slack there is a small
	// fraction of it. The post-handshake window holds session tickets and is
	// a few hundred bytes in total, so the same 512 B swallowed the whole
	// measurement: a relay sending no tickets at all against a site sending
	// two was reported as indistinguishable. A canary found that by removing
	// the tickets and watching the gate stay green.
	//
	// It stays above zero because ticket contents carry timestamps and nonces
	// and are not byte-identical between connections, and a harness that
	// reports that variance is one people stop reading.
	postHandshakeAbsoluteTolerance = 128

	// helloSizeTolerance accommodates a browser profile's own variance. A
	// current Chrome ClientHello is not a fixed size: the GREASE ECH payload
	// randomizes it in 32-byte steps across roughly a 100-byte band (measured
	// at 1720–1816 bytes for HelloChrome_Auto in uTLS 1.8.2). A tighter bound
	// would report that variance as a distinguisher, and a harness that cries
	// wolf is a harness people stop reading.
	helloSizeTolerance = 160

	// answerLatencyAbsoluteTolerance and answerLatencyRelativeTolerance bound
	// how far the relay's ClientHello-to-ServerHello gap may sit from the real
	// site's. This is a shape measurement like the others, just on the time
	// axis: the relay answers a genuine client out of local state while the
	// same relay answers everyone else by splicing, which costs a round trip to
	// the borrowed site. Unequalized, one relay IP shows two separate latency
	// modes, which no real web server does.
	//
	// The absolute floor is what makes this usable on a loopback harness, where
	// both sides answer in under a millisecond and scheduling noise is most of
	// the signal; the relative term is what makes it mean something against a
	// real remote site.
	answerLatencyAbsoluteTolerance = 30 * time.Millisecond
	answerLatencyRelativeTolerance = 0.5

	// serverHelloSizeTolerance is tighter because a ServerHello's contents are
	// determined by the negotiated group and the echoed session_id, with no
	// randomized padding.
	serverHelloSizeTolerance = 64
)

// Compare measures a Warren trace against a real TLS trace to the same site.
func Compare(warren, real Trace) Report {
	r := Report{Warren: warren, Real: real}

	wFlight, wRecords := serverFlightAfterCCS(warren)
	rFlight, rRecords := serverFlightAfterCCS(real)

	// The headline measurement. A real TLS 1.3 server follows its
	// ChangeCipherSpec with EncryptedExtensions, Certificate, CertificateVerify
	// and Finished — kilobytes of encrypted handshake — before the client sends
	// anything. A peer that sends nothing there is separable on record sizes
	// alone, with no decryption and no client of its own.
	tolerance := max(float64(flightAbsoluteTolerance), float64(rFlight)*flightRelativeTolerance)
	r.Findings = append(r.Findings, Finding{
		Name:          "server flight after CCS",
		Warren:        fmt.Sprintf("%d B in %d records", wFlight, wRecords),
		Real:          fmt.Sprintf("%d B in %d records", rFlight, rRecords),
		Distinguisher: absDiff(wFlight, rFlight) > int(tolerance),
		Note:          "a real server's encrypted certificate flight; ADR 0001 Stage A",
	})

	wSeq := handshakeSequence(warren)
	rSeq := handshakeSequence(real)
	r.Findings = append(r.Findings, Finding{
		Name:          "record sequence to first payload",
		Warren:        wSeq,
		Real:          rSeq,
		Distinguisher: wSeq != rSeq,
	})

	wHello, rHello := firstRecordLen(warren, FromClient), firstRecordLen(real, FromClient)
	r.Findings = append(r.Findings, Finding{
		Name:          "ClientHello size",
		Warren:        fmt.Sprintf("%d B", wHello),
		Real:          fmt.Sprintf("%d B", rHello),
		Distinguisher: absDiff(wHello, rHello) > helloSizeTolerance,
		Note:          "both should carry a hybrid post-quantum key share; the profile's own size band is ~100 B wide",
	})

	// Session tickets: a real server sends them right after the client's
	// Finished, and a peer that skips them is separable a few records later than
	// the certificate flight would have given it away.
	wPost, wPostRecords := serverRecordsAfterClientFinished(warren)
	rPost, rPostRecords := serverRecordsAfterClientFinished(real)
	postTolerance := max(float64(postHandshakeAbsoluteTolerance), float64(rPost)*flightRelativeTolerance)
	postDiffers := absDiff(wPost, rPost) > int(postTolerance)

	// Silence where the site reliably speaks is categorical, not a matter of
	// degree. Whatever the byte tolerance is set to, one peer sending nothing
	// at all in a window the other always uses is the kind of difference a
	// classifier keys on, so it is never inside tolerance.
	if (wPostRecords == 0) != (rPostRecords == 0) {
		postDiffers = true
	}

	r.Findings = append(r.Findings, Finding{
		Name:          "post-handshake server records",
		Warren:        fmt.Sprintf("%d B in %d records", wPost, wPostRecords),
		Real:          fmt.Sprintf("%d B in %d records", rPost, rPostRecords),
		Distinguisher: postDiffers,
		Note:          "session tickets, in practice",
	})

	wSH, rSH := firstRecordLen(warren, FromServer), firstRecordLen(real, FromServer)
	r.Findings = append(r.Findings, Finding{
		Name:          "ServerHello size",
		Warren:        fmt.Sprintf("%d B", wSH),
		Real:          fmt.Sprintf("%d B", rSH),
		Distinguisher: absDiff(wSH, rSH) > serverHelloSizeTolerance,
	})

	// How long the peer took to answer, which is a shape measurement on the
	// time axis and the cheapest one a passive observer has: it needs no
	// decryption, no key, and no probe of its own, just a clock.
	wLatency, rLatency := answerLatency(warren), answerLatency(real)
	latencyTolerance := max(answerLatencyAbsoluteTolerance, time.Duration(float64(rLatency)*answerLatencyRelativeTolerance))
	r.Findings = append(r.Findings, Finding{
		Name:          "ServerHello latency",
		Warren:        wLatency.Round(time.Millisecond).String(),
		Real:          rLatency.Round(time.Millisecond).String(),
		Distinguisher: absDuration(wLatency, rLatency) > latencyTolerance,
		Note:          "the relay answers from local state; splicing costs a round trip to the borrowed site",
	})

	return r
}

// CompareAnswerPaths measures a relay against itself rather than against the
// site it borrows, which is the comparison a censor can make most cheaply.
//
// One relay IP answers on two paths. A client holding a valid tag is answered
// out of local state plus whatever wait the borrowed site's measured latency
// imposes. Everyone else — a probe, a stray HTTPS client, a Warren client with
// the wrong key — is spliced, which costs the relay a fresh TCP connection to
// the borrowed site on top of that site's own answer time.
//
// If those two costs differ, connections to that one address split into two
// latency modes, and no real web server does that. It is the cheapest
// distinguisher on the list: no decryption, no key, no active probing beyond
// one ordinary handshake, just a clock and enough samples.
//
// Comparing the relay to the real site (Compare) cannot see this, because the
// two sit on different network paths and are expected to differ. Only the
// relay against itself isolates the part the relay controls.
func CompareAnswerPaths(warrenViaRelay, splicedViaRelay Trace) Finding {
	warren, spliced := answerLatency(warrenViaRelay), answerLatency(splicedViaRelay)
	tolerance := max(answerLatencyAbsoluteTolerance, time.Duration(float64(spliced)*answerLatencyRelativeTolerance))
	return Finding{
		Name:          "answer latency, both paths",
		Warren:        warren.Round(time.Millisecond).String(),
		Real:          spliced.Round(time.Millisecond).String() + " (spliced)",
		Distinguisher: absDuration(warren, spliced) > tolerance,
		Note:          "same relay, tagged vs untagged; a split here is bimodality at one address",
	}
}

// answerLatency is the gap between the client's first record and the server's,
// i.e. ClientHello to ServerHello.
func answerLatency(t Trace) time.Duration {
	clientAt, ok := firstRecordAt(t, FromClient)
	if !ok {
		return 0
	}
	serverAt, ok := firstRecordAt(t, FromServer)
	if !ok {
		return 0
	}
	if serverAt < clientAt {
		return 0
	}
	return serverAt - clientAt
}

func firstRecordAt(t Trace, dir Direction) (time.Duration, bool) {
	for _, rec := range t.Records {
		if rec.Dir == dir {
			return rec.At, true
		}
	}
	return 0, false
}

func absDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a - b
	}
	return b - a
}

// serverFlightAfterCCS totals the server records between the first
// change_cipher_spec and the client's first application_data record.
func serverFlightAfterCCS(t Trace) (bytes, records int) {
	seenCCS := false
	for _, rec := range t.Records {
		if rec.Type == TypeChangeCipherSpec {
			seenCCS = true
			continue
		}
		if !seenCCS {
			continue
		}
		if rec.Dir == FromClient && rec.Type == TypeApplicationData {
			break
		}
		if rec.Dir == FromServer {
			bytes += rec.Len
			records++
		}
	}
	return bytes, records
}

// serverRecordsAfterClientFinished totals what the server sends once the client
// has confirmed the handshake, up to the client's first payload record.
func serverRecordsAfterClientFinished(t Trace) (bytes, records int) {
	seenClientFinished := false
	for _, rec := range t.Records {
		if rec.Dir == FromClient && rec.Type == TypeApplicationData {
			if seenClientFinished {
				break // the client's second app record is its payload
			}
			seenClientFinished = true
			continue
		}
		if seenClientFinished && rec.Dir == FromServer {
			bytes += rec.Len
			records++
		}
	}
	return bytes, records
}

// handshakeSequence renders the record types up to and including the client's
// first application_data record, which is where a session stops looking like a
// handshake and starts looking like traffic.
func handshakeSequence(t Trace) string {
	var parts []string
	for _, rec := range t.Records {
		parts = append(parts, fmt.Sprintf("%s:%s", shortDir(rec.Dir), shortType(rec.Type)))
		if rec.Dir == FromClient && rec.Type == TypeApplicationData {
			break
		}
		if len(parts) >= 12 {
			break
		}
	}
	return strings.Join(parts, " ")
}

func firstRecordLen(t Trace, dir Direction) int {
	for _, rec := range t.Records {
		if rec.Dir == dir {
			return rec.Len
		}
	}
	return 0
}

func shortDir(d Direction) string {
	if d == FromClient {
		return "C"
	}
	return "S"
}

func shortType(t byte) string {
	switch t {
	case TypeHandshake:
		return "hs"
	case TypeChangeCipherSpec:
		return "ccs"
	case TypeApplicationData:
		return "app"
	case TypeAlert:
		return "alert"
	default:
		return "?"
	}
}

func absDiff(a, b int) int {
	if a > b {
		return a - b
	}
	return b - a
}
