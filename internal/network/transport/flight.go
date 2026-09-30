package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/croc100/warren/internal/network/tlsrec"
)

// A real TLS 1.3 server does not go quiet after its ServerHello. It sends
// EncryptedExtensions, Certificate, CertificateVerify and Finished as encrypted
// records — usually a couple of kilobytes — the client answers with a small
// Finished, and the server then typically sends session tickets. Warren used to
// send nothing there, which a classifier separates on record sizes alone, with
// no decryption and no Warren client of its own (ADR 0001).
//
// The fix cannot be a hardcoded pad. How that flight looks is a property of the
// site being borrowed and of the TLS stack behind it: Go emits one record per
// handshake message, OpenSSL coalesces several, certificate chains differ by
// kilobytes between sites, and the number and size of session tickets differ
// again. A constant would make every Warren relay look like the same wrong
// server.
//
// So the relay measures the site it borrows from — a genuine TLS handshake with
// the same parroted fingerprint a Warren client would use — records the exact
// record-level shape of the answer, and replays that shape. The records it emits
// then carry Warren's own key confirmation rather than pure padding, so the
// shape has a job to do.

// ShapedRecord is one record the relay will emit: how many body bytes, and how
// long to wait first. Delay matters because a real server pauses to sign, and a
// flight that arrives instantly when the real site takes 4 ms is its own signal.
type ShapedRecord struct {
	Len   int
	Delay time.Duration
}

// FlightProfile is what one borrowed site's TLS answer looks like.
type FlightProfile struct {
	Site string
	SNI  string

	// Group is the key-exchange group the site actually negotiated. Warren's
	// ServerHello carries a hybrid post-quantum key share, so a site that
	// negotiates something else cannot plausibly be the one answering: its real
	// ServerHello would be hundreds of bytes smaller. Checked by Validate.
	Group          uint16
	ServerHelloLen int

	// ServerHelloDelay is how long the borrowed site took to answer a
	// ClientHello, measured from the relay's own vantage point: one network
	// round trip to the site plus whatever the site spends choosing parameters
	// and signing.
	//
	// The relay waits this long before its own ServerHello, and that is a
	// security property rather than cosmetics. A relay has two answer paths and
	// they have structurally different latencies: a genuine Warren client is
	// answered from local state in microseconds, while an unauthenticated
	// connection is spliced, which costs a fresh TCP dial to the borrowed site
	// and the site's own answer time. Unequalized, connections to one relay IP
	// split into two visibly separate latency modes — some answered instantly,
	// the rest tens of milliseconds later — and a real web server does not do
	// that. It needs no decryption and no Warren client to see; a passive
	// observer timing ClientHello to ServerHello is enough.
	ServerHelloDelay time.Duration

	// ServerFlight is the server's records between its ChangeCipherSpec and the
	// client's Finished; PostClientFlight is what it sends afterwards, which is
	// where session tickets live.
	ServerFlight     []ShapedRecord
	PostClientFlight []ShapedRecord

	// ClientFinishedLen is the size of the record a real client sends to
	// confirm the handshake, measured rather than assumed.
	ClientFinishedLen int

	SampledAt time.Time
}

var (
	ErrNoFlightProfile = errors.New("transport: relay has no flight profile for its fallback site")
	ErrSiteNotHybrid   = errors.New("transport: fallback site does not negotiate a hybrid post-quantum key exchange")
	ErrFlightTooSmall  = errors.New("transport: fallback site's handshake flight is too small to carry a confirmation")
)

// Budget caps applied when replaying a profile, so a slow or hostile site cannot
// turn every Warren handshake into a stall.
const (
	maxShapedRecordDelay = 250 * time.Millisecond
	maxShapedFlightDelay = 2 * time.Second
	minConfirmationBytes = 8
	maxFlightRecords     = 64

	// maxServerHelloDelay caps the wait before the relay's own ServerHello.
	// A borrowed site that is briefly slow, or one measured across a bad
	// moment, must not turn every Warren handshake into a stall — and a
	// connection held open waiting is a connection an attacker did not have to
	// pay for. Half a second is well past any plausible intercontinental round
	// trip to a healthy site.
	maxServerHelloDelay = 500 * time.Millisecond
)

// ProfileOptions tunes a measurement run.
type ProfileOptions struct {
	Fingerprint utls.ClientHelloID
	Timeout     time.Duration

	// SkipVerify disables certificate verification while profiling. Off by
	// default on purpose: a censor able to intercept the relay's own profiling
	// connection could otherwise feed it a bogus shape, and the relay would
	// then faithfully imitate a server that doesn't exist. Tests set it.
	SkipVerify bool

	// TicketWait is how long to keep listening after the handshake for
	// post-handshake records (session tickets).
	TicketWait time.Duration
}

func (o ProfileOptions) withDefaults() ProfileOptions {
	if o.Fingerprint.Client == "" {
		o.Fingerprint = DefaultFingerprint
	}
	if o.Timeout == 0 {
		o.Timeout = 15 * time.Second
	}
	if o.TicketWait == 0 {
		o.TicketWait = 400 * time.Millisecond
	}
	return o
}

// ProfileSite performs one genuine TLS handshake with the borrowed site and
// returns the record shape of its answer.
func ProfileSite(ctx context.Context, addr, sni string, opts ProfileOptions) (*FlightProfile, error) {
	opts = opts.withDefaults()

	d := net.Dialer{Timeout: opts.Timeout}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("transport: profile %s: %w", addr, err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(opts.Timeout))

	tap := newProfilingTap(raw)
	conn := utls.UClient(tap, &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: opts.SkipVerify,
	}, opts.Fingerprint)
	defer conn.Close()

	if err := conn.Handshake(); err != nil {
		return nil, fmt.Errorf("transport: profile %s (%s): %w", addr, sni, err)
	}

	// Session tickets arrive after the handshake completes, so keep reading for
	// a moment. A read timeout here is the expected outcome, not a failure.
	raw.SetReadDeadline(time.Now().Add(opts.TicketWait))
	conn.Read(make([]byte, 512))

	profile, err := tap.profile(addr, sni)
	if err != nil {
		return nil, err
	}
	return profile, nil
}

// profilingTap watches both directions of a handshake at the record layer.
type profilingTap struct {
	net.Conn
	mu sync.Mutex

	fromServer []tlsrec.Record
	fromClient []tlsrec.Record

	// serverHello holds the first server handshake record's body, so the
	// negotiated group can be read straight off the wire rather than trusted
	// from the TLS library's own view of the session.
	serverHello    []byte
	serverHelloCap int

	inScanner  *tlsrec.Scanner
	outScanner *tlsrec.Scanner
}

func newProfilingTap(c net.Conn) *profilingTap {
	t := &profilingTap{Conn: c, serverHelloCap: 8 << 10}
	started := time.Now()
	t.inScanner = tlsrec.NewScanner(started, func(r tlsrec.Record) {
		t.mu.Lock()
		t.fromServer = append(t.fromServer, r)
		t.mu.Unlock()
	})
	t.outScanner = tlsrec.NewScanner(started, func(r tlsrec.Record) {
		t.mu.Lock()
		t.fromClient = append(t.fromClient, r)
		t.mu.Unlock()
	})
	return t
}

func (t *profilingTap) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	if n > 0 {
		t.inScanner.Write(p[:n])
		t.mu.Lock()
		if len(t.serverHello) < t.serverHelloCap {
			t.serverHello = append(t.serverHello, p[:n]...)
		}
		t.mu.Unlock()
	}
	return n, err
}

func (t *profilingTap) Write(p []byte) (int, error) {
	n, err := t.Conn.Write(p)
	if n > 0 {
		t.outScanner.Write(p[:n])
	}
	return n, err
}

// profile turns the observation into a FlightProfile.
func (t *profilingTap) profile(addr, sni string) (*FlightProfile, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	p := &FlightProfile{Site: addr, SNI: sni, SampledAt: time.Now()}

	// The client's Finished is its first application_data record; everything the
	// server sent before that is its handshake flight, everything after is
	// post-handshake (tickets). The client's *first* record is its ClientHello,
	// and the gap from there to the ServerHello is how long this site takes to
	// answer — the latency the relay has to reproduce.
	var clientFinishedAt, clientHelloAt time.Duration
	found, sawHello := false, false
	for _, r := range t.fromClient {
		if !sawHello && r.Type == tlsrec.Handshake {
			clientHelloAt = r.At
			sawHello = true
		}
		if r.Type == tlsrec.ApplicationData {
			p.ClientFinishedLen = r.Len
			clientFinishedAt = r.At
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("transport: profiling saw no client Finished record")
	}
	if !sawHello {
		return nil, errors.New("transport: profiling saw no ClientHello record")
	}

	var prev time.Duration
	sawCCS := false
	for _, r := range t.fromServer {
		switch {
		case r.Type == tlsrec.Handshake && p.ServerHelloLen == 0:
			p.ServerHelloLen = r.Len
			p.ServerHelloDelay = clamp(r.At-clientHelloAt, 0, maxServerHelloDelay)
			prev = r.At
		case r.Type == tlsrec.ChangeCipherSpec:
			sawCCS = true
			prev = r.At
		case r.Type == tlsrec.ApplicationData && sawCCS:
			rec := ShapedRecord{Len: r.Len, Delay: clamp(r.At-prev, 0, maxShapedRecordDelay)}
			prev = r.At
			if r.At <= clientFinishedAt {
				p.ServerFlight = append(p.ServerFlight, rec)
			} else if len(p.PostClientFlight) < maxFlightRecords {
				p.PostClientFlight = append(p.PostClientFlight, rec)
			}
		}
	}

	if _, group, _, err := parseServerHelloParts(serverHelloBody(t.serverHello)); err == nil {
		p.Group = group
	}
	if len(p.ServerFlight) > maxFlightRecords {
		p.ServerFlight = p.ServerFlight[:maxFlightRecords]
	}
	return p, nil
}

// serverHelloBody strips the record header from the captured server stream.
func serverHelloBody(stream []byte) []byte {
	if len(stream) < tlsrec.HeaderLen {
		return nil
	}
	end := tlsrec.HeaderLen + int(stream[3])<<8 + int(stream[4])
	if end > len(stream) {
		end = len(stream)
	}
	return stream[tlsrec.HeaderLen:end]
}

// Validate reports whether a profile is usable, i.e. whether imitating this site
// is actually plausible.
func (p *FlightProfile) Validate() error {
	if p == nil {
		return ErrNoFlightProfile
	}
	if p.Group != uint16(utls.X25519MLKEM768) {
		// Warren's ServerHello carries a 1120-byte hybrid key share. A site that
		// negotiates classical X25519 answers with a ServerHello hundreds of
		// bytes smaller, so pairing with it makes the *first* server packet a
		// distinguisher — worse than the gap this profile exists to close.
		return fmt.Errorf("%w: negotiated group 0x%04x, want X25519MLKEM768 (0x%04x)",
			ErrSiteNotHybrid, p.Group, uint16(utls.X25519MLKEM768))
	}
	if p.ConfirmationCapacity() < minConfirmationBytes {
		return fmt.Errorf("%w: largest flight record is %d bytes", ErrFlightTooSmall, p.largestFlightRecord())
	}
	if p.ClientFinishedLen < aeadRecordOverhead+1 {
		return fmt.Errorf("transport: measured client Finished record is implausibly small (%d bytes)", p.ClientFinishedLen)
	}
	return nil
}

// confirmationIndex picks which flight record carries the key confirmation: the
// largest one, since the first (EncryptedExtensions-sized) record is often too
// small to hold a MAC.
func (p *FlightProfile) confirmationIndex() int {
	best, bestLen := -1, 0
	for i, r := range p.ServerFlight {
		if r.Len > bestLen {
			best, bestLen = i, r.Len
		}
	}
	return best
}

func (p *FlightProfile) largestFlightRecord() int {
	if i := p.confirmationIndex(); i >= 0 {
		return p.ServerFlight[i].Len
	}
	return 0
}

// ConfirmationCapacity is how many confirmation bytes fit in the carrier record.
func (p *FlightProfile) ConfirmationCapacity() int {
	return p.largestFlightRecord() - aeadRecordOverhead - flightHeaderLen
}

// TotalServerFlight is the number of bytes the shaped flight will put on the
// wire, for logging and for comparison against the real site's.
func (p *FlightProfile) TotalServerFlight() int {
	total := 0
	for _, r := range p.ServerFlight {
		total += r.Len
	}
	return total
}

func (p *FlightProfile) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s (%s): group 0x%04x, ServerHello %d B after %s, flight %d B in %d records",
		p.Site, p.SNI, p.Group, p.ServerHelloLen, p.ServerHelloDelay.Round(time.Millisecond),
		p.TotalServerFlight(), len(p.ServerFlight))
	if len(p.PostClientFlight) > 0 {
		post := 0
		for _, r := range p.PostClientFlight {
			post += r.Len
		}
		fmt.Fprintf(&b, ", post-handshake %d B in %d records", post, len(p.PostClientFlight))
	}
	fmt.Fprintf(&b, ", client Finished %d B", p.ClientFinishedLen)
	return b.String()
}

func clamp(d, lo, hi time.Duration) time.Duration {
	if d < lo {
		return lo
	}
	if d > hi {
		return hi
	}
	return d
}

// AtomicFlight holds the current profile for a long-running relay. A borrowed
// site's certificate rotates every couple of months, and its TLS stack can be
// reconfigured at any time, so a profile measured at startup drifts. A relay
// re-measures on a schedule and stores the result here; connections pick up the
// new shape without a restart, and readers never see a half-updated profile.
type AtomicFlight struct {
	v atomic.Pointer[FlightProfile]
}

func (a *AtomicFlight) Store(p *FlightProfile) { a.v.Store(p) }

// Load returns the current profile, or nil if none has been stored. A nil
// profile makes Serve refuse to run and makes an in-flight relay fall back to
// splicing, which is the safe direction: no Warren sessions rather than sessions
// with a shape that advertises itself.
func (a *AtomicFlight) Load() *FlightProfile { return a.v.Load() }
