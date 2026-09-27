package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/croc100/warren/internal/network/tlsrec"
)

// TestServeRefusesWithoutUsableProfile pins the fail-closed decision. A relay
// that cannot imitate its borrowed site's handshake announces itself to anyone
// measuring record sizes, and serving clients anyway would put them at more risk
// than not running at all.
func TestServeRefusesWithoutUsableProfile(t *testing.T) {
	priv, _, err := GenerateServerIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	cases := []struct {
		name    string
		flight  *FlightProfile
		wantErr error
	}{
		{"no profile at all", nil, ErrNoFlightProfile},
		{
			// A site that negotiates classical X25519 answers with a ServerHello
			// hundreds of bytes smaller than Warren's hybrid one, so pairing with
			// it makes the *first* server packet a distinguisher.
			name: "site does not negotiate a hybrid group",
			flight: func() *FlightProfile {
				p := testFlight()
				p.Group = 0x001d // X25519
				return p
			}(),
			wantErr: ErrSiteNotHybrid,
		},
		{
			name: "flight too small to carry a confirmation",
			flight: func() *FlightProfile {
				p := testFlight()
				p.ServerFlight = []ShapedRecord{{Len: 20}}
				return p
			}(),
			wantErr: ErrFlightTooSmall,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer ln.Close()

			err = Serve(context.Background(), ln, Config{
				ServerPrivateKey: priv,
				FallbackSNI:      "www.example.com",
				FallbackAddr:     "127.0.0.1:1",
				Flight:           tc.flight,
			}, func(net.Conn) {})

			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Serve returned %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestShapedFlightReproducesProfile is Stage A's core assertion: the records the
// relay puts on the wire after its ServerHello have exactly the sizes the
// borrowed site's own handshake had, in the same order, and the client's
// confirmation record is the size a real client's Finished was measured to be.
//
// Sizes are compared exactly rather than approximately on purpose. Approximate
// shaping is how you end up looking like a server that doesn't exist.
func TestShapedFlightReproducesProfile(t *testing.T) {
	addr, clientCfg := startRelay(t, echoHandler)
	flight := testFlight()

	tap := newRecordTap(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := Dial(ctx, tap.addr, clientCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	roundTrip(t, conn, "hello")
	conn.Close()
	time.Sleep(200 * time.Millisecond)

	server, client := tap.records()

	// Server: handshake (ServerHello), CCS, then the flight, then the
	// post-handshake records, then the echo.
	if len(server) < 2+len(flight.ServerFlight)+len(flight.PostClientFlight) {
		t.Fatalf("server sent %d records, too few for the profile:\n%s", len(server), formatRecords(server))
	}
	if server[0].Type != tlsrec.Handshake || server[1].Type != tlsrec.ChangeCipherSpec {
		t.Fatalf("server did not open with ServerHello then CCS:\n%s", formatRecords(server))
	}

	for i, want := range flight.ServerFlight {
		got := server[2+i]
		if got.Type != tlsrec.ApplicationData || got.Len != want.Len {
			t.Errorf("flight record %d = %s/%d B, want application_data/%d B", i, tlsrec.TypeName(got.Type), got.Len, want.Len)
		}
	}
	for i, want := range flight.PostClientFlight {
		got := server[2+len(flight.ServerFlight)+i]
		if got.Type != tlsrec.ApplicationData || got.Len != want.Len {
			t.Errorf("post-handshake record %d = %s/%d B, want application_data/%d B", i, tlsrec.TypeName(got.Type), got.Len, want.Len)
		}
	}

	// Client: ClientHello, CCS, then a Finished-sized confirmation, then payload.
	if len(client) < 4 {
		t.Fatalf("client sent %d records, want at least 4:\n%s", len(client), formatRecords(client))
	}
	if client[0].Type != tlsrec.Handshake || client[1].Type != tlsrec.ChangeCipherSpec {
		t.Fatalf("client did not open with ClientHello then CCS:\n%s", formatRecords(client))
	}
	if client[2].Len != flight.ClientFinishedLen {
		t.Errorf("client confirmation record is %d B, want the measured client Finished size %d B",
			client[2].Len, flight.ClientFinishedLen)
	}
}

// TestClientRejectsBadServerConfirmation covers what the shaped flight buys
// beyond shape: the client learns the relay derived the same session key, and the
// confirmation binds the handshake transcript, so a relay that got either wrong
// is refused before the client sends anything.
func TestClientRejectsBadServerConfirmation(t *testing.T) {
	clientEnd, serverEnd := net.Pipe()
	defer clientEnd.Close()
	defer serverEnd.Close()

	key := make([]byte, 32)
	client, err := newAEADConn(clientEnd, key, true)
	if err != nil {
		t.Fatalf("client conn: %v", err)
	}
	server, err := newAEADConn(serverEnd, key, false)
	if err != nil {
		t.Fatalf("server conn: %v", err)
	}

	go func() {
		wrong := make([]byte, 32)
		for i := range wrong {
			wrong[i] = 0xAA
		}
		server.sendShapedFlight(testFlight(), wrong)
	}()

	expected := make([]byte, 32) // all zeros: not what the peer sent
	if _, err := client.readServerFlight(expected); !errors.Is(err, ErrBadConfirmation) {
		t.Fatalf("got %v, want ErrBadConfirmation", err)
	}
}

// TestFillerRecordsAreInvisible: the shaping mechanism must never leak into the
// byte stream a caller sees. This is also the mechanism the traffic-shaping
// regimes in DESIGN.md §6.4 will reuse, so it has to hold for arbitrary
// interleavings, not just the handshake's.
func TestFillerRecordsAreInvisible(t *testing.T) {
	clientEnd, serverEnd := net.Pipe()
	defer clientEnd.Close()
	defer serverEnd.Close()

	key := make([]byte, 32)
	reader, err := newAEADConn(clientEnd, key, true)
	if err != nil {
		t.Fatalf("reader: %v", err)
	}
	writer, err := newAEADConn(serverEnd, key, false)
	if err != nil {
		t.Fatalf("writer: %v", err)
	}

	go func() {
		writer.writeFrame(kindFiller, nil, 250)
		writer.writeFrame(kindData, []byte("one"), 0)
		writer.writeFrame(kindFiller, nil, 1400)
		writer.writeFrame(kindFiller, nil, 60)
		writer.writeFrame(kindData, []byte("two"), 0)
	}()

	got := make([]byte, 6)
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "onetwo" {
		t.Fatalf("got %q, want %q — filler leaked into the payload stream", got, "onetwo")
	}
}

func TestProfileValidateAcceptsAMeasuredSite(t *testing.T) {
	p := testFlight()
	if err := p.Validate(); err != nil {
		t.Fatalf("a plausible profile was rejected: %v", err)
	}
	if p.Group != uint16(utls.X25519MLKEM768) {
		t.Fatalf("test profile is not hybrid")
	}
	if p.TotalServerFlight() != 27+823+281+69 {
		t.Fatalf("TotalServerFlight = %d", p.TotalServerFlight())
	}
	if got := p.confirmationIndex(); got != 1 {
		t.Fatalf("confirmation carrier index = %d, want the largest record (1)", got)
	}
}

// --- test plumbing ---------------------------------------------------------

// recordTap proxies TCP and parses both directions at the record layer.
type recordTap struct {
	addr   string
	mu     sync.Mutex
	server []tlsrec.Record
	client []tlsrec.Record
}

func newRecordTap(t *testing.T, target string) *recordTap {
	t.Helper()
	tap := &recordTap{}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tap listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	tap.addr = ln.Addr().String()

	go func() {
		for {
			down, err := ln.Accept()
			if err != nil {
				return
			}
			go func(down net.Conn) {
				defer down.Close()
				up, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer up.Close()

				started := time.Now()
				toServer := tlsrec.NewScanner(started, func(r tlsrec.Record) {
					tap.mu.Lock()
					tap.client = append(tap.client, r)
					tap.mu.Unlock()
				})
				toClient := tlsrec.NewScanner(started, func(r tlsrec.Record) {
					tap.mu.Lock()
					tap.server = append(tap.server, r)
					tap.mu.Unlock()
				})

				done := make(chan struct{}, 2)
				go func() { io.Copy(io.MultiWriter(up, toServer), down); done <- struct{}{} }()
				go func() { io.Copy(io.MultiWriter(down, toClient), up); done <- struct{}{} }()
				<-done
			}(down)
		}
	}()
	return tap
}

func (tp *recordTap) records() (server, client []tlsrec.Record) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	return append([]tlsrec.Record(nil), tp.server...), append([]tlsrec.Record(nil), tp.client...)
}

func formatRecords(recs []tlsrec.Record) string {
	out := ""
	for _, r := range recs {
		out += "  " + tlsrec.TypeName(r.Type) + " " + itoa(r.Len) + " B\n"
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
