package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func startFallbackEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fallback listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c) // echo
			}(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

// startRelay brings up a relay with a fresh identity key and an echoing
// fallback site, and returns its address plus the client-side Config a genuine
// Warren client would hold (the relay's *public* key only — clients never see
// the identity key, which is the point of replacing the shared PSK).
// testFlight is a stand-in for a real measurement, using the record shape an
// OpenSSL-backed site actually produced when profiled: a small
// EncryptedExtensions record, a certificate-sized one, a CertificateVerify, a
// Finished, and two session tickets afterwards.
func testFlight() *FlightProfile {
	return &FlightProfile{
		Site:              "127.0.0.1:0",
		SNI:               "www.example.com",
		Group:             uint16(utls.X25519MLKEM768),
		ServerHelloLen:    1210,
		ServerFlight:      []ShapedRecord{{Len: 27}, {Len: 823}, {Len: 281}, {Len: 69}},
		PostClientFlight:  []ShapedRecord{{Len: 250}, {Len: 250}},
		ClientFinishedLen: 69,
		SampledAt:         time.Now(),
	}
}

func startRelay(t *testing.T, handle Handler) (addr string, clientCfg Config) {
	t.Helper()
	priv, pub, err := GenerateServerIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	relayCfg := Config{
		ServerPrivateKey: priv,
		FallbackSNI:      "www.example.com",
		FallbackAddr:     startFallbackEcho(t),
		Flight:           testFlight(),
	}
	go Serve(ctx, ln, relayCfg, handle)

	return ln.Addr().String(), Config{ServerPublicKey: pub, FallbackSNI: "www.example.com"}
}

func echoHandler(conn net.Conn) {
	defer conn.Close()
	io.Copy(conn, conn)
}

func roundTrip(t *testing.T, conn net.Conn, msg string) {
	t.Helper()
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	out := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, out); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(out) != msg {
		t.Fatalf("got %q, want %q", out, msg)
	}
}

// TestGenuineClient_ReachesWarrenProtocol proves the full hybrid handshake: the
// client authenticates with a tag only the holder of the relay's identity key
// can verify, the relay answers with a ServerHello carrying the ML-KEM
// ciphertext, and application data survives the round trip under the derived
// session key.
func TestGenuineClient_ReachesWarrenProtocol(t *testing.T) {
	addr, clientCfg := startRelay(t, echoHandler)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := Dial(ctx, addr, clientCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	roundTrip(t, conn, "hello")
}

// TestUntaggedClient_FallsBackToRealSite proves that a connection which does
// not present a valid tag (i.e. any non-Warren client, or a censor's probe) is
// transparently spliced through to the fallback address rather than reaching
// the Warren handler at all.
func TestUntaggedClient_FallsBackToRealSite(t *testing.T) {
	handlerReached := make(chan struct{}, 1)
	addr, _ := startRelay(t, func(conn net.Conn) {
		handlerReached <- struct{}{}
		conn.Close()
	})

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()

	// A well-formed record header claiming a ClientHello, with garbage inside:
	// this drives the parse-then-tag-check path deterministically rather than
	// the sniff-timeout path, and stands in for both an ordinary non-Warren
	// connection and a censor's active probe.
	junk := make([]byte, 300)
	rand.Read(junk)
	junk[0], junk[1], junk[2] = recordTypeHandshake, 0x03, 0x01
	body := len(junk) - recordHeaderLen
	junk[3], junk[4] = byte(body>>8), byte(body)
	junk[5] = 0x01 // client_hello
	raw.Write(junk)

	echoed := make([]byte, len(junk))
	raw.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(raw, echoed); err != nil {
		t.Fatalf("expected spliced echo from fallback, got: %v", err)
	}
	if !bytes.Equal(junk, echoed) {
		t.Fatal("splice roundtrip mismatch: bytes were not passed through to the real site verbatim")
	}

	select {
	case <-handlerReached:
		t.Fatal("Warren handler was reached by an untagged connection")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestWrongRelayKey_FallsBackToRealSite is the property the static PSK could
// not provide: a client that holds *a* Warren key but not *this relay's* key is
// indistinguishable from a probe, because the tag is derived from an exchange
// with the relay's identity key rather than from a secret every client shares.
func TestWrongRelayKey_FallsBackToRealSite(t *testing.T) {
	handlerReached := make(chan struct{}, 1)
	addr, clientCfg := startRelay(t, func(conn net.Conn) {
		handlerReached <- struct{}{}
		conn.Close()
	})

	_, otherPub, err := GenerateServerIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	clientCfg.ServerPublicKey = otherPub

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if conn, err := Dial(ctx, addr, clientCfg); err == nil {
		conn.Close()
		t.Fatal("dial with the wrong relay key succeeded; it must be treated as a non-Warren connection")
	}

	select {
	case <-handlerReached:
		t.Fatal("Warren handler was reached by a client holding the wrong relay key")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestReplayedClientHello_FallsBackToRealSite covers the one thing a captured
// hello would otherwise buy a censor: the tag is a function of the hello, so a
// replay validates by construction. The relay must therefore refuse a random it
// has already seen and splice the replay to the real site, so probing with a
// recorded hello looks exactly like visiting the borrowed site.
func TestReplayedClientHello_FallsBackToRealSite(t *testing.T) {
	handlerReached := make(chan struct{}, 2)
	addr, clientCfg := startRelay(t, func(conn net.Conn) {
		handlerReached <- struct{}{}
		echoHandler(conn)
	})

	capture := &recorder{}
	proxyAddr := startProxy(t, addr, capture, 0, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := Dial(ctx, proxyAddr, clientCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	roundTrip(t, conn, "hello")
	conn.Close()

	select {
	case <-handlerReached:
	case <-time.After(3 * time.Second):
		t.Fatal("genuine client never reached the handler")
	}

	helloRecord := firstRecord(t, capture.bytes())

	replay, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer replay.Close()
	if _, err := replay.Write(helloRecord); err != nil {
		t.Fatalf("replay write: %v", err)
	}

	// The fallback echoes our own bytes back, so the first three bytes are the
	// replayed record header (0x16 0x03 0x01). A relay that accepted the replay
	// would instead answer with a ServerHello record (0x16 0x03 0x03).
	head := make([]byte, 3)
	replay.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(replay, head); err != nil {
		t.Fatalf("expected the replay to be spliced to the real site: %v", err)
	}
	if head[2] != 0x01 {
		t.Fatalf("replayed hello was answered with a ServerHello (record version 0x%02x), not spliced to the real site", head[2])
	}

	select {
	case <-handlerReached:
		t.Fatal("a replayed ClientHello reached the Warren handler")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestSegmentedClientHello_StillAuthenticates closes the gap the earlier proof
// of concept documented but never tested: a hybrid post-quantum ClientHello is
// ~1.5 KB and arrives across several TCP segments on a real network, where the
// loopback tests always delivered it in one piece.
func TestSegmentedClientHello_StillAuthenticates(t *testing.T) {
	addr, clientCfg := startRelay(t, echoHandler)
	proxyAddr := startProxy(t, addr, nil, 137, 2*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := Dial(ctx, proxyAddr, clientCfg)
	if err != nil {
		t.Fatalf("dial through a fragmenting path: %v", err)
	}
	defer conn.Close()

	roundTrip(t, conn, "hello")
}

// TestClientWireShapeIsTLSRecords asserts the record-type sequence a client
// puts on the wire: handshake (ClientHello), change_cipher_spec, then
// application_data. That is what a real TLS 1.3 client in middlebox-
// compatibility mode emits, and it is what removes Warren's old bespoke
// 4-byte length prefix as a distinguisher.
func TestClientWireShapeIsTLSRecords(t *testing.T) {
	addr, clientCfg := startRelay(t, echoHandler)

	capture := &recorder{}
	proxyAddr := startProxy(t, addr, capture, 0, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := Dial(ctx, proxyAddr, clientCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	roundTrip(t, conn, "hello")
	conn.Close()

	want := []byte{recordTypeHandshake, recordTypeChangeCipherSpec, recordTypeApplicationData}
	got := recordTypes(t, capture.bytes(), len(want))
	if !bytes.Equal(got, want) {
		t.Fatalf("client record types on the wire = %#v, want %#v", got, want)
	}
}

// TestEphemeralSecretsDifferPerConnection is the forward-secrecy property in
// the small: nothing about a session is a function of long-term keys alone, so
// seizing a relay's identity key later does not decrypt sessions recorded
// earlier.
func TestEphemeralSecretsDifferPerConnection(t *testing.T) {
	priv, pub, err := GenerateServerIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	first, err := newClientKeys(pub)
	if err != nil {
		t.Fatalf("client keys: %v", err)
	}
	second, err := newClientKeys(pub)
	if err != nil {
		t.Fatalf("client keys: %v", err)
	}
	if bytes.Equal(first.share, second.share) {
		t.Fatal("two connections produced the same key share")
	}
	if bytes.Equal(first.authSS, second.authSS) {
		t.Fatal("two connections produced the same authentication secret")
	}

	clientRandom := make([]byte, 32)
	rand.Read(clientRandom)
	sessionID := make([]byte, sessionIDLen)
	copy(sessionID, deriveTag(first.authSS, clientRandom, first.share))

	acceptA, err := serverAccept(priv, clientRandom, sessionID, first.share)
	if err != nil {
		t.Fatalf("serverAccept: %v", err)
	}
	acceptB, err := serverAccept(priv, clientRandom, sessionID, first.share)
	if err != nil {
		t.Fatalf("serverAccept: %v", err)
	}
	if bytes.Equal(acceptA.sessionKey, acceptB.sessionKey) {
		t.Fatal("the relay derived the same session key twice for identical client input; its ephemeral half is not ephemeral")
	}

	otherPriv, _, err := GenerateServerIdentity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	if _, err := serverAccept(otherPriv, clientRandom, sessionID, first.share); err == nil {
		t.Fatal("a relay holding a different identity key validated the tag")
	}
}

// TestDefaultFingerprintOffersHybridPQKeyShare is a staleness guard, not a
// crypto test. Mainstream browsers offer X25519MLKEM768 by default, so a
// parroted ClientHello that only offers classical groups is anomalous against
// the real traffic distribution it's hiding in — the disguise rots quietly as
// the pinned profile ages. This fails as soon as DefaultFingerprint is moved
// back to a pre-PQ profile, which would also break the handshake, since Warren
// hides its own key exchange in that share.
func TestDefaultFingerprintOffersHybridPQKeyShare(t *testing.T) {
	uconn := utls.UClient(nil, &utls.Config{ServerName: "example.com"}, DefaultFingerprint)
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("build handshake state: %v", err)
	}

	for _, ks := range uconn.HandshakeState.Hello.KeyShares {
		if ks.Group == utls.X25519MLKEM768 {
			if len(ks.Data) != hybridClientShareLen {
				t.Fatalf("hybrid share is %d bytes, want %d", len(ks.Data), hybridClientShareLen)
			}
			return
		}
	}
	t.Fatalf("default fingerprint %+v offers no hybrid post-quantum key share; real browsers do", DefaultFingerprint)
}

// TestClientHelloSpansMultipleSegments records the size shift a hybrid PQ key
// share causes: the hello no longer fits the single small segment the loopback
// tests would otherwise exercise.
func TestClientHelloSpansMultipleSegments(t *testing.T) {
	uconn := utls.UClient(nil, &utls.Config{ServerName: "example.com"}, DefaultFingerprint)
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("build handshake state: %v", err)
	}
	uconn.HandshakeState.Hello.Raw = nil
	raw, err := uconn.HandshakeState.Hello.Marshal()
	if err != nil {
		t.Fatalf("marshal client hello: %v", err)
	}
	if len(raw) < 1000 {
		t.Fatalf("client hello is %d bytes, expected a post-quantum-sized hello (>1000); profile may have regressed", len(raw))
	}
	t.Logf("default profile client hello: %d bytes", len(raw))
}

// --- test plumbing ---------------------------------------------------------

// recorder accumulates everything a client sent towards the relay.
type recorder struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (r *recorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.Write(p)
}

func (r *recorder) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.buf.Bytes()...)
}

// startProxy relays TCP to target, optionally recording the client->relay
// direction and optionally re-segmenting it into chunk-sized writes with a
// delay, which is how the segmented-arrival case is reproduced on loopback.
func startProxy(t *testing.T, target string, capture io.Writer, chunk int, delay time.Duration) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			go func(client net.Conn) {
				defer client.Close()
				upstream, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer upstream.Close()
				go io.Copy(client, upstream)

				var w io.Writer = upstream
				if capture != nil {
					w = io.MultiWriter(upstream, capture)
				}
				if chunk <= 0 {
					io.Copy(w, client)
					return
				}
				buf := make([]byte, chunk)
				for {
					n, err := client.Read(buf)
					if n > 0 {
						if _, werr := w.Write(buf[:n]); werr != nil {
							return
						}
						time.Sleep(delay)
					}
					if err != nil {
						return
					}
				}
			}(client)
		}
	}()
	return ln.Addr().String()
}

// firstRecord returns the first complete TLS record in stream.
func firstRecord(t *testing.T, stream []byte) []byte {
	t.Helper()
	if len(stream) < recordHeaderLen {
		t.Fatal("captured stream is too short to contain a record")
	}
	end := recordHeaderLen + int(stream[3])<<8 + int(stream[4])
	if end > len(stream) {
		t.Fatalf("captured record claims %d bytes but only %d were captured", end, len(stream))
	}
	return stream[:end]
}

// recordTypes walks a captured stream and returns the first n record types.
func recordTypes(t *testing.T, stream []byte, n int) []byte {
	t.Helper()
	var types []byte
	for len(stream) >= recordHeaderLen && len(types) < n {
		types = append(types, stream[0])
		end := recordHeaderLen + int(stream[3])<<8 + int(stream[4])
		if end > len(stream) {
			t.Fatalf("truncated record in capture: want %d bytes, have %d", end, len(stream))
		}
		stream = stream[end:]
	}
	return types
}

// TestSpliceMirrorsUpstreamReset covers a distinguisher the probe harness found:
// a real HTTPS server given plaintext HTTP typically aborts the connection with
// an RST, and a relay that relays the site's bytes but then closes cleanly with
// a FIN is separable on TCP teardown alone — no TLS analysis required.
func TestSpliceMirrorsUpstreamReset(t *testing.T) {
	// A fallback "site" that aborts every connection the way OpenSSL does when
	// it is handed something that isn't TLS.
	site, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { site.Close() })
	go func() {
		for {
			c, err := site.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				c.SetReadDeadline(time.Now().Add(2 * time.Second))
				c.Read(make([]byte, 64))
				if tcp, ok := c.(*net.TCPConn); ok {
					tcp.SetLinger(0)
				}
				c.Close()
			}(c)
		}
	}()

	priv, _, err := GenerateServerIdentity()
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
		FallbackAddr:     site.Addr().String(),
		Flight:           testFlight(),
	}, func(conn net.Conn) { conn.Close() })

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("GET / HTTP/1.0\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadFull(conn, make([]byte, 16))
	if !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("got %v, want ECONNRESET mirrored from the upstream site", err)
	}
}
