package transport

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/croc100/warren/internal/network/tlsrec"
)

const (
	// aeadRecordOverhead is the Poly1305 tag every record carries.
	aeadRecordOverhead = 16

	// flightHeaderLen is the one-byte kind prefix inside every record's
	// plaintext. It is what lets the relay emit records whose only purpose is to
	// have the right size — and, later, what the traffic-shaping regimes in
	// DESIGN.md §6.4 will reuse to pad or inject cover traffic without the peer
	// mistaking filler for payload.
	flightHeaderLen = 1

	// maxPayloadLen keeps a record body (kind + payload + tag) inside TLS's 2^14
	// limit, so Warren's records sit in the same size distribution as a real TLS
	// peer's rather than at lengths no TLS stack would produce.
	maxPayloadLen = 1<<14 - aeadRecordOverhead - flightHeaderLen
)

// Record kinds, carried in the first plaintext byte.
const (
	kindData    = 0x01 // application payload
	kindFiller  = 0x02 // exists only to occupy space the real server would have used
	kindConfirm = 0x03 // key confirmation, carried inside the shaped flight
)

var (
	errFrameTooLarge   = errors.New("transport: record exceeds the TLS record length limit")
	errBadKind         = errors.New("transport: unknown record kind")
	errShortRecord     = errors.New("transport: record too short to carry a kind byte")
	ErrBadConfirmation = errors.New("transport: peer's key confirmation did not verify")
)

// aeadConn wraps a net.Conn with ChaCha20-Poly1305 protection keyed by the
// session key both peers derived from the hybrid handshake, framed as TLS
// application_data records. Client and server use disjoint nonce spaces
// (odd/even counters) so the same key can safely encrypt both directions without
// a nonce collision.
type aeadConn struct {
	net.Conn
	aead interface {
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
		NonceSize() int
		Overhead() int
	}
	sendCounter uint64
	recvCounter uint64
	sendOdd     bool
	readBuf     []byte
}

func newAEADConn(conn net.Conn, key []byte, isClient bool) (*aeadConn, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &aeadConn{Conn: conn, aead: aead, sendOdd: isClient}, nil
}

func (c *aeadConn) nonce(counter uint64, odd bool) []byte {
	n := make([]byte, c.aead.NonceSize())
	if odd {
		counter |= 1 << 63
	}
	binary.BigEndian.PutUint64(n[c.aead.NonceSize()-8:], counter)
	return n
}

// writeFrame emits one record. When targetBody is non-zero the record body is
// made exactly that many bytes — payload is padded with zeros — which is how the
// relay reproduces a borrowed site's record sizes.
func (c *aeadConn) writeFrame(kind byte, payload []byte, targetBody int) error {
	plaintext := make([]byte, 0, flightHeaderLen+len(payload))
	plaintext = append(plaintext, kind)
	plaintext = append(plaintext, payload...)

	if targetBody > 0 {
		want := targetBody - aeadRecordOverhead
		if want < len(plaintext) {
			return fmt.Errorf("transport: cannot fit %d bytes of payload in a %d-byte record", len(payload), targetBody)
		}
		if targetBody > tlsrec.MaxRecordLen {
			return errFrameTooLarge
		}
		plaintext = append(plaintext, make([]byte, want-len(plaintext))...)
	}

	header := tlsrec.Header(tlsrec.ApplicationData, len(plaintext)+c.aead.Overhead())
	// The header is authenticated as additional data, exactly as TLS 1.3 does: a
	// middlebox that rewrites a record length can't make the peer accept it.
	sealed := c.aead.Seal(nil, c.nonce(c.sendCounter, c.sendOdd), plaintext, header)
	c.sendCounter++

	_, err := c.Conn.Write(append(header, sealed...))
	return err
}

// readFrame reads exactly one record and returns its kind and payload.
func (c *aeadConn) readFrame() (byte, []byte, error) {
	var head [tlsrec.HeaderLen]byte
	if _, err := io.ReadFull(c.Conn, head[:]); err != nil {
		return 0, nil, err
	}
	if head[0] != tlsrec.ApplicationData {
		return 0, nil, fmt.Errorf("%w: got 0x%02x, want application_data", errUnexpectedRecordType, head[0])
	}
	bodyLen := int(head[3])<<8 | int(head[4])
	if bodyLen <= c.aead.Overhead() || bodyLen > tlsrec.MaxRecordLen {
		return 0, nil, errFrameTooLarge
	}
	sealed := make([]byte, bodyLen)
	if _, err := io.ReadFull(c.Conn, sealed); err != nil {
		return 0, nil, err
	}
	plain, err := c.aead.Open(nil, c.nonce(c.recvCounter, !c.sendOdd), sealed, head[:])
	if err != nil {
		return 0, nil, err
	}
	c.recvCounter++
	if len(plain) < flightHeaderLen {
		return 0, nil, errShortRecord
	}
	return plain[0], plain[flightHeaderLen:], nil
}

// Write sends application data, chunked into records.
func (c *aeadConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxPayloadLen {
			chunk = chunk[:maxPayloadLen]
		}
		if err := c.writeFrame(kindData, chunk, 0); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

// Read returns application data, transparently discarding filler records. The
// relay's post-handshake shaping (session-ticket-shaped records) and any future
// cover traffic arrive as filler, so a caller never sees them.
func (c *aeadConn) Read(p []byte) (int, error) {
	for len(c.readBuf) == 0 {
		kind, payload, err := c.readFrame()
		if err != nil {
			return 0, err
		}
		switch kind {
		case kindData:
			c.readBuf = payload
		case kindFiller, kindConfirm:
			// Filler is discarded. A confirmation arriving after the handshake
			// is out of place but harmless, and treating it as fatal would turn
			// a peer's harmless retransmission habit into a dropped connection.
			continue
		default:
			return 0, fmt.Errorf("%w: 0x%02x", errBadKind, kind)
		}
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

// --- the shaped flight -----------------------------------------------------

// confirmOverhead is the fixed part of a server confirmation payload: the MAC
// length byte, the client's expected Finished-record size, and how many flight
// records still follow the carrier.
const confirmOverhead = 1 + 2 + 1

// minConfirmPayload is the smallest useful confirmation: the fixed fields plus
// eight bytes of MAC. Truncating the MAC is acceptable here because it only
// confirms the peer derived the same key — application data is protected by the
// AEAD, and a wrong guess kills the connection rather than being retried.
const minConfirmPayload = confirmOverhead + minConfirmationBytes

// sendShapedFlight emits the server's handshake flight with the borrowed site's
// record sizes and pacing, carrying Warren's key confirmation in the largest
// record.
func (c *aeadConn) sendShapedFlight(p *FlightProfile, mac []byte) error {
	carrier := p.confirmationIndex()
	if carrier < 0 {
		return ErrFlightTooSmall
	}
	remaining := len(p.ServerFlight) - carrier - 1
	if remaining > 255 {
		remaining = 255
	}

	budget := maxShapedFlightDelay
	for i, rec := range p.ServerFlight {
		delay := clamp(rec.Delay, 0, min(maxShapedRecordDelay, budget))
		if delay > 0 {
			time.Sleep(delay)
			budget -= delay
		}

		kind, payload := byte(kindFiller), []byte(nil)
		if i == carrier {
			kind = kindConfirm
			payload = buildConfirmPayload(mac, p.ConfirmationCapacity(), p.ClientFinishedLen, remaining)
		}
		if err := c.writeFrame(kind, payload, rec.Len); err != nil {
			return err
		}
	}
	return nil
}

// sendPostClientFlight emits what the borrowed site sends after the client's
// Finished — session tickets, in practice.
func (c *aeadConn) sendPostClientFlight(p *FlightProfile) error {
	budget := maxShapedFlightDelay
	for _, rec := range p.PostClientFlight {
		delay := clamp(rec.Delay, 0, min(maxShapedRecordDelay, budget))
		if delay > 0 {
			time.Sleep(delay)
			budget -= delay
		}
		if err := c.writeFrame(kindFiller, nil, rec.Len); err != nil {
			return err
		}
	}
	return nil
}

func buildConfirmPayload(mac []byte, capacity, clientFinishedLen, remaining int) []byte {
	macLen := min(len(mac), capacity-confirmOverhead)
	if macLen < minConfirmationBytes {
		macLen = minConfirmationBytes
	}
	if macLen > len(mac) {
		macLen = len(mac)
	}

	out := make([]byte, 0, confirmOverhead+macLen)
	out = append(out, byte(macLen))
	out = append(out, mac[:macLen]...)
	out = binary.BigEndian.AppendUint16(out, uint16(clientFinishedLen))
	return append(out, byte(remaining))
}

// parsedConfirm is what a client learns from the server's confirmation record.
type parsedConfirm struct {
	MAC               []byte
	ClientFinishedLen int
	Remaining         int
}

func parseConfirmPayload(payload []byte) (parsedConfirm, error) {
	if len(payload) < confirmOverhead+minConfirmationBytes {
		return parsedConfirm{}, ErrBadConfirmation
	}
	macLen := int(payload[0])
	if macLen < minConfirmationBytes || 1+macLen+3 > len(payload) {
		return parsedConfirm{}, ErrBadConfirmation
	}
	rest := payload[1+macLen:]
	return parsedConfirm{
		MAC:               payload[1 : 1+macLen],
		ClientFinishedLen: int(binary.BigEndian.Uint16(rest[:2])),
		Remaining:         int(rest[2]),
	}, nil
}

// clientConfirmPayload is the client's side: just a length-prefixed MAC, since
// the client has nothing to tell the relay about shape.
func clientConfirmPayload(mac []byte, targetBody int) []byte {
	capacity := targetBody - aeadRecordOverhead - flightHeaderLen - 1
	macLen := min(len(mac), capacity)
	if macLen < minConfirmationBytes {
		macLen = minConfirmationBytes
	}
	out := make([]byte, 0, 1+macLen)
	out = append(out, byte(macLen))
	return append(out, mac[:macLen]...)
}

func parseClientConfirmPayload(payload []byte) ([]byte, error) {
	if len(payload) < 1+minConfirmationBytes {
		return nil, ErrBadConfirmation
	}
	macLen := int(payload[0])
	if macLen < minConfirmationBytes || 1+macLen > len(payload) {
		return nil, ErrBadConfirmation
	}
	return payload[1 : 1+macLen], nil
}

// readServerFlight consumes the relay's shaped flight, verifying the key
// confirmation inside it and then draining the records that follow the carrier.
//
// Draining by count rather than by waiting for a pause is deliberate: the count
// travels inside the confirmation, so the client answers only once the whole
// flight has arrived. A timing heuristic here would put the client's
// ChangeCipherSpec in the middle of the server's flight on a slow link, and that
// ordering is exactly what this whole exercise is trying to get right.
func (c *aeadConn) readServerFlight(expectedMAC []byte) (parsedConfirm, error) {
	for {
		kind, payload, err := c.readFrame()
		if err != nil {
			return parsedConfirm{}, err
		}
		switch kind {
		case kindFiller:
			continue
		case kindConfirm:
			confirm, err := parseConfirmPayload(payload)
			if err != nil {
				return parsedConfirm{}, err
			}
			if !hmac.Equal(confirm.MAC, expectedMAC[:min(len(confirm.MAC), len(expectedMAC))]) {
				return parsedConfirm{}, ErrBadConfirmation
			}
			for i := 0; i < confirm.Remaining; i++ {
				kind, _, err := c.readFrame()
				if err != nil {
					return parsedConfirm{}, err
				}
				if kind != kindFiller {
					return parsedConfirm{}, fmt.Errorf("%w: kind 0x%02x inside the shaped flight", errBadKind, kind)
				}
			}
			return confirm, nil
		case kindData:
			// Data before the confirmation means the peer is not following the
			// handshake; treat it as a protocol error rather than silently
			// accepting a session whose key was never confirmed.
			return parsedConfirm{}, ErrBadConfirmation
		default:
			return parsedConfirm{}, fmt.Errorf("%w: 0x%02x", errBadKind, kind)
		}
	}
}

// readClientConfirmation is the relay's half: the client's Finished-shaped
// record has to carry a matching confirmation before any data is accepted.
func (c *aeadConn) readClientConfirmation(expectedMAC []byte) error {
	kind, payload, err := c.readFrame()
	if err != nil {
		return err
	}
	if kind != kindConfirm {
		return fmt.Errorf("%w: expected a confirmation, got kind 0x%02x", errBadKind, kind)
	}
	mac, err := parseClientConfirmPayload(payload)
	if err != nil {
		return err
	}
	if !hmac.Equal(mac, expectedMAC[:min(len(mac), len(expectedMAC))]) {
		return ErrBadConfirmation
	}
	return nil
}
