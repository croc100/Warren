package transport

import (
	"encoding/binary"
	"errors"
	"io"
	"net"

	"golang.org/x/crypto/chacha20poly1305"
)

// maxPlaintextLen keeps a sealed record (plaintext + 16-byte tag) inside TLS's
// 2^14 record body limit, so Warren's records sit in the same size distribution
// as a real TLS peer's rather than at lengths no TLS stack would produce.
const maxPlaintextLen = 1<<14 - 16

var errFrameTooLarge = errors.New("transport: record exceeds the TLS record length limit")

// aeadConn wraps a net.Conn with ChaCha20-Poly1305 protection keyed by the
// session key both peers derived from the hybrid handshake, framed as TLS
// application_data records. Client and server use disjoint nonce spaces
// (odd/even counters) so the same key can safely encrypt both directions
// without a nonce collision.
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

func recordHeader(bodyLen int) []byte {
	return []byte{recordTypeApplicationData, 0x03, 0x03, byte(bodyLen >> 8), byte(bodyLen)}
}

func (c *aeadConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxPlaintextLen {
			chunk = chunk[:maxPlaintextLen]
		}
		header := recordHeader(len(chunk) + c.aead.Overhead())
		// The header is authenticated as additional data, exactly as TLS
		// 1.3 does: a middlebox that rewrites a record length can't make
		// the peer accept the result.
		sealed := c.aead.Seal(nil, c.nonce(c.sendCounter, c.sendOdd), chunk, header)
		c.sendCounter++

		if _, err := c.Conn.Write(append(header, sealed...)); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (c *aeadConn) Read(p []byte) (int, error) {
	if len(c.readBuf) == 0 {
		var head [recordHeaderLen]byte
		if _, err := io.ReadFull(c.Conn, head[:]); err != nil {
			return 0, err
		}
		if head[0] != recordTypeApplicationData {
			return 0, errUnexpectedRecordType
		}
		bodyLen := int(head[3])<<8 | int(head[4])
		if bodyLen <= c.aead.Overhead() || bodyLen > maxRecordLen {
			return 0, errFrameTooLarge
		}
		sealed := make([]byte, bodyLen)
		if _, err := io.ReadFull(c.Conn, sealed); err != nil {
			return 0, err
		}
		plain, err := c.aead.Open(nil, c.nonce(c.recvCounter, !c.sendOdd), sealed, head[:])
		if err != nil {
			return 0, err
		}
		c.recvCounter++
		c.readBuf = plain
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}
