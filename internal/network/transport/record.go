package transport

import (
	"bufio"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"fmt"
	"io"
)

// TLS record layer constants. Warren doesn't implement TLS, but everything it
// puts on the wire is framed as TLS records: a censor's classifier sees record
// headers with plausible types, versions, and lengths rather than a bespoke
// length prefix, which is one of the cheapest distinguishers to remove.
const (
	recordHeaderLen = 5

	recordTypeChangeCipherSpec = 0x14
	recordTypeHandshake        = 0x16
	recordTypeApplicationData  = 0x17

	// maxRecordLen is TLS's own ceiling for a record body (2^14 plus the
	// expansion allowance for a protected record). Anything larger is not
	// something a real TLS peer would send.
	maxRecordLen = 1<<14 + 256

	mlkemCiphertextLen = mlkem.CiphertextSize768
)

var randReader io.Reader = rand.Reader

// readRecord consumes one TLS record of the expected type and returns its body.
func readRecord(br *bufio.Reader, wantType byte) ([]byte, error) {
	var head [recordHeaderLen]byte
	if _, err := io.ReadFull(br, head[:]); err != nil {
		return nil, ErrShortRead
	}
	if head[0] != wantType {
		return nil, fmt.Errorf("%w: got 0x%02x, want 0x%02x", errUnexpectedRecordType, head[0], wantType)
	}
	bodyLen := int(head[3])<<8 | int(head[4])
	if bodyLen == 0 || bodyLen > maxRecordLen {
		return nil, fmt.Errorf("transport: record body length %d out of range", bodyLen)
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(br, body); err != nil {
		return nil, ErrShortRead
	}
	return body, nil
}

// changeCipherSpecRecord is the one-byte legacy record both TLS 1.3 peers send
// in middlebox-compatibility mode, which is the mode a non-empty session_id
// signals. Warren sends it for the same reason a real peer does: its absence
// would be visible.
func changeCipherSpecRecord() []byte {
	return []byte{recordTypeChangeCipherSpec, 0x03, 0x03, 0x00, 0x01, 0x01}
}

func ecdhX25519PublicKey(b []byte) (*ecdh.PublicKey, error) {
	pub, err := ecdh.X25519().NewPublicKey(b)
	if err != nil {
		return nil, fmt.Errorf("transport: peer ephemeral key: %w", err)
	}
	return pub, nil
}
