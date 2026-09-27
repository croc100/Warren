// Package tlsrec is the TLS record-layer vocabulary Warren shares between the
// transport (which shapes records to look like a real server's) and the probe
// harness (which measures whether that worked).
//
// It is deliberately tiny and dependency-free: parsing a record header is five
// bytes of arithmetic, and having one implementation of it means the thing being
// measured and the thing doing the measuring cannot disagree about what a record
// boundary is.
package tlsrec

import (
	"fmt"
	"time"
)

const HeaderLen = 5

const (
	ChangeCipherSpec = 0x14
	Alert            = 0x15
	Handshake        = 0x16
	ApplicationData  = 0x17
)

// MaxRecordLen is TLS's ceiling for a protected record body: 2^14 plus the
// expansion allowance. Anything larger is not something a real TLS peer sends.
const MaxRecordLen = 1<<14 + 256

func TypeName(t byte) string {
	switch t {
	case ChangeCipherSpec:
		return "change_cipher_spec"
	case Alert:
		return "alert"
	case Handshake:
		return "handshake"
	case ApplicationData:
		return "application_data"
	default:
		return fmt.Sprintf("unknown(0x%02x)", t)
	}
}

func ShortTypeName(t byte) string {
	switch t {
	case Handshake:
		return "hs"
	case ChangeCipherSpec:
		return "ccs"
	case ApplicationData:
		return "app"
	case Alert:
		return "alert"
	default:
		return "?"
	}
}

// Header builds a record header for a body of the given length.
func Header(recordType byte, bodyLen int) []byte {
	return []byte{recordType, 0x03, 0x03, byte(bodyLen >> 8), byte(bodyLen)}
}

// Record is one observed record header and when it appeared.
type Record struct {
	Type byte
	Len  int
	At   time.Duration
}

// Scanner turns a byte stream into records. It is an io.Writer so it can sit in
// an io.MultiWriter beside the real destination.
//
// It buffers across writes rather than assuming a write boundary is a record
// boundary: records span TCP segments (a hybrid post-quantum ClientHello always
// does) and several small records often arrive together. Assuming otherwise is
// the same mistake that makes naive DPI miss a segmented ClientHello.
type Scanner struct {
	started time.Time
	on      func(Record)
	buf     []byte
	pending int // bytes still owed to the record being consumed
}

func NewScanner(started time.Time, on func(Record)) *Scanner {
	return &Scanner{started: started, on: on}
}

func (s *Scanner) Write(p []byte) (int, error) {
	at := time.Since(s.started)
	s.buf = append(s.buf, p...)

	for {
		if s.pending > 0 {
			n := min(s.pending, len(s.buf))
			s.buf = s.buf[n:]
			s.pending -= n
			if s.pending > 0 {
				break
			}
		}
		if len(s.buf) < HeaderLen {
			break
		}
		rec := Record{Type: s.buf[0], Len: int(s.buf[3])<<8 | int(s.buf[4]), At: at}
		s.buf = s.buf[HeaderLen:]
		s.pending = rec.Len
		s.on(rec)
	}
	return len(p), nil
}
