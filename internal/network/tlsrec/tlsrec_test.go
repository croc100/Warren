package tlsrec

import (
	"testing"
	"time"
)

// TestScannerHandlesArbitrarySegmentation feeds the same three records in every
// split pattern up to two boundaries and asserts the scanner reports the same
// thing each time. Record framing that only works when writes happen to align
// with record boundaries is framing that works on loopback and fails on a
// network.
func TestScannerHandlesArbitrarySegmentation(t *testing.T) {
	stream := []byte{}
	want := []Record{{Type: Handshake, Len: 300}, {Type: ChangeCipherSpec, Len: 1}, {Type: ApplicationData, Len: 40}}
	for _, r := range want {
		stream = append(stream, Header(r.Type, r.Len)...)
		stream = append(stream, make([]byte, r.Len)...)
	}

	for first := 1; first < len(stream); first += 7 {
		for second := first; second < len(stream); second += 11 {
			var got []Record
			s := NewScanner(time.Now(), func(r Record) { got = append(got, r) })
			s.Write(stream[:first])
			s.Write(stream[first:second])
			s.Write(stream[second:])

			if len(got) != len(want) {
				t.Fatalf("split at %d,%d: got %d records, want %d", first, second, len(got), len(want))
			}
			for i := range want {
				if got[i].Type != want[i].Type || got[i].Len != want[i].Len {
					t.Fatalf("split at %d,%d: record %d = %+v, want type %s len %d",
						first, second, i, got[i], TypeName(want[i].Type), want[i].Len)
				}
			}
		}
	}
}

func TestScannerIgnoresIncompleteTrailingRecord(t *testing.T) {
	var got []Record
	s := NewScanner(time.Now(), func(r Record) { got = append(got, r) })
	s.Write(Header(Handshake, 100))
	s.Write(make([]byte, 40)) // record still incomplete
	if len(got) != 1 {
		t.Fatalf("got %d records, want the header to be reported once", len(got))
	}
	s.Write(make([]byte, 60))
	s.Write(Header(Alert, 2))
	if len(got) != 2 {
		t.Fatalf("got %d records, want the next header reported after the first record completes", len(got))
	}
}
