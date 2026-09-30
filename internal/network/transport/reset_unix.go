//go:build !windows

package transport

import (
	"errors"
	"syscall"
)

// isConnReset reports whether err is the peer having reset the connection.
//
// This is split per platform because the answer genuinely differs, and getting
// it wrong is silent. How a connection ends is observable: the relay mirrors an
// upstream reset so that a spliced connection tears down the way the borrowed
// site's own connection would (see spliceToFallback). A detector that never
// matches turns every mirrored reset into a clean FIN, which is a distinguisher
// on teardown alone — the exact defect cmd/probe found in the first place.
func isConnReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET)
}
