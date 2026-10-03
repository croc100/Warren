//go:build windows

package transport

import (
	"errors"
	"syscall"
)

// isConnReset reports whether err is the peer having reset the connection.
//
// Windows needs its own answer. A peer reset arrives from Winsock as
// WSAECONNRESET (10054); syscall.ECONNRESET on Windows is a Go-internal
// synthetic errno (0x20000017) that a socket never actually returns, so
// errors.Is(err, syscall.ECONNRESET) is false for every real reset on this
// platform. Both are accepted here rather than only the Winsock code, so the
// check keeps working if the runtime ever starts normalising one to the other.
//
// This mattered: with only the portable-looking constant, a Windows relay
// mirrored no resets at all and closed every spliced connection with a FIN
// while the borrowed site sent RST. Windows is also the operating system most
// of the residential relay pool this design bets on would run, and CI ran only
// on Linux, so nothing caught it.
func isConnReset(err error) bool {
	return errors.Is(err, syscall.WSAECONNRESET) || errors.Is(err, syscall.ECONNRESET)
}
