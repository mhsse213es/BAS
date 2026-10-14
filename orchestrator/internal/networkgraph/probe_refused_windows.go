//go:build windows

package networkgraph

import (
	"errors"

	"golang.org/x/sys/windows"
)

// isConnRefused reports whether err is a connection-actively-refused dial
// error. On Windows the real wire-level error is WSAECONNREFUSED (10061,
// golang.org/x/sys/windows.WSAECONNREFUSED) -- Go's own syscall.ECONNREFUSED
// on Windows is a different, unrelated numeric value defined purely for
// POSIX-errno-string compatibility, so errors.Is(err, syscall.ECONNREFUSED)
// never matches a real refused connection on this platform. The standard
// library's syscall package has no exported WSAECONNREFUSED; x/sys/windows
// is the canonical source for it.
func isConnRefused(err error) bool {
	return errors.Is(err, windows.WSAECONNREFUSED)
}
