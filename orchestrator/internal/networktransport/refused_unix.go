//go:build !windows

package networktransport

import (
	"errors"
	"syscall"
)

// isConnRefused reports whether err is a connection-actively-refused
// dial error. See refused_windows.go for why Windows needs a different
// constant. Duplicated from internal/networkgraph's own
// probe_refused_unix.go.
func isConnRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}
