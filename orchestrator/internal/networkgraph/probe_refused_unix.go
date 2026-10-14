//go:build !windows

package networkgraph

import (
	"errors"
	"syscall"
)

// isConnRefused reports whether err is a connection-actively-refused dial
// error. On Unix platforms syscall.ECONNREFUSED is the real wire-level
// errno. See probe_refused_windows.go for why Windows needs a different
// constant.
func isConnRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}
