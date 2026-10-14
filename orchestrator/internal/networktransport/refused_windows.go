//go:build windows

package networktransport

import (
	"errors"

	"golang.org/x/sys/windows"
)

// isConnRefused reports whether err is a connection-actively-refused
// dial error. Duplicated from internal/networkgraph's own
// probe_refused_windows.go, which keeps the same function unexported --
// this codebase's established convention for small logic shared across
// independent domain packages (see internal/networktopology's and
// internal/networkpolicy's own duplicated CIDR-containment checks).
func isConnRefused(err error) bool {
	return errors.Is(err, windows.WSAECONNREFUSED)
}
