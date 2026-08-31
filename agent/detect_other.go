//go:build !windows

package main

import (
	"time"

	"audspect/agent/protocol"
)

// collectAlerts is a no-op on non-Windows agents in v1.
func collectAlerts(from, to time.Time, maxEvents, maxBytes int) ([]protocol.AlertRecord, bool) {
	return nil, false
}
