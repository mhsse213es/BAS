//go:build !windows && !linux && !darwin

package main

import (
	"time"

	"audspect/agent/protocol"
)

// collectAlerts has no implementation on platforms outside windows/linux/darwin.
// Returning (nil,false) is the honest answer: it says "this agent did not look",
// which the server must not read as "nothing detected anything".
func collectAlerts(from, to time.Time, maxEvents, maxBytes int) ([]protocol.AlertRecord, bool) {
	return nil, false
}
