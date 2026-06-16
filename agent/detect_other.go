//go:build !windows

package main

import "time"

// collectAlerts is a no-op on non-Windows agents in v1.
func collectAlerts(from, to time.Time, maxEvents, maxBytes int) ([]AlertRecord, bool) {
	return nil, false
}
