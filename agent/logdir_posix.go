//go:build linux || darwin

package main

// logDir returns the platform log directory.
func logDir() string {
	return "/var/log/bas-agent"
}

// spoolDir returns the directory where run results awaiting delivery are
// persisted, so a buffered assessment survives a process restart.
func spoolDir() string {
	return "/var/lib/bas-agent/spool"
}
