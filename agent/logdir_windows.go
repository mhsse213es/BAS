//go:build windows

package main

import "os"

// logDir returns the platform log directory.
// Uses C:\ProgramData\BASAgent\logs — writable by SYSTEM, visible to Administrators.
func logDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return base + `\BASAgent\logs`
}

// spoolDir returns the directory where run results awaiting delivery are
// persisted. Uses C:\ProgramData\BASAgent\spool — survives a process restart so
// an assessment buffered during a server outage is delivered after the agent (or
// the whole endpoint) comes back.
func spoolDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return base + `\BASAgent\spool`
}
