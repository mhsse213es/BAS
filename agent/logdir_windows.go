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

// agentLogDir is where the agent's diagnostic log (agent.log) is written first: C:\Program Files\Audspect\agent.log.
// The service runs as SYSTEM, which may write there; every user may read it. A process that cannot write there (the
// tray and status window run as the signed-in user) falls back to its own folder.
func agentLogDir() string {
	base := os.Getenv("ProgramFiles")
	if base == "" {
		base = `C:\Program Files`
	}
	return base + `\Audspect`
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
