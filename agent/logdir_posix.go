//go:build linux || darwin

package main

// logDir returns the platform log directory.
func logDir() string {
	return "/var/log/bas-agent"
}

// agentLogDir is where the agent's diagnostic log (agent.log) is written first: the same folder as the structured
// logs, so there is one place to look.
func agentLogDir() string {
	return logDir()
}

// spoolDir returns the directory where run results awaiting delivery are
// persisted, so a buffered assessment survives a process restart.
func spoolDir() string {
	return "/var/lib/bas-agent/spool"
}
