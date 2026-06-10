package api

import "time"

// AgentOfflineAfter is how long after its last heartbeat an agent is considered
// offline. A dead/rebooted endpoint stops heartbeating; once last_update is older
// than this the agent shows "offline" and any run it was executing is reaped.
// Single source of truth: the background staleness monitor (cmd/server) and the
// read-path/dispatch-path checks below all use this value. Comfortably exceeds the
// heartbeat interval to avoid flapping on a single missed beat.
const AgentOfflineAfter = 90 * time.Second

// effectiveAgentStatus overrides the stored connectivity status with "offline"
// when the agent's last heartbeat is older than AgentOfflineAfter. Stored status
// only changes on heartbeat, so without this a dead agent shows its last-known
// status until the background monitor next runs. Computing it on read makes the
// dashboard correct immediately and stays right even if the monitor is delayed.
// Independent of the security `state` (active/quarantined/…).
func effectiveAgentStatus(stored string, lastUpdate, now time.Time) string {
	if now.Sub(lastUpdate) > AgentOfflineAfter {
		return "offline"
	}
	return stored
}

// runIsStale reports whether a 'running' scenario_run should be reaped: either its
// agent has gone offline (heartbeat older than AgentOfflineAfter — the agent died
// mid-run) or the run has exceeded the hard staleRunGuard ceiling (a wedged run on
// a still-live agent). The offline check frees a dead-agent run at dispatch time
// instead of waiting the full staleRunGuard.
func runIsStale(runStarted, agentLastUpdate, now time.Time) bool {
	if now.Sub(agentLastUpdate) > AgentOfflineAfter {
		return true
	}
	return now.Sub(runStarted) > staleRunGuard
}
