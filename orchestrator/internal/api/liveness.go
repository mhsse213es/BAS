package api

import (
	"time"

	"github.com/audspect/bas/internal/models"
)

// runIsStale reports whether a 'running' scenario_run should be reaped: either its
// agent has gone offline (heartbeat older than models.AgentOfflineAfter — the agent died
// mid-run) or the run has exceeded the hard staleRunGuard ceiling (a wedged run on
// a still-live agent). The offline check frees a dead-agent run at dispatch time
// instead of waiting the full staleRunGuard.
func runIsStale(runStarted, agentLastUpdate, now time.Time) bool {
	if now.Sub(agentLastUpdate) > models.AgentOfflineAfter {
		return true
	}
	return now.Sub(runStarted) > staleRunGuard
}
