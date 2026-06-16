// Package campaign derives a campaign's rollup (status, progress, result mix)
// from its child runs. Pure + server-side; compute-on-read, no stored counters.
package campaign

import "github.com/audspect/bas/internal/models"

// ChildRun is the minimal projection of a child scenario_run needed for rollup.
// Results and Score are consumed by Aggregate (result mix / effectiveness), not
// by DeriveStatus.
type ChildRun struct {
	Status  string // running | completed | partial | failed
	Results []models.SimulationResult
	Score   *models.Score
}

// Skip records a target agent that could not be dispatched at launch.
type Skip struct {
	AgentID string `json:"agentId"`
	Reason  string `json:"reason"`
}

// isTerminal reports whether a child-run status is a finished state. Any value
// outside the known terminal set (incl. "running" or an unexpected status) is
// treated as in-flight, so the campaign reads as "running" until every child
// reaches a recognised terminal state — we never report a campaign done while a
// child is in an unknown state.
func isTerminal(s string) bool { return s == "completed" || s == "partial" || s == "failed" }

// DeriveStatus computes the campaign status. Only `stopped` is sticky (operator
// action); everything else is derived. Empty = zero dispatched children (all
// targets skipped) — "no executable targets", distinct from failed. The `skips`
// count is accepted for call-site symmetry with Aggregate; status keys off the
// child runs (an all-skipped campaign has zero children → empty).
func DeriveStatus(runs []ChildRun, skips int, stopped bool) string {
	if stopped {
		return "stopped"
	}
	if len(runs) == 0 {
		return "empty"
	}
	allCompleted, allFailed, anyRunning := true, true, false
	for _, r := range runs {
		if !isTerminal(r.Status) {
			anyRunning = true
		}
		if r.Status != "completed" {
			allCompleted = false
		}
		if r.Status != "failed" {
			allFailed = false
		}
	}
	if anyRunning {
		return "running"
	}
	if allCompleted {
		return "completed"
	}
	if allFailed {
		return "failed"
	}
	return "partial"
}
