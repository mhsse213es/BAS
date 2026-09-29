// Package campaign derives a campaign's rollup (status, progress, result mix)
// from its child runs. Pure + server-side; compute-on-read, no stored counters.
package campaign

import "github.com/audspect/bas/internal/models"

// ChildRun is the minimal projection of a child scenario_run needed for rollup.
// Results and DetectedTechs are consumed by Aggregate (result mix), not by
// DeriveStatus.
type ChildRun struct {
	Status  string // running | completed | partial | failed
	Results []models.SimulationResult
	Score   *models.Score
	// DetectedTechs marks which technique IDs the EDR/SIEM caught for this child.
	// A failed technique (control allowed it) is "detected" only if it shows up
	// here — i.e. the attack succeeded but the blue team still saw it. Otherwise
	// it's a true miss.
	DetectedTechs map[string]bool
	// Paused mirrors scenario_runs.paused -- only meaningful while Status ==
	// "running" (agent-confirmed via its own paused run_event, see
	// event_handlers.go), same as a single run's own Paused field.
	Paused bool
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

// Summary is the compute-on-read rollup of a campaign: derived status, progress,
// target reconciliation, and the security result mix across all child runs.
type Summary struct {
	Status     string `json:"status"`
	Progress   int    `json:"progress"`   // % of dispatched children in a terminal state
	Targets    int    `json:"targets"`    // dispatched + skipped (reconciles to the launch set)
	Dispatched int    `json:"dispatched"` // children that actually got a run row
	Skipped    int    `json:"skipped"`    // targets we couldn't dispatch (offline/busy/...)
	Prevented  int    `json:"prevented"`  // technique results a control stopped (pass/blocked)
	Detected   int    `json:"detected"`   // technique allowed by control but seen by EDR/SIEM
	Missed     int    `json:"missed"`     // technique allowed AND not seen — the real gap
	Errored    int    `json:"errored"`    // execution error or skipped step (excluded from score)
	// Paused is true while at least one still-running child is paused --
	// enough to drive a "Resume campaign" vs "Pause campaign" toggle. A
	// campaign fanned out across many agents pauses independently per
	// agent, so this is "any", not "all": as long as one child needs a
	// Resume, that's the action the operator can still take.
	Paused bool `json:"paused"`
}

// Aggregate rolls child runs + launch-time skips into a campaign Summary. The
// result mix follows the platform's verdict taxonomy: pass/blocked = the control
// prevented the technique; fail = the control allowed it (split into Detected vs
// Missed by whether the blue team still saw it); error/skipped are excluded from
// effectiveness. Progress is the share of dispatched children that have reached a
// terminal state; status is derived (compute-on-read, never stored).
func Aggregate(runs []ChildRun, skips []Skip) Summary {
	s := Summary{
		Dispatched: len(runs),
		Skipped:    len(skips),
	}
	s.Targets = s.Dispatched + s.Skipped

	terminal := 0
	for _, r := range runs {
		if isTerminal(r.Status) {
			terminal++
		}
		if r.Status == "running" && r.Paused {
			s.Paused = true
		}
		for _, res := range r.Results {
			switch res.Result {
			case models.ResultPass, models.ResultBlocked:
				s.Prevented++
			case models.ResultFail:
				if r.DetectedTechs[res.Technique.ID] {
					s.Detected++
				} else {
					s.Missed++
				}
			case models.ResultError, models.ResultSkipped:
				s.Errored++
				// models.ResultVetoed intentionally falls into no case here:
				// a B5 veto is neither a tested-and-stopped control nor a
				// tested-and-missed one, and this switch has no
				// unconditional counter it would otherwise dilute (verified
				// -- B5 Task 9 audit).
			}
		}
	}

	if s.Dispatched > 0 {
		s.Progress = terminal * 100 / s.Dispatched
	}
	s.Status = DeriveStatus(runs, s.Skipped, false)
	return s
}
