package api

import (
	"context"
	"log"
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

// neverStartedGuard is how long a 'running' scenario_run may sit with zero
// reported progress (steps_total still 0 — no run_started event has ever
// arrived) before it's presumed to have never actually reached the agent.
// Deliberately much shorter than staleRunGuard (2h): a run that genuinely
// started just takes however long it takes, but one that never started
// should report that within seconds, not hours. This exists because
// ws.Hub.SendToAgent reports success the moment a message is queued, not
// once it's actually transmitted — a large ScenarioCommand that can't be
// written within the connection's write deadline drops silently, leaving
// nothing to tell the run it never arrived. Without this, such a run sits
// at "running"/0-of-0 forever (or until staleRunGuard, reactively, only if
// another dispatch to the same agent happens to be attempted).
const neverStartedGuard = 60 * time.Second

// ReapNeverStartedRuns marks any 'running' scenario_run that has exceeded
// neverStartedGuard with zero reported progress as 'failed'. Called on a
// poll tick (see cmd/server/main.go). Safe to call concurrently with
// itself or with a genuine run_started event landing mid-sweep: the UPDATE
// re-checks status/steps_total in its own WHERE clause, so a run that
// starts progressing between the SELECT and the UPDATE is never clobbered.
func (h *Handler) ReapNeverStartedRuns(ctx context.Context) error {
	rows, err := h.db.Query(ctx,
		`SELECT id, agent_id FROM scenario_runs
		  WHERE status = 'running' AND steps_total = 0
		    AND started_at < NOW() - make_interval(secs => $1)`,
		int(neverStartedGuard.Seconds()),
	)
	if err != nil {
		return err
	}
	type stuckRun struct{ id, agentID string }
	var stuck []stuckRun
	for rows.Next() {
		var s stuckRun
		if err := rows.Scan(&s.id, &s.agentID); err != nil {
			continue
		}
		stuck = append(stuck, s)
	}
	rows.Close()

	for _, s := range stuck {
		tag, err := h.db.Exec(ctx,
			`UPDATE scenario_runs SET status = 'failed', completed_at = NOW()
			  WHERE id = $1 AND status = 'running' AND steps_total = 0`,
			s.id,
		)
		if err != nil {
			log.Printf("[dispatch] reap never-started run %s: %v", s.id, err)
			continue
		}
		if tag.RowsAffected() > 0 {
			log.Printf("[dispatch] run %s on agent %s never started (no progress within %s) — marked failed", s.id, s.agentID, neverStartedGuard)
		}
	}
	return nil
}
