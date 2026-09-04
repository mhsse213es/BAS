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

// abandonedRunGuard is how long a 'running' scenario_run's agent may sit
// offline (stale heartbeat) before ReapAbandonedRuns force-marks the run
// 'partial' on the server's own initiative. Deliberately longer than the
// agent's own runDisconnectWatchdog (agent/agent.go: disconnectGracePeriod
// = 90s, matched to AgentOfflineAfter) plus a fair reconnect-and-submit
// window -- an agent that's merely had a brief network blip should get the
// chance to resolve its own run first via its spooled Partial submission.
// This reaper exists only for the agent that never comes back at all
// (crashed, uninstalled, decommissioned): without it, that run would sit
// "Running" until the unrelated, purely-reactive staleRunGuard (2h) in
// dispatchRun's concurrency guard happens to fire -- which requires another
// dispatch attempt to that exact agent, something that may never happen for
// a dead one. See
// docs/superpowers/specs/2026-08-18-individual-run-disconnect-resilience-design.md.
const abandonedRunGuard = 5 * time.Minute

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

// ReapAbandonedRuns marks any 'running' scenario_run 'partial' once its
// agent has been offline (stale heartbeat) past abandonedRunGuard. Called
// on the same poll tick as ReapNeverStartedRuns (see cmd/server/main.go).
// Mirrors that function's structure: match rows first, then UPDATE each
// with its own "AND status = 'running'" re-check in the WHERE clause so a
// run that started progressing (or was independently resolved by the
// agent's own watchdog + late submission) between the SELECT and the
// UPDATE is never clobbered.
func (h *Handler) ReapAbandonedRuns(ctx context.Context) error {
	rows, err := h.db.Query(ctx,
		`SELECT sr.id, sr.agent_id
		   FROM scenario_runs sr
		   JOIN agents a ON a.agent_id = sr.agent_id
		  WHERE sr.status = 'running'
		    AND a.last_update < NOW() - make_interval(secs => $1)`,
		int(abandonedRunGuard.Seconds()),
	)
	if err != nil {
		return err
	}
	type abandonedRun struct{ id, agentID string }
	var abandoned []abandonedRun
	for rows.Next() {
		var a abandonedRun
		if err := rows.Scan(&a.id, &a.agentID); err != nil {
			continue
		}
		abandoned = append(abandoned, a)
	}
	rows.Close()

	for _, a := range abandoned {
		tag, err := h.db.Exec(ctx,
			`UPDATE scenario_runs SET status = 'partial', completed_at = NOW()
			  WHERE id = $1 AND status = 'running'`,
			a.id,
		)
		if err != nil {
			log.Printf("[dispatch] reap abandoned run %s: %v", a.id, err)
			continue
		}
		if tag.RowsAffected() > 0 {
			log.Printf("[dispatch] run %s on agent %s abandoned (agent offline beyond %s) — marked partial", a.id, a.agentID, abandonedRunGuard)
		}
	}
	return nil
}

// ReapStaleRuns marks any 'running' scenario_run 'partial' once it has run
// past staleRunGuard, regardless of agent status. This is the run-level
// wall-clock budget that was previously enforced only reactively -- see
// runIsStale, checked exclusively at dispatchRun's concurrency guard, which
// requires a NEW dispatch to that exact agent to ever fire. A run wedged on
// an agent that stays reachable (heartbeating normally) but never confirms
// completion nor honors command_cancel would otherwise sit "running" forever
// unless someone happens to start another run on the same agent.
// ReapAbandonedRuns already covers the agent-offline case on its own,
// shorter guard (5m); this reaper is the backstop for everything else,
// mirroring its structure: match rows first, then UPDATE each with its own
// "AND status = 'running'" re-check so a run that completes between the
// SELECT and the UPDATE is never clobbered.
func (h *Handler) ReapStaleRuns(ctx context.Context) error {
	rows, err := h.db.Query(ctx,
		`SELECT id, agent_id FROM scenario_runs
		  WHERE status = 'running'
		    AND started_at < NOW() - make_interval(secs => $1)`,
		int(staleRunGuard.Seconds()),
	)
	if err != nil {
		return err
	}
	type staleRun struct{ id, agentID string }
	var stale []staleRun
	for rows.Next() {
		var r staleRun
		if err := rows.Scan(&r.id, &r.agentID); err != nil {
			continue
		}
		stale = append(stale, r)
	}
	rows.Close()

	for _, r := range stale {
		tag, err := h.db.Exec(ctx,
			`UPDATE scenario_runs SET status = 'partial', completed_at = NOW()
			  WHERE id = $1 AND status = 'running'`,
			r.id,
		)
		if err != nil {
			log.Printf("[dispatch] reap stale run %s: %v", r.id, err)
			continue
		}
		if tag.RowsAffected() > 0 {
			h.markVariantRunPartial(ctx, r.id)
			log.Printf("[dispatch] run %s on agent %s exceeded wall-clock budget (%s) — marked partial", r.id, r.agentID, staleRunGuard)
		}
	}
	return nil
}
