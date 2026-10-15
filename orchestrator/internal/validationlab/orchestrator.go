// Package validationlab drives TCF-originated DRAFT content through a
// factory-owned lab agent for EXECUTION-level validation. See
// docs/superpowers/specs/2026-10-14-tcf-phase6-validation-lab-design.md.
package validationlab

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/contentregistry"
	"github.com/audspect/bas/internal/scenario"
)

// dispatcher is the one entry point into dispatchRun this package needs --
// a separate package cannot call internal/api's unexported dispatchRun
// directly (Task 6 adds *api.Handler's exported wrapper).
type dispatcher interface {
	DispatchFactoryValidation(ctx context.Context, sc *scenario.Scenario, agentID string) (runID, skipReason string, err error)
}

type Orchestrator struct {
	pool         *pgxpool.Pool
	reg          *contentregistry.Registry
	dispatcher   dispatcher
	labAgentID   string
	pollInterval time.Duration
	stopCh       chan struct{}
	stopOnce     sync.Once
	timeout      time.Duration
	pollEvery    time.Duration
}

func NewOrchestrator(pool *pgxpool.Pool, reg *contentregistry.Registry, d dispatcher, labAgentID string, pollInterval time.Duration) *Orchestrator {
	return &Orchestrator{
		pool: pool, reg: reg, dispatcher: d, labAgentID: labAgentID, pollInterval: pollInterval,
		stopCh: make(chan struct{}), timeout: 10 * time.Minute, pollEvery: 5 * time.Second,
	}
}

// selectEligible returns DRAFT content_version ids that are genuinely
// factory-originated. ActorComposer is always factory output; ActorGenerator
// is shared by factory generation (which carries a 'generated_for' provenance
// link) and plain intel intake (no such link, exempt), so the generator branch
// requires the provenance link -- the same discriminator the publish gate uses
// (see contentregistry.hasGenerationProvenance).
func (o *Orchestrator) selectEligible(ctx context.Context) ([]string, error) {
	rows, err := o.pool.Query(ctx,
		`SELECT cv.id FROM content_versions cv
		  WHERE cv.lifecycle = 'DRAFT'
		    AND ( cv.created_by = $2
		       OR ( cv.created_by = $1 AND EXISTS (
		              SELECT 1 FROM content_version_threats t
		               WHERE t.content_version_id = cv.id AND t.relationship_kind = 'generated_for') ) )
		  ORDER BY cv.created_at ASC`,
		contentregistry.ActorGenerator, contentregistry.ActorComposer)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// runOnce performs one scan tick: claim each eligible candidate, re-check
// safety, and either refuse back to DRAFT or dispatch. Processes at most
// one candidate that reaches dispatch per tick -- v1's single lab agent can
// only run one validation at a time (scenario_runs' own unique running-run
// index enforces this at the DB level regardless).
func (o *Orchestrator) runOnce(ctx context.Context) error {
	ids, err := o.selectEligible(ctx)
	if err != nil {
		return err
	}
	dispatched := false
	for _, id := range ids {
		// Only one validation runs per tick (single lab slot). Once this tick
		// has dispatched one, stop BEFORE claiming any further candidate --
		// claiming without dispatching would strand it in VALIDATING with no
		// in-flight row, where no recovery path reaches it. Un-dispatched
		// candidates stay DRAFT and a later tick takes them. A safety-recheck
		// refusal below does NOT set dispatched, so the loop continues to the
		// next candidate after returning the refused one to DRAFT.
		if dispatched {
			break
		}
		if err := o.reg.Transition(ctx, id, contentregistry.LifecycleValidating, contentregistry.ActorValidationLab, "claimed for validation"); err != nil {
			continue // already claimed by another tick/instance, or no longer DRAFT -- not an error, just skip
		}
		v, err := o.reg.LoadVersion(ctx, id)
		if err != nil {
			log.Printf("[validationlab] load claimed version %s: %v", id, err)
			_ = o.reg.Transition(ctx, id, contentregistry.LifecycleDraft, contentregistry.ActorValidationLab, "load failed after claim")
			continue
		}
		if err := o.reg.DispatchSafetyRecheck(ctx, v); err != nil {
			log.Printf("[validationlab] %s failed dispatch safety re-check: %v", id, err)
			_ = o.reg.Transition(ctx, id, contentregistry.LifecycleDraft, contentregistry.ActorValidationLab, "dispatch safety re-check refused")
			continue
		}
		if o.dispatcher == nil {
			// No dispatcher wired (test/unconfigured): the claim and safety
			// re-check above have run; leave this one claimed in VALIDATING and
			// stop. resolveOrphaned recovers a VALIDATING row whose in-flight
			// placeholder (written only once a real dispatcher runs) ages out or
			// whose execution row is already terminal.
			break
		}
		dispatched = true
		o.dispatchAndResolve(ctx, id, v)
	}
	return nil
}

// dispatchAndResolve dispatches a claimed, safety-checked version via the
// orchestrator's dispatcher and resolves it (immediately, on a dispatch
// failure, or after polling the dispatched run to completion/timeout).
func (o *Orchestrator) dispatchAndResolve(ctx context.Context, versionID string, v contentregistry.Version) {
	sc, err := v.Parse()
	if err != nil {
		log.Printf("[validationlab] %s failed to parse for dispatch: %v", versionID, err)
		o.recordExecutionOutcome(ctx, versionID, "", "ERROR", map[string]any{"error": err.Error()})
		_ = o.reg.Transition(ctx, versionID, contentregistry.LifecycleDraft, contentregistry.ActorValidationLab, "parse failed")
		return
	}
	runID, skipReason, err := o.dispatcher.DispatchFactoryValidation(ctx, sc, o.labAgentID)
	if err != nil || runID == "" {
		reason := skipReason
		if err != nil {
			reason = err.Error()
		}
		o.recordExecutionOutcome(ctx, versionID, "", "ERROR", map[string]any{"dispatch_failure": reason})
		_ = o.reg.Transition(ctx, versionID, contentregistry.LifecycleDraft, contentregistry.ActorValidationLab, "dispatch failed: "+reason)
		return
	}
	o.recordExecutionOutcome(ctx, versionID, runID, "NO_DATA", map[string]any{"status": "dispatched"})
	o.pollAndResolve(ctx, versionID, runID)
}

// recordExecutionOutcome writes the one EXECUTION-level content_validations
// row for a validation attempt. outcome='NO_DATA' with a non-null run_id is
// the in-flight placeholder written at dispatch time; a later call with the
// real PASS/FAIL/ERROR updates that same row in place by UPDATE (an
// ON CONFLICT on a partial unique index keyed on outcome='NO_DATA' cannot
// catch this: the new row's own outcome is never 'NO_DATA' at that point,
// so it would never satisfy the index's predicate and the conflict would
// never fire). A dispatch failure with no prior placeholder, or the very
// first placeholder write itself, falls through to a plain INSERT.
func (o *Orchestrator) recordExecutionOutcome(ctx context.Context, versionID, runID, outcome string, detail map[string]any) {
	d, _ := json.Marshal(detail)
	var runIDArg any
	if runID != "" {
		runIDArg = runID
	}
	tag, err := o.pool.Exec(ctx,
		`UPDATE content_validations SET outcome = $2, run_id = $3, detail = $4
		  WHERE content_version_id = $1 AND level = 'EXECUTION' AND outcome = 'NO_DATA'`,
		versionID, outcome, runIDArg, d)
	if err != nil {
		log.Printf("[validationlab] update outcome for %s: %v", versionID, err)
		return
	}
	if tag.RowsAffected() > 0 {
		return
	}
	if _, err := o.pool.Exec(ctx,
		`INSERT INTO content_validations (content_version_id, level, outcome, run_id, validator, validator_version, detail)
		 VALUES ($1, 'EXECUTION', $2, $3, 'validationlab', '1', $4)`,
		versionID, outcome, runIDArg, d); err != nil {
		log.Printf("[validationlab] insert outcome for %s: %v", versionID, err)
	}
}

// pollAndResolve waits (bounded) for a just-dispatched run to complete, then
// resolves the version. Shares its resolution logic with resolveOrphaned so
// a crash between dispatch and completion is handled identically to a live
// wait, not as a special case.
func (o *Orchestrator) pollAndResolve(ctx context.Context, versionID, runID string) {
	deadline := time.Now().Add(o.timeout)
	for time.Now().Before(deadline) {
		if o.resolveIfComplete(ctx, versionID, runID) {
			return
		}
		select {
		case <-o.stopCh:
			return // shutdown interrupts the poll; resolveOrphaned recovers this run later
		case <-time.After(o.pollEvery):
		}
	}
	o.recordExecutionOutcome(ctx, versionID, runID, "ERROR", map[string]any{"error": "validation run timed out"})
	_ = o.reg.Transition(ctx, versionID, contentregistry.LifecycleDraft, contentregistry.ActorValidationLab, "validation timed out")
}

// resolveIfComplete checks one run's current status and, if terminal,
// records the outcome and transitions the version. Returns true once
// resolved (terminal), false if still running.
//
// A run's status alone is not the validation verdict: a run is 'completed'
// whenever the agent submitted a non-partial snapshot, INCLUDING an
// all-skipped run that executed nothing (handlers.go completes a len(steps)==0
// run immediately). A factory validation must prove the content actually
// EXECUTED correctly, so a completed run is judged from its per-step results:
// PASS only when at least one step executed (pass/fail) and none errored;
// nothing executed -> NO_DATA; a step errored -> FAIL; malformed -> ERROR.
func (o *Orchestrator) resolveIfComplete(ctx context.Context, versionID, runID string) bool {
	var status string
	var resultsJSON []byte
	if err := o.pool.QueryRow(ctx, `SELECT status, results FROM scenario_runs WHERE id = $1`, runID).Scan(&status, &resultsJSON); err != nil {
		log.Printf("[validationlab] read run %s status: %v", runID, err)
		return false
	}
	if status == "running" {
		return false
	}
	outcome, reason := "FAIL", "validation run status: "+status
	if status == "completed" {
		outcome, reason = classifyCompletedRun(resultsJSON)
	}
	o.recordExecutionOutcome(ctx, versionID, runID, outcome, map[string]any{"run_id": runID, "status": status, "reason": reason})
	if outcome == "PASS" {
		_ = o.reg.Transition(ctx, versionID, contentregistry.LifecycleValidated, contentregistry.ActorValidationLab, reason)
	} else {
		_ = o.reg.Transition(ctx, versionID, contentregistry.LifecycleDraft, contentregistry.ActorValidationLab, reason)
	}
	return true
}

// classifyCompletedRun maps a completed run's per-step results to a validation
// outcome. CheckResult values: pass|fail mean the step executed (fail = the
// technique succeeded against the control, still a clean execution for the
// factory's "does it run" question); error means the step itself errored;
// skipped means it never ran.
func classifyCompletedRun(resultsJSON []byte) (outcome, reason string) {
	if len(resultsJSON) == 0 {
		return "NO_DATA", "run completed with no results recorded"
	}
	var rs []struct {
		Result string `json:"result"`
	}
	if err := json.Unmarshal(resultsJSON, &rs); err != nil {
		return "ERROR", "run results were malformed"
	}
	executed, errored := 0, 0
	for _, r := range rs {
		switch r.Result {
		case "pass", "fail":
			executed++
		case "error":
			errored++
		}
	}
	switch {
	case errored > 0:
		return "FAIL", "one or more steps errored during execution"
	case executed == 0:
		return "NO_DATA", "no steps executed (all skipped); nothing to validate"
	default:
		return "PASS", "content executed cleanly"
	}
}

// Start launches the orchestrator's periodic scan loop in the background.
func (o *Orchestrator) Start() {
	go o.run()
	log.Printf("[validationlab] started (poll interval: %s)", o.pollInterval)
}

// Stop ends the periodic scan loop. Safe to call more than once.
func (o *Orchestrator) Stop() {
	o.stopOnce.Do(func() { close(o.stopCh) })
}

func (o *Orchestrator) run() {
	ticker := time.NewTicker(o.pollInterval)
	defer ticker.Stop()
	ctx := context.Background()
	_ = o.resolveOrphaned(ctx) // recover anything left mid-flight by a previous process, before scanning for new work
	for {
		select {
		case <-o.stopCh:
			return
		case <-ticker.C:
			if err := o.runOnce(ctx); err != nil {
				log.Printf("[validationlab] runOnce: %v", err)
			}
			_ = o.resolveOrphaned(ctx)
		}
	}
}

// resolveOrphaned scans every VALIDATING version and resolves it from durable
// state alone, recovering from any crash window:
//   - latest EXECUTION row terminal (PASS/FAIL/ERROR): the outcome was recorded
//     but the lifecycle transition was lost -- re-apply it (self-heal).
//   - latest EXECUTION row NO_DATA with a run_id: still in flight -- resolve from
//     the run's status, or, if it never reached a terminal status and the
//     placeholder is older than the timeout, force it to ERROR/DRAFT so the
//     single lab slot is never held forever.
func (o *Orchestrator) resolveOrphaned(ctx context.Context) error {
	rows, err := o.pool.Query(ctx,
		`SELECT cv.id, v.run_id, v.outcome, v.created_at
		   FROM content_versions cv
		   JOIN LATERAL (
		     SELECT run_id, outcome, created_at FROM content_validations
		      WHERE content_version_id = cv.id AND level = 'EXECUTION'
		      ORDER BY created_at DESC LIMIT 1
		   ) v ON true
		  WHERE cv.lifecycle = 'VALIDATING'`)
	if err != nil {
		return err
	}
	type pending struct {
		versionID string
		runID     *string
		outcome   string
		createdAt time.Time
	}
	var work []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.versionID, &p.runID, &p.outcome, &p.createdAt); err != nil {
			rows.Close()
			return err
		}
		work = append(work, p)
	}
	rows.Close()

	for _, p := range work {
		switch p.outcome {
		case "NO_DATA":
			if p.runID != nil && o.resolveIfComplete(ctx, p.versionID, *p.runID) {
				continue // resolved from a now-terminal run status
			}
			if time.Since(p.createdAt) > o.timeout {
				var rid string
				if p.runID != nil {
					rid = *p.runID
				}
				o.recordExecutionOutcome(ctx, p.versionID, rid, "ERROR", map[string]any{"error": "orphaned validation exceeded timeout"})
				_ = o.reg.Transition(ctx, p.versionID, contentregistry.LifecycleDraft, contentregistry.ActorValidationLab, "orphaned validation timed out")
			}
		case "PASS":
			_ = o.reg.Transition(ctx, p.versionID, contentregistry.LifecycleValidated, contentregistry.ActorValidationLab, "recovered: execution outcome already PASS")
		default: // FAIL, ERROR -- outcome recorded, transition lost
			_ = o.reg.Transition(ctx, p.versionID, contentregistry.LifecycleDraft, contentregistry.ActorValidationLab, "recovered: execution outcome terminal ("+p.outcome+")")
		}
	}
	return nil
}
