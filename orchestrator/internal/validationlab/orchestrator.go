// Package validationlab drives TCF-originated DRAFT content through a
// factory-owned lab agent for EXECUTION-level validation. See
// docs/superpowers/specs/2026-10-14-tcf-phase6-validation-lab-design.md.
package validationlab

import (
	"context"
	"encoding/json"
	"log"
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
		if dispatched || o.dispatcher == nil {
			// Already dispatched one this tick (or no dispatcher wired up yet)
			// -- leave this candidate claimed in VALIDATING; a later tick's
			// crash-recovery scan will pick it up.
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
		time.Sleep(o.pollEvery)
	}
	o.recordExecutionOutcome(ctx, versionID, runID, "ERROR", map[string]any{"error": "validation run timed out"})
	_ = o.reg.Transition(ctx, versionID, contentregistry.LifecycleDraft, contentregistry.ActorValidationLab, "validation timed out")
}

// resolveIfComplete checks one run's current status and, if terminal,
// records the outcome and transitions the version. Returns true once
// resolved (terminal), false if still running.
func (o *Orchestrator) resolveIfComplete(ctx context.Context, versionID, runID string) bool {
	var status string
	if err := o.pool.QueryRow(ctx, `SELECT status FROM scenario_runs WHERE id = $1`, runID).Scan(&status); err != nil {
		log.Printf("[validationlab] read run %s status: %v", runID, err)
		return false
	}
	switch status {
	case "running":
		return false
	case "completed":
		o.recordExecutionOutcome(ctx, versionID, runID, "PASS", map[string]any{"run_id": runID, "status": status})
		_ = o.reg.Transition(ctx, versionID, contentregistry.LifecycleValidated, contentregistry.ActorValidationLab, "validation passed")
	default: // failed, partial
		o.recordExecutionOutcome(ctx, versionID, runID, "FAIL", map[string]any{"run_id": runID, "status": status})
		_ = o.reg.Transition(ctx, versionID, contentregistry.LifecycleDraft, contentregistry.ActorValidationLab, "validation failed")
	}
	return true
}

// Start launches the orchestrator's periodic scan loop in the background.
func (o *Orchestrator) Start() {
	go o.run()
	log.Printf("[validationlab] started (poll interval: %s)", o.pollInterval)
}

// Stop ends the periodic scan loop.
func (o *Orchestrator) Stop() {
	close(o.stopCh)
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

// resolveOrphaned scans every VALIDATING version with an in-flight
// content_validations row and resolves it from durable state alone --
// recovers correctly whether this process dispatched it, a now-dead
// process dispatched it, or it has already completed and simply hasn't
// been resolved yet.
func (o *Orchestrator) resolveOrphaned(ctx context.Context) error {
	rows, err := o.pool.Query(ctx,
		`SELECT cv.id, v.run_id FROM content_versions cv
		   JOIN content_validations v ON v.content_version_id = cv.id AND v.level = 'EXECUTION' AND v.outcome = 'NO_DATA'
		  WHERE cv.lifecycle = 'VALIDATING' AND v.run_id IS NOT NULL`)
	if err != nil {
		return err
	}
	type pending struct{ versionID, runID string }
	var work []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.versionID, &p.runID); err != nil {
			rows.Close()
			return err
		}
		work = append(work, p)
	}
	rows.Close()
	for _, p := range work {
		o.resolveIfComplete(ctx, p.versionID, p.runID)
	}
	return nil
}
