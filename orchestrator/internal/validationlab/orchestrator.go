// Package validationlab drives TCF-originated DRAFT content through a
// factory-owned lab agent for EXECUTION-level validation. See
// docs/superpowers/specs/2026-10-14-tcf-phase6-validation-lab-design.md.
package validationlab

import (
	"context"
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

// selectEligible returns DRAFT content_version ids whose created_by marks
// them as TCF-originated and that are not already mid-flight.
func (o *Orchestrator) selectEligible(ctx context.Context) ([]string, error) {
	rows, err := o.pool.Query(ctx,
		`SELECT id FROM content_versions
		  WHERE lifecycle = 'DRAFT' AND created_by IN ($1, $2)
		  ORDER BY created_at ASC`,
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

// dispatchAndResolve is replaced below (Task 6) to actually dispatch via the
// orchestrator's dispatcher, poll for completion, and resolve the version's
// lifecycle. Task 5's own tests never reach this -- they construct the
// Orchestrator with a nil dispatcher, which runOnce checks for above.
func (o *Orchestrator) dispatchAndResolve(ctx context.Context, versionID string, v contentregistry.Version) {
	_ = v
	log.Printf("[validationlab] %s claimed and safety-checked, but no dispatcher is wired up", versionID)
}
