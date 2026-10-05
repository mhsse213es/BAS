// Package verifysync persists automatic (on-host) detection verification
// results into internal/verification's store. Nothing else does this today
// — Store.Attest is otherwise only called by manual analyst review and the
// SP3 API connectors — leaving verification_history empty for the common
// case of a purely-automatic BAS run. See design spec
// docs/superpowers/specs/2026-07-27-automatic-verdict-persistence-design.md.
//
// Safety invariant: this package NEVER supersedes an existing
// verification_history record of any source. It reads
// Store.CurrentForRun before attesting and only fills expectations with no
// active record at all.
package verifysync

import (
	"context"
	"encoding/json"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/verification"
)

// Job periodically persists automatic verification results for completed
// BAS runs.
type Job struct {
	db        *pgxpool.Pool
	store     *verification.Store
	scenarios reporting.ScenarioResolver
	batchSize int
	// runContent, when set, resolves each run against its pinned content
	// version instead of scenarios (TCF Phase 1 §7).
	runContent reporting.RunContentFunc
}

// WithRunContent attaches the run-scoped content view. Must be called before
// the Job's Tick is scheduled. Returns the job for chaining.
func (j *Job) WithRunContent(f reporting.RunContentFunc) *Job { j.runContent = f; return j }

// NewJob builds a Job. batchSize defaults to 50 (bounds each Tick's DB work
// regardless of how many runs are pending).
func NewJob(db *pgxpool.Pool, store *verification.Store, scenarios reporting.ScenarioResolver) *Job {
	return &Job{db: db, store: store, scenarios: scenarios, batchSize: 50}
}

// Tick processes up to one batch of not-yet-processed runs. Safe to call on
// every scheduler tick regardless of how many runs are pending.
func (j *Job) Tick(ctx context.Context) {
	rows, err := j.db.Query(ctx,
		`SELECT id, scenario_id, results FROM scenario_runs
		 WHERE status IN ('completed','failed','partial') AND NOT auto_verified
		 LIMIT $1`, j.batchSize)
	if err != nil {
		log.Printf("[verifysync] query pending runs: %v", err)
		return
	}
	type pending struct {
		runID, scenarioID string
		resultsRaw        []byte
	}
	var runs []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.runID, &p.scenarioID, &p.resultsRaw); err != nil {
			rows.Close()
			log.Printf("[verifysync] scan pending run: %v", err)
			return
		}
		runs = append(runs, p)
	}
	rows.Close()

	for _, p := range runs {
		if err := j.processRun(ctx, p.runID, p.scenarioID, p.resultsRaw); err != nil {
			log.Printf("[verifysync] process run %s: %v", p.runID, err)
			continue // leave auto_verified=false, retried next tick
		}
		if _, err := j.db.Exec(ctx,
			`UPDATE scenario_runs SET auto_verified=true WHERE id=$1`, p.runID); err != nil {
			log.Printf("[verifysync] mark run %s processed: %v", p.runID, err)
		}
	}
}

func (j *Job) processRun(ctx context.Context, runID, scenarioID string, resultsRaw []byte) error {
	var results []models.SimulationResult
	if len(resultsRaw) > 0 {
		if err := json.Unmarshal(resultsRaw, &results); err != nil {
			return err
		}
	}
	if err := j.annotateSinkReceipts(ctx, runID, results); err != nil {
		return err
	}
	resolver := j.scenarios
	if j.runContent != nil {
		if info := j.runContent(ctx, runID); info.Resolver != nil {
			resolver = info.Resolver
		}
	}
	specs := reporting.ResolveStepDetectionSpecs(resolver, scenarioID)
	if len(specs) == 0 {
		return nil // nothing declared any expectation
	}
	verdicts := reporting.ComputeAutomaticVerifications(specs, results)

	existing, err := j.store.CurrentForRun(ctx, runID)
	if err != nil {
		return err
	}

	for _, vr := range verdicts {
		result, ok := mapStatusToResult(vr.Status)
		if !ok {
			continue // Pending/Unknown — nothing provable, never attested
		}
		if _, already := existing[vr.ExpectedID]; already {
			continue // safety invariant: never supersede an existing record, of any source
		}
		if _, err := j.store.Attest(ctx, verification.AttestInput{
			RunID:         runID,
			ExpectationID: vr.ExpectedID,
			TechniqueID:   vr.TechniqueID,
			Domain:        vr.Domain,
			Provider:      vr.Provider,
			Result:        result,
			WorkflowState: verification.StateApproved,
			Source:        verification.SourceAutomatic,
			VerifiedBy:    "automatic",
			RuleIDs:       vr.RuleIDs,
		}); err != nil {
			return err
		}
	}
	return nil
}

// annotateSinkReceipts sets SinkTokenObserved on each result whose
// technique had a sink token issued for this run -- true if
// dlp_sink_receipts shows it was received at least once, false if the
// token was issued but never received, left nil (untouched) for any
// technique with no issued token at all. Mutates results in place; this
// is the one place in the DLP sink verification path that touches the
// database -- internal/reporting stays a pure function throughout.
func (j *Job) annotateSinkReceipts(ctx context.Context, runID string, results []models.SimulationResult) error {
	rows, err := j.db.Query(ctx,
		`SELECT t.technique_id, EXISTS (
		   SELECT 1 FROM dlp_sink_receipts r WHERE r.token = t.token
		 ) AS received
		 FROM dlp_sink_tokens t WHERE t.run_id = $1`,
		runID,
	)
	if err != nil {
		return err
	}
	observed := map[string]bool{}
	for rows.Next() {
		var techniqueID string
		var received bool
		if err := rows.Scan(&techniqueID, &received); err != nil {
			rows.Close()
			return err
		}
		observed[techniqueID] = received
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range results {
		if received, ok := observed[results[i].ID]; ok {
			r := received
			results[i].SinkTokenObserved = &r
		}
	}
	return nil
}

func mapStatusToResult(status string) (string, bool) {
	switch status {
	case reporting.StatusDetected:
		return verification.ResultDetected, true
	case reporting.StatusNotDetected:
		return verification.ResultNotDetected, true
	case reporting.StatusNotApplicable:
		return verification.ResultNotApplicable, true
	default:
		return "", false
	}
}
