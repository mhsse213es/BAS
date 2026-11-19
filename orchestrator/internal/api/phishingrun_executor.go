package api

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/phishingrun"
)

// PhishingRunRequest is one request to run a registered phishing
// scenario for real. Parameters carries whatever scenario-specific
// arguments that scenario's own executor needs (e.g. PH-DET-002's
// executionId/targetId) -- validated by the executor, not here.
// InitiatedBy is set by the caller (the handler, from auth claims),
// never trusted from request body fields a client could forge.
type PhishingRunRequest struct {
	ScenarioID  string
	Parameters  map[string]any
	InitiatedBy string
}

// ExecutePhishingRun runs one registered scenario end to end:
// validates it is registered (an unregistered scenario ID never
// inserts a row, even though it may be a real catalog entry -- see
// LookupPhishingRunExecutor's own doc comment), inserts a pending row,
// runs the executor, and writes the terminal status. Synchronous,
// unlike ExecuteEmailGWRun's async dwell-window goroutine: this
// slice's one registered scenario (PH-DET-002) has no real dwell
// window to wait out.
func ExecutePhishingRun(ctx context.Context, pool *pgxpool.Pool, env PhishingRunExecutorEnv, req PhishingRunRequest) (*phishingrun.PhishingRun, error) {
	executor, ok := LookupPhishingRunExecutor(req.ScenarioID)
	if !ok {
		return nil, fmt.Errorf("phishingrun: scenario %q is not executable in this deployment", req.ScenarioID)
	}

	run := &phishingrun.PhishingRun{
		ID:          newID(),
		ScenarioID:  req.ScenarioID,
		Status:      phishingrun.StatusPending,
		InitiatedBy: req.InitiatedBy,
		StartedAt:   time.Now(),
		ExecutionID: executionIDFromParams(req.Parameters),
	}
	if err := db.InsertPhishingRun(ctx, pool, run); err != nil {
		return nil, fmt.Errorf("phishingrun: insert run: %w", err)
	}

	outcome, execErr := executor(ctx, env, run.ID, req.Parameters)
	if execErr != nil {
		run.Status = phishingrun.StatusFailed
		run.Error = execErr.Error()
		if err := db.UpdatePhishingRunStatus(ctx, pool, run.ID, run.Status, nil, run.Error); err != nil {
			return nil, fmt.Errorf("phishingrun: write failed status: %w", err)
		}
		completedAt := time.Now()
		run.CompletedAt = &completedAt
		return run, execErr
	}

	result, err := json.Marshal(outcome)
	if err != nil {
		return nil, fmt.Errorf("phishingrun: marshal outcome: %w", err)
	}
	run.Status = phishingrun.StatusCompleted
	run.Result = result
	if err := db.UpdatePhishingRunStatus(ctx, pool, run.ID, run.Status, result, ""); err != nil {
		return nil, fmt.Errorf("phishingrun: write completed status: %w", err)
	}
	completedAt := time.Now()
	run.CompletedAt = &completedAt
	return run, nil
}
