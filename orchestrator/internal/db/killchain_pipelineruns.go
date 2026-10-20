package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Pipeline run states. A run is written as running before its check starts, and becomes
// completed once its results are written. A completed run never changes.
const (
	PipelineRunning   = "running"
	PipelineCompleted = "completed"
)

// ErrPipelineRunNotFound means no run was ever started under that execution ID.
var ErrPipelineRunNotFound = errors.New("pipeline run not found")

// PipelineRun is one persisted pipeline check. Results holds the JSON of the per-stage
// results once the run is completed.
type PipelineRun struct {
	ExecutionID string
	CampaignID  string
	StageKey    string
	ConnectorID string
	State       string
	StartedAt   time.Time
	CompletedAt time.Time
	Results     []byte
}

// BeginPipelineRun records that a check is starting. Beginning the same execution ID twice
// is a no-op, so a retried start does not create a second run.
func (s KillChainStore) BeginPipelineRun(ctx context.Context, r PipelineRun) error {
	if r.ExecutionID == "" || r.CampaignID == "" || r.StageKey == "" || r.ConnectorID == "" {
		return fmt.Errorf("pipeline run needs execution, campaign, stage and connector identifiers")
	}
	_, err := s.Pool.Exec(ctx, `INSERT INTO killchain_pipeline_runs
		(execution_id, campaign_id, stage_key, connector_id, state, started_at)
		VALUES ($1, $2, $3, $4, 'running', $5)
		ON CONFLICT (execution_id) DO NOTHING`,
		r.ExecutionID, r.CampaignID, r.StageKey, r.ConnectorID, r.StartedAt.UTC())
	return err
}

// CompletePipelineRun writes the results of a running check. Completing a run that is already
// completed with identical results succeeds without change. Completing it with different
// results is refused, because a completed run is final.
func (s KillChainStore) CompletePipelineRun(ctx context.Context, executionID string, results []byte, at time.Time) error {
	if !json.Valid(results) {
		return fmt.Errorf("pipeline results are not valid JSON")
	}
	tag, err := s.Pool.Exec(ctx, `UPDATE killchain_pipeline_runs
		SET state = 'completed', results = $2, completed_at = $3
		WHERE execution_id = $1 AND state = 'running'`, executionID, results, at.UTC())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	existing, err := s.PipelineRun(ctx, executionID)
	if err != nil {
		return err
	}
	if existing.State == PipelineCompleted && string(existing.Results) == string(results) {
		return nil
	}
	return fmt.Errorf("pipeline run %s is already completed with different results", executionID)
}

// PipelineRun reads one run. A missing run is ErrPipelineRunNotFound; any other error is a
// read failure, which is retryable and must not be treated as the run not existing.
func (s KillChainStore) PipelineRun(ctx context.Context, executionID string) (PipelineRun, error) {
	var r PipelineRun
	var completed *time.Time
	var results []byte
	err := s.Pool.QueryRow(ctx, `SELECT execution_id, campaign_id, stage_key, connector_id, state,
		started_at, completed_at, results FROM killchain_pipeline_runs WHERE execution_id = $1`, executionID).
		Scan(&r.ExecutionID, &r.CampaignID, &r.StageKey, &r.ConnectorID, &r.State, &r.StartedAt, &completed, &results)
	if errors.Is(err, pgx.ErrNoRows) {
		return PipelineRun{}, ErrPipelineRunNotFound
	}
	if err != nil {
		return PipelineRun{}, err
	}
	if completed != nil {
		r.CompletedAt = *completed
	}
	r.Results = results
	return r, nil
}
