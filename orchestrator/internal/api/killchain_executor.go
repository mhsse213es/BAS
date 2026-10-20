package api

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/killchain"
	"github.com/audspect/bas/internal/scenario"
)

// ErrNoAgentBinding is returned when a stage's scenario resolves as executable
// but the campaign has no agent to run it on.
var ErrNoAgentBinding = errors.New("no agent is bound to this campaign; dispatch is not wired")

// scenarioResolver is the one way a scenario may be obtained for execution.
// *scenario.Engine satisfies it.
type scenarioResolver interface {
	ResolveExecutable(ctx context.Context, id string) (scenario.ExecutableVersion, error)
}

// runSnapshot is the part of a scenario run the campaign needs. It is the
// run's own record, not an independent ground truth.
type runSnapshot struct {
	ExecutionID string
	ScenarioID  string
	AgentID     string
	Status      string
	CompletedAt time.Time
}

// scenarioRunReader reads a scenario run by its execution ID.
type scenarioRunReader interface {
	ScenarioRun(ctx context.Context, executionID string) (runSnapshot, error)
}

// EngineStageExecutor runs campaign stages through the scenario engine's
// executable gate. It never runs a scenario the gate refuses, and it never
// fabricates evidence.
//
// Start is still refusing: dispatching a run needs an agent and operator
// confirmations that this path does not yet supply. Collect is written and
// tested against a reader, so it is ready once Start can dispatch.
type EngineStageExecutor struct {
	Resolver scenarioResolver
	Runs     scenarioRunReader
	// AgentID is the agent a campaign runs on. Empty means no binding.
	AgentID string
}

// Start checks the scenario through the executable gate, then refuses to
// dispatch.
func (x EngineStageExecutor) Start(ctx context.Context, campaignID string, st killchain.StageDef) (string, error) {
	if x.Resolver == nil {
		return "", fmt.Errorf("scenario %s: %w", st.ScenarioID, killchain.ErrNoExecutor)
	}
	if _, err := x.Resolver.ResolveExecutable(ctx, st.ScenarioID); err != nil {
		return "", fmt.Errorf("scenario %s is not executable: %w", st.ScenarioID, err)
	}
	if x.AgentID == "" {
		return "", fmt.Errorf("scenario %s resolves as executable, but campaign %s: %w", st.ScenarioID, campaignID, ErrNoAgentBinding)
	}
	return "", fmt.Errorf("scenario %s: %w", st.ScenarioID, killchain.ErrNoExecutor)
}

// Collect reads a dispatched run and maps it to stage evidence.
func (x EngineStageExecutor) Collect(ctx context.Context, executionID string) (killchain.StageEvidence, bool, bool, error) {
	if x.Runs == nil {
		return killchain.StageEvidence{}, true, true, killchain.ErrNoExecutor
	}
	snap, err := x.Runs.ScenarioRun(ctx, executionID)
	if err != nil {
		return killchain.StageEvidence{}, false, false, err
	}
	switch snap.Status {
	case "running", "dispatched", "pending":
		return killchain.StageEvidence{}, false, false, nil
	case "completed":
		return evidenceFromRun(snap), true, false, nil
	case "failed", "error", "partial":
		// partial means not every step ran, so the stage is not a clean run.
		return killchain.StageEvidence{}, true, true, nil
	default:
		return killchain.StageEvidence{}, true, true, fmt.Errorf("unknown scenario run status %q", snap.Status)
	}
}

// evidenceFromRun records only what a completed run proves. The run shows that
// the scenario was dispatched and finished, so Attempted is yes. It does not
// show whether the action executed, whether a control blocked it, or whether
// anything detected it. Those stay missing, so the stage comes out
// INCONCLUSIVE with each gap named.
func evidenceFromRun(snap runSnapshot) killchain.StageEvidence {
	return killchain.StageEvidence{
		ExecutionID: snap.ExecutionID,
		GroundTruth: killchain.GroundTruth{
			Source:    "scenario run record (not independent of Audspect)",
			Attempted: killchain.TriYes,
		},
		Provenance: killchain.Provenance{
			SourceSystem: "scenario_runs",
			Reference:    snap.ExecutionID,
			ReadAt:       snap.CompletedAt,
		},
		Timestamps: killchain.Timestamps{ActionAt: snap.CompletedAt},
	}
}

// poolRunReader reads scenario_runs directly. It is read-only.
type poolRunReader struct {
	pool *pgxpool.Pool
}

// ScenarioRun returns one run's status, or an error if it does not exist.
func (p poolRunReader) ScenarioRun(ctx context.Context, executionID string) (runSnapshot, error) {
	var s runSnapshot
	var completed *time.Time
	err := p.pool.QueryRow(ctx, `SELECT id, scenario_id, agent_id, status, completed_at
		FROM scenario_runs WHERE id = $1`, executionID).Scan(&s.ExecutionID, &s.ScenarioID, &s.AgentID, &s.Status, &completed)
	if errors.Is(err, pgx.ErrNoRows) {
		return runSnapshot{}, fmt.Errorf("scenario run %s not found", executionID)
	}
	if err != nil {
		return runSnapshot{}, err
	}
	if completed != nil {
		s.CompletedAt = *completed
	}
	return s, nil
}
