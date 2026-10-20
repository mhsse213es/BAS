package api

import (
	"context"
	"errors"
	"fmt"
	"github.com/audspect/bas/internal/db"
	"strings"
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
// Start checks the gate, then dispatches through the existing run path. The run
// path enforces agent state and busy checks. Campaign stages are posture-only,
// so no live-run confirmations apply.
type EngineStageExecutor struct {
	Resolver scenarioResolver
	Runs     scenarioRunReader
	// Attestations supplies the per-expectation results the verification path wrote
	// for a run. Nil leaves detection missing, which the verdict reports as a gap.
	Attestations attestationReader
	// GroundTruth supplies the independent ground-truth record for a run. Nil or
	// no record leaves execution missing, which the verdict reports as a gap.
	GroundTruth groundTruthReader
	// HostEvents supplies the run's Security events and audit state. Nil leaves host
	// evidence unread. Hosts and Scenarios are needed to match it.
	HostEvents hostEventReader
	Hosts      agentHostReader
	Scenarios  scenarioLookup
	// AgentID is the agent a campaign runs on. Empty means no binding.
	AgentID string
	// Dispatcher starts a run through the existing run path. Nil means no dispatch.
	Dispatcher stageDispatcher
	// Options are the operator-approved settings for every stage of the campaign.
	Options stageDispatchOptions
	// Pipelines runs read-only detection-pipeline stages. Nil refuses them.
	Pipelines *pipelineStageRunner
	// OSes reads the agent's OS for the live stage OS check. Nil refuses live stages,
	// because the check cannot run.
	OSes agentOSReader
	// Audit records live stage decisions. Nil records nothing.
	Audit stageAuditFunc
	// Now is the clock for the execution window. Nil uses the wall clock.
	Now func() time.Time
}

// stageDispatchOptions are the settings a campaign run is approved with.
type stageDispatchOptions struct {
	Mode        string
	Reason      string
	InitiatedBy *string
	// ConfirmLive and ConfirmLab are the campaign approval. They are checked per stage,
	// against the stage's own mode.
	ConfirmLive bool
	ConfirmLab  bool
}

// stageDispatcher is the existing run path, reached through a narrow seam.
type stageDispatcher interface {
	DispatchStage(ctx context.Context, sc *scenario.Scenario, agentID string, o stageDispatchOptions) (runID string, skipReason string, err error)
}

// Start checks the scenario through the executable gate, then dispatches it.
func (x EngineStageExecutor) Start(ctx context.Context, campaignID string, st killchain.StageDef) (string, error) {
	if st.Pipeline != nil || st.Inject != nil {
		if x.Pipelines == nil {
			return "", fmt.Errorf("stage %s: %w", st.Key, killchain.ErrNoExecutor)
		}
		return x.Pipelines.start(ctx, campaignID, st)
	}
	if x.Resolver == nil {
		return "", fmt.Errorf("scenario %s: %w", st.ScenarioID, killchain.ErrNoExecutor)
	}
	if _, err := x.Resolver.ResolveExecutable(ctx, st.ScenarioID); err != nil {
		return "", fmt.Errorf("scenario %s is not executable: %w", st.ScenarioID, err)
	}
	if x.AgentID == "" {
		return "", fmt.Errorf("scenario %s resolves as executable, but campaign %s: %w", st.ScenarioID, campaignID, ErrNoAgentBinding)
	}
	if x.Dispatcher == nil {
		return "", fmt.Errorf("scenario %s: %w", st.ScenarioID, killchain.ErrNoExecutor)
	}
	ev, err := x.Resolver.ResolveExecutable(ctx, st.ScenarioID)
	if err != nil {
		return "", fmt.Errorf("scenario %s is not executable: %w", st.ScenarioID, err)
	}
	mode := st.EffectiveMode()
	opts := x.Options
	opts.Mode = mode
	if mode != killchain.ModePosture {
		return x.startLive(ctx, campaignID, st, ev.Scenario, opts)
	}
	return x.dispatch(ctx, ev.Scenario, opts, st)
}

// startLive gates one live stage at start, audits the decision, and dispatches only when
// every gate passes. Gates are re-checked here because the approval may be hours old and
// the execution window may have closed since.
func (x EngineStageExecutor) startLive(ctx context.Context, campaignID string, st killchain.StageDef, sc *scenario.Scenario, opts stageDispatchOptions) (string, error) {
	detail := map[string]any{
		"stage": st.Key, "scenarioId": st.ScenarioID, "agentId": x.AgentID, "mode": opts.Mode,
		"approvedBy": derefString(opts.InitiatedBy), "reason": opts.Reason,
	}
	if err := x.gateLiveStage(ctx, sc, opts); err != nil {
		detail["gate"] = err.Error()
		x.audit(ctx, "killchain.stage.refused", campaignID, detail, "denied")
		return "", fmt.Errorf("stage %s: %w", st.Key, err)
	}
	runID, err := x.dispatch(ctx, sc, opts, st)
	if err != nil {
		detail["gate"] = err.Error()
		x.audit(ctx, "killchain.stage.refused", campaignID, detail, "error")
		return "", err
	}
	detail["runId"] = runID
	x.audit(ctx, "killchain.stage.start", campaignID, detail, "success")
	return runID, nil
}

// gateLiveStage runs every gate for a live stage. Approval and the flag come first,
// then the agent's OS must be known and must match, then the scenario and window rules.
func (x EngineStageExecutor) gateLiveStage(ctx context.Context, sc *scenario.Scenario, opts stageDispatchOptions) error {
	approved := opts.ConfirmLive && (opts.Mode != killchain.ModeLab || opts.ConfirmLab)
	if err := checkLiveStageStart(opts.Mode, approved); err != nil {
		return err
	}
	if x.OSes == nil {
		return errors.New("cannot read the agent's OS, so the live stage OS check cannot run")
	}
	agentOS, err := x.OSes.AgentOS(ctx, x.AgentID)
	if err != nil {
		return fmt.Errorf("read agent OS: %w", err)
	}
	if agentOS == "" {
		return errors.New("agent OS is unknown, so the live stage OS check cannot run")
	}
	clock := x.Now
	if clock == nil {
		clock = time.Now
	}
	_, err = checkLiveGates(sc, opts.Mode, opts.ConfirmLive, opts.ConfirmLab, agentOS, clock())
	return err
}

// dispatch hands a stage to the run path and returns the run id.
func (x EngineStageExecutor) dispatch(ctx context.Context, sc *scenario.Scenario, opts stageDispatchOptions, st killchain.StageDef) (string, error) {
	runID, skip, err := x.Dispatcher.DispatchStage(ctx, sc, x.AgentID, opts)
	if err != nil {
		return "", fmt.Errorf("scenario %s could not be dispatched: %w", st.ScenarioID, err)
	}
	if skip != "" {
		return "", fmt.Errorf("scenario %s was not dispatched: %s", st.ScenarioID, skip)
	}
	if runID == "" {
		return "", fmt.Errorf("scenario %s: dispatch returned no run id", st.ScenarioID)
	}
	return runID, nil
}

// audit records a live-stage decision when an auditor is wired. Nil means none.
func (x EngineStageExecutor) audit(ctx context.Context, action, resource string, detail map[string]any, outcome string) {
	if x.Audit != nil {
		x.Audit(ctx, action, resource, detail, outcome)
	}
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// Collect reads a dispatched run and maps it to stage evidence.
func (x EngineStageExecutor) Collect(ctx context.Context, executionID string) (killchain.StageEvidence, bool, bool, error) {
	if strings.HasPrefix(executionID, pipelineExecPrefix) {
		if x.Pipelines == nil {
			return killchain.StageEvidence{}, true, true, killchain.ErrNoExecutor
		}
		return x.Pipelines.collect(ctx, executionID)
	}
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
		ev := evidenceFromRun(snap)
		if x.Attestations != nil {
			// A read error is returned, not recorded, so the stage stays dispatched and is retried.
			recs, err := x.Attestations.CurrentForRun(ctx, executionID)
			if err != nil {
				return killchain.StageEvidence{}, false, false, err
			}
			ev.Detection = detectionFromRecords(recs)
		}
		if x.GroundTruth != nil {
			rec, ok, err := x.GroundTruth.GroundTruthForRun(ctx, executionID)
			if err != nil {
				return killchain.StageEvidence{}, false, false, err
			}
			if ok {
				ev.GroundTruth.Source = rec.Source
				ev.GroundTruth.Executed = rec.Executed
				ev.GroundTruth.Reference = rec.Reference
				return ev, true, false, nil
			}
		}
		if x.HostEvents != nil && x.Hosts != nil && x.Scenarios != nil {
			rec, ok, gaps, err := x.hostGroundTruth(ctx, snap)
			if err != nil {
				return killchain.StageEvidence{}, false, false, err
			}
			ev.SourceGaps = gaps
			if ok {
				ev.GroundTruth.Source = rec.Source
				ev.GroundTruth.Executed = rec.Executed
				ev.GroundTruth.Reference = rec.Reference
			}
		}
		return ev, true, false, nil
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
			Source:    db.RunRecordSource,
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

// agentOSReader returns the classified OS of an agent. Empty means unknown.
type agentOSReader interface {
	AgentOS(ctx context.Context, agentID string) (string, error)
}

// stageAuditFunc records one audit event.
type stageAuditFunc func(ctx context.Context, action, resource string, detail map[string]any, outcome string)
