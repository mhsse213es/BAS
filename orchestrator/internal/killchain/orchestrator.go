package killchain

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrNoExecutor is returned by an executor that has no adapter for a scenario.
// The stage is then recorded as ERROR. It is never recorded as a pass, and no
// result is invented.
var ErrNoExecutor = errors.New("killchain: no execution adapter is wired for this scenario")

// StageRecord is one stage's persisted state.
type StageRecord struct {
	Key         string         `json:"key"`
	State       StageState     `json:"state"`
	Verdict     Verdict        `json:"verdict,omitempty"`
	Reasons     []string       `json:"reasons,omitempty"`
	ExecutionID string         `json:"executionId,omitempty"`
	Evidence    *StageEvidence `json:"evidence,omitempty"`
}

// CampaignRecord is a stored campaign: its definition and every stage record.
type CampaignRecord struct {
	ID      string
	Def     CampaignDef
	AgentID string // the agent a campaign runs on; empty means no binding
	// CreatedBy is the user who created the campaign. Lab approval must come from another user.
	CreatedBy string
	Stages    map[string]StageRecord
}

// Store persists campaign state. Implementations must make PutStage durable
// before returning, so a crash never loses a verdict that was reported.
type Store interface {
	Campaign(ctx context.Context, id string) (CampaignRecord, error)
	PutStage(ctx context.Context, campaignID string, rec StageRecord) error
}

// Executor runs one stage through an existing execution path. Start must not
// re-run a stage that already has an execution: the orchestrator only calls it
// for a stage in the pending state.
type Executor interface {
	// Start begins one stage and returns its execution identifier.
	Start(ctx context.Context, campaignID string, st StageDef) (executionID string, err error)
	// Collect returns the stage's evidence once it is available. done is false
	// while the execution is still running. failed is true when execution
	// itself failed, and that yields ERROR regardless of evidence.
	Collect(ctx context.Context, executionID string) (ev StageEvidence, done bool, failed bool, err error)
}

// Orchestrator walks a campaign graph. It keeps no state of its own. Every
// decision comes from stored stage records, so a restart resumes correctly.
type Orchestrator struct {
	Store    Store
	Executor Executor
	Now      func() time.Time
}

// Advance moves the campaign as far as it can. It returns when a stage is still
// running, or when every stage has a verdict. It is safe to call repeatedly.
func (o Orchestrator) Advance(ctx context.Context, campaignID string) (Rollup, error) {
	rec, err := o.Store.Campaign(ctx, campaignID)
	if err != nil {
		return Rollup{}, err
	}
	order, err := rec.Def.Validate()
	if err != nil {
		return Rollup{}, err
	}

	stages := rec.Stages
	for _, key := range order {
		st, _ := rec.Def.Stage(key)
		sr := stageOrPending(stages, key)
		if sr.Verdict != "" {
			continue
		}
		if sr.State == StateInterrupted {
			continue
		}

		if sr.State == StateDispatched {
			done, err := o.collect(ctx, campaignID, rec.Def, st, &sr)
			if err != nil {
				return Rollup{}, err
			}
			stages[key] = sr
			if !done {
				break
			}
			continue
		}

		// The stage is pending. Decide whether its upstream stages let it run.
		gate, waiting := o.gate(st, stages)
		if waiting {
			break
		}
		if !gate.open {
			sr = StageRecord{Key: key, State: StateNotReached, Verdict: VerdictNotTested,
				Reasons: []string{gate.reason}}
			if err := o.Store.PutStage(ctx, campaignID, sr); err != nil {
				return Rollup{}, err
			}
			stages[key] = sr
			continue
		}

		execID, err := o.Executor.Start(ctx, campaignID, st)
		if err != nil {
			sr = errorRecord(key, fmt.Sprintf("could not start stage: %v", err))
			if err := o.Store.PutStage(ctx, campaignID, sr); err != nil {
				return Rollup{}, err
			}
			stages[key] = sr
			continue
		}
		sr = StageRecord{Key: key, State: StateDispatched, ExecutionID: execID}
		if err := o.Store.PutStage(ctx, campaignID, sr); err != nil {
			return Rollup{}, err
		}
		stages[key] = sr
		done, err := o.collect(ctx, campaignID, rec.Def, st, &sr)
		if err != nil {
			return Rollup{}, err
		}
		stages[key] = sr
		if !done {
			break
		}
	}
	return Roll(toResults(order, stages)), nil
}

// Reconcile marks every dispatched stage as interrupted. It runs at boot,
// before Advance, because an execution that was running when the process
// stopped can no longer be trusted to finish. Its partial evidence is kept, and
// it is never re-executed.
func (o Orchestrator) Reconcile(ctx context.Context, campaignID string) error {
	rec, err := o.Store.Campaign(ctx, campaignID)
	if err != nil {
		return err
	}
	for _, sr := range rec.Stages {
		if sr.State != StateDispatched {
			continue
		}
		sr.State = StateInterrupted
		sr.Verdict = VerdictInconclusive
		sr.Reasons = []string{"stage interrupted before a result was recorded; partial evidence kept, not re-executed"}
		if err := o.Store.PutStage(ctx, campaignID, sr); err != nil {
			return err
		}
	}
	return nil
}

// collect asks the executor for the result of a dispatched stage. It reports
// whether the stage reached a terminal verdict.
func (o Orchestrator) collect(ctx context.Context, campaignID string, def CampaignDef, st StageDef, sr *StageRecord) (bool, error) {
	ev, done, failed, err := o.Executor.Collect(ctx, sr.ExecutionID)
	if err != nil {
		*sr = errorRecord(st.Key, fmt.Sprintf("could not collect result: %v", err))
		return true, o.Store.PutStage(ctx, campaignID, *sr)
	}
	if !done {
		return false, nil
	}
	if failed {
		*sr = errorRecord(st.Key, "execution failed")
		sr.ExecutionID = ev.ExecutionID
		return true, o.Store.PutStage(ctx, campaignID, *sr)
	}
	rec, err := o.finalize(ctx, campaignID, def, st, sr.ExecutionID, ev)
	if err != nil {
		return false, err
	}
	*sr = rec
	return true, nil
}

// finalize turns a finished execution's evidence into the stored stage record.
// It is shared by normal collection and boot-time recovery, so both apply the
// same causal check and the same evaluation.
func (o Orchestrator) finalize(ctx context.Context, campaignID string, def CampaignDef, st StageDef, execID string, ev StageEvidence) (StageRecord, error) {
	ev.CampaignID = campaignID
	ev.StageKey = st.Key
	ev.ExecutionID = execID
	if st.Pipeline != nil || st.Inject != nil {
		pv, reasons := PipelineVerdict(ev.Pipeline)
		rec := StageRecord{Key: st.Key, State: StateCompleted, Verdict: pv, Reasons: reasons, ExecutionID: execID, Evidence: &ev}
		return rec, o.Store.PutStage(ctx, campaignID, rec)
	}
	ev.MissingEvidence = ev.Missing()
	state := StateCompleted
	v := Evaluate(StageInput{State: state, Policy: st.Policy, Evidence: &ev})
	if err := CheckCausedBy(def, st.Key, ev.CausedBy); err != nil {
		// Evidence that cites a non-upstream cause cannot be trusted to order a timeline.
		v = StageVerdict{Verdict: VerdictInconclusive, Reasons: []string{err.Error()}}
	}
	rec := StageRecord{Key: st.Key, State: state, Verdict: v.Verdict, Reasons: v.Reasons,
		ExecutionID: execID, Evidence: &ev}
	return rec, o.Store.PutStage(ctx, campaignID, rec)
}

// Recover resolves stages that were dispatched before a restart. A finished run
// is collected. A run that is still going is marked interrupted and is never
// re-executed. A read error leaves the stage dispatched, so the next boot retries
// it. It is never recorded as ERROR, because that would be permanent. It returns
// how many stages it resolved.
func (o Orchestrator) Recover(ctx context.Context, campaignID string) (int, error) {
	rec, err := o.Store.Campaign(ctx, campaignID)
	if err != nil {
		return 0, err
	}
	order, err := rec.Def.Validate()
	if err != nil {
		return 0, err
	}
	resolved := 0
	for _, key := range order {
		sr, ok := rec.Stages[key]
		if !ok || sr.State != StateDispatched {
			continue
		}
		st, _ := rec.Def.Stage(key)
		ev, done, failed, err := o.Executor.Collect(ctx, sr.ExecutionID)
		if err != nil {
			continue
		}
		switch {
		case !done:
			sr.State = StateInterrupted
			sr.Verdict = VerdictInconclusive
			sr.Reasons = []string{"stage interrupted by a restart before its run finished; partial evidence kept, not re-executed"}
			if err := o.Store.PutStage(ctx, campaignID, sr); err != nil {
				return resolved, err
			}
		case failed:
			failedRec := errorRecord(key, "execution failed")
			failedRec.ExecutionID = sr.ExecutionID
			if err := o.Store.PutStage(ctx, campaignID, failedRec); err != nil {
				return resolved, err
			}
		default:
			if _, err := o.finalize(ctx, campaignID, rec.Def, st, sr.ExecutionID, ev); err != nil {
				return resolved, err
			}
		}
		resolved++
	}
	return resolved, nil
}

type gateResult struct {
	open   bool
	reason string
}

// gate decides whether a pending stage may run. waiting is true when an
// upstream stage has no verdict yet, so the decision must wait.
func (o Orchestrator) gate(st StageDef, stages map[string]StageRecord) (gateResult, bool) {
	for _, r := range st.Requires {
		up := stageOrPending(stages, r)
		if up.Verdict == "" {
			return gateResult{}, true
		}
		if !st.Continues(up.Verdict) {
			return gateResult{open: false, reason: fmt.Sprintf(
				"not reached: upstream stage %q reported %s, which closes this path", r, up.Verdict)}, false
		}
	}
	return gateResult{open: true}, false
}

func stageOrPending(stages map[string]StageRecord, key string) StageRecord {
	if sr, ok := stages[key]; ok {
		return sr
	}
	return StageRecord{Key: key, State: StatePending}
}

func errorRecord(key, reason string) StageRecord {
	return StageRecord{Key: key, State: StateFailed, Verdict: VerdictError, Reasons: []string{reason}}
}

func toResults(order []string, stages map[string]StageRecord) []StageResult {
	out := make([]StageResult, 0, len(order))
	for _, k := range order {
		sr := stageOrPending(stages, k)
		out = append(out, StageResult{Key: k, State: sr.State, Verdict: sr.Verdict})
	}
	return out
}

// UnwiredExecutor is the production executor until a scenario adapter is
// wired. It refuses every stage, so a campaign run without an adapter ends in
// ERROR, never a fabricated result.
type UnwiredExecutor struct{}

// Start always refuses with ErrNoExecutor.
func (UnwiredExecutor) Start(context.Context, string, StageDef) (string, error) {
	return "", ErrNoExecutor
}

// Collect is never reached, because Start always refuses.
func (UnwiredExecutor) Collect(context.Context, string) (StageEvidence, bool, bool, error) {
	return StageEvidence{}, false, true, ErrNoExecutor
}
