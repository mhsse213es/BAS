package killchain

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// memStore is an in-memory Store. It counts writes so tests can check that a
// stage is recorded before the next one starts.
type memStore struct {
	campaigns map[string]CampaignRecord
	writes    int
}

func (m *memStore) Campaign(_ context.Context, id string) (CampaignRecord, error) {
	rec, ok := m.campaigns[id]
	if !ok {
		return CampaignRecord{}, errors.New("not found")
	}
	cp := CampaignRecord{ID: rec.ID, Def: rec.Def, Stages: map[string]StageRecord{}}
	for k, v := range rec.Stages {
		cp.Stages[k] = v
	}
	return cp, nil
}

func (m *memStore) PutStage(_ context.Context, id string, sr StageRecord) error {
	m.writes++
	rec := m.campaigns[id]
	if rec.Stages == nil {
		rec.Stages = map[string]StageRecord{}
	}
	rec.Stages[sr.Key] = sr
	m.campaigns[id] = rec
	return nil
}

// fakeExec returns fixed evidence per stage key. pendingCalls makes Collect
// report not done for a number of calls first. failStart and failRun force the
// error paths.
type fakeExec struct {
	starts       map[string]int
	evidence     map[string]StageEvidence
	pendingCalls map[string]int
	failStart    map[string]bool
	failRun      map[string]bool
}

func newFakeExec() *fakeExec {
	return &fakeExec{starts: map[string]int{}, evidence: map[string]StageEvidence{},
		pendingCalls: map[string]int{}, failStart: map[string]bool{}, failRun: map[string]bool{}}
}

func (f *fakeExec) Start(_ context.Context, _ string, st StageDef) (string, error) {
	f.starts[st.Key]++
	if f.failStart[st.Key] {
		return "", errors.New("adapter refused")
	}
	return "exec-" + st.Key, nil
}

func (f *fakeExec) Collect(_ context.Context, execID string) (StageEvidence, bool, bool, error) {
	key := strings.TrimPrefix(execID, "exec-")
	if f.pendingCalls[key] > 0 {
		f.pendingCalls[key]--
		return StageEvidence{}, false, false, nil
	}
	if f.failRun[key] {
		return StageEvidence{}, true, true, nil
	}
	ev := f.evidence[key]
	return ev, true, false, nil
}

// blockedEv is evidence for a stage whose prevention worked.
func blockedEv() StageEvidence {
	return StageEvidence{
		GroundTruth: GroundTruth{Source: "host", Attempted: TriYes, Executed: TriNo},
		Prevention:  PreventionEvidence{Value: PreventionBlocked},
		Detection:   DetectionEvidence{Value: DetectionDetected, TelemetryHealth: TelemetryHealthy, WindowComplete: TriYes},
		Response:    ResponseEvidence{Value: ResponseContainedVerified},
	}
}

// progressEv is evidence for a stage where the action executed and was not detected.
func progressEv() StageEvidence {
	return StageEvidence{
		GroundTruth: GroundTruth{Source: "host", Attempted: TriYes, Executed: TriYes},
		Prevention:  PreventionEvidence{Value: PreventionAllowed},
		Detection:   DetectionEvidence{Value: DetectionNotDetected, TelemetryHealth: TelemetryHealthy, WindowComplete: TriYes},
		Response:    ResponseEvidence{Value: ResponseNotApplicable},
	}
}

func chainDef() CampaignDef {
	return CampaignDef{ID: "camp", Version: 1, Stages: []StageDef{
		{Key: "initial", ScenarioID: "s-a"},
		{Key: "exec", ScenarioID: "s-b", Requires: []string{"initial"}},
		{Key: "lateral", ScenarioID: "s-c", Requires: []string{"exec"}},
	}}
}

func newOrch(def CampaignDef, exec Executor) (Orchestrator, *memStore) {
	st := &memStore{campaigns: map[string]CampaignRecord{def.ID: {ID: def.ID, Def: def, Stages: map[string]StageRecord{}}}}
	return Orchestrator{Store: st, Executor: exec}, st
}

func TestAdvance_BlockedInitialAccessLeavesDownstreamNotTested(t *testing.T) {
	ex := newFakeExec()
	ex.evidence["initial"] = blockedEv()
	o, st := newOrch(chainDef(), ex)
	r, err := o.Advance(context.Background(), "camp")
	if err != nil {
		t.Fatal(err)
	}
	if ex.starts["exec"] != 0 || ex.starts["lateral"] != 0 {
		t.Fatalf("downstream stages must not execute after a block: %v", ex.starts)
	}
	rec := st.campaigns["camp"]
	if rec.Stages["initial"].Verdict != VerdictBlocked {
		t.Fatalf("initial = %s, want BLOCKED", rec.Stages["initial"].Verdict)
	}
	for _, k := range []string{"exec", "lateral"} {
		if rec.Stages[k].Verdict != VerdictNotTested || rec.Stages[k].State != StateNotReached {
			t.Fatalf("%s = %s/%s, want NOT_TESTED/not_reached", k, rec.Stages[k].Verdict, rec.Stages[k].State)
		}
	}
	if r.Reached != 1 || r.Status != "completed" {
		t.Fatalf("rollup = %+v", r)
	}
}

func TestAdvance_ProgressingStageContinuesDownstream(t *testing.T) {
	ex := newFakeExec()
	ex.evidence["initial"] = progressEv()
	ex.evidence["exec"] = progressEv()
	ex.evidence["lateral"] = progressEv()
	o, _ := newOrch(chainDef(), ex)
	if _, err := o.Advance(context.Background(), "camp"); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"initial", "exec", "lateral"} {
		if ex.starts[k] != 1 {
			t.Fatalf("%s started %d times, want 1", k, ex.starts[k])
		}
	}
}

func TestAdvance_StartFailureIsErrorAndClosesPath(t *testing.T) {
	ex := newFakeExec()
	ex.failStart["initial"] = true
	o, st := newOrch(chainDef(), ex)
	r, _ := o.Advance(context.Background(), "camp")
	rec := st.campaigns["camp"]
	if rec.Stages["initial"].Verdict != VerdictError {
		t.Fatalf("initial = %s, want ERROR", rec.Stages["initial"].Verdict)
	}
	if rec.Stages["exec"].Verdict != VerdictNotTested {
		t.Fatalf("exec = %s, want NOT_TESTED", rec.Stages["exec"].Verdict)
	}
	if !r.Failed || r.Status != "failed" {
		t.Fatalf("rollup = %+v", r)
	}
}

// With no adapter wired, a campaign must end in ERROR and never a pass.
func TestAdvance_UnwiredExecutorNeverProducesAPass(t *testing.T) {
	o, st := newOrch(chainDef(), UnwiredExecutor{})
	r, err := o.Advance(context.Background(), "camp")
	if err != nil {
		t.Fatal(err)
	}
	rec := st.campaigns["camp"]
	if rec.Stages["initial"].Verdict != VerdictError {
		t.Fatalf("initial = %s, want ERROR", rec.Stages["initial"].Verdict)
	}
	if !strings.Contains(rec.Stages["initial"].Reasons[0], "no execution adapter") {
		t.Fatalf("reason must say no adapter is wired: %v", rec.Stages["initial"].Reasons)
	}
	if r.Status == "completed" {
		t.Fatalf("an unwired campaign must not report completed")
	}
}

// A running stage must not be started again, and downstream must wait for it.
func TestAdvance_WaitsForRunningStageWithoutRestarting(t *testing.T) {
	ex := newFakeExec()
	ex.evidence["initial"] = blockedEv()
	ex.pendingCalls["initial"] = 2
	o, _ := newOrch(chainDef(), ex)
	ctx := context.Background()
	r1, _ := o.Advance(ctx, "camp")
	if r1.Status != "partial" {
		t.Fatalf("status after first pass = %s, want partial", r1.Status)
	}
	if _, err := o.Advance(ctx, "camp"); err != nil {
		t.Fatal(err)
	}
	r3, _ := o.Advance(ctx, "camp")
	if ex.starts["initial"] != 1 {
		t.Fatalf("initial started %d times, want exactly 1", ex.starts["initial"])
	}
	if r3.Status != "completed" {
		t.Fatalf("status = %s, want completed", r3.Status)
	}
}

// Advance is safe to repeat. A finished campaign does no further work.
func TestAdvance_IsRestartSafe(t *testing.T) {
	ex := newFakeExec()
	ex.evidence["initial"] = blockedEv()
	o, st := newOrch(chainDef(), ex)
	ctx := context.Background()
	if _, err := o.Advance(ctx, "camp"); err != nil {
		t.Fatal(err)
	}
	before := st.writes
	if _, err := o.Advance(ctx, "camp"); err != nil {
		t.Fatal(err)
	}
	if st.writes != before {
		t.Fatalf("a finished campaign wrote %d more records", st.writes-before)
	}
	if ex.starts["initial"] != 1 {
		t.Fatalf("initial started %d times", ex.starts["initial"])
	}
}

// After a crash mid-stage, Reconcile marks the stage interrupted. Advance must
// not re-execute it, must keep the campaign partial, and must not treat its
// missing result as a pass.
func TestReconcile_InterruptedStageIsNotReExecuted(t *testing.T) {
	ex := newFakeExec()
	o, st := newOrch(chainDef(), ex)
	st.campaigns["camp"] = CampaignRecord{ID: "camp", Def: chainDef(), Stages: map[string]StageRecord{
		"initial": {Key: "initial", State: StateDispatched, ExecutionID: "exec-initial"},
	}}
	ctx := context.Background()
	if err := o.Reconcile(ctx, "camp"); err != nil {
		t.Fatal(err)
	}
	if got := st.campaigns["camp"].Stages["initial"]; got.State != StateInterrupted || got.Verdict != VerdictInconclusive {
		t.Fatalf("after reconcile: %s/%s", got.State, got.Verdict)
	}
	r, err := o.Advance(ctx, "camp")
	if err != nil {
		t.Fatal(err)
	}
	if ex.starts["initial"] != 0 {
		t.Fatalf("an interrupted stage was re-executed")
	}
	if r.Status != "partial" {
		t.Fatalf("status = %s, want partial", r.Status)
	}
}

func TestAdvance_RejectsInvalidDefinition(t *testing.T) {
	bad := chainDef()
	bad.Stages[0].Requires = []string{"lateral"}
	o, _ := newOrch(bad, newFakeExec())
	if _, err := o.Advance(context.Background(), "camp"); err == nil {
		t.Fatalf("a cyclic definition must be refused")
	}
}

func TestAdvance_RollupIsStableAcrossReads(t *testing.T) {
	ex := newFakeExec()
	ex.evidence["initial"] = blockedEv()
	o, _ := newOrch(chainDef(), ex)
	ctx := context.Background()
	first, _ := o.Advance(ctx, "camp")
	second, _ := o.Advance(ctx, "camp")
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("rollup changed between reads: %+v vs %+v", first, second)
	}
}
