package killchain

import (
	"context"
	"errors"
	"testing"
)

// readerExec makes Collect fail with a read error for the named stage.
type readerExec struct {
	*fakeExec
	readErr map[string]bool
}

func (r readerExec) Collect(ctx context.Context, execID string) (StageEvidence, bool, bool, error) {
	if r.readErr[execID[len("exec-"):]] {
		return StageEvidence{}, false, false, errors.New("db unavailable")
	}
	return r.fakeExec.Collect(ctx, execID)
}

func dispatchedCampaign(keys ...string) map[string]StageRecord {
	out := map[string]StageRecord{}
	for _, k := range keys {
		out[k] = StageRecord{Key: k, State: StateDispatched, ExecutionID: "exec-" + k}
	}
	return out
}

func TestRecover_FinishedRunIsCollected(t *testing.T) {
	ex := newFakeExec()
	ex.evidence["initial"] = blockedEv()
	o, st := newOrch(chainDef(), ex)
	st.campaigns["camp"] = CampaignRecord{ID: "camp", Def: chainDef(), Stages: dispatchedCampaign("initial")}
	n, err := o.Recover(context.Background(), "camp")
	if err != nil || n != 1 {
		t.Fatalf("resolved = %d, err = %v", n, err)
	}
	got := st.campaigns["camp"].Stages["initial"]
	if got.Verdict != VerdictBlocked || got.State != StateCompleted {
		t.Fatalf("collected stage = %s/%s, want BLOCKED/completed", got.Verdict, got.State)
	}
	if ex.starts["initial"] != 0 {
		t.Fatalf("recovery must never start a stage")
	}
}

func TestRecover_RunStillGoingIsInterruptedNotRestarted(t *testing.T) {
	ex := newFakeExec()
	ex.pendingCalls["initial"] = 1
	o, st := newOrch(chainDef(), ex)
	st.campaigns["camp"] = CampaignRecord{ID: "camp", Def: chainDef(), Stages: dispatchedCampaign("initial")}
	if _, err := o.Recover(context.Background(), "camp"); err != nil {
		t.Fatal(err)
	}
	got := st.campaigns["camp"].Stages["initial"]
	if got.State != StateInterrupted || got.Verdict != VerdictInconclusive {
		t.Fatalf("stage = %s/%s, want interrupted/INCONCLUSIVE", got.State, got.Verdict)
	}
	if ex.starts["initial"] != 0 {
		t.Fatalf("an unfinished run must not be restarted")
	}
}

func TestRecover_FailedRunKeepsExecutionID(t *testing.T) {
	ex := newFakeExec()
	ex.failRun["initial"] = true
	o, st := newOrch(chainDef(), ex)
	st.campaigns["camp"] = CampaignRecord{ID: "camp", Def: chainDef(), Stages: dispatchedCampaign("initial")}
	if _, err := o.Recover(context.Background(), "camp"); err != nil {
		t.Fatal(err)
	}
	got := st.campaigns["camp"].Stages["initial"]
	if got.Verdict != VerdictError || got.ExecutionID != "exec-initial" {
		t.Fatalf("stage = %s exec=%q, want ERROR with its execution id", got.Verdict, got.ExecutionID)
	}
}

// A read error must leave the stage dispatched for the next boot. It must not
// become a permanent ERROR.
func TestRecover_ReadErrorLeavesStageForRetry(t *testing.T) {
	ex := readerExec{fakeExec: newFakeExec(), readErr: map[string]bool{"initial": true}}
	o, st := newOrch(chainDef(), ex)
	st.campaigns["camp"] = CampaignRecord{ID: "camp", Def: chainDef(), Stages: dispatchedCampaign("initial")}
	n, err := o.Recover(context.Background(), "camp")
	if err != nil || n != 0 {
		t.Fatalf("resolved = %d, err = %v; a read error must resolve nothing", n, err)
	}
	if got := st.campaigns["camp"].Stages["initial"]; got.State != StateDispatched || got.Verdict != "" {
		t.Fatalf("stage = %s/%s, want still dispatched with no verdict", got.State, got.Verdict)
	}
}

func TestRecover_IgnoresStagesThatAreNotDispatched(t *testing.T) {
	ex := newFakeExec()
	o, st := newOrch(chainDef(), ex)
	st.campaigns["camp"] = CampaignRecord{ID: "camp", Def: chainDef(), Stages: map[string]StageRecord{}}
	n, err := o.Recover(context.Background(), "camp")
	if err != nil || n != 0 || ex.starts["initial"] != 0 {
		t.Fatalf("n=%d err=%v starts=%v", n, err, ex.starts)
	}
}
