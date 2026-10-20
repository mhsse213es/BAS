package killchain

import (
	"context"
	"os"

	"github.com/audspect/bas/internal/integrity"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// These tests use synthetic fixture evidence. They prove the evaluation path
// from a campaign file to a timeline and a rollup. They do not prove that any
// product blocks, detects or contains anything in a live or lab environment.

func loadVerticalSlice(t *testing.T) CampaignDef {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("campaigns", "identity-endpoint-lateral.json"))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := os.ReadFile(filepath.Join("campaigns", "identity-endpoint-lateral.json.sig"))
	if err != nil {
		t.Fatalf("the shipped campaign must be signed: %v", err)
	}
	def, err := LoadSignedCampaign(data, sig, integrity.CompiledVerifier{})
	if err != nil {
		t.Fatalf("the shipped campaign must parse and validate: %v", err)
	}
	return def
}

func verticalOrch(def CampaignDef, ex Executor) (Orchestrator, *memStore) {
	return newOrch(def, ex)
}

// Fixture: identity access blocked. Nothing downstream may be reported as tested.
func TestVerticalSlice_BlockedAtIdentityLeavesChainNotTested(t *testing.T) {
	def := loadVerticalSlice(t)
	ex := newFakeExec()
	ex.evidence["identity"] = blockedEv()
	o, st := verticalOrch(def, ex)
	r, err := o.Advance(context.Background(), def.ID)
	if err != nil {
		t.Fatal(err)
	}
	rec := st.campaigns[def.ID]
	if rec.Stages["identity"].Verdict != VerdictBlocked {
		t.Fatalf("identity = %s, want BLOCKED", rec.Stages["identity"].Verdict)
	}
	for _, k := range []string{"endpoint", "lateral"} {
		if rec.Stages[k].Verdict != VerdictNotTested {
			t.Fatalf("%s = %s, want NOT_TESTED", k, rec.Stages[k].Verdict)
		}
		if ex.starts[k] != 0 {
			t.Fatalf("%s was executed after the path closed", k)
		}
	}
	if r.Status != "completed" || r.Failed {
		t.Fatalf("rollup = %+v", r)
	}
}

// Fixture: the identity action executed although policy says it must be blocked.
// That is a control failure, so the campaign is failed. The chain still continues,
// because ALLOWED lets downstream stages run.
func TestVerticalSlice_AllowedAtIdentityIsAFailureAndChainContinues(t *testing.T) {
	def := loadVerticalSlice(t)
	ex := newFakeExec()
	ex.evidence["identity"] = progressEv()
	ex.evidence["endpoint"] = blockedEv()
	o, st := verticalOrch(def, ex)
	r, err := o.Advance(context.Background(), def.ID)
	if err != nil {
		t.Fatal(err)
	}
	rec := st.campaigns[def.ID]
	if rec.Stages["identity"].Verdict != VerdictAllowed {
		t.Fatalf("identity = %s, want ALLOWED", rec.Stages["identity"].Verdict)
	}
	if ex.starts["endpoint"] != 1 {
		t.Fatalf("endpoint should run after an ALLOWED identity stage")
	}
	if !r.Failed || r.Status != "failed" {
		t.Fatalf("an ALLOWED stage must make the campaign failed: %+v", r)
	}
}

// Fixture: lateral movement executed and was detected, but containment was not
// verified. The report must show DETECTED_NOT_CONTAINED, not a pass.
func TestVerticalSlice_DetectedNotContainedIsVisibleNotPassed(t *testing.T) {
	def := loadVerticalSlice(t)
	ex := newFakeExec()
	// Upstream stages must not close the path, or lateral never runs. Use
	// evidence that lets the chain reach lateral: not-applicable prevention and
	// an undetected, complete window. That is NOT_DETECTED, which continues.
	upstream := withPrevention(progressEv(), PreventionNotApplicable)
	ex.evidence["identity"] = upstream
	ex.evidence["endpoint"] = upstream
	lateral := StageEvidence{
		GroundTruth: GroundTruth{Source: "host-process-record", Attempted: TriYes, Executed: TriNo},
		Prevention:  PreventionEvidence{Value: PreventionNotApplicable},
		Detection:   DetectionEvidence{Value: DetectionDetected, TelemetryHealth: TelemetryHealthy, WindowComplete: TriYes},
		Response:    ResponseEvidence{Value: ResponseNotContained},
	}
	ex.evidence["lateral"] = lateral

	o, st := verticalOrch(def, ex)
	r, err := o.Advance(context.Background(), def.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.campaigns[def.ID].Stages["lateral"].Verdict; got != VerdictDetectedNotContained {
		t.Fatalf("lateral = %s, want DETECTED_NOT_CONTAINED", got)
	}
	if r.Counts[VerdictDetectedNotContained] != 1 {
		t.Fatalf("the uncontained stage must be counted: %+v", r.Counts)
	}
}

func withPrevention(ev StageEvidence, v PreventionValue) StageEvidence {
	ev.Prevention = PreventionEvidence{Value: v}
	return ev
}

// The whole chain produces one timeline built only from stored records.
func TestVerticalSlice_TimelineIsCorrelatedAndStable(t *testing.T) {
	def := loadVerticalSlice(t)
	ex := newFakeExec()
	ex.evidence["identity"] = blockedEv()
	o, st := verticalOrch(def, ex)
	if _, err := o.Advance(context.Background(), def.ID); err != nil {
		t.Fatal(err)
	}
	rec := st.campaigns[def.ID]
	first, err := BuildTimeline(rec.Def, rec.Stages)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 3 {
		t.Fatalf("timeline has %d events, want 3 (one per stage, including NOT_TESTED)", len(first))
	}
	if first[0].Stage != "identity" || first[0].Verdict != VerdictBlocked {
		t.Fatalf("first event = %+v", first[0])
	}
	again, _ := BuildTimeline(rec.Def, rec.Stages)
	if !reflect.DeepEqual(first, again) {
		t.Fatalf("timeline changed between builds")
	}
}

// The scenario reference is a real, documented gap. The lateral stage points at
// a scenario whose YAML has no id: field, so this test records it rather than
// hiding it. It must stay true until the ID is confirmed.
func TestVerticalSlice_KnownGapLateralScenarioIDRecorded(t *testing.T) {
	def := loadVerticalSlice(t)
	st, _ := def.Stage("lateral")
	if !strings.Contains(st.ScenarioID, "caldera") {
		t.Fatalf("lateral stage scenario changed to %q; update the audit's open items", st.ScenarioID)
	}
}
