package killchain

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestAncestors_AreTransitiveAndExcludeSelf(t *testing.T) {
	def := chainDef()
	got := def.Ancestors("lateral")
	want := map[string]bool{"exec": true, "initial": true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ancestors(lateral) = %v, want %v", got, want)
	}
	if def.Ancestors("initial")["initial"] {
		t.Fatalf("a stage must not be its own ancestor")
	}
}

func TestCheckCausedBy(t *testing.T) {
	def := chainDef()
	if err := CheckCausedBy(def, "lateral", "exec"); err != nil {
		t.Fatalf("upstream cause refused: %v", err)
	}
	if err := CheckCausedBy(def, "exec", ""); err != nil {
		t.Fatalf("empty cause must be allowed: %v", err)
	}
	if err := CheckCausedBy(def, "initial", "lateral"); err == nil {
		t.Fatalf("a downstream cause must be refused")
	}
	if err := CheckCausedBy(def, "exec", "exec"); err == nil {
		t.Fatalf("a stage may not cause itself")
	}
}

// Evidence that cites a non-upstream cause must not be trusted. The stage
// becomes inconclusive, and the reason names the bad link.
func TestAdvance_NonUpstreamCausedByIsInconclusive(t *testing.T) {
	ex := newFakeExec()
	ev := progressEv()
	ev.CausedBy = "lateral"
	ex.evidence["initial"] = ev
	o, st := newOrch(chainDef(), ex)
	if _, err := o.Advance(context.Background(), "camp"); err != nil {
		t.Fatal(err)
	}
	got := st.campaigns["camp"].Stages["initial"]
	if got.Verdict != VerdictInconclusive {
		t.Fatalf("verdict = %s, want INCONCLUSIVE", got.Verdict)
	}
	if !strings.Contains(strings.Join(got.Reasons, " "), "not an upstream stage") {
		t.Fatalf("reason must name the bad causal link: %v", got.Reasons)
	}
}

func TestBuildTimeline_OrdersByActionTimeThenTopology(t *testing.T) {
	def := chainDef()
	t0 := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	stages := map[string]StageRecord{
		"initial": {Key: "initial", Verdict: VerdictDetected, ExecutionID: "e1",
			Evidence: &StageEvidence{Timestamps: Timestamps{ActionAt: t0.Add(2 * time.Minute)}}},
		"exec": {Key: "exec", Verdict: VerdictAllowed, ExecutionID: "e2",
			Evidence: &StageEvidence{CausedBy: "initial", Timestamps: Timestamps{ActionAt: t0}}},
		"lateral": {Key: "lateral", Verdict: VerdictNotTested},
	}
	events, err := BuildTimeline(def, stages)
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, e := range events {
		order = append(order, e.Stage)
	}
	if !reflect.DeepEqual(order, []string{"exec", "initial", "lateral"}) {
		t.Fatalf("timeline order = %v", order)
	}
	if events[0].CausedBy != "initial" {
		t.Fatalf("causal link missing from the timeline: %+v", events[0])
	}
}

func TestBuildTimeline_SkipsStagesWithoutVerdictAndIsStable(t *testing.T) {
	def := chainDef()
	stages := map[string]StageRecord{
		"initial": {Key: "initial", Verdict: VerdictBlocked},
	}
	first, err := BuildTimeline(def, stages)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || first[0].Stage != "initial" {
		t.Fatalf("timeline = %+v, want only the blocked initial stage", first)
	}
	for i := 0; i < 20; i++ {
		again, _ := BuildTimeline(def, stages)
		if !reflect.DeepEqual(again, first) {
			t.Fatalf("timeline changed on read %d", i)
		}
	}
}

func TestBuildTimeline_RejectsInvalidDefinition(t *testing.T) {
	bad := chainDef()
	bad.Stages[0].Requires = []string{"lateral"}
	if _, err := BuildTimeline(bad, nil); err == nil {
		t.Fatalf("a cyclic definition must not produce a timeline")
	}
}
