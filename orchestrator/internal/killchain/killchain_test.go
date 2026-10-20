package killchain

import (
	"reflect"
	"strings"
	"testing"
)

// complete returns evidence with every required field established. Tests
// change one field at a time from this baseline.
func complete() *StageEvidence {
	return &StageEvidence{
		CampaignID: "c1", StageKey: "s1",
		GroundTruth: GroundTruth{Source: "host-process-record", Attempted: TriYes, Executed: TriNo},
		Prevention:  PreventionEvidence{Value: PreventionBlocked, ControlID: "edr-1"},
		Detection:   DetectionEvidence{Value: DetectionDetected, TelemetryHealth: TelemetryHealthy, WindowComplete: TriYes},
		Response:    ResponseEvidence{Value: ResponseContainedVerified},
	}
}

func withEv(f func(*StageEvidence)) *StageEvidence {
	e := complete()
	f(e)
	return e
}

func completed(e *StageEvidence, p Policy) StageInput {
	return StageInput{State: StateCompleted, Evidence: e, Policy: p}
}

// Policy is a shorthand so table rows stay readable.
type Policy = StagePolicy

func TestEvaluate_EachVerdictIsReachable(t *testing.T) {
	cases := []struct {
		name string
		in   StageInput
		want Verdict
	}{
		{"blocked", completed(complete(), Policy{}), VerdictBlocked},
		{"detected", completed(withEv(func(e *StageEvidence) {
			e.Prevention.Value = PreventionNotApplicable
			e.GroundTruth.Attempted = TriYes
		}), Policy{}), VerdictDetected},
		{"allowed", completed(withEv(func(e *StageEvidence) {
			e.Prevention.Value = PreventionAllowed
			e.GroundTruth.Executed = TriYes
		}), Policy{ShouldBlock: true}), VerdictAllowed},
		{"detected not contained", completed(withEv(func(e *StageEvidence) {
			e.Prevention.Value = PreventionNotApplicable
			e.GroundTruth.Attempted = TriYes
			e.Response.Value = ResponseNotContained
		}), Policy{ContainmentRequired: true}), VerdictDetectedNotContained},
		{"not detected", completed(withEv(func(e *StageEvidence) {
			e.Prevention.Value = PreventionNotApplicable
			e.Detection = DetectionEvidence{Value: DetectionNotDetected, TelemetryHealth: TelemetryHealthy, WindowComplete: TriYes}
			e.Response.Value = ResponseNotApplicable
		}), Policy{}), VerdictNotDetected},
		{"not tested", StageInput{State: StateNotReached}, VerdictNotTested},
		{"inconclusive", completed(withEv(func(e *StageEvidence) { e.Detection.Value = DetectionInconclusive }), Policy{}), VerdictInconclusive},
		{"error", StageInput{State: StateFailed}, VerdictError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Evaluate(c.in).Verdict; got != c.want {
				t.Fatalf("verdict = %s, want %s", got, c.want)
			}
		})
	}
}

func TestEvaluate_AllEightVerdictsAppearInVocabulary(t *testing.T) {
	if len(AllVerdicts) != 8 {
		t.Fatalf("expected the eight mandatory verdicts, got %d", len(AllVerdicts))
	}
}

func TestEvaluate_ErrorOverridesEverything(t *testing.T) {
	in := completed(withEv(func(e *StageEvidence) { e.Prevention.Value = PreventionAllowed; e.GroundTruth.Executed = TriYes }), Policy{ShouldBlock: true})
	in.ExecFailed = true
	if got := Evaluate(in).Verdict; got != VerdictError {
		t.Fatalf("verdict = %s, want ERROR", got)
	}
}

func TestEvaluate_NotReachedIsNotTestedEvenWithEvidence(t *testing.T) {
	in := completed(complete(), Policy{})
	in.State = StateNotReached
	if got := Evaluate(in).Verdict; got != VerdictNotTested {
		t.Fatalf("verdict = %s, want NOT_TESTED", got)
	}
}

func TestEvaluate_InterruptedIsInconclusiveNotDetected(t *testing.T) {
	in := completed(complete(), Policy{})
	in.State = StateInterrupted
	if got := Evaluate(in).Verdict; got != VerdictInconclusive {
		t.Fatalf("verdict = %s, want INCONCLUSIVE", got)
	}
}

// Missing evidence must never produce a pass-like verdict. Each row removes
// one required field and checks the verdict is INCONCLUSIVE.
func TestEvaluate_MissingFieldNeverPasses(t *testing.T) {
	mutations := map[string]func(*StageEvidence){
		"ground truth source":   func(e *StageEvidence) { e.GroundTruth.Source = "" },
		"attempted":             func(e *StageEvidence) { e.GroundTruth.Attempted = "" },
		"executed":              func(e *StageEvidence) { e.GroundTruth.Executed = "" },
		"prevention value":      func(e *StageEvidence) { e.Prevention.Value = "" },
		"detection value":       func(e *StageEvidence) { e.Detection.Value = "" },
		"telemetry health":      func(e *StageEvidence) { e.Detection.TelemetryHealth = "" },
		"response for detected": func(e *StageEvidence) { e.Response.Value = "" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			e := complete()
			mutate(e)
			got := Evaluate(completed(e, Policy{})).Verdict
			if got != VerdictInconclusive {
				t.Fatalf("missing %s: verdict = %s, want INCONCLUSIVE", name, got)
			}
		})
	}
}

func TestEvaluate_MissingWindowNeverGivesNotDetected(t *testing.T) {
	e := withEv(func(e *StageEvidence) {
		e.Prevention.Value = PreventionNotApplicable
		e.Detection = DetectionEvidence{Value: DetectionNotDetected, TelemetryHealth: TelemetryHealthy}
	})
	if got := Evaluate(completed(e, Policy{})).Verdict; got != VerdictInconclusive {
		t.Fatalf("verdict = %s, want INCONCLUSIVE", got)
	}
}

func TestEvaluate_NotDetectedRequiresHealthyTelemetry(t *testing.T) {
	e := withEv(func(e *StageEvidence) {
		e.Prevention.Value = PreventionNotApplicable
		e.Detection = DetectionEvidence{Value: DetectionNotDetected, TelemetryHealth: TelemetryUnhealthy, WindowComplete: TriYes}
	})
	if got := Evaluate(completed(e, Policy{})).Verdict; got != VerdictInconclusive {
		t.Fatalf("verdict = %s, want INCONCLUSIVE", got)
	}
}

// Contradictions are inconclusive, never blocked.
func TestEvaluate_BlockedButExecutedIsContradictory(t *testing.T) {
	e := withEv(func(e *StageEvidence) { e.GroundTruth.Executed = TriYes })
	if got := Evaluate(completed(e, Policy{})).Verdict; got != VerdictInconclusive {
		t.Fatalf("verdict = %s, want INCONCLUSIVE", got)
	}
}

func TestEvaluate_BlockedWithoutAttemptIsNotBlocked(t *testing.T) {
	e := withEv(func(e *StageEvidence) { e.GroundTruth.Attempted = TriNo })
	if got := Evaluate(completed(e, Policy{})).Verdict; got != VerdictInconclusive {
		t.Fatalf("verdict = %s, want INCONCLUSIVE", got)
	}
}

// Precedence: INCONCLUSIVE beats ALLOWED, so an allowed action with a missing
// fact is not reported as a verified control failure.
func TestEvaluate_InconclusiveBeatsAllowed(t *testing.T) {
	e := withEv(func(e *StageEvidence) {
		e.Prevention.Value = PreventionAllowed
		e.GroundTruth.Executed = TriYes
		e.Detection.TelemetryHealth = ""
	})
	if got := Evaluate(completed(e, Policy{ShouldBlock: true})).Verdict; got != VerdictInconclusive {
		t.Fatalf("verdict = %s, want INCONCLUSIVE", got)
	}
}

// ALLOWED needs a verified policy. Without ShouldBlock the same observation is
// not a violation.
func TestEvaluate_AllowedNeedsVerifiedPolicy(t *testing.T) {
	e := withEv(func(e *StageEvidence) {
		e.Prevention.Value = PreventionAllowed
		e.GroundTruth.Executed = TriYes
		e.Detection = DetectionEvidence{Value: DetectionNotDetected, TelemetryHealth: TelemetryHealthy, WindowComplete: TriYes}
		e.Response.Value = ResponseNotApplicable
	})
	if got := Evaluate(completed(e, Policy{ShouldBlock: false})).Verdict; got == VerdictAllowed {
		t.Fatalf("ALLOWED without a verified blocking policy")
	}
}

// BLOCKED and DETECTED can both hold. Prevention wins the verdict, and the
// detection value stays in the evidence.
func TestEvaluate_BlockedAndDetectedKeepDimensionsSeparate(t *testing.T) {
	e := complete()
	v := Evaluate(completed(e, Policy{}))
	if v.Verdict != VerdictBlocked {
		t.Fatalf("verdict = %s, want BLOCKED", v.Verdict)
	}
	if e.Detection.Value != DetectionDetected {
		t.Fatalf("detection dimension was altered: %s", e.Detection.Value)
	}
}

// Detected but not contained is never reported as a pass.
func TestEvaluate_DetectedNotContainedIsNotDetected(t *testing.T) {
	e := withEv(func(e *StageEvidence) {
		e.Prevention.Value = PreventionNotApplicable
		e.GroundTruth.Attempted = TriYes
		e.Response.Value = ResponseNotContained
	})
	if got := Evaluate(completed(e, Policy{ContainmentRequired: true})).Verdict; got != VerdictDetectedNotContained {
		t.Fatalf("verdict = %s, want DETECTED_NOT_CONTAINED", got)
	}
}

func TestEvaluate_ContainmentInconclusiveWhenRequired(t *testing.T) {
	e := withEv(func(e *StageEvidence) {
		e.Prevention.Value = PreventionNotApplicable
		e.GroundTruth.Attempted = TriYes
		e.Response.Value = ResponseInconclusive
	})
	if got := Evaluate(completed(e, Policy{ContainmentRequired: true})).Verdict; got != VerdictInconclusive {
		t.Fatalf("verdict = %s, want INCONCLUSIVE", got)
	}
}

func TestEvaluate_IsDeterministic(t *testing.T) {
	in := completed(complete(), Policy{})
	first := Evaluate(in)
	for i := 0; i < 50; i++ {
		if got := Evaluate(in); !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d differs: %+v vs %+v", i, got, first)
		}
	}
}

func TestMissing_OrderIsFixed(t *testing.T) {
	e := &StageEvidence{}
	got := e.Missing()
	want := []string{
		"groundTruth.source", "groundTruth.attempted", "groundTruth.executed",
		"prevention.value", "detection.value", "detection.telemetryHealth",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("missing = %v, want %v", got, want)
	}
}

func baseCampaign() CampaignDef {
	return CampaignDef{ID: "camp", Version: 1, Stages: []StageDef{
		{Key: "initial", ScenarioID: "s-a"},
		{Key: "exec", ScenarioID: "s-b", Requires: []string{"initial"}},
		{Key: "lateral", ScenarioID: "s-c", Requires: []string{"exec"}},
	}}
}

func TestValidate_AcceptsValidDAGAndReturnsDeterministicOrder(t *testing.T) {
	got, err := baseCampaign().Validate()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"initial", "exec", "lateral"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}

func TestValidate_RejectsBadGraphs(t *testing.T) {
	cases := map[string]func(*CampaignDef){
		"cycle": func(c *CampaignDef) {
			c.Stages[0].Requires = []string{"lateral"}
		},
		"self requirement": func(c *CampaignDef) {
			c.Stages[1].Requires = []string{"exec"}
		},
		"unknown requirement": func(c *CampaignDef) {
			c.Stages[1].Requires = []string{"nope"}
		},
		"duplicate key": func(c *CampaignDef) {
			c.Stages[2].Key = "exec"
		},
		"bad key": func(c *CampaignDef) {
			c.Stages[0].Key = "Initial Access"
		},
		"missing scenario": func(c *CampaignDef) {
			c.Stages[0].ScenarioID = ""
		},
		"bad continueOn": func(c *CampaignDef) {
			c.Stages[1].ContinueOn = []Verdict{"MAYBE"}
		},
		"no stages": func(c *CampaignDef) {
			c.Stages = nil
		},
		"zero version": func(c *CampaignDef) {
			c.Version = 0
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := baseCampaign()
			mutate(&c)
			if _, err := c.Validate(); err == nil {
				t.Fatalf("expected an error")
			}
		})
	}
}

func TestContinues_DefaultAndOverride(t *testing.T) {
	s := StageDef{Key: "x", ScenarioID: "y"}
	if s.Continues(VerdictBlocked) {
		t.Fatalf("BLOCKED must close the path by default")
	}
	if s.Continues(VerdictNotTested) || s.Continues(VerdictError) {
		t.Fatalf("NOT_TESTED and ERROR must close the path by default")
	}
	if !s.Continues(VerdictInconclusive) {
		t.Fatalf("INCONCLUSIVE must continue by default")
	}
	s.ContinueOn = []Verdict{VerdictBlocked}
	if !s.Continues(VerdictBlocked) || s.Continues(VerdictAllowed) {
		t.Fatalf("explicit continueOn must replace the default set")
	}
}

func TestRoll_PartialTakesPrecedenceOverFailed(t *testing.T) {
	r := Roll([]StageResult{
		{Key: "a", Verdict: VerdictAllowed},
		{Key: "b", State: StateDispatched},
	})
	if r.Status != "partial" {
		t.Fatalf("status = %s, want partial", r.Status)
	}
	if !r.Failed {
		t.Fatalf("an ALLOWED stage must still be visible as a failure")
	}
}

func TestRoll_NotTestedExcludedFromReached(t *testing.T) {
	r := Roll([]StageResult{
		{Key: "a", Verdict: VerdictBlocked},
		{Key: "b", Verdict: VerdictNotTested},
		{Key: "c", Verdict: VerdictNotTested},
	})
	if r.Reached != 1 || r.Total != 3 || r.Counts[VerdictNotTested] != 2 {
		t.Fatalf("rollup = %+v", r)
	}
	if r.Status != "completed" {
		t.Fatalf("status = %s, want completed", r.Status)
	}
}

func TestRoll_InterruptedIsPartialEvenWithVerdict(t *testing.T) {
	r := Roll([]StageResult{{Key: "a", State: StateInterrupted, Verdict: VerdictInconclusive}})
	if r.Status != "partial" {
		t.Fatalf("status = %s, want partial", r.Status)
	}
}

func TestRoll_NeverSaysPassed(t *testing.T) {
	r := Roll([]StageResult{{Key: "a", Verdict: VerdictBlocked}})
	if strings.Contains(r.Status, "pass") {
		t.Fatalf("status must not claim a pass: %s", r.Status)
	}
}

func TestMapPrevention_AmbiguousIsUnknown(t *testing.T) {
	cases := map[string]PreventionValue{
		"blocked":        PreventionBlocked,
		"Blocked":        PreventionBlocked,
		"allowed":        PreventionAllowed,
		"quarantined":    PreventionUnknown,
		"terminated":     PreventionUnknown,
		"mfa_challenged": PreventionUnknown,
		"":               PreventionUnknown,
		"weird":          PreventionUnknown,
	}
	for in, want := range cases {
		if got := MapPrevention(in); got != want {
			t.Errorf("MapPrevention(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestMapTelemetryHealth_OnlyPresentIsHealthy(t *testing.T) {
	if MapTelemetryHealth("Present") != TelemetryHealthy {
		t.Fatalf("Present must be healthy")
	}
	for _, s := range []string{"Absent", "Delayed", "Incomplete", "Unverifiable"} {
		if MapTelemetryHealth(s) != TelemetryUnhealthy {
			t.Errorf("%s must be unhealthy", s)
		}
	}
	if MapTelemetryHealth("surprise") != "" {
		t.Fatalf("an unrecognised value must be missing, not healthy")
	}
}

func TestMapDetection_PresenceIsNotDetection(t *testing.T) {
	if MapDetection("detected") != DetectionDetected {
		t.Fatalf("detected must map to detected")
	}
	if MapDetection("Present") != DetectionInconclusive {
		t.Fatalf("a telemetry presence value must not become a detection")
	}
	if MapDetection("") != DetectionInconclusive {
		t.Fatalf("empty must be inconclusive")
	}
}
