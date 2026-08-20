package scenario

import "testing"

// TestBuildARTTechniquesSteps_ReportsSkippedTechniques mirrors
// TestBuildCalderaAbilitiesSteps_ReportsSkippedAbilities: a technique with no
// local ART atomic for the platform must be reported in the skipped list
// (Framework "art"), not silently dropped, while techniques that DO resolve
// still dispatch normally alongside it.
func TestBuildARTTechniquesSteps_ReportsSkippedTechniques(t *testing.T) {
	store := &ARTStore{steps: map[string][]ScenarioStep{
		"T1059": {{Name: "exec", TechniqueID: "T1059", Platform: "linux", Executor: "bash", Command: "id"}},
	}}
	steps, skipped, err := buildARTTechniquesSteps([]string{"T1059", "T1055", "T1003"}, store, "linux")
	if err != nil {
		t.Fatalf("buildARTTechniquesSteps: %v", err)
	}
	if len(steps) != 1 {
		t.Fatalf("len(steps) = %d, want 1 (only T1059 has a linux atomic)", len(steps))
	}
	if len(skipped) != 2 {
		t.Fatalf("len(skipped) = %d, want 2 (T1055, T1003)", len(skipped))
	}
	byID := map[string]CalderaSkippedAbility{}
	for _, sk := range skipped {
		byID[sk.TechniqueID] = sk
	}
	for _, tid := range []string{"T1055", "T1003"} {
		sk, ok := byID[tid]
		if !ok {
			t.Errorf("expected %s in skipped list, got %+v", tid, skipped)
			continue
		}
		if sk.Framework != "art" {
			t.Errorf("%s Framework = %q, want \"art\"", tid, sk.Framework)
		}
		if sk.Reason == "" {
			t.Errorf("%s Reason is empty, want a explanation", tid)
		}
	}
}

// TestBuildARTTechniquesSteps_AllSkippedStillErrors proves art_techniques
// keeps the same hard-fail-on-total-loss behavior as caldera_abilities
// (TestBuildCalderaAbilitiesSteps_AllSkippedStillErrors) -- when every
// requested technique comes up empty, callers still get an error, not a
// silently-empty success; the skipped list is still populated even on that
// error path so a caller could act on it if it chose to.
func TestBuildARTTechniquesSteps_AllSkippedStillErrors(t *testing.T) {
	store := &ARTStore{steps: map[string][]ScenarioStep{}}
	steps, skipped, err := buildARTTechniquesSteps([]string{"T1055", "T1003"}, store, "linux")
	if err == nil {
		t.Fatal("expected an error when every requested technique is skipped")
	}
	if len(steps) != 0 {
		t.Errorf("expected no steps, got %d", len(steps))
	}
	if len(skipped) != 2 {
		t.Errorf("expected both techniques reported as skipped even on the error path, got %d: %+v", len(skipped), skipped)
	}
}

// TestBuildStepsRaw_ARTTechniquesComposesWithExplicitSteps proves a scenario
// can mix the art_techniques shorthand with explicit steps: entries in the
// same file -- previously the shorthand's early return meant steps: was
// silently ignored whenever art_techniques was non-empty.
func TestBuildStepsRaw_ARTTechniquesComposesWithExplicitSteps(t *testing.T) {
	store := &ARTStore{steps: map[string][]ScenarioStep{
		"T1059": {{Name: "exec", TechniqueID: "T1059", Platform: "linux", Executor: "bash", Command: "id"}},
	}}
	sc := &Scenario{
		ARTTechniques: []string{"T1059"},
		Steps: []Step{
			{Name: "custom check", TechniqueID: "T1200", Framework: "custom", Command: "echo hi"},
		},
	}
	steps, _, err := buildStepsRaw(sc, "", "", store, "linux")
	if err != nil {
		t.Fatalf("buildStepsRaw: %v", err)
	}
	if len(steps) != 2 {
		t.Fatalf("len(steps) = %d, want 2 (1 ART + 1 explicit)", len(steps))
	}
	gotART, gotCustom := false, false
	for _, s := range steps {
		if s.TechniqueID == "T1059" {
			gotART = true
		}
		if s.TechniqueID == "T1200" && s.Command == "echo hi" {
			gotCustom = true
		}
	}
	if !gotART {
		t.Error("missing the art_techniques-built T1059 step")
	}
	if !gotCustom {
		t.Error("missing the explicit steps: T1200 custom step")
	}
}

// TestBuildStepsRaw_ARTAllPlatformComposesWithExplicitSteps proves the
// composability fix isn't limited to art_techniques -- an "everything
// available" sweep mode (art_all_platform) also gets explicit steps:
// appended after it, per the same fix applied uniformly across all 7
// shorthand modes.
func TestBuildStepsRaw_ARTAllPlatformComposesWithExplicitSteps(t *testing.T) {
	store := &ARTStore{steps: map[string][]ScenarioStep{
		"T1059": {{Name: "exec", TechniqueID: "T1059", Platform: "linux", Executor: "bash", Command: "id"}},
	}}
	sc := &Scenario{
		ARTAllPlatform: true,
		Steps: []Step{
			{Name: "custom check", TechniqueID: "T1200", Framework: "custom", Command: "echo hi"},
		},
	}
	steps, _, err := buildStepsRaw(sc, "", "", store, "linux")
	if err != nil {
		t.Fatalf("buildStepsRaw: %v", err)
	}
	if len(steps) != 2 {
		t.Fatalf("len(steps) = %d, want 2 (1 ART sweep + 1 explicit)", len(steps))
	}
}

// TestBuildStepsRaw_ShorthandErrorStillAbortsBuild proves an
// infrastructure-level error from a matched shorthand (ART store
// unavailable) still aborts the whole build immediately -- steps: is only
// ever appended after a SUCCESSFUL shorthand resolution, never used as a
// silent fallback when the shorthand itself fails.
func TestBuildStepsRaw_ShorthandErrorStillAbortsBuild(t *testing.T) {
	sc := &Scenario{
		ARTTechniques: []string{"T1059"},
		Steps: []Step{
			{Name: "custom check", TechniqueID: "T1200", Framework: "custom", Command: "echo hi"},
		},
	}
	_, _, err := buildStepsRaw(sc, "", "", nil, "linux") // nil artStore -> hard error
	if err == nil {
		t.Fatal("expected an error when artStore is nil, not a silent fallback to steps:")
	}
}

// TestBuildStepsRaw_NeitherShorthandNorStepsReturnsEmpty proves the
// no-shorthand-configured, no-steps-declared case is unchanged: an empty,
// non-nil-error result, not a spurious error.
func TestBuildStepsRaw_NeitherShorthandNorStepsReturnsEmpty(t *testing.T) {
	steps, skipped, err := buildStepsRaw(&Scenario{}, "", "", nil, "windows")
	if err != nil {
		t.Fatalf("buildStepsRaw: unexpected error %v", err)
	}
	if len(steps) != 0 || len(skipped) != 0 {
		t.Errorf("steps=%v skipped=%v, want both empty", steps, skipped)
	}
}
