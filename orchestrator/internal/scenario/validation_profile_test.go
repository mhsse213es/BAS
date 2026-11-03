package scenario

import (
	"reflect"
	"testing"
)

// step is a tiny helper to build a ScenarioStep with just the fields the
// selector reads.
func vstep(taskID, techniqueID, proxy string) ScenarioStep {
	return ScenarioStep{TaskID: taskID, TechniqueID: techniqueID, ProxyTechniqueID: proxy}
}

// taskIDs extracts the TaskID sequence of a selection for order/determinism
// assertions.
func taskIDs(steps []ScenarioStep) []string {
	out := make([]string, len(steps))
	for i, s := range steps {
		out[i] = s.TaskID
	}
	return out
}

// Three techniques, three atomics each. PerTechnique=1 keeps exactly one
// representative atomic per technique; nothing is truncated.
func TestSelectRepresentative_OnePerTechnique(t *testing.T) {
	steps := []ScenarioStep{
		vstep("a3", "T1", ""), vstep("a1", "T1", ""), vstep("a2", "T1", ""),
		vstep("b2", "T2", ""), vstep("b1", "T2", ""), vstep("b3", "T2", ""),
		vstep("c1", "T3", ""), vstep("c3", "T3", ""), vstep("c2", "T3", ""),
	}
	sub, cov := SelectRepresentative(steps, RepresentativeLimits{MaxSteps: 25, PerTechnique: 1})

	if len(sub) != 3 {
		t.Fatalf("selected %d, want 3 (one per technique)", len(sub))
	}
	// Stable sort by (TechniqueID, ProxyTechniqueID, TaskID) means the
	// lexically-first TaskID of each technique is the representative.
	if got, want := taskIDs(sub), []string{"a1", "b1", "c1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("selected TaskIDs = %v, want %v (stable-first per technique)", got, want)
	}
	want := ValidationCoverage{
		Profile: "representative", TotalSteps: 9, SelectedSteps: 3, SkippedSteps: 6,
		TechniquesTotal: 3, TechniquesSelected: 3, Truncated: false,
	}
	if cov != want {
		t.Fatalf("coverage = %+v, want %+v", cov, want)
	}
}

// Determinism: the same input selected twice yields the identical subset.
func TestSelectRepresentative_Deterministic(t *testing.T) {
	steps := []ScenarioStep{
		vstep("x9", "T2", ""), vstep("x1", "T1", ""), vstep("x5", "T2", ""),
		vstep("x2", "T1", ""), vstep("x7", "T3", ""),
	}
	lim := RepresentativeLimits{MaxSteps: 25, PerTechnique: 1}
	a, _ := SelectRepresentative(steps, lim)
	b, _ := SelectRepresentative(steps, lim)
	if !reflect.DeepEqual(taskIDs(a), taskIDs(b)) {
		t.Fatalf("non-deterministic: %v vs %v", taskIDs(a), taskIDs(b))
	}
}

// The global MaxSteps cap drops steps the per-technique rule would have kept,
// and flags Truncated.
func TestSelectRepresentative_MaxStepsCap(t *testing.T) {
	var steps []ScenarioStep
	for i := 'a'; i <= 'z'; i++ { // 26 distinct techniques, one atomic each
		steps = append(steps, vstep(string(i), "T"+string(i), ""))
	}
	sub, cov := SelectRepresentative(steps, RepresentativeLimits{MaxSteps: 25, PerTechnique: 1})
	if len(sub) != 25 {
		t.Fatalf("selected %d, want 25 (hard cap)", len(sub))
	}
	if !cov.Truncated {
		t.Fatalf("Truncated=false, want true (26 techniques capped to 25)")
	}
	if cov.TotalSteps != 26 || cov.SelectedSteps != 25 || cov.SkippedSteps != 1 || cov.TechniquesSelected != 25 || cov.TechniquesTotal != 26 {
		t.Fatalf("coverage = %+v", cov)
	}
}

// Empty input: empty subset, zeroed coverage (profile still stamped).
func TestSelectRepresentative_Empty(t *testing.T) {
	sub, cov := SelectRepresentative(nil, DefaultRepresentativeLimits())
	if len(sub) != 0 {
		t.Fatalf("selected %d, want 0", len(sub))
	}
	if cov.Profile != "representative" || cov.TotalSteps != 0 || cov.SelectedSteps != 0 || cov.Truncated {
		t.Fatalf("coverage = %+v, want zeroed representative", cov)
	}
}

// PerTechnique > 1 keeps that many per technique, in stable TaskID order.
func TestSelectRepresentative_PerTechniqueTwo(t *testing.T) {
	steps := []ScenarioStep{
		vstep("a3", "T1", ""), vstep("a1", "T1", ""), vstep("a2", "T1", ""),
		vstep("b1", "T2", ""),
	}
	sub, cov := SelectRepresentative(steps, RepresentativeLimits{MaxSteps: 25, PerTechnique: 2})
	if got, want := taskIDs(sub), []string{"a1", "a2", "b1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("selected = %v, want %v (two per technique, stable order)", got, want)
	}
	if cov.SelectedSteps != 3 || cov.TechniquesSelected != 2 || cov.SkippedSteps != 1 {
		t.Fatalf("coverage = %+v", cov)
	}
}

// Steps without a TechniqueID (some Caldera/custom steps) must not all
// collapse into one "" bucket, and "" must not be counted as a technique.
func TestSelectRepresentative_TechniquelessStepsNotCollapsed(t *testing.T) {
	steps := []ScenarioStep{
		vstep("n1", "", ""), vstep("n2", "", ""), vstep("n3", "", ""),
		vstep("a2", "T1", ""), vstep("a1", "T1", ""),
	}
	sub, cov := SelectRepresentative(steps, RepresentativeLimits{MaxSteps: 25, PerTechnique: 1})
	// 3 technique-less steps each kept (own bucket) + 1 for T1 = 4.
	if len(sub) != 4 {
		t.Fatalf("selected %d, want 4 (3 technique-less kept individually + 1 for T1)", len(sub))
	}
	if cov.TechniquesTotal != 1 || cov.TechniquesSelected != 1 {
		t.Fatalf("techniques total=%d selected=%d, want 1/1 (empty TechniqueID is not a technique)", cov.TechniquesTotal, cov.TechniquesSelected)
	}
}

func TestDefaultRepresentativeLimits(t *testing.T) {
	if got := DefaultRepresentativeLimits(); got.MaxSteps != 25 || got.PerTechnique != 1 {
		t.Fatalf("defaults = %+v, want {25,1}", got)
	}
}
