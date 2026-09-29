package scenario

import "testing"

func TestResolveExecutionClass_ExactMatch(t *testing.T) {
	got := ResolveExecutionClass("T1490", "vss_delete")
	if got.Class != ClassDestructive {
		t.Errorf("T1490:vss_delete class = %q, want %q", got.Class, ClassDestructive)
	}
	if got.DestructiveAction != "vss_delete" {
		t.Errorf("DestructiveAction = %q, want %q", got.DestructiveAction, "vss_delete")
	}
	if got.BlastRadius == "" {
		t.Error("BlastRadius is empty for a destructive action -- must describe the real impact")
	}
}

func TestResolveExecutionClass_NoActionKeyFallsBackToDefault(t *testing.T) {
	// Seed a technique with only a "default" entry, via a technique known to
	// have exactly one behavior. T1082 (System Information Discovery) is
	// already proven read-only in resource.go's discoveryProfiles.
	got := ResolveExecutionClass("T1082", "")
	if got.Class != ClassNonDestructive {
		t.Errorf("T1082 (no action_key) class = %q, want %q", got.Class, ClassNonDestructive)
	}
}

func TestResolveExecutionClass_UnknownActionKeyFailsClosed(t *testing.T) {
	// T1490 has curated entries, but not this action_key -- must NOT fall
	// back to a technique-wide default. This is the exact ambiguity the
	// catalog exists to eliminate.
	got := ResolveExecutionClass("T1490", "totally_unreviewed_action")
	if got.Class != ClassDestructive {
		t.Errorf("unknown action_key under a partially-catalogued technique = %q, want %q (fail closed)", got.Class, ClassDestructive)
	}
}

func TestResolveExecutionClass_UnknownTechniqueFailsClosed(t *testing.T) {
	got := ResolveExecutionClass("T9999", "anything")
	if got.Class != ClassDestructive {
		t.Errorf("wholly unknown technique class = %q, want %q (fail closed)", got.Class, ClassDestructive)
	}
}

func TestResolveExecutionClass_CaseNormalization(t *testing.T) {
	// Mirrors ResourceProfileFor's existing strings.ToUpper/TrimSpace handling
	// for technique IDs (resource.go) -- action_key normalization is new here.
	got := ResolveExecutionClass("t1490", "VSS_DELETE")
	if got.Class != ClassDestructive {
		t.Errorf("case-insensitive lookup failed: class = %q, want %q", got.Class, ClassDestructive)
	}
}

func TestAttachExecutionClassifications(t *testing.T) {
	steps := []ScenarioStep{
		{TechniqueID: "T1490", ActionKey: "vss_delete"},
		{TechniqueID: "T1082"}, // no action_key -> "default"
		{TechniqueID: "T9999"}, // wholly unknown -> fail closed
	}
	AttachExecutionClassifications(steps)

	if steps[0].ExecutionClass != ClassDestructive {
		t.Errorf("steps[0].ExecutionClass = %q, want %q", steps[0].ExecutionClass, ClassDestructive)
	}
	if steps[0].DestructiveAction != "vss_delete" {
		t.Errorf("steps[0].DestructiveAction = %q, want %q", steps[0].DestructiveAction, "vss_delete")
	}
	if steps[1].ExecutionClass != ClassNonDestructive {
		t.Errorf("steps[1].ExecutionClass = %q, want %q", steps[1].ExecutionClass, ClassNonDestructive)
	}
	if steps[2].ExecutionClass != ClassDestructive {
		t.Errorf("steps[2].ExecutionClass = %q, want %q (fail closed)", steps[2].ExecutionClass, ClassDestructive)
	}
}
