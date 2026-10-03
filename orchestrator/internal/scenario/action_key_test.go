package scenario

import "testing"

func TestAssignActionKeys_SetsSlugDerivedKey(t *testing.T) {
	steps := []ScenarioStep{
		{TechniqueID: "T1082", Name: "System Info", Executor: "psh", Command: "systeminfo"},
		{TechniqueID: "T1082", Name: "Another Query", Executor: "psh", Command: "whoami"},
	}
	assignActionKeys(steps, "art")
	if steps[0].ActionKey != "system_info" {
		t.Errorf("steps[0].ActionKey = %q, want %q", steps[0].ActionKey, "system_info")
	}
	if steps[1].ActionKey != "another_query" {
		t.Errorf("steps[1].ActionKey = %q, want %q", steps[1].ActionKey, "another_query")
	}
}

func TestAssignActionKeys_CollidingItemsGetEmptyActionKey(t *testing.T) {
	// Today's existing fallback (ActionKey == "" -> ResolveExecutionClass's
	// "enumerate" default) is left unchanged for exactly the items this
	// audit already found genuinely collide on identity -- see
	// corpusaudit's SourceCounts.Collisions doc comment. A synthetic key
	// here would resolve to the catalog's "unclassified" sentinel
	// (nothing in execclass_generated.go was ever written for an
	// excluded collision) and fail closed to destructive, which would be
	// a real regression for these confirmed-benign items.
	steps := []ScenarioStep{
		{TechniqueID: "T1490", Name: "Disable Recovery", Executor: "psh", Command: "bcdedit /set recoveryenabled no"},
		{TechniqueID: "T1490", Name: "Disable Recovery", Executor: "psh", Command: "wbadmin delete catalog -quiet"},
	}
	assignActionKeys(steps, "caldera")
	if steps[0].ActionKey != "" || steps[1].ActionKey != "" {
		t.Errorf("colliding steps must keep ActionKey empty, got %q and %q", steps[0].ActionKey, steps[1].ActionKey)
	}
}

func TestAssignActionKeys_SameCommandDuplicates_ShareOneKey(t *testing.T) {
	steps := []ScenarioStep{
		{TechniqueID: "T1082", Name: "System Info", Executor: "psh", Command: "systeminfo"},
		{TechniqueID: "T1082", Name: "System Info", Executor: "psh", Command: "systeminfo"},
	}
	assignActionKeys(steps, "art")
	if steps[0].ActionKey == "" || steps[0].ActionKey != steps[1].ActionKey {
		t.Errorf("expected both identical-command duplicates to share one non-empty action_key, got %q and %q", steps[0].ActionKey, steps[1].ActionKey)
	}
}

// TestAssignActionKeys_RealReviewedItem_ResolvesToDestructiveNotEnumerate
// pins the end-to-end contract this whole fix exists for: a real ART
// atomic's Name, run through the exact same derivation cmd/auditcorpus
// used to populate execclass_generated.go, must resolve to that
// committed entry's real classification -- not collapse onto T1490's
// "enumerate" fallback (which is non_destructive), silently misclassifying
// a genuinely destructive atomic the way the whole B5 ART/Caldera audit
// found and fixed for the audit tool's own report, but NOT (before this
// fix) for real dispatch.
func TestAssignActionKeys_RealReviewedItem_ResolvesToDestructiveNotEnumerate(t *testing.T) {
	steps := []ScenarioStep{
		{TechniqueID: "T1490", Name: "T1490 - Test 1: Windows - Delete Volume Shadow Copies", Executor: "psh", Command: "vssadmin.exe delete shadows /all /quiet"},
	}
	assignActionKeys(steps, "art")
	if steps[0].ActionKey == "" {
		t.Fatal("expected a real action_key to be assigned, got empty")
	}
	got := ResolveExecutionClass(steps[0].TechniqueID, steps[0].ActionKey)
	if got.Class != ClassDestructive {
		t.Errorf("ResolveExecutionClass(%q, %q) = %q, want %q -- fell back to the enumerate default instead of the real committed catalog entry",
			steps[0].TechniqueID, steps[0].ActionKey, got.Class, ClassDestructive)
	}
}
