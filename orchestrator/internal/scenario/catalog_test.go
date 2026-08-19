package scenario

import "testing"

func newTestStore() *ARTStore {
	return &ARTStore{steps: map[string][]ScenarioStep{
		"T1059": {
			{Name: "exec a", TechniqueID: "T1059", Executor: "powershell", Command: "whoami"},
			{Name: "exec b", TechniqueID: "T1059", Executor: "cmd", Command: "whoami"},
		},
		"T1083": {{Name: "discovery", TechniqueID: "T1083", Executor: "powershell", Command: "dir"}},
		"T1003": {{Name: "cred dump", TechniqueID: "T1003", Executor: "powershell", Command: "lsass"}},
	}}
}

// ListTechniqueMeta returns one catalog entry per technique, sorted by ID, with
// the representative atomic name and the test count.
func TestListTechniqueMeta(t *testing.T) {
	meta := newTestStore().ListTechniqueMeta()
	if len(meta) != 3 {
		t.Fatalf("len(meta) = %d, want 3", len(meta))
	}
	// sorted by ID: T1003, T1059, T1083
	if meta[0].ID != "T1003" || meta[1].ID != "T1059" || meta[2].ID != "T1083" {
		t.Fatalf("unexpected order: %v", []string{meta[0].ID, meta[1].ID, meta[2].ID})
	}
	if meta[1].Tests != 2 {
		t.Errorf("T1059 tests = %d, want 2", meta[1].Tests)
	}
	if meta[1].Name != "exec a" {
		t.Errorf("T1059 name = %q, want representative %q", meta[1].Name, "exec a")
	}
}

// TestListTechniqueMeta_ExcludesTechniquesWithNoWindowsStep proves
// ListTechniqueMeta actually honors its own doc comment ("returns one
// catalog entry per technique that has at least one Windows step").
// Previously it returned every technique key in the store unconditionally,
// with no platform check at all -- inconsistent with the sibling
// ListTechniquesByPlatform("windows") (used by /api/art/content/status'
// windowsRunnable count), which does filter correctly. That inconsistency
// is exactly why the Full Variant Sweep card and the Customize technique
// picker showed 314 techniques (ListTechniqueMeta, unfiltered) while a
// non-customized full sweep actually only dispatched 268 (the real
// Windows-runnable count) -- two different functions over the same data,
// silently disagreeing.
func TestListTechniqueMeta_ExcludesTechniquesWithNoWindowsStep(t *testing.T) {
	store := &ARTStore{steps: map[string][]ScenarioStep{
		"T1059": {{Name: "exec", TechniqueID: "T1059", Platform: "windows", Executor: "powershell", Command: "whoami"}},
		"T1499": {{Name: "linux dos", TechniqueID: "T1499", Platform: "linux", Executor: "sh", Command: "true"}},
		"T1204": {{Name: "no platform set", TechniqueID: "T1204", Executor: "powershell", Command: "whoami"}}, // empty Platform defaults to windows
	}}
	meta := store.ListTechniqueMeta()
	ids := make(map[string]bool, len(meta))
	for _, m := range meta {
		ids[m.ID] = true
	}
	if !ids["T1059"] {
		t.Error("T1059 (has a windows step) should be included")
	}
	if !ids["T1204"] {
		t.Error("T1204 (empty Platform, defaults to windows) should be included")
	}
	if ids["T1499"] {
		t.Error("T1499 (linux-only, no windows step at all) must be excluded -- ListTechniqueMeta's own doc comment promises windows-only")
	}
	if len(meta) != 2 {
		t.Errorf("len(meta) = %d, want 2 (T1499 excluded)", len(meta))
	}
}

// ListTechniqueMetaByPlatform is ListTechniqueMeta scoped to an arbitrary
// platform -- powers the Customize picker for art_selective_platform
// (Linux/macOS) scenarios, which need their own technique catalog rather
// than the Windows-only one ListTechniqueMeta always returns.
func TestListTechniqueMetaByPlatform(t *testing.T) {
	store := &ARTStore{steps: map[string][]ScenarioStep{
		"T1059": {{Name: "exec sh", TechniqueID: "T1059", Platform: "linux", Executor: "sh", Command: "whoami"}},
		"T1499": {{Name: "windows dos", TechniqueID: "T1499", Platform: "windows", Executor: "powershell", Command: "true"}},
	}}
	meta := store.ListTechniqueMetaByPlatform("linux")
	if len(meta) != 1 || meta[0].ID != "T1059" {
		t.Fatalf("meta = %+v, want exactly [T1059] (T1499 is windows-only, must be excluded from a linux query)", meta)
	}
}

// ListTechniqueMeta must still behave exactly as before after being
// refactored to delegate to ListTechniqueMetaByPlatform("windows") --
// regression guard for the refactor.
func TestListTechniqueMeta_StillWindowsOnlyAfterRefactor(t *testing.T) {
	meta := newTestStore().ListTechniqueMeta()
	byPlatform := newTestStore().ListTechniqueMetaByPlatform("windows")
	if len(meta) != len(byPlatform) {
		t.Fatalf("ListTechniqueMeta() len = %d, ListTechniqueMetaByPlatform(\"windows\") len = %d -- must match", len(meta), len(byPlatform))
	}
}

// ListAtomicsByPlatform returns one row per individual atomic test (not
// aggregated per technique like ListTechniqueMeta) -- powers the read-only
// "Detailed view" shown for the art_all_windows Full Sweep scenario, which
// now runs every atomic per technique and so no longer offers a selectable
// subset.
func TestListAtomicsByPlatform(t *testing.T) {
	atoms := newTestStore().ListAtomicsByPlatform("windows")
	if len(atoms) != 4 {
		t.Fatalf("len(atoms) = %d, want 4 (T1059 x2, T1083 x1, T1003 x1)", len(atoms))
	}
	// sorted by technique ID, then name: T1003, T1059(exec a, exec b), T1083
	want := []struct{ tech, name string }{
		{"T1003", "cred dump"},
		{"T1059", "exec a"},
		{"T1059", "exec b"},
		{"T1083", "discovery"},
	}
	for i, w := range want {
		if atoms[i].TechniqueID != w.tech || atoms[i].Name != w.name {
			t.Errorf("atoms[%d] = %+v, want {TechniqueID:%s Name:%s}", i, atoms[i], w.tech, w.name)
		}
	}
}

// A technique with no Windows atomics at all (Linux-only) must not appear
// in ListAtomicsByPlatform("windows") -- same platform-filtering contract
// as ListTechniqueMeta.
func TestListAtomicsByPlatform_ExcludesNonMatchingPlatform(t *testing.T) {
	store := &ARTStore{steps: map[string][]ScenarioStep{
		"T1059": {{Name: "exec", TechniqueID: "T1059", Platform: "windows", Executor: "powershell", Command: "whoami"}},
		"T1499": {{Name: "linux dos", TechniqueID: "T1499", Platform: "linux", Executor: "sh", Command: "true"}},
	}}
	atoms := store.ListAtomicsByPlatform("windows")
	if len(atoms) != 1 {
		t.Fatalf("len(atoms) = %d, want 1 (T1499's linux-only atomic excluded)", len(atoms))
	}
	if atoms[0].TechniqueID != "T1059" {
		t.Errorf("atoms[0].TechniqueID = %q, want T1059", atoms[0].TechniqueID)
	}
}

// UnknownTechniques flags only the IDs absent from the store and is case/space
// insensitive on the valid ones.
func TestUnknownTechniques(t *testing.T) {
	store := newTestStore()
	missing := store.UnknownTechniques([]string{" t1059 ", "T1083", "T9999", "T0000"})
	if len(missing) != 2 {
		t.Fatalf("missing = %v, want 2 unknown", missing)
	}
	if missing[0] != "T9999" || missing[1] != "T0000" {
		t.Errorf("missing = %v, want [T9999 T0000]", missing)
	}
	if got := store.UnknownTechniques([]string{"T1059", "t1003"}); len(got) != 0 {
		t.Errorf("UnknownTechniques(valid set) = %v, want empty", got)
	}
}

// A subset selection builds steps for only the chosen techniques (depth: every
// atomic for each), confirming the override path the run handler relies on.
func TestBuildARTTechniquesSubset(t *testing.T) {
	store := newTestStore()
	steps, err := buildARTTechniquesSteps([]string{"T1059"}, store, "windows")
	if err != nil {
		t.Fatalf("buildARTTechniquesSteps: %v", err)
	}
	if len(steps) != 2 {
		t.Fatalf("len(steps) = %d, want 2 (both T1059 atomics)", len(steps))
	}
	for _, s := range steps {
		if s.TechniqueID != "T1059" {
			t.Errorf("unexpected technique in subset: %s", s.TechniqueID)
		}
	}
}

// A technique ID repeated in the input list (including case/whitespace
// variants) must not expand its atomic tests more than once — callers
// (operator subsets, campaigns, generated packs) don't all guarantee a
// unique list.
func TestBuildARTTechniquesSubset_DedupsRepeatedTechnique(t *testing.T) {
	store := newTestStore()
	steps, err := buildARTTechniquesSteps([]string{"T1059", "t1059", " T1059 "}, store, "windows")
	if err != nil {
		t.Fatalf("buildARTTechniquesSteps: %v", err)
	}
	if len(steps) != 2 {
		t.Fatalf("len(steps) = %d, want 2 (T1059 atomics expanded exactly once)", len(steps))
	}
}
