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
	steps, err := buildARTTechniquesSteps([]string{"T1059"}, store)
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
