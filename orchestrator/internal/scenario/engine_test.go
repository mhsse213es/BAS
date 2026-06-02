package scenario

import (
	"path/filepath"
	"testing"
)

func TestSaveAndDelete(t *testing.T) {
	dir := t.TempDir()
	e := NewEngine(dir)
	if err := e.Load(); err != nil {
		t.Fatalf("load empty: %v", err)
	}

	sc := &Scenario{
		ID:          "my-custom-chain",
		Name:        "My Custom Chain",
		Description: "test",
		MITREPhases: []string{"execution"},
		Steps: []Step{
			{Name: "step one", TechniqueID: "T1059.001", Framework: "custom", Executor: "powershell", Command: "whoami"},
		},
	}

	if err := e.Save(sc); err != nil {
		t.Fatalf("save: %v", err)
	}
	if sc.Source != "custom" {
		t.Fatalf("expected source=custom, got %q", sc.Source)
	}

	// File should exist in custom/.
	want := filepath.Join(dir, "custom", "my-custom-chain.yaml")
	if _, ok := e.Get("my-custom-chain"); !ok {
		t.Fatalf("scenario not in memory after save")
	}

	// Reload from disk and confirm it parses with the right source.
	e2 := NewEngine(dir)
	if err := e2.Load(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	got, ok := e2.Get("my-custom-chain")
	if !ok {
		t.Fatalf("scenario not found after reload (expected file at %s)", want)
	}
	if got.Source != "custom" {
		t.Fatalf("reloaded source = %q, want custom", got.Source)
	}
	if len(got.Steps) != 1 || got.Steps[0].TechniqueID != "T1059.001" {
		t.Fatalf("reloaded steps mismatch: %+v", got.Steps)
	}

	// Delete should remove it from memory and disk.
	if err := e2.Delete("my-custom-chain"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := e2.Get("my-custom-chain"); ok {
		t.Fatalf("scenario still present after delete")
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name string
		sc   Scenario
		ok   bool
	}{
		{"bad id", Scenario{ID: "Bad ID!", Name: "x", LocalCheck: true}, false},
		{"no name", Scenario{ID: "ok-id", LocalCheck: true}, false},
		{"no mode", Scenario{ID: "ok-id", Name: "x"}, false},
		{"step no technique", Scenario{ID: "ok-id", Name: "x", Steps: []Step{{Name: "s"}}}, false},
		{"valid local", Scenario{ID: "ok-id", Name: "x", LocalCheck: true}, true},
		{"valid steps", Scenario{ID: "ok-id", Name: "x", Steps: []Step{{Name: "s", TechniqueID: "T1059"}}}, true},
	}
	for _, c := range cases {
		err := c.sc.Validate()
		if c.ok && err != nil {
			t.Errorf("%s: expected valid, got %v", c.name, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s: expected error, got nil", c.name)
		}
	}
}
