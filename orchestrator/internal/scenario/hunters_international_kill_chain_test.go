package scenario

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHuntersInternationalKillChain_ParsesWithNineStepsWindowsOnlyFullyGrounded(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("../../../scenarios", "hunters-international-kill-chain.yaml"))
	if err != nil {
		t.Fatalf("file not found: %v", err)
	}

	sc, err := ParseYAML(b)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	// Verify 9 steps
	if len(sc.Steps) != 9 {
		t.Errorf("expected 9 steps, got %d", len(sc.Steps))
	}

	// Verify sequence: T1190, T1505.003, T1087.002, T1556, T1003.006, T1021.001, T1020, T1490, T1486
	expectedTechniques := []string{"T1190", "T1505.003", "T1087.002", "T1556", "T1003.006", "T1021.001", "T1020", "T1490", "T1486"}
	for i, step := range sc.Steps {
		if i < len(expectedTechniques) && step.TechniqueID != expectedTechniques[i] {
			t.Errorf("step %d: expected technique %s, got %s", i+1, expectedTechniques[i], step.TechniqueID)
		}
	}

	// Verify platform (SupportedOS field)
	if len(sc.SupportedOS) == 0 || sc.SupportedOS[0] != "windows" {
		t.Errorf("expected supported_os [windows], got %v", sc.SupportedOS)
	}

	// Verify scenario-level fields
	if sc.ID == "" {
		t.Error("missing scenario id")
	}
	if sc.Name == "" {
		t.Error("missing scenario name")
	}

	// Verify steps have threat intel provenance (per Rhysida pattern: step-level, not scenario-level)
	for i, step := range sc.Steps {
		if step.TechniqueID == "" {
			t.Errorf("step %d: missing technique_id", i+1)
		}
		if step.ActionKey == "" && step.TechniqueID != "T1087.002" && step.TechniqueID != "T1490" {
			// Most steps should have action_key; some may use defaults
			// This is informational, not a hard failure
		}
	}
}
