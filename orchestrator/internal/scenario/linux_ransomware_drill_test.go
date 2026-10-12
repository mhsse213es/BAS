package scenario

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxRansomwareDrill_ParsesWithFourStepsLinuxOnly(t *testing.T) {
	path := filepath.Join("..", "..", "..", "scenarios", "linux-ransomware-drill.yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sc, err := ParseYAML(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(sc.SupportedOS) != 1 || sc.SupportedOS[0] != "linux" {
		t.Fatalf("SupportedOS = %v, want exactly [\"linux\"]", sc.SupportedOS)
	}
	if len(sc.Steps) != 4 {
		t.Fatalf("len(Steps) = %d, want 4", len(sc.Steps))
	}
	wantTechniques := []string{"T1490", "T1490", "T1486", "T1486"}
	for i, want := range wantTechniques {
		if sc.Steps[i].TechniqueID != want {
			t.Errorf("Steps[%d].TechniqueID = %q, want %q", i, sc.Steps[i].TechniqueID, want)
		}
	}
	for _, step := range sc.Steps {
		for _, p := range step.DetectionProfiles {
			if len(p) >= 8 && p[:8] == "windows_" {
				t.Errorf("step %q uses a windows_-prefixed detection profile %q -- a Linux scenario must never report Windows coverage", step.Name, p)
			}
		}
	}
}
