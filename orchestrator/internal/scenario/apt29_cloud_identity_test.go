package scenario

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAPT29CloudIdentity_StepCountAndTechniques(t *testing.T) {
	dir, err := filepath.Abs("../../../scenarios")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "apt29-cloud-identity.yaml"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	sc, err := ParseYAML(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	wantTechniques := []string{"T1098.001", "T1550.001", "T1556.007", "T1114", "T1087.004"}
	if len(sc.Steps) != len(wantTechniques) {
		t.Fatalf("got %d steps, want %d", len(sc.Steps), len(wantTechniques))
	}
	for i, want := range wantTechniques {
		if got := sc.Steps[i].TechniqueID; got != want {
			t.Errorf("step %d: technique_id = %q, want %q", i, got, want)
		}
	}
	for i := range sc.Steps {
		if len(sc.Steps[i].DetectionProfiles) != 1 || sc.Steps[i].DetectionProfiles[0] != "windows_apt29_cloud_identity" {
			t.Errorf("step %d: DetectionProfiles = %v, want [windows_apt29_cloud_identity]", i, sc.Steps[i].DetectionProfiles)
		}
	}
	if len(sc.SupportedOS) != 1 || sc.SupportedOS[0] != "windows" {
		t.Fatalf("SupportedOS = %v, want [windows]", sc.SupportedOS)
	}
}

// TestAPT29CloudIdentity_Stages1And2HaveSecondSafetyNetCleanup is the fix for the
// final-review finding: the plan specified a second-safety-net cleanup for the two
// cloud stages that mutate tenant state (service-principal credential, OAuth grant),
// but they shipped with cleanup: "". A failed in-command removePassword/grant-delete
// (swallowed by -ErrorAction SilentlyContinue) would otherwise leave tenant state
// behind with no second line of defense.
func TestAPT29CloudIdentity_Stages1And2HaveSecondSafetyNetCleanup(t *testing.T) {
	dir, err := filepath.Abs("../../../scenarios")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "apt29-cloud-identity.yaml"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	sc, err := ParseYAML(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for i, name := range []string{
		"APT29 Cloud Stage 1 — Service Principal Credential Addition",
		"APT29 Cloud Stage 2 — OAuth Application Permission Abuse",
	} {
		var step *Step
		for j := range sc.Steps {
			if sc.Steps[j].Name == name {
				step = &sc.Steps[j]
				break
			}
		}
		if step == nil {
			t.Fatalf("stage %d: step %q not found", i+1, name)
		}
		if step.Cleanup == "" {
			t.Errorf("stage %d (%q): Cleanup is empty, want a second-safety-net cleanup block", i+1, name)
		}
	}
}
