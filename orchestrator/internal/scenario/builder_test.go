package scenario

import "testing"

// The full ART sweep dispatches one representative atomic for EVERY technique in
// the store — including destructive/Impact techniques, by operator choice. (This
// is an authorized BAS product; impact-tactic coverage is intentional. Run the
// full sweep only in a maintenance window — T1529's atomic reboots the host.)
func TestBuildARTAllWindowsStepsIncludesAllTechniques(t *testing.T) {
	store := &ARTStore{steps: map[string][]ScenarioStep{
		"T1059": {{Name: "exec", TechniqueID: "T1059", Platform: "windows", Executor: "powershell", Command: "whoami"}},
		"T1083": {{Name: "discovery", TechniqueID: "T1083", Platform: "windows", Executor: "powershell", Command: "dir"}},
		"T1529": {{Name: "reboot", TechniqueID: "T1529", Platform: "windows", Executor: "powershell", Command: "Restart-Computer -Force"}},
		"T1485": {{Name: "wipe", TechniqueID: "T1485", Platform: "windows", Executor: "powershell", Command: "Remove-Item C:\\ -Recurse"}},
	}}

	steps, err := buildARTPlatformSteps("windows", store)
	if err != nil {
		t.Fatalf("buildARTAllWindowsSteps: %v", err)
	}

	got := map[string]bool{}
	for _, s := range steps {
		got[s.TechniqueID] = true
	}
	for _, tech := range []string{"T1059", "T1083", "T1529", "T1485"} {
		if !got[tech] {
			t.Errorf("full sweep missing %s — should include all techniques (got %v)", tech, got)
		}
	}
	if len(steps) != 4 {
		t.Errorf("len(steps) = %d, want 4 (one atomic per technique)", len(steps))
	}
}
