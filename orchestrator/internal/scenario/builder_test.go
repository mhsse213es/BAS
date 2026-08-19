package scenario

import "testing"

// The full ART sweep dispatches EVERY Windows atomic for EVERY technique in
// the store — including destructive/Impact techniques, by operator choice. (This
// is an authorized BAS product; impact-tactic coverage is intentional. Run the
// full sweep only in a maintenance window — T1529's atomic reboots the host.)
// T1059 has two distinct atomics here specifically to prove a multi-atomic
// technique dispatches all of them, not just the first.
func TestBuildARTAllWindowsStepsIncludesAllTechniques(t *testing.T) {
	store := &ARTStore{steps: map[string][]ScenarioStep{
		"T1059": {
			{Name: "exec ps", TechniqueID: "T1059", Platform: "windows", Executor: "powershell", Command: "whoami"},
			{Name: "exec cmd", TechniqueID: "T1059", Platform: "windows", Executor: "cmd", Command: "whoami"},
		},
		"T1083": {{Name: "discovery", TechniqueID: "T1083", Platform: "windows", Executor: "powershell", Command: "dir"}},
		"T1529": {{Name: "reboot", TechniqueID: "T1529", Platform: "windows", Executor: "powershell", Command: "Restart-Computer -Force"}},
		"T1485": {{Name: "wipe", TechniqueID: "T1485", Platform: "windows", Executor: "powershell", Command: "Remove-Item C:\\ -Recurse"}},
	}}

	steps, err := buildARTPlatformSteps("windows", store)
	if err != nil {
		t.Fatalf("buildARTAllWindowsSteps: %v", err)
	}

	got := map[string]bool{}
	t1059Names := map[string]bool{}
	for _, s := range steps {
		got[s.TechniqueID] = true
		if s.TechniqueID == "T1059" {
			t1059Names[s.Name] = true
		}
	}
	for _, tech := range []string{"T1059", "T1083", "T1529", "T1485"} {
		if !got[tech] {
			t.Errorf("full sweep missing %s — should include all techniques (got %v)", tech, got)
		}
	}
	if !t1059Names["exec ps"] || !t1059Names["exec cmd"] {
		t.Errorf("T1059 has 2 atomics but full sweep only dispatched %v — must include every atomic per technique, not just the first", t1059Names)
	}
	if len(steps) != 5 {
		t.Errorf("len(steps) = %d, want 5 (both T1059 atomics + 1 each for T1083/T1529/T1485)", len(steps))
	}
}
