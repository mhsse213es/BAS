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

// ARTSelectiveWindows/ARTSelectivePlatform must dispatch through BuildSteps to
// the exact same full-depth builder as ARTAllWindows/ARTAllPlatform -- the
// "Selective" scenarios are meant to have byte-for-byte identical default
// coverage to the "Full Sweep" ones, differing only in the frontend's
// Customize-vs-Detailed-view affordance, never in what actually runs.
func TestBuildSteps_ARTSelectiveWindows_MatchesARTAllWindows(t *testing.T) {
	store := &ARTStore{steps: map[string][]ScenarioStep{
		"T1059": {
			{Name: "exec ps", TechniqueID: "T1059", Platform: "windows", Executor: "powershell", Command: "whoami"},
			{Name: "exec cmd", TechniqueID: "T1059", Platform: "windows", Executor: "cmd", Command: "whoami"},
		},
		"T1083": {{Name: "discovery", TechniqueID: "T1083", Platform: "windows", Executor: "powershell", Command: "dir"}},
	}}

	allSteps, _, err := BuildSteps(&Scenario{ARTAllWindows: true}, "", "", store, "windows")
	if err != nil {
		t.Fatalf("BuildSteps(ARTAllWindows): %v", err)
	}
	selSteps, _, err := BuildSteps(&Scenario{ARTSelectiveWindows: true}, "", "", store, "windows")
	if err != nil {
		t.Fatalf("BuildSteps(ARTSelectiveWindows): %v", err)
	}
	if len(selSteps) != len(allSteps) {
		t.Fatalf("len(selSteps) = %d, len(allSteps) = %d -- selective must match full sweep exactly", len(selSteps), len(allSteps))
	}
	if len(selSteps) != 3 {
		t.Errorf("len(selSteps) = %d, want 3", len(selSteps))
	}
}

// Same guarantee for the non-Windows sibling: ARTSelectivePlatform must match
// ARTAllPlatform's output for a given agentOS.
func TestBuildSteps_ARTSelectivePlatform_MatchesARTAllPlatform(t *testing.T) {
	store := &ARTStore{steps: map[string][]ScenarioStep{
		"T1059": {{Name: "exec sh", TechniqueID: "T1059", Platform: "linux", Executor: "sh", Command: "whoami"}},
		"T1083": {{Name: "discovery", TechniqueID: "T1083", Platform: "linux", Executor: "sh", Command: "ls"}},
	}}

	allSteps, _, err := BuildSteps(&Scenario{ARTAllPlatform: true}, "", "", store, "linux")
	if err != nil {
		t.Fatalf("BuildSteps(ARTAllPlatform): %v", err)
	}
	selSteps, _, err := BuildSteps(&Scenario{ARTSelectivePlatform: true}, "", "", store, "linux")
	if err != nil {
		t.Fatalf("BuildSteps(ARTSelectivePlatform): %v", err)
	}
	if len(selSteps) != len(allSteps) {
		t.Fatalf("len(selSteps) = %d, len(allSteps) = %d -- selective must match full sweep exactly", len(selSteps), len(allSteps))
	}
	if len(selSteps) != 2 {
		t.Errorf("len(selSteps) = %d, want 2", len(selSteps))
	}
}
