package scenario

import "testing"

// Destructive ATT&CK techniques (Impact tactic / host-availability) must never be
// dispatched by the automated full ART sweep — they can take a live endpoint down
// (T1529 rebooted a production host in the field).
func TestIsDestructiveTechnique(t *testing.T) {
	destructive := []string{
		"T1529",     // System Shutdown/Reboot
		"T1485",     // Data Destruction
		"T1486",     // Data Encrypted for Impact
		"T1490",     // Inhibit System Recovery
		"T1489",     // Service Stop
		"T1531",     // Account Access Removal
		"T1561",     // Disk Wipe
		"T1529.001", // sub-technique resolves to its base
		"t1485",     // case-insensitive
	}
	for _, id := range destructive {
		if !isDestructiveTechnique(id) {
			t.Errorf("isDestructiveTechnique(%q) = false, want true", id)
		}
	}
	safe := []string{"T1059", "T1083", "T1057", "T1016", "T1082"}
	for _, id := range safe {
		if isDestructiveTechnique(id) {
			t.Errorf("isDestructiveTechnique(%q) = true, want false", id)
		}
	}
}

func TestBuildARTAllWindowsStepsExcludesDestructive(t *testing.T) {
	store := &ARTStore{steps: map[string][]ScenarioStep{
		"T1059": {{Name: "exec", TechniqueID: "T1059", Executor: "powershell", Command: "whoami"}},
		"T1083": {{Name: "discovery", TechniqueID: "T1083", Executor: "powershell", Command: "dir"}},
		"T1529": {{Name: "reboot", TechniqueID: "T1529", Executor: "powershell", Command: "Restart-Computer -Force"}},
		"T1485": {{Name: "wipe", TechniqueID: "T1485", Executor: "powershell", Command: "Remove-Item C:\\ -Recurse"}},
	}}

	steps, err := buildARTAllWindowsSteps(store)
	if err != nil {
		t.Fatalf("buildARTAllWindowsSteps: %v", err)
	}

	got := map[string]bool{}
	for _, s := range steps {
		got[s.TechniqueID] = true
	}
	if !got["T1059"] || !got["T1083"] {
		t.Errorf("benign techniques dropped: got %v", got)
	}
	if got["T1529"] || got["T1485"] {
		t.Errorf("destructive technique included in full sweep: got %v", got)
	}
	if len(steps) != 2 {
		t.Errorf("len(steps) = %d, want 2 (only benign)", len(steps))
	}
}
