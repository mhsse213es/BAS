package scenario

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAPT29KillChainPhase7_StepCountAndTechniques is the running contract for
// scenarios/apt29-kill-chain-phase7.yaml, a parallel, independently-built 30-stage
// expansion kept under its own id (apt29-kill-chain-phase7) rather than merged with
// the separately-maintained apt29-kill-chain scenario, since both were built
// concurrently and overlap on some technique coverage. See the scenario's own
// description and docs/apt29-phase7-mastery-qa-log.md.
func TestAPT29KillChainPhase7_StepCountAndTechniques(t *testing.T) {
	dir, err := filepath.Abs("../../../scenarios")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "apt29-kill-chain-phase7.yaml"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	sc, err := ParseYAML(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if sc.ID != "apt29-kill-chain-phase7" {
		t.Fatalf("id = %q, want apt29-kill-chain-phase7 (must not collide with the separately-maintained apt29-kill-chain scenario)", sc.ID)
	}
	wantTechniques := []string{
		"T1482", "T1059.001", "T1547.001", "T1053.005", "T1071.004",
		"T1069.002", "T1018", "T1018", "T1518.001", "T1016",
		"T1047", "T1218.011", "T1027", "T1685.001",
		"T1547.001", "T1546.003", "T1543.003", "T1546.015",
		"T1003.001", "T1555.004", "T1555.003", "T1558.003", "T1555",
		"T1021.002", "T1021.006", "T1569.002",
		"T1071.001", "T1071.004", "T1005", "T1041",
	}
	if len(sc.Steps) != len(wantTechniques) {
		t.Fatalf("got %d steps, want %d", len(sc.Steps), len(wantTechniques))
	}
	for i, want := range wantTechniques {
		if got := sc.Steps[i].TechniqueID; got != want {
			t.Errorf("step %d: technique_id = %q, want %q", i, got, want)
		}
	}
}

// TestAPT29KillChainPhase7_Stage11HidesItsWindow is the fix for a window-flash
// finding: the user reported unrelated scenarios popping Calculator/Notepad/
// PowerShell on an interactive desktop. Stage 11 (WMI process execution)
// originally spawned cmd.exe via Win32_Process.Create, which has no window-style
// parameter, so a console window could flash. The fix routes the WMI-spawned
// command through powershell.exe -WindowStyle Hidden, which does suppress its
// own window.
func TestAPT29KillChainPhase7_Stage11HidesItsWindow(t *testing.T) {
	dir, err := filepath.Abs("../../../scenarios")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "apt29-kill-chain-phase7.yaml"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	sc, err := ParseYAML(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var step *Step
	for i := range sc.Steps {
		if sc.Steps[i].Name == "APT29 Stage 11 — WMI-Based Process Execution Simulation (T1047)" {
			step = &sc.Steps[i]
			break
		}
	}
	if step == nil {
		t.Fatal("stage 11 not found")
	}
	if !strings.Contains(step.Command, "-WindowStyle Hidden") {
		t.Errorf("stage 11 command does not request a hidden window: %s", step.Command)
	}
	if strings.Contains(step.Command, "CommandLine = \"cmd.exe") {
		t.Errorf("stage 11 still spawns cmd.exe directly via WMI (no window-style parameter available there)")
	}
}
