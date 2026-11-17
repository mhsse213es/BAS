package scenario

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadCarbanakChain(t *testing.T) *Scenario {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "scenarios", "carbanak-kill-chain.yaml"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	sc, err := ParseYAML(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return sc
}

func carbanakStep(t *testing.T, sc *Scenario, prefix string) *Step {
	t.Helper()
	for i := range sc.Steps {
		if strings.HasPrefix(sc.Steps[i].Name, prefix) {
			return &sc.Steps[i]
		}
	}
	t.Fatalf("no step with name prefix %q", prefix)
	return nil
}

func TestCarbanakStage3UsesHostFirewallSubTechnique(t *testing.T) {
	st := carbanakStep(t, loadCarbanakChain(t), "Carbanak Stage 3 ")
	if st.TechniqueID != "T1686.003" {
		t.Fatalf("stage 3 technique_id = %q, want T1686.003 (Windows Host Firewall)", st.TechniqueID)
	}
}

func TestCarbanakStage4UsesQueryOnlyLSASSAccess(t *testing.T) {
	st := carbanakStep(t, loadCarbanakChain(t), "Carbanak Stage 4 ")
	if !strings.Contains(st.Command, "0x1000") {
		t.Fatalf("stage 4 must open LSASS with query-only access 0x1000")
	}
	if strings.Contains(st.Command, "0x1010") {
		t.Fatalf("stage 4 still requests PROCESS_VM_READ (0x1010)")
	}
}

func TestCarbanakFraudSequenceReplacesDecoy(t *testing.T) {
	sc := loadCarbanakChain(t)
	if len(sc.Steps) < 14 {
		t.Fatalf("chain has %d steps, want at least 14 (stages 1-7 plus 8a-8g)", len(sc.Steps))
	}
	wantControl := map[string]string{
		"Carbanak Stage 8a ": "evidence",
		"Carbanak Stage 8b ": "prevent",
		"Carbanak Stage 8c ": "detect",
		"Carbanak Stage 8d ": "prevent",
		"Carbanak Stage 8e ": "prevent",
		"Carbanak Stage 8f ": "verify",
		"Carbanak Stage 8g ": "detect",
	}
	for prefix, control := range wantControl {
		st := carbanakStep(t, sc, prefix)
		if !strings.Contains(st.Command, "expected_control='"+control+"'") {
			t.Errorf("%s: marker expected_control %q missing", prefix, control)
		}
		if !strings.Contains(st.Command, "BAS-FRAUD-CONTROL") {
			t.Errorf("%s: no BAS-FRAUD-CONTROL marker printed", prefix)
		}
	}
	for _, st := range sc.Steps {
		if strings.Contains(st.Command, "bas_carbanak_fraud_") {
			t.Errorf("step %q still writes the decoy transfer dir", st.Name)
		}
	}
	if !strings.Contains(carbanakStep(t, sc, "Carbanak Stage 8a ").Command, "bas_carbanak_run") {
		t.Error("8a must record the shared run state for 8b-8g")
	}
}

func TestCarbanakDiscoveryAndCredentialStagesTask9(t *testing.T) {
	sc := loadCarbanakChain(t)
	want := map[string]string{
		"Carbanak Stage 10 ": "T1083",
		"Carbanak Stage 11 ": "T1046",
		"Carbanak Stage 12 ": "T1069.002",
		"Carbanak Stage 13 ": "T1135",
		"Carbanak Stage 14 ": "T1555.004",
		"Carbanak Stage 15 ": "T1555.003",
		"Carbanak Stage 17 ": "T1558.003",
		"Carbanak Stage 18 ": "T1552.001",
	}
	forbidden := []string{"ReadProcessMemory", "CredRead", "CryptUnprotectData", "MiniDump", "VM_READ"}
	for prefix, tech := range want {
		st := carbanakStep(t, sc, prefix)
		if st.TechniqueID != tech {
			t.Errorf("%s technique_id = %q, want %q", prefix, st.TechniqueID, tech)
		}
		for _, f := range forbidden {
			if strings.Contains(st.Command, f) {
				t.Errorf("%s command contains forbidden %q", prefix, f)
			}
		}
		if len(st.ThreatIntelSources) == 0 {
			t.Errorf("%s has no threat_intel_sources", prefix)
		}
		if !strings.Contains(st.Command, "[BAS-SIM-CARBANAK-S") {
			t.Errorf("%s missing [BAS-SIM-CARBANAK-Sn] marker", prefix)
		}
	}
}
