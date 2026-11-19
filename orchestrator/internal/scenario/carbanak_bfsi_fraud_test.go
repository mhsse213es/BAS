package scenario

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadBFSIScenario(t *testing.T, file string) *Scenario {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "scenarios", file))
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	sc, err := ParseYAML(b)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	return sc
}

func TestCarbanakBFSIFraudScenarios(t *testing.T) {
	cases := []struct {
		file, tech, control string
		gap                 bool
	}{
		{"carbanak-bfsi-beneficiary-creation.yaml", "", "prevent", true},
		{"carbanak-bfsi-amount-manipulation.yaml", "T1565.002", "detect", false},
		{"carbanak-bfsi-unauthorized-approval.yaml", "T1078", "prevent", false},
		{"carbanak-bfsi-session-misuse.yaml", "T1078", "detect", false},
		{"carbanak-bfsi-off-hours-transfer.yaml", "T1078", "detect", false},
		{"carbanak-bfsi-limit-modification.yaml", "", "prevent", true},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			sc := loadBFSIScenario(t, c.file)
			if len(sc.Steps) != 1 {
				t.Fatalf("steps = %d, want 1", len(sc.Steps))
			}
			st := sc.Steps[0]
			if st.TechniqueID != c.tech {
				t.Errorf("technique_id = %q, want %q", st.TechniqueID, c.tech)
			}
			if c.gap && st.AttackGap != AttackGapNoCleanTechnique {
				t.Errorf("attack_gap = %q, want %q", st.AttackGap, AttackGapNoCleanTechnique)
			}
			if !c.gap && st.AttackGap != "" {
				t.Errorf("attack_gap = %q, want unset", st.AttackGap)
			}
			if !strings.Contains(st.Command, "expected_control='"+c.control+"'") {
				t.Errorf("marker expected_control %q missing", c.control)
			}
			if !strings.Contains(st.Command, "BAS-FRAUD-CONTROL") {
				t.Error("no BAS-FRAUD-CONTROL marker")
			}
			if !strings.Contains(st.Command, "NewGuid") {
				t.Error("run id must be generated fresh (NewGuid)")
			}
			if strings.Contains(st.Command, "bas_carbanak_run") {
				t.Error("must not read the shared chain run file")
			}
		})
	}
}
