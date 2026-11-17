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
