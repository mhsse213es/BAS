package scenario

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCarbanakBFSIAppDiscoveryScenario(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "scenarios", "carbanak-bfsi-app-discovery.yaml"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	sc, err := ParseYAML(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if sc.ProductLine != "killchain" {
		t.Errorf("product_line = %q, want killchain", sc.ProductLine)
	}
	if len(sc.Steps) != 1 {
		t.Fatalf("steps = %d, want 1", len(sc.Steps))
	}
	st := sc.Steps[0]
	if st.TechniqueID != "T1057" {
		t.Errorf("technique_id = %q, want T1057", st.TechniqueID)
	}
	if st.AttackGap != "" {
		t.Errorf("attack_gap = %q, want unset", st.AttackGap)
	}
	if !strings.Contains(st.Command, "EXEC") || !strings.Contains(st.Command, "[BAS-SIM-CARBANAK-S9]") {
		t.Error("command must print an EXEC line with the S9 marker")
	}
	for _, f := range []string{"ReadProcessMemory", "CredRead", "MiniDump", "VM_READ"} {
		if strings.Contains(st.Command, f) {
			t.Errorf("command contains forbidden %q", f)
		}
	}
}
