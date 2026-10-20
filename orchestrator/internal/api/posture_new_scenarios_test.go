package api

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

// The posture-only enterprise scenarios load through the real engine, verify their
// signatures, and expose the steps and verdict contract the posture runner needs.
func TestPostureScenarios_LoadAndDeclareSteps(t *testing.T) {
	eng := scenario.NewEngine(filepath.Join("..", "..", "..", "scenarios"))
	if err := eng.Load(); err != nil {
		t.Fatalf("engine load: %v", err)
	}
	for _, id := range []string{"windows-persistence-posture", "windows-east-west-host-firewall-posture", "windows-backup-posture", "windows-detection-prerequisites-posture", "windows-credential-protection-posture", "windows-execution-control-posture"} {
		sc, ok := eng.Get(id)
		if !ok {
			t.Fatalf("%s did not load (signature or parse)", id)
		}
		if sc.Executable {
			t.Fatalf("%s must be posture-only (executable: false)", id)
		}
		if len(sc.Steps) == 0 {
			t.Fatalf("%s has no steps", id)
		}
		for _, st := range sc.Steps {
			if st.Command == "" || st.TechniqueID == "" || st.CheckID == "" {
				t.Fatalf("%s step %q is missing command, technique or check id", id, st.Name)
			}
			if !strings.Contains(st.Command, "PASS:") || !strings.Contains(st.Command, "FAIL:") {
				t.Fatalf("%s step %q does not emit a PASS and FAIL verdict", id, st.Name)
			}
		}
	}
}
