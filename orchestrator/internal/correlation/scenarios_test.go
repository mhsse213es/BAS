package correlation

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

// writeScenarioFixture writes into dir/custom/ -- scenario.Engine.Load only
// requires a signature for files directly under the scenarios root
// ("builtin" source); files under custom/ are operator-created and
// intentionally unsigned (engine.go:82-90).
func writeScenarioFixture(t *testing.T, dir, filename, content string) {
	t.Helper()
	customDir := filepath.Join(dir, "custom")
	if err := os.MkdirAll(customDir, 0o755); err != nil {
		t.Fatalf("mkdir custom dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(customDir, filename), []byte(content), 0o644); err != nil {
		t.Fatalf("write scenario fixture: %v", err)
	}
}

func TestScenariosForTechnique_MatchesAndDeduplicatesPerScenario(t *testing.T) {
	dir := t.TempDir()
	writeScenarioFixture(t, dir, "sc-match.yaml",
		"id: sc-match\nname: Matching Scenario\nsteps:\n"+
			"  - name: step one\n    technique_id: T1059.001\n"+
			"  - name: step two\n    technique_id: T1059.001\n") // same technique twice -- must not double-count
	writeScenarioFixture(t, dir, "sc-nomatch.yaml",
		"id: sc-nomatch\nname: Unrelated Scenario\nsteps:\n"+
			"  - name: step one\n    technique_id: T1003\n")

	eng := scenario.NewEngine(dir)
	if err := eng.Load(); err != nil {
		t.Fatalf("engine.Load: %v", err)
	}

	got := scenariosForTechnique(eng, "T1059.001")
	if len(got) != 1 {
		t.Fatalf("got %d scenarios, want exactly 1 (deduplicated within the matching scenario)", len(got))
	}
	if got[0].ID != "sc-match" || got[0].Name != "Matching Scenario" {
		t.Errorf("got %+v, want {sc-match, Matching Scenario}", got[0])
	}
}

func TestScenariosForTechnique_NoMatch_ReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	writeScenarioFixture(t, dir, "sc-nomatch.yaml",
		"id: sc-nomatch\nname: Unrelated Scenario\nsteps:\n"+
			"  - name: step one\n    technique_id: T1003\n")
	eng := scenario.NewEngine(dir)
	if err := eng.Load(); err != nil {
		t.Fatalf("engine.Load: %v", err)
	}

	got := scenariosForTechnique(eng, "T9999.999")
	if len(got) != 0 {
		t.Errorf("got %v, want empty", got)
	}
}

func TestScenariosForTechnique_CaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	writeScenarioFixture(t, dir, "sc-match.yaml",
		"id: sc-match\nname: Matching Scenario\nsteps:\n"+
			"  - name: step one\n    technique_id: T1059.001\n")
	eng := scenario.NewEngine(dir)
	if err := eng.Load(); err != nil {
		t.Fatalf("engine.Load: %v", err)
	}

	got := scenariosForTechnique(eng, "t1059.001")
	if len(got) != 1 {
		t.Fatalf("got %d scenarios, want 1 (case-insensitive match)", len(got))
	}
}
