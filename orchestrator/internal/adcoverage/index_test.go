package adcoverage

import (
	"os"
	"testing"
	"testing/fstest"

	"github.com/audspect/bas/internal/adbench"
)

func TestIndexScenarios_GroupsByTechniqueSkipsNonYAMLAndEmptyTechnique(t *testing.T) {
	fsys := fstest.MapFS{
		"a.yaml": {Data: []byte("id: scen-a\nname: A\nsteps:\n" +
			"  - name: step1\n    technique_id: T1001\n    framework: custom\n" +
			"  - name: no-tech\n    technique_id: \"\"\n    framework: custom\n")},
		"b.yaml": {Data: []byte("id: scen-b\nname: B\nsteps:\n" +
			"  - name: step2\n    technique_id: T1001\n    framework: art\n")},
		"a.yaml.sig": {Data: []byte("not a scenario, must be ignored")},
		"notes.txt":  {Data: []byte("ignored")},
	}
	index, err := IndexScenarios(fsys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(index["T1001"]) != 2 {
		t.Fatalf("expected 2 steps for T1001 (from a.yaml + b.yaml), got %+v", index["T1001"])
	}
	if _, ok := index[""]; ok {
		t.Error("empty-technique step must be skipped, not indexed under \"\"")
	}
}

func TestIndexScenarios_EmptyCorpusIsEmptyIndexNilError(t *testing.T) {
	index, err := IndexScenarios(fstest.MapFS{})
	if err != nil {
		t.Fatalf("empty corpus must not error: %v", err)
	}
	if len(index) != 0 {
		t.Fatalf("expected empty index, got %+v", index)
	}
}

// Integration: the REAL scenarios/ corpus must reflect reality.
func TestIndexScenarios_RealCorpusReflectsReality(t *testing.T) {
	// adcoverage is at orchestrator/internal/adcoverage; scenarios/ is at the
	// repo root, three levels up.
	index, err := IndexScenarios(os.DirFS("../../../scenarios"))
	if err != nil {
		t.Fatalf("indexing the real corpus failed: %v", err)
	}
	if len(index["T1558.003"]) == 0 {
		t.Fatal("expected real scenario coverage for T1558.003 (Kerberoasting)")
	}

	rep := Map(adbench.All(), index)
	covered := map[string]bool{}
	for _, c := range rep.Covered {
		covered[c.Primitive.ID] = true
	}
	gaps := map[string]bool{}
	for _, g := range rep.Gaps {
		gaps[g.Primitive.ID] = true
	}
	// Kerberoasting/AS-REP primitives carry T1558.003/004 -> covered.
	for _, id := range []string{"spn-enumerate", "kerberoast-tgs-request", "asrep-roast-discover"} {
		if !covered[id] {
			t.Errorf("expected %s covered by the real corpus", id)
		}
	}
	// DCSync (T1003.006) and ADCS (T1649) have no scenario coverage -> gaps.
	for _, id := range []string{"dcsync", "adcs-esc1", "adcs-esc2", "adcs-esc3", "adcs-esc4"} {
		if !gaps[id] {
			t.Errorf("expected %s in gaps (no scenario coverage)", id)
		}
	}
}
