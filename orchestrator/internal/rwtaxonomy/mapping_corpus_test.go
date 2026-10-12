package rwtaxonomy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

// ransomwareScenarioFiles matches internal/rwdetect/profiles_test.go's own
// list and internal/api.ransomwareScenarioIDs' 8 entries exactly -- kept as
// its own small copy here since that list is unexported in rwdetect.
var ransomwareScenarioFiles = []string{
	"akira-kill-chain.yaml", "blackcat-kill-chain.yaml", "clop-kill-chain.yaml",
	"lockbit-kill-chain.yaml", "play-kill-chain.yaml", "ransomhub-kill-chain.yaml",
	"ransomware-drill.yaml", "endpoint-mastery/em-07-ransomware-readiness.yaml",
	"linux-ransomware-drill.yaml", "black-basta-kill-chain.yaml", "medusa-kill-chain.yaml",
	"rhysida-kill-chain.yaml",
}

// repoScenariosDir resolves ../../../scenarios relative to this package --
// same relative depth as internal/rwdetect's own helper (internal/rwtaxonomy
// and internal/rwdetect sit at the same depth under orchestrator/internal/).
func repoScenariosDir(t *testing.T) string {
	dir, err := filepath.Abs("../../../scenarios")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("scenarios dir not found at %s: %v", dir, err)
	}
	return dir
}

// TestTechniqueDomain_MatchesRealCorpus is the single most important test
// in this package: it parses all 8 real scenario YAMLs fresh, collects
// every distinct technique_id actually used, and checks a two-way match
// against TechniqueDomain's keys. A scenario introducing an unmapped
// technique fails the first loop; a mapping entry whose technique was
// removed/renamed from every scenario fails the second loop -- a stale
// mapping is caught just as reliably as a missing one.
func TestTechniqueDomain_MatchesRealCorpus(t *testing.T) {
	seen := map[string]bool{}
	for _, file := range ransomwareScenarioFiles {
		b, err := os.ReadFile(filepath.Join(repoScenariosDir(t), file))
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		sc, err := scenario.ParseYAML(b)
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		for _, step := range sc.Steps {
			if step.TechniqueID != "" {
				seen[step.TechniqueID] = true
			}
		}
	}

	for id := range seen {
		if _, ok := TechniqueDomain[id]; !ok {
			t.Errorf("real corpus references technique %q, not in TechniqueDomain -- mapping is stale (unmapped technique introduced)", id)
		}
	}
	for id := range TechniqueDomain {
		if !seen[id] {
			t.Errorf("TechniqueDomain maps %q, but no real scenario step references it -- mapping is stale (technique retired from corpus)", id)
		}
	}
}
