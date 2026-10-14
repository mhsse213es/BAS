package contentregistry

import (
	"os"
	"path/filepath"
	"testing"
)

// ransomwareScenarioFiles is the same 9-file list sub-project #9 already
// finalized across five other packages this session (internal/rwdetect,
// internal/rwevidence, internal/rwtaxonomy, internal/api, web/ransomware.js).
// Kept as its own small copy here per that same established convention --
// each package that needs a real-corpus check owns its own list.
var ransomwareScenarioFiles = []string{
	"akira-kill-chain.yaml", "blackcat-kill-chain.yaml", "clop-kill-chain.yaml",
	"lockbit-kill-chain.yaml", "play-kill-chain.yaml", "ransomhub-kill-chain.yaml",
	"ransomware-drill.yaml", "endpoint-mastery/em-07-ransomware-readiness.yaml",
	"linux-ransomware-drill.yaml", "black-basta-kill-chain.yaml", "medusa-kill-chain.yaml",
	"rhysida-kill-chain.yaml", "hunters-international-kill-chain.yaml",
}

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

// TestRealRansomwareCorpus_StillParsesAndStructurallyPasses is this plan's
// compatibility proof: none of the 9 real ransomware scenarios set any of
// the new threat-intel provenance fields, so stepProvenanceProblems (Task 2)
// must add zero new structural problems for any of them -- the existing
// content is completely unaffected by this change.
func TestRealRansomwareCorpus_StillParsesAndStructurallyPasses(t *testing.T) {
	dir := repoScenariosDir(t)
	for _, file := range ransomwareScenarioFiles {
		b, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		a, err := analyzeArtifact(b)
		if err != nil {
			t.Fatalf("%s: analyze: %v", file, err)
		}
		if a.structural.outcome != "PASS" {
			t.Errorf("%s: structural = %+v, want PASS", file, a.structural)
		}
	}
}
