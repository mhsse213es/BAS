package rwdetect

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

// ransomwareScenarioFiles matches internal/api.ransomwareScenarioIDs' 8
// entries exactly (also mirrored, separately, by
// internal/rwevidence/realcorpus_test.go's own list) -- kept as its own
// small copy here since that list is unexported in rwevidence.
var ransomwareScenarioFiles = []string{
	"akira-kill-chain.yaml", "blackcat-kill-chain.yaml", "clop-kill-chain.yaml",
	"lockbit-kill-chain.yaml", "play-kill-chain.yaml", "ransomhub-kill-chain.yaml",
	"ransomware-drill.yaml", "endpoint-mastery/em-07-ransomware-readiness.yaml",
}

// repoScenariosDir resolves ../../../scenarios relative to this package --
// same relative depth as internal/rwevidence/realcorpus_test.go's own
// helper (internal/rwdetect and internal/rwevidence sit at the same depth
// under orchestrator/internal/), reused in shape, not imported (it's
// unexported there).
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

func TestRansomwareRelevantProfiles_MatchesRealCorpus(t *testing.T) {
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
			for _, p := range step.DetectionProfiles {
				seen[p] = true
			}
		}
	}

	want := map[string]bool{}
	for _, p := range RansomwareRelevantProfiles {
		want[p] = true
	}

	for p := range seen {
		if !want[p] {
			t.Errorf("real corpus references profile %q, not in RansomwareRelevantProfiles -- list is stale", p)
		}
	}
	for p := range want {
		if !seen[p] {
			t.Errorf("RansomwareRelevantProfiles lists %q, but no real scenario step references it -- list is stale", p)
		}
	}
}
