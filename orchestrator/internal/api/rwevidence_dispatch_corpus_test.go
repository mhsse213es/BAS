package api

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func repoScenariosDirForRWDispatch(t *testing.T) string {
	dir, err := filepath.Abs("../../../scenarios")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("scenarios dir not found at %s: %v", dir, err)
	}
	return dir
}

// TestRansomwareScenarioIDs_MatchesRealCorpus is the fail-closed test
// ransomwareScenarioIDs never had: a scenario missing from this map is
// never evaluated by rwevidence at all, with no error anywhere -- this
// proves every ransomware-tagged scenario file on disk has a matching
// entry, and every entry still has a matching file.
func TestRansomwareScenarioIDs_MatchesRealCorpus(t *testing.T) {
	files := []string{
		"akira-kill-chain.yaml", "blackcat-kill-chain.yaml", "clop-kill-chain.yaml",
		"lockbit-kill-chain.yaml", "play-kill-chain.yaml", "ransomhub-kill-chain.yaml",
		"ransomware-drill.yaml", "endpoint-mastery/em-07-ransomware-readiness.yaml",
		"linux-ransomware-drill.yaml", "black-basta-kill-chain.yaml",
	}
	dir := repoScenariosDirForRWDispatch(t)
	seen := map[string]bool{}
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		sc, err := scenario.ParseYAML(b)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		seen[sc.ID] = true
	}
	for id := range seen {
		if !ransomwareScenarioIDs[id] {
			t.Errorf("real corpus file for scenario %q exists, but ransomwareScenarioIDs is missing it -- this run would silently never be evaluated by rwevidence", id)
		}
	}
	for id := range ransomwareScenarioIDs {
		if !seen[id] {
			t.Errorf("ransomwareScenarioIDs lists %q, but no real scenario file declares that id -- stale entry", id)
		}
	}
}
