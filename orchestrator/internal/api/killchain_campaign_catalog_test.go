package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/killchain"
	"github.com/audspect/bas/internal/scenario"
)

// The shipped campaign definitions are loaded the way the server loads a submitted one:
// signature verified against the compiled key, definition parsed, and validated. Every
// scenario a stage names must exist in the scenario catalogue, and every dependency must
// name a stage in the same campaign. A campaign that fails here cannot be created.
func TestCampaignCatalog_ShippedCampaignsLoadAndResolve(t *testing.T) {
	campDir := filepath.Join("..", "..", "..", "campaigns", "killchain")
	scenDir := filepath.Join("..", "..", "..", "scenarios")

	eng := scenario.NewEngine(scenDir)
	if err := eng.Load(); err != nil {
		t.Fatalf("scenario engine load: %v", err)
	}

	files, err := filepath.Glob(filepath.Join(campDir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no shipped campaign definitions found")
	}

	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := os.ReadFile(f + ".sig")
		if err != nil {
			t.Fatalf("%s: missing signature: %v", filepath.Base(f), err)
		}
		def, err := killchain.LoadSignedCampaign(raw, sig, killChainVerifier)
		if err != nil {
			t.Fatalf("%s: signature or parse: %v", filepath.Base(f), err)
		}
		if _, err := def.Validate(); err != nil {
			t.Fatalf("%s: validate: %v", filepath.Base(f), err)
		}
		keys := map[string]bool{}
		for _, st := range def.Stages {
			keys[st.Key] = true
		}
		for _, st := range def.Stages {
			if _, ok := eng.Get(st.ScenarioID); !ok {
				t.Errorf("%s: stage %s names scenario %q, which is not in the catalogue", filepath.Base(f), st.Key, st.ScenarioID)
			}
			for _, dep := range st.Requires {
				if !keys[dep] {
					t.Errorf("%s: stage %s requires %q, which is not a stage in this campaign", filepath.Base(f), st.Key, dep)
				}
			}
			if !strings.HasPrefix(st.Policy.Source, "fullkillchain.txt") {
				t.Errorf("%s: stage %s has no fullkillchain.txt source: %q", filepath.Base(f), st.Key, st.Policy.Source)
			}
			if st.EffectiveMode() != killchain.ModePosture {
				t.Errorf("%s: stage %s is %s; shipped campaigns must stay posture until approval and staging", filepath.Base(f), st.Key, st.EffectiveMode())
			}
		}
	}
}
