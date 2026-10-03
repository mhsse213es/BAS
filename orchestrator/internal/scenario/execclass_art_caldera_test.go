package scenario_test

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/scenario/corpusaudit"
)

// TestExecutionClassifications_ARTCalderaCorpusFullyResolved is the real
// release gate for the B5 ART/Caldera audit: it re-runs the exact same
// resolution cmd/auditcorpus uses against a live stack and asserts
// unresolved == 0 for both sources. It needs DATABASE_URL and
// CALDERA_URL pointing at a real, populated local compose stack (see
// packaging/compose/docker-compose.yml) -- without them, it skips
// cleanly rather than failing, matching this repo's existing
// testcontainer-suite convention (see internal/api's tests).
func TestExecutionClassifications_ARTCalderaCorpusFullyResolved(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	calderaURL := os.Getenv("CALDERA_URL")
	if dbURL == "" || calderaURL == "" {
		t.Skip("DATABASE_URL/CALDERA_URL not set -- skipping the live-stack ART/Caldera corpus gate (run via the local compose stack to exercise this for real)")
	}
	calderaKey := os.Getenv("CALDERA_API_KEY")

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Fatalf("connect to postgres: %v", err)
	}
	defer pool.Close()

	artStore, err := scenario.NewARTStoreFromDB(ctx, pool, nil)
	if err != nil {
		t.Fatalf("load ART atomics: %v", err)
	}

	var items []corpusaudit.DiscoveredItem
	for _, tech := range artStore.ListTechniques() {
		for _, step := range artStore.GetStepsByPlatform(tech, "windows") {
			items = append(items, corpusaudit.DiscoveredItem{
				Source: "art", TechniqueID: step.TechniqueID, Name: step.Name,
				Executor: step.Executor, Command: step.Command,
				Reachable: step.Command != "" && step.TechniqueID != "",
			})
		}
	}
	if len(items) == 0 {
		t.Fatal("loaded zero ART atomics -- art_atomic_tests appears empty; this is an environment problem, not a resolved-vs-unresolved question")
	}

	raw, err := scenario.FetchRawCalderaAbilities(calderaURL, calderaKey)
	if err != nil {
		t.Fatalf("fetch Caldera abilities: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("fetched zero Caldera abilities -- Caldera appears unloaded; this is an environment problem, not a resolved-vs-unresolved question")
	}
	for _, ab := range raw {
		items = append(items, corpusaudit.DiscoveredItem{
			Source: "caldera", TechniqueID: ab.TechniqueID, Name: ab.Name,
			Executor: ab.Executor, Command: ab.Command, AbilityID: ab.AbilityID,
			Reachable: ab.Command != "" && ab.TechniqueID != "",
		})
	}

	keyed, collisions := corpusaudit.DeriveActionKeys(items)
	for _, c := range collisions {
		t.Logf("unresolved action_key collision (counts as unresolved below): %v", c)
	}

	reviewed, err := corpusaudit.LoadReviewedDecisions("execclass_reviewed.yaml")
	if err != nil {
		t.Fatalf("load execclass_reviewed.yaml: %v", err)
	}

	classified := corpusaudit.Triage(keyed, reviewed)
	report := corpusaudit.BuildReport(classified)

	if report.ART.Unresolved != 0 {
		t.Errorf("ART corpus has %d unresolved (technique_id, action_key) pairs -- see internal/scenario/testdata/execclass_corpus_report.md "+
			"and docs/superpowers/plans/2026-10-03-b5-art-caldera-corpus-audit.md's Task 8 for the review methodology", report.ART.Unresolved)
	}
	if report.Caldera.Unresolved != 0 {
		t.Errorf("Caldera corpus has %d unresolved (technique_id, action_key) pairs -- see internal/scenario/testdata/execclass_corpus_report.md "+
			"and docs/superpowers/plans/2026-10-03-b5-art-caldera-corpus-audit.md's Task 8 for the review methodology", report.Caldera.Unresolved)
	}
}
