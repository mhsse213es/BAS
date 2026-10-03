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
		// Logged, not failed: a collision-excluded item is reported under
		// report.*.Collisions (not Unresolved) -- see report.go's doc
		// comment. It already fails closed at runtime (no catalog entry ->
		// "destructive"/unclassified -> blocked), so this gate does not
		// treat it as a safety gap, only surfaces it for visibility.
		t.Logf("action_key collision (see report.*.Collisions, not folded into Unresolved): %v", c)
	}

	reviewed, err := corpusaudit.LoadReviewedDecisions("execclass_reviewed.yaml")
	if err != nil {
		t.Fatalf("load execclass_reviewed.yaml: %v", err)
	}

	classified := corpusaudit.Triage(keyed, reviewed)
	report := corpusaudit.BuildReport(classified, collisions)

	if report.ART.Unresolved != 0 {
		t.Errorf("ART corpus has %d unresolved (technique_id, action_key) pairs -- see internal/scenario/testdata/execclass_corpus_report.md "+
			"and docs/superpowers/plans/2026-10-03-b5-art-caldera-corpus-audit.md's Task 8 for the review methodology", report.ART.Unresolved)
	}
	if report.Caldera.Unresolved != 0 {
		t.Errorf("Caldera corpus has %d unresolved (technique_id, action_key) pairs -- see internal/scenario/testdata/execclass_corpus_report.md "+
			"and docs/superpowers/plans/2026-10-03-b5-art-caldera-corpus-audit.md's Task 8 for the review methodology", report.Caldera.Unresolved)
	}
}

// TestARTCalderaStores_RealStepsResolveSpecificClassNotEnumerate is the
// end-to-end proof the final review of the B5 ART/Caldera audit asked
// for: unlike the gate test above (which re-derives action_key from raw
// data independently of the real stores, a closed loop that never
// touches ScenarioStep.ActionKey as the real dispatch path builds it),
// this test uses the real *ARTStore/*CalderaStore's own steps -- exactly
// what AttachExecutionClassifications consumes in builder.go -- and
// confirms a meaningful fraction resolve to something other than the
// technique's "enumerate" fallback. Before the ActionKey-wiring fix, 100%
// of real ART/Caldera steps resolved via ActionKey == "" -> "enumerate",
// regardless of what the step actually does; this pins that regression.
func TestARTCalderaStores_RealStepsResolveSpecificClassNotEnumerate(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	calderaURL := os.Getenv("CALDERA_URL")
	if dbURL == "" || calderaURL == "" {
		t.Skip("DATABASE_URL/CALDERA_URL not set -- skipping the live-stack ActionKey-wiring end-to-end check")
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
	var artSteps []scenario.ScenarioStep
	for _, tech := range artStore.ListTechniques() {
		artSteps = append(artSteps, artStore.GetStepsByPlatform(tech, "windows")...)
	}
	if len(artSteps) == 0 {
		t.Fatal("loaded zero ART atomics -- environment problem, not an ActionKey-wiring question")
	}

	calderaStore := scenario.NewCalderaStore(calderaURL, calderaKey)
	var calderaSteps []scenario.ScenarioStep
	for _, tech := range calderaStore.ListTechniqueIDs() {
		calderaSteps = append(calderaSteps, calderaStore.GetAbilities(tech)...)
	}
	if len(calderaSteps) == 0 {
		t.Fatal("loaded zero Caldera abilities -- environment problem, not an ActionKey-wiring question")
	}

	for _, tc := range []struct {
		label string
		steps []scenario.ScenarioStep
	}{{"ART", artSteps}, {"Caldera", calderaSteps}} {
		label, steps := tc.label, tc.steps
		var withKey, resolvedSpecific int
		for _, s := range steps {
			if s.ActionKey != "" {
				withKey++
				if got := scenario.ResolveExecutionClass(s.TechniqueID, s.ActionKey); got.DestructiveAction != "enumerate" {
					resolvedSpecific++
				}
			}
		}
		if withKey == 0 {
			t.Errorf("%s: zero real steps got a non-empty ActionKey -- the wiring fix did not take effect for this source", label)
		}
		if resolvedSpecific == 0 {
			t.Errorf("%s: %d steps had an ActionKey, but zero resolved to anything other than the bare \"enumerate\" fallback", label, withKey)
		}
		t.Logf("%s: %d/%d steps got a real ActionKey, %d of those resolved to a specific (non-enumerate) classification",
			label, withKey, len(steps), resolvedSpecific)
	}
}
