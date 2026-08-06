package correlation

import (
	"context"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/reporting/attackdata"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

func mustExec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

// findTechniqueWithNoGroupAttribution returns a real bundled technique ID
// that has a Name but zero attackdata.GroupTechniqueIndex() attribution --
// dynamically discovered rather than hardcoded so this test doesn't silently
// break if a future MITRE bundle update adds group attribution for whatever
// ID today's snapshot happens to lack one for. Fatal if the bundle assumption
// (coverage is inherently partial -- some technique has none) ever breaks.
func findTechniqueWithNoGroupAttribution(t *testing.T) string {
	t.Helper()
	attributed := map[string]bool{}
	for _, ids := range attackdata.GroupTechniqueIndex() {
		for _, id := range ids {
			attributed[strings.ToUpper(id)] = true
		}
	}
	for _, ref := range attackdata.All() {
		if !attributed[strings.ToUpper(ref.ID)] {
			return ref.ID
		}
	}
	t.Fatal("test fixture assumption broken: every bundled technique has group attribution")
	return ""
}

func TestCorrelateTechnique_ZeroRelationships_StillPopulatesCanonicalTechnique(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	techID := findTechniqueWithNoGroupAttribution(t)
	want := attackdata.Lookup(techID)
	if want == nil || want.Name == "" {
		t.Fatalf("test fixture assumption broken: %s has no bundled Name", techID)
	}

	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		eng := NewEngine(pool, scenario.NewEngine(t.TempDir()))
		tc, err := eng.CorrelateTechnique(context.Background(), techID)
		if err != nil {
			t.Fatalf("CorrelateTechnique: %v", err)
		}
		// This is the regression test for self-review catch #1: with zero
		// actor/campaign/malware/tool relationships, TechniqueNeighborhood
		// returns a completely empty Neighborhood -- Technique.Name must
		// still be correct, proving it comes from resolveCanonicalTechnique,
		// never from Neighborhood.Nodes[0].Label.
		if tc.Technique.Name != want.Name {
			t.Errorf("Technique.Name = %q, want %q (must come from attackdata, not relationship data)", tc.Technique.Name, want.Name)
		}
		if len(tc.Actors) != 0 || len(tc.Campaigns) != 0 || len(tc.Malware) != 0 || len(tc.Tools) != 0 {
			t.Errorf("expected zero relationships for this fixture technique, got Actors=%v Campaigns=%v Malware=%v Tools=%v", tc.Actors, tc.Campaigns, tc.Malware, tc.Tools)
		}
	})
}

func TestCorrelateTechnique_KnownActor_PopulatesActors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	// "Wizard Spider" is a real bundled ATT&CK group -- same fixture
	// internal/threatgraph's own tests and internal/connector/otx_test.go rely on.
	wantTechs := attackdata.GroupTechniqueIndex()["Wizard Spider"]
	if len(wantTechs) == 0 {
		t.Fatal("test fixture assumption broken: \"Wizard Spider\" not found in GroupTechniqueIndex()")
	}
	techID := wantTechs[0]

	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		eng := NewEngine(pool, scenario.NewEngine(t.TempDir()))
		tc, err := eng.CorrelateTechnique(context.Background(), techID)
		if err != nil {
			t.Fatalf("CorrelateTechnique: %v", err)
		}
		found := false
		for _, a := range tc.Actors {
			if a.Label == "Wizard Spider" {
				found = true
			}
		}
		if !found {
			t.Errorf("Actors = %+v, want to include Wizard Spider", tc.Actors)
		}
	})
}

func TestCorrelateTechnique_WithScenario_PopulatesScenariosAndRunRecommendation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		dir := t.TempDir()
		customDir := dir + "/custom"
		if err := os.MkdirAll(customDir, 0o755); err != nil {
			t.Fatalf("mkdir custom dir: %v", err)
		}
		if err := os.WriteFile(customDir+"/sc.yaml", []byte(
			"id: corr-fixture-sc\nname: Correlation Fixture Scenario\nsteps:\n  - name: step one\n    technique_id: T1059.001\n"),
			0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		scEngine := scenario.NewEngine(dir)
		if err := scEngine.Load(); err != nil {
			t.Fatalf("scEngine.Load: %v", err)
		}

		eng := NewEngine(pool, scEngine)
		tc, err := eng.CorrelateTechnique(context.Background(), "T1059.001")
		if err != nil {
			t.Fatalf("CorrelateTechnique: %v", err)
		}
		if len(tc.Scenarios) != 1 || tc.Scenarios[0].ID != "corr-fixture-sc" {
			t.Fatalf("Scenarios = %+v, want [corr-fixture-sc]", tc.Scenarios)
		}
		if tc.Validation != nil {
			t.Fatalf("Validation = %+v, want nil (never run)", tc.Validation)
		}
		if tc.Recommendation.Action != "run" {
			t.Errorf("Recommendation.Action = %q, want run", tc.Recommendation.Action)
		}
	})
}

func TestCorrelateTechnique_NoScenario_RecommendationIsNoScenario(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		eng := NewEngine(pool, scenario.NewEngine(t.TempDir()))
		tc, err := eng.CorrelateTechnique(context.Background(), "T1546.008") // real ID, unlikely to be in any test's empty scenario dir
		if err != nil {
			t.Fatalf("CorrelateTechnique: %v", err)
		}
		if tc.Recommendation.Action != "no_scenario" {
			t.Errorf("Recommendation.Action = %q, want no_scenario", tc.Recommendation.Action)
		}
	})
}

func TestCorrelateTechnique_PreventionVerdict_SetsValidationAndRecommendation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('corr-a1', 'CORR-HOST')`)
		mustExec(t, pool, `INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('corr-run-1', 'corr-scn-1', 'Corr Test Run', 'corr-a1', 'completed', $1::jsonb, NOW())`,
			`[{"technique":{"id":"T1003"},"result":"fail","executedAt":"2026-01-01T00:00:00Z"}]`)

		dir := t.TempDir()
		customDir := dir + "/custom"
		if err := os.MkdirAll(customDir, 0o755); err != nil {
			t.Fatalf("mkdir custom dir: %v", err)
		}
		if err := os.WriteFile(customDir+"/sc.yaml", []byte(
			"id: corr-fixture-sc2\nname: Corr Fixture 2\nsteps:\n  - name: step one\n    technique_id: T1003\n"),
			0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		scEngine := scenario.NewEngine(dir)
		if err := scEngine.Load(); err != nil {
			t.Fatalf("scEngine.Load: %v", err)
		}

		eng := NewEngine(pool, scEngine)
		tc, err := eng.CorrelateTechnique(context.Background(), "T1003")
		if err != nil {
			t.Fatalf("CorrelateTechnique: %v", err)
		}
		if tc.Validation == nil || tc.Validation.Source != "prevention" || tc.Validation.Verdict != "fail" {
			t.Fatalf("Validation = %+v, want {fail, prevention, ...}", tc.Validation)
		}
		if tc.Recommendation.Action != "revalidate" {
			t.Errorf("Recommendation.Action = %q, want revalidate", tc.Recommendation.Action)
		}
	})
}

func TestCorrelateActor_TwoTechniques_EachIndependentlyCorrelated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	wantTechs := attackdata.GroupTechniqueIndex()["Wizard Spider"]
	if len(wantTechs) < 2 {
		t.Fatal("test fixture assumption broken: \"Wizard Spider\" needs at least 2 techniques")
	}

	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO threat_actor_profiles (name, aliases, sectors, regions, source)
			VALUES ('Wizard Spider', '{}', '{}', '{}', 'test')`)
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('corr-actor-a1', 'CORR-ACTOR-HOST')`)
		mustExec(t, pool, `INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('corr-actor-run', 'corr-actor-scn', 'Corr Actor Run', 'corr-actor-a1', 'completed', $1::jsonb, NOW())`,
			`[{"technique":{"id":"`+wantTechs[0]+`"},"result":"pass","executedAt":"2026-01-01T00:00:00Z"}]`)
		mustExec(t, pool, `INSERT INTO intelligence_campaigns (id, name, description, actor_ids, technique_ids, source_provider)
			VALUES ('corr-actor-campaign', 'Corr Actor Campaign', '', $1, '{}', 'test')`, []string{"Wizard Spider"})

		eng := NewEngine(pool, scenario.NewEngine(t.TempDir()))
		ac, err := eng.CorrelateActor(context.Background(), "Wizard Spider")
		if err != nil {
			t.Fatalf("CorrelateActor: %v", err)
		}
		if len(ac.Techniques) != len(wantTechs) {
			t.Fatalf("Techniques = %d, want %d (full ResolveActorTechniques roster)", len(ac.Techniques), len(wantTechs))
		}
		var sawValidated, sawUnvalidated bool
		for _, tc := range ac.Techniques {
			if tc.Technique.ID == strings.ToUpper(wantTechs[0]) {
				if tc.Validation == nil || tc.Validation.Verdict != "pass" {
					t.Errorf("technique %s: Validation = %+v, want {pass, prevention}", wantTechs[0], tc.Validation)
				}
				sawValidated = true
			} else if tc.Validation == nil {
				sawUnvalidated = true
			}
		}
		if !sawValidated || !sawUnvalidated {
			t.Errorf("expected a mix of validated/unvalidated techniques, got sawValidated=%v sawUnvalidated=%v", sawValidated, sawUnvalidated)
		}
		foundCampaign := false
		for _, c := range ac.Campaigns {
			if c.Label == "Corr Actor Campaign" {
				foundCampaign = true
			}
		}
		if !foundCampaign {
			t.Errorf("Campaigns = %+v, want to include Corr Actor Campaign", ac.Campaigns)
		}
	})
}

func TestCorrelateActor_DiscardsActorNeighborhoodTechniqueNodes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	// Disambiguation regression test: ActorNeighborhood internally resolves
	// its own (unaliased) technique nodes via GroupTechniqueIndex()[name] --
	// CorrelateActor's technique roster must come exclusively from
	// ResolveActorTechniques, so ac.Techniques' length must equal the
	// alias-aware roster length even though ActorNeighborhood also returns
	// technique-type nodes internally.
	wantTechs := attackdata.GroupTechniqueIndex()["Wizard Spider"]
	if len(wantTechs) == 0 {
		t.Fatal("test fixture assumption broken")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO threat_actor_profiles (name, aliases, sectors, regions, source)
			VALUES ('Wizard Spider', '{}', '{}', '{}', 'test')`)

		eng := NewEngine(pool, scenario.NewEngine(t.TempDir()))
		ac, err := eng.CorrelateActor(context.Background(), "Wizard Spider")
		if err != nil {
			t.Fatalf("CorrelateActor: %v", err)
		}
		if len(ac.Techniques) != len(wantTechs) {
			t.Fatalf("Techniques = %d, want exactly %d (ResolveActorTechniques' roster, not ActorNeighborhood's)", len(ac.Techniques), len(wantTechs))
		}
	})
}

func TestCorrelateActor_UnknownActor_ReturnsEmptyNotError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		eng := NewEngine(pool, scenario.NewEngine(t.TempDir()))
		ac, err := eng.CorrelateActor(context.Background(), "NoSuchActor")
		if err != nil {
			t.Fatalf("CorrelateActor: %v", err)
		}
		if len(ac.Techniques) != 0 || len(ac.Campaigns) != 0 {
			t.Errorf("got %+v, want empty (no profile row, no known aliases)", ac)
		}
	})
}
