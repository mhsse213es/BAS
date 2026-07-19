package recommend

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/reporting/attackdata"
	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
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

// seedTechnique inserts a technique plus one ART atomic test for it, making it
// part of the executable universe Build() ranks over.
func seedTechnique(t *testing.T, pool *pgxpool.Pool, id, name, tactic string) {
	t.Helper()
	mustExec(t, pool, `INSERT INTO techniques (technique_id, name, tactic) VALUES ($1, $2, $3)`, id, name, tactic)
	mustExec(t, pool, `
		INSERT INTO art_atomic_tests (technique_id, test_index, name, executor, command)
		VALUES ($1, 1, 'atomic', 'powershell', 'whoami')`, id)
}

// seedKEV links a technique to a KEV-listed CVE through the Relationship Store,
// at the Active/High confidence the engine's queries require.
// relationship_type is NOT NULL with no default — 'Commonly Associated' is the
// value content_import.go's own migration uses.
func seedKEV(t *testing.T, pool *pgxpool.Pool, techID, cveID string) {
	t.Helper()
	mustExec(t, pool, `INSERT INTO cves (cve_id, cvss, source) VALUES ($1, 9.8, 'cisa-kev')`, cveID)
	mustExec(t, pool, `
		INSERT INTO technique_cve_relationships
			(technique_id, cve_id, relationship_type, status, effective_confidence)
		VALUES ($1, $2, 'Commonly Associated', 'Active', 'High')`, techID, cveID)
}

func findTech(recs Recommendations, id string) (RecommendedTechnique, bool) {
	for _, t := range recs.Techniques {
		if t.TechniqueID == id {
			return t, true
		}
	}
	return RecommendedTechnique{}, false
}

func rankOf(recs Recommendations, id string) int {
	for i, t := range recs.Techniques {
		if t.TechniqueID == id {
			return i
		}
	}
	return -1
}

func TestBuild_EmptyUniverse_ReturnsEmptyNotError(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		recs, err := Build(context.Background(), pool, nil, attackpath.Summary{}, 20, nil, nil)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if len(recs.Techniques) != 0 {
			t.Errorf("Techniques = %d, want 0 with no seeded content", len(recs.Techniques))
		}
		if recs.Techniques == nil {
			t.Error("Techniques must be an empty slice, not nil — the UI iterates it without a guard")
		}
		if recs.HasData {
			t.Error("HasData = true, want false with no seeded content")
		}
	})
}

// TestBuild_OnlyARTTestableTechniquesAreRanked pins the executable filter:
// recommending a technique with no atomic test to run is noise.
func TestBuild_OnlyARTTestableTechniquesAreRanked(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechnique(t, pool, "T1059.001", "PowerShell", "execution")
		// Seeded technique with NO art_atomic_tests row — must not be ranked.
		mustExec(t, pool, `INSERT INTO techniques (technique_id, name, tactic) VALUES ('T1136.001', 'Local Account', 'persistence')`)

		recs, err := Build(context.Background(), pool, nil, attackpath.Summary{}, 20, nil, nil)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if _, ok := findTech(recs, "T1059.001"); !ok {
			t.Error("expected the ART-testable technique to be ranked")
		}
		if _, ok := findTech(recs, "T1136.001"); ok {
			t.Error("technique with no ART atomic test must not be ranked")
		}
	})
}

// TestBuild_KEVOutranksNoSignal: two never-tested techniques, identical except
// one is KEV-listed. The KEV one must rank first.
func TestBuild_KEVOutranksNoSignal(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechnique(t, pool, "T1003.001", "LSASS Memory", "credential-access")
		seedTechnique(t, pool, "T1217", "Browser Bookmark Discovery", "discovery")
		seedKEV(t, pool, "T1003.001", "CVE-2024-0001")

		recs, err := Build(context.Background(), pool, nil, attackpath.Summary{}, 20, nil, nil)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		kevRank, plainRank := rankOf(recs, "T1003.001"), rankOf(recs, "T1217")
		if kevRank == -1 || plainRank == -1 {
			t.Fatalf("both techniques should be ranked; got kev=%d plain=%d", kevRank, plainRank)
		}
		if kevRank >= plainRank {
			t.Errorf("KEV-listed technique ranked %d, should outrank the no-signal one at %d", kevRank, plainRank)
		}
		kev, _ := findTech(recs, "T1003.001")
		if !kev.KEV {
			t.Error("KEV flag not surfaced on the recommendation")
		}
	})
}

func TestBuild_SectorRegionRelevantOutranksNonRelevant(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		groupIdx := attackdata.GroupTechniqueIndex()
		if len(groupIdx) == 0 {
			t.Skip("no embedded ATT&CK group data available")
		}
		var relevantGroup, relevantTech string
		for g, techs := range groupIdx {
			if len(techs) > 0 {
				relevantGroup, relevantTech = g, techs[0]
				break
			}
		}

		seedTechnique(t, pool, relevantTech, "Relevant Technique", "execution")
		seedTechnique(t, pool, "T9999", "Non-Relevant Technique", "execution")

		_, err := pool.Exec(context.Background(),
			`INSERT INTO threat_actor_profiles (name, aliases, sectors, regions, source)
			 VALUES ($1, '{}', $2, '{}', 'bundle')`,
			relevantGroup, []string{"government"})
		if err != nil {
			t.Fatalf("seed profile: %v", err)
		}

		recs, err := Build(context.Background(), pool, nil, attackpath.Summary{}, 20, []string{"government"}, nil)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}

		relevantRank, nonRelevantRank := rankOf(recs, relevantTech), rankOf(recs, "T9999")
		if relevantRank == -1 || nonRelevantRank == -1 {
			t.Fatalf("expected both techniques ranked, got %+v", recs.Techniques)
		}
		if relevantRank >= nonRelevantRank {
			t.Errorf("sector-relevant technique (rank %d) did not outrank non-relevant one (rank %d)", relevantRank, nonRelevantRank)
		}
	})
}

// TestBuild_NeverTestedOutranksRecentlyTested: identical threat signals, but one
// was tested today. The untested one must rank first.
func TestBuild_NeverTestedOutranksRecentlyTested(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechnique(t, pool, "T1003.001", "LSASS Memory", "credential-access")
		seedTechnique(t, pool, "T1055", "Process Injection", "defense-evasion")
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('a1', 'HOST-1')`)
		mustExec(t, pool, `
			INSERT INTO scenario_runs (scenario_id, agent_id, status, results, completed_at)
			VALUES ('s1', 'a1', 'completed', $1::jsonb, NOW())`,
			`[{"technique":{"id":"T1055","name":"Process Injection","tactic":"defense-evasion"},
			   "result":"pass","executedAt":"2026-07-17T10:00:00Z"}]`)

		recs, err := Build(context.Background(), pool, nil, attackpath.Summary{}, 20, nil, nil)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if rankOf(recs, "T1003.001") >= rankOf(recs, "T1055") {
			t.Errorf("never-tested T1003.001 (rank %d) should outrank recently-tested T1055 (rank %d)",
				rankOf(recs, "T1003.001"), rankOf(recs, "T1055"))
		}
		tested, _ := findTech(recs, "T1055")
		if tested.CoverageState != "recent" {
			t.Errorf("CoverageState = %q, want %q", tested.CoverageState, "recent")
		}
		if tested.LastTestedAt == nil {
			t.Error("LastTestedAt should be populated for a tested technique")
		}
		if tested.LastVerdict != "pass" {
			t.Errorf("LastVerdict = %q, want %q", tested.LastVerdict, "pass")
		}
	})
}

// TestBuild_ErroredRunsCountAsNeverTested pins the 4-verdict taxonomy: an
// ERROR means the BAS could not execute the technique, so it tells us nothing
// about coverage and must not suppress the recommendation.
func TestBuild_ErroredRunsCountAsNeverTested(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechnique(t, pool, "T1055", "Process Injection", "defense-evasion")
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('a1', 'HOST-1')`)
		mustExec(t, pool, `
			INSERT INTO scenario_runs (scenario_id, agent_id, status, results, completed_at)
			VALUES ('s1', 'a1', 'completed', $1::jsonb, NOW())`,
			`[{"technique":{"id":"T1055","name":"Process Injection","tactic":"defense-evasion"},
			   "result":"error","executedAt":"2026-07-17T10:00:00Z"}]`)

		recs, err := Build(context.Background(), pool, nil, attackpath.Summary{}, 20, nil, nil)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		got, ok := findTech(recs, "T1055")
		if !ok {
			t.Fatal("errored technique should still be ranked")
		}
		if got.CoverageState != "never-tested" {
			t.Errorf("CoverageState = %q, want never-tested (an ERROR is not a real test)", got.CoverageState)
		}
	})
}

// TestBuild_EnvironmentRelevanceRaisesRank: identical never-tested techniques
// with no threat signal, but T1021.002 (SMB) traverses a real edge in the
// collected graph. It must outrank the environment-irrelevant one.
func TestBuild_EnvironmentRelevanceRaisesRank(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechnique(t, pool, "T1021.002", "SMB/Windows Admin Shares", "lateral-movement")
		seedTechnique(t, pool, "T1217", "Browser Bookmark Discovery", "discovery")

		// A two-host graph with a real SMB edge. DefaultEdgeTechniqueMapper maps
		// EdgeSMB -> T1021.002, so only that technique gets environment signal.
		// AddEdge auto-creates both endpoints as bare host nodes.
		g := attackpath.New()
		g.AddEdge(attackpath.Edge{From: "HOST-A", To: "HOST-B", Kind: attackpath.EdgeSMB})

		recs, err := Build(context.Background(), pool, g, attackpath.Summary{}, 20, nil, nil)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if rankOf(recs, "T1021.002") >= rankOf(recs, "T1217") {
			t.Errorf("environment-relevant T1021.002 (rank %d) should outrank irrelevant T1217 (rank %d)",
				rankOf(recs, "T1021.002"), rankOf(recs, "T1217"))
		}
		smb, _ := findTech(recs, "T1021.002")
		if smb.EnvironmentRisk == 0 {
			t.Error("EnvironmentRisk should be non-zero for a technique traversing a real graph edge")
		}
		other, _ := findTech(recs, "T1217")
		if other.EnvironmentRisk != 0 {
			t.Errorf("EnvironmentRisk = %d for a technique with no graph edge, want 0 (never fabricate relevance)", other.EnvironmentRisk)
		}
	})
}

// TestBuild_SuggestedScenarioCarriesTopN pins the runnable-output contract.
func TestBuild_SuggestedScenarioCarriesTopN(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechnique(t, pool, "T1003.001", "LSASS Memory", "credential-access")
		seedTechnique(t, pool, "T1055", "Process Injection", "defense-evasion")
		seedTechnique(t, pool, "T1217", "Browser Bookmark Discovery", "discovery")
		seedKEV(t, pool, "T1003.001", "CVE-2024-0001")

		recs, err := Build(context.Background(), pool, nil, attackpath.Summary{}, 2, nil, nil)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if len(recs.Techniques) != 2 {
			t.Fatalf("limit=2 returned %d techniques, want 2", len(recs.Techniques))
		}
		if len(recs.SuggestedScenario.ARTTechniques) != 2 {
			t.Fatalf("SuggestedScenario has %d techniques, want 2", len(recs.SuggestedScenario.ARTTechniques))
		}
		for i, want := range []string{recs.Techniques[0].TechniqueID, recs.Techniques[1].TechniqueID} {
			if recs.SuggestedScenario.ARTTechniques[i] != want {
				t.Errorf("SuggestedScenario.ARTTechniques[%d] = %q, want %q (must mirror the ranked order)",
					i, recs.SuggestedScenario.ARTTechniques[i], want)
			}
		}
		if recs.SuggestedScenario.ID == "" || recs.SuggestedScenario.Name == "" {
			t.Error("SuggestedScenario needs an ID and Name for the scenario-creation flow")
		}
		if !recs.HasData {
			t.Error("HasData = false with seeded content, want true")
		}
	})
}
