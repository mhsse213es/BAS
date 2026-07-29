package search

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

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

func TestReindex_RebuildsOneTypeWithoutTouchingOthers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := reindexOneType(ctx, pool, "scenario", []Document{
			{DocType: "scenario", SourceID: "s1", Title: "Scenario One"},
		}); err != nil {
			t.Fatalf("seed scenario type: %v", err)
		}
		if err := reindexOneType(ctx, pool, "actor", []Document{
			{DocType: "actor", SourceID: "a1", Title: "Actor One"},
		}); err != nil {
			t.Fatalf("seed actor type: %v", err)
		}

		// Rebuild only "scenario" with a different document set.
		if err := reindexOneType(ctx, pool, "scenario", []Document{
			{DocType: "scenario", SourceID: "s2", Title: "Scenario Two"},
		}); err != nil {
			t.Fatalf("rebuild scenario type: %v", err)
		}

		var scenarioCount, actorCount int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM search_documents WHERE doc_type = 'scenario'`).Scan(&scenarioCount); err != nil {
			t.Fatalf("count scenario docs: %v", err)
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM search_documents WHERE doc_type = 'actor'`).Scan(&actorCount); err != nil {
			t.Fatalf("count actor docs: %v", err)
		}
		if scenarioCount != 1 {
			t.Errorf("scenario doc count = %d, want 1 (old s1 replaced by new s2, not accumulated)", scenarioCount)
		}
		if actorCount != 1 {
			t.Errorf("actor doc count = %d, want 1 (untouched by the scenario rebuild)", actorCount)
		}
	})
}

func TestReindexAll_PopulatesScenarioRunFindingDocuments(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id) VALUES ('agent-search-1')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status) VALUES ('run-search-1', 'scn-1', 'agent-search-1', 'Search Test Run', 'completed')`); err != nil {
			t.Fatalf("seed scenario_runs: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO findings (agent_id, technique_id, control_class, technique_name, severity) VALUES ('agent-search-1', 'T1059', 'prevention', 'Command and Scripting Interpreter', 'High')`); err != nil {
			t.Fatalf("seed findings: %v", err)
		}

		tmpDir := t.TempDir()
		engine := scenario.NewEngine(tmpDir)

		if err := ReindexAll(ctx, pool, engine); err != nil {
			t.Fatalf("ReindexAll: %v", err)
		}

		var runTitle, findingTitle string
		if err := pool.QueryRow(ctx, `SELECT title FROM search_documents WHERE doc_type = 'run' AND source_id = 'run-search-1'`).Scan(&runTitle); err != nil {
			t.Fatalf("query run document: %v", err)
		}
		if runTitle != "Search Test Run" {
			t.Errorf("run title = %q, want %q", runTitle, "Search Test Run")
		}
		if err := pool.QueryRow(ctx, `SELECT title FROM search_documents WHERE doc_type = 'finding' AND source_id != ''`).Scan(&findingTitle); err != nil {
			t.Fatalf("query finding document: %v", err)
		}
		if findingTitle != "Command and Scripting Interpreter" {
			t.Errorf("finding title = %q, want %q", findingTitle, "Command and Scripting Interpreter")
		}
	})
}

func TestReindexAll_PopulatesActorCampaignMalwareToolTechniqueDocuments(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx,
			`INSERT INTO threat_actor_profiles (name, aliases, sectors, regions, source) VALUES ('SearchTestActor', '{}', '{}', '{}', 'test')`); err != nil {
			t.Fatalf("seed threat_actor_profiles: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO intelligence_campaigns (id, name, description, actor_ids, technique_ids, source_provider) VALUES ('search-campaign-1', 'Search Test Campaign', '', '{}', '{}', 'test')`); err != nil {
			t.Fatalf("seed intelligence_campaigns: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO intelligence_malware (id, name, aliases, technique_ids, actor_ids, campaign_ids, source_provider) VALUES ('search-malware-1', 'Search Test Malware', '{}', '{}', '{}', '{}', 'test')`); err != nil {
			t.Fatalf("seed intelligence_malware: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO intelligence_tools (id, name, aliases, technique_ids, actor_ids, campaign_ids, source_provider) VALUES ('search-tool-1', 'Search Test Tool', '{}', '{}', '{}', '{}', 'test')`); err != nil {
			t.Fatalf("seed intelligence_tools: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO techniques (technique_id, name, tactic, description) VALUES ('T1059.001', 'PowerShell', 'execution', 'Adversaries may abuse PowerShell')`); err != nil {
			t.Fatalf("seed techniques: %v", err)
		}

		engine := scenario.NewEngine(t.TempDir())
		if err := ReindexAll(ctx, pool, engine); err != nil {
			t.Fatalf("ReindexAll: %v", err)
		}

		for _, tc := range []struct {
			docType, sourceID, wantTitle string
		}{
			{"actor", "SearchTestActor", "SearchTestActor"},
			{"campaign", "search-campaign-1", "Search Test Campaign"},
			{"malware", "search-malware-1", "Search Test Malware"},
			{"tool", "search-tool-1", "Search Test Tool"},
			{"technique", "T1059.001", "T1059.001 PowerShell"},
		} {
			var title string
			err := pool.QueryRow(ctx,
				`SELECT title FROM search_documents WHERE doc_type = $1 AND source_id = $2`,
				tc.docType, tc.sourceID).Scan(&title)
			if err != nil {
				t.Errorf("query %s document: %v", tc.docType, err)
				continue
			}
			if title != tc.wantTitle {
				t.Errorf("%s title = %q, want %q", tc.docType, title, tc.wantTitle)
			}
		}
	})
}

func TestQuery_RanksTitleMatchAboveDescriptionMatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := reindexOneType(ctx, pool, "scenario", []Document{
			{DocType: "scenario", SourceID: "title-match", Title: "Ransomware Simulation", Description: "generic description"},
			{DocType: "scenario", SourceID: "desc-match", Title: "Unrelated Name", Description: "involves ransomware behavior"},
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}

		results, err := Query(ctx, pool, "ransomware", 10)
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(results) != 2 {
			t.Fatalf("Query() = %+v, want 2 results", results)
		}
		if results[0].SourceID != "title-match" {
			t.Errorf("results[0].SourceID = %q, want %q (title match must rank above description-only match)", results[0].SourceID, "title-match")
		}
	})
}

func TestQuery_EmptyQueryReturnsEmptyNotFullTable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := reindexOneType(ctx, pool, "scenario", []Document{
			{DocType: "scenario", SourceID: "s1", Title: "Anything"},
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}

		results, err := Query(ctx, pool, "   ", 10)
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(results) != 0 {
			t.Fatalf("Query(\"   \") = %+v, want empty (guard against an accidental full-table dump)", results)
		}
	})
}

func TestQuery_TypeFilterOnlyReturnsMatchingType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := reindexOneType(ctx, pool, "scenario", []Document{
			{DocType: "scenario", SourceID: "s1", Title: "Ransomware Simulation"},
		}); err != nil {
			t.Fatalf("seed scenario: %v", err)
		}
		if err := reindexOneType(ctx, pool, "finding", []Document{
			{DocType: "finding", SourceID: "f1", Title: "Ransomware Finding"},
		}); err != nil {
			t.Fatalf("seed finding: %v", err)
		}

		results, err := Query(ctx, pool, "type:scenario ransomware", 10)
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(results) != 1 || results[0].DocType != "scenario" {
			t.Fatalf("Query(\"type:scenario ransomware\") = %+v, want only the scenario doc", results)
		}
	})
}

func TestQuery_TypeOnlyBrowsesAllOfThatTypeOrderedByTitle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := reindexOneType(ctx, pool, "scenario", []Document{
			{DocType: "scenario", SourceID: "s1", Title: "Zebra Scenario"},
			{DocType: "scenario", SourceID: "s2", Title: "Apple Scenario"},
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}

		results, err := Query(ctx, pool, "type:scenario", 10)
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(results) != 2 {
			t.Fatalf("Query(\"type:scenario\") = %+v, want both scenarios (browse mode, no keyword needed)", results)
		}
		if results[0].Title != "Apple Scenario" || results[1].Title != "Zebra Scenario" {
			t.Errorf("order = [%s, %s], want alphabetical by title", results[0].Title, results[1].Title)
		}
	})
}

func TestQuery_InvalidTypeFilterIgnoredFallsBackToPlainSearch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := reindexOneType(ctx, pool, "scenario", []Document{
			{DocType: "scenario", SourceID: "s1", Title: "Ransomware Simulation"},
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}

		plain, err := Query(ctx, pool, "ransomware", 10)
		if err != nil {
			t.Fatalf("Query(plain): %v", err)
		}
		withBadFilter, err := Query(ctx, pool, "type:bogus ransomware", 10)
		if err != nil {
			t.Fatalf("Query(bad filter): %v", err)
		}
		if len(withBadFilter) != len(plain) || withBadFilter[0].SourceID != plain[0].SourceID {
			t.Fatalf("Query(\"type:bogus ransomware\") = %+v, want identical to plain %+v (bad filter ignored)", withBadFilter, plain)
		}
	})
}

func TestQuery_DuplicateTypeFilterRejectedFallsBackToPlainSearch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := reindexOneType(ctx, pool, "scenario", []Document{
			{DocType: "scenario", SourceID: "s1", Title: "Ransomware Simulation"},
		}); err != nil {
			t.Fatalf("seed scenario: %v", err)
		}
		if err := reindexOneType(ctx, pool, "actor", []Document{
			{DocType: "actor", SourceID: "a1", Title: "Ransomware Actor"},
		}); err != nil {
			t.Fatalf("seed actor: %v", err)
		}

		results, err := Query(ctx, pool, "type:scenario type:actor ransomware", 10)
		if err != nil {
			t.Fatalf("Query: %v", err)
		}
		if len(results) != 2 {
			t.Fatalf("Query() = %+v, want both scenario and actor docs (duplicate type: filters rejected, not applied)", results)
		}
	})
}
