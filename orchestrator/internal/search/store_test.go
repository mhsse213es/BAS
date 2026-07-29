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
