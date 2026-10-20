package db_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/killchain"
)

func seedProofRuns(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	stmts := []string{
		`INSERT INTO agents (agent_id, hostname) VALUES ('pa1', 'PROOF-1') ON CONFLICT DO NOTHING`,
		`INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at, mode)
		 VALUES ('pr-lab', 'scn-proof', 'lab', 'pa1', 'completed', '[]', NOW(), 'lab')`,
		`INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at, mode)
		 VALUES ('pr-post', 'scn-proof', 'posture', 'pa1', 'completed', '[]', NOW(), 'posture')`,
		`INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at, mode)
		 VALUES ('pr-fail', 'scn-proof', 'lab failed', 'pa1', 'failed', '[]', NOW(), 'lab')`,
	}
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
}

func TestCheckRunRef_AcceptsOnlyCompletedRunOfRightScenarioAndMode(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedProofRuns(t, pool)
		s := db.KillChainStore{Pool: pool}
		ctx := context.Background()
		if err := s.CheckRunRef(ctx, "pr-lab", "scn-proof", "lab"); err != nil {
			t.Fatalf("a completed lab run must be accepted: %v", err)
		}
		cases := map[string]struct {
			run, scenario, mode, want string
		}{
			"wrong mode":     {"pr-post", "scn-proof", "lab", "needs a \"lab\" run"},
			"failed run":     {"pr-fail", "scn-proof", "lab", "only a completed run"},
			"wrong scenario": {"pr-lab", "scn-other", "lab", "not \"scn-other\""},
			"unknown run":    {"nope", "scn-proof", "lab", "does not exist"},
		}
		for name, c := range cases {
			err := s.CheckRunRef(ctx, c.run, c.scenario, c.mode)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("%s: err = %v, want it to contain %q", name, err, c.want)
			}
		}
	})
}

func TestCoverageProof_UpsertAndListRoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedProofRuns(t, pool)
		ctx := context.Background()
		s := db.KillChainStore{Pool: pool}
		p := db.CoverageProof{
			ScenarioID: "scn-proof", Domain: "endpoint", Platform: "windows", Control: "edr", Campaign: "identity-endpoint-lateral",
			Proof:      killchain.Proof{CatalogEntry: true, FixtureTestID: "fx-1", AdapterTestID: "ad-1", LabRunID: "pr-lab"},
			RecordedBy: "user-1",
		}
		if err := s.UpsertCoverageProof(ctx, p); err != nil {
			t.Fatal(err)
		}
		// A second write replaces the first, so the record is idempotent.
		if err := s.UpsertCoverageProof(ctx, p); err != nil {
			t.Fatal(err)
		}
		rows, err := s.ListCoverageProofs(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var got *db.CoverageProof
		for i := range rows {
			if rows[i].ScenarioID == "scn-proof" {
				got = &rows[i]
			}
		}
		if got == nil {
			t.Fatalf("proof not listed")
		}
		if got.Domain != "endpoint" || got.Proof.LabRunID != "pr-lab" {
			t.Fatalf("round trip lost fields: %+v", got)
		}
		if lvl := got.Proof.Level(); lvl != killchain.MaturityLabValidated {
			t.Fatalf("level = %s, want lab-validated", lvl)
		}
	})
}
