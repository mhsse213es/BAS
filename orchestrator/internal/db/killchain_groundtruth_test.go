package db_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/killchain"
)

func TestGroundTruth_PutAndGetRoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedIdentityRun(t, pool)
		ctx := context.Background()
		s := db.KillChainStore{Pool: pool}
		rec := db.GroundTruthRecord{RunID: "id-run", Source: "dc-01 security log", SourceClass: killchain.SourceEventLog,
			Executed: killchain.TriYes, Reference: "host-1:evt-123", RecordedBy: "user-1"}
		if err := s.PutGroundTruth(ctx, rec); err != nil {
			t.Fatal(err)
		}
		got, ok, err := s.GroundTruthForRun(ctx, "id-run")
		if err != nil || !ok {
			t.Fatalf("ok=%v err=%v", ok, err)
		}
		if got.Source != "dc-01 security log" || got.Executed != killchain.TriYes || got.Reference != "host-1:evt-123" {
			t.Fatalf("round trip lost fields: %+v", got)
		}
	})
}

func TestGroundTruth_RefusalsAreEnforcedByTheStore(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedIdentityRun(t, pool)
		ctx := context.Background()
		s := db.KillChainStore{Pool: pool}
		base := db.GroundTruthRecord{RunID: "id-run", Source: "dc-01 security log", SourceClass: killchain.SourceEventLog, Executed: killchain.TriYes, Reference: "ref"}
		cases := map[string]struct {
			mut  func(r *db.GroundTruthRecord)
			want string
		}{
			"run-record source is not independent": {func(r *db.GroundTruthRecord) { r.Source = db.RunRecordSource }, "not independent"},
			"empty source":                         {func(r *db.GroundTruthRecord) { r.Source = "" }, "source is required"},
			"no reference to the evidence":         {func(r *db.GroundTruthRecord) { r.Reference = "" }, "reference is required"},
			"executed must be yes or no":           {func(r *db.GroundTruthRecord) { r.Executed = killchain.TriUnknown }, "yes or no"},
			"unknown run":                          {func(r *db.GroundTruthRecord) { r.RunID = "nope" }, "does not exist"},
			"failed run cannot carry ground truth": {func(r *db.GroundTruthRecord) { r.RunID = "id-fail" }, "only a completed run"},
		}
		for name, c := range cases {
			r := base
			c.mut(&r)
			err := s.PutGroundTruth(ctx, r)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("%s: err = %v, want it to contain %q", name, err, c.want)
			}
		}
	})
}

func TestGroundTruth_MissingRunReturnsNotFound(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := db.KillChainStore{Pool: pool}
		_, ok, err := s.GroundTruthForRun(context.Background(), "never-recorded")
		if err != nil || ok {
			t.Fatalf("ok=%v err=%v; no record must be reported as not found", ok, err)
		}
	})
}

func seedIdentityRun(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	stmts := []string{
		`INSERT INTO agents (agent_id, hostname) VALUES ('ia1', 'ID-1') ON CONFLICT DO NOTHING`,
		`INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at, mode)
		 VALUES ('id-run', 'credential-access', 'id', 'ia1', 'completed', '[]', NOW(), 'posture')`,
		`INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at, mode)
		 VALUES ('id-fail', 'credential-access', 'id fail', 'ia1', 'failed', '[]', NOW(), 'posture')`,
	}
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
}

// The source class must be one the run's scenario accepts. An operator's
// observation cannot close an identity run, even with a reference attached.
func TestGroundTruth_SourceClassIsEnforcedPerScenario(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedIdentityRun(t, pool)
		ctx := context.Background()
		s := db.KillChainStore{Pool: pool}
		base := db.GroundTruthRecord{RunID: "id-run", Source: "dc-01 security log", Executed: killchain.TriYes,
			Reference: "dc-01:4624@2026-10-20T09:00Z"}

		refused := base
		refused.SourceClass = killchain.SourceOperatorObservation
		if err := s.PutGroundTruth(ctx, refused); err == nil || !strings.Contains(err.Error(), "not accepted") {
			t.Fatalf("operator observation on an identity run: err = %v", err)
		}

		ok := base
		ok.SourceClass = killchain.SourceEventLog
		if err := s.PutGroundTruth(ctx, ok); err != nil {
			t.Fatalf("host event log on an identity run must be accepted: %v", err)
		}
		got, found, err := s.GroundTruthForRun(ctx, "id-run")
		if err != nil || !found || got.SourceClass != killchain.SourceEventLog {
			t.Fatalf("class not round-tripped: found=%v err=%v rec=%+v", found, err, got)
		}
	})
}
