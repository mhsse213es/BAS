package dashboard

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/exposure"
	"github.com/audspect/bas/internal/pathcorrelation"
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

// TestCompute_EmptyFleet_ReturnsZeroScores pins the empty-fleet shape.
// DetectionCoverage is 100, not 0 — pathcorrelation.Correlate treats "no
// edges to fail detection on" as a vacuous 100, the same established
// convention GetAttackPathCorrelation documents ("a zero-value 100-scored
// result rather than erroring when nothing is collected").
func TestCompute_EmptyFleet_ReturnsZeroScores(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		snap, err := Compute(context.Background(), pool)
		if err != nil {
			t.Fatalf("Compute: %v", err)
		}
		want := Snapshot{DetectionCoverage: 100}
		if snap != want {
			t.Errorf("Compute() = %+v, want %+v on an empty fleet", snap, want)
		}
	})
}

func TestCompute_AvgRiskScoreFromRecentRuns(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('a1', 'HOST-1')`)
		mustExec(t, pool, `
			INSERT INTO scenario_runs (scenario_id, agent_id, status, score, completed_at)
			VALUES ('scn-1', 'a1', 'completed', '{"riskScore": 42}'::jsonb, NOW())`)
		mustExec(t, pool, `
			INSERT INTO scenario_runs (scenario_id, agent_id, status, score, completed_at)
			VALUES ('scn-2', 'a1', 'completed', '{"riskScore": 58}'::jsonb, NOW())`)
		// Old run, outside the 30-day window — must not affect the average.
		mustExec(t, pool, `
			INSERT INTO scenario_runs (scenario_id, agent_id, status, score, completed_at)
			VALUES ('scn-3', 'a1', 'completed', '{"riskScore": 0}'::jsonb, NOW() - INTERVAL '90 days')`)

		snap, err := Compute(context.Background(), pool)
		if err != nil {
			t.Fatalf("Compute: %v", err)
		}
		if snap.AvgRiskScore != 50 {
			t.Errorf("AvgRiskScore = %d, want 50 (avg of 42 and 58, excluding the 90-day-old run)", snap.AvgRiskScore)
		}
	})
}

// TestCompute_ExposureAndDetectionMatchDirectCalls pins Compute's fleet
// aggregation against the same exposure.Build/pathcorrelation.Correlate
// calls made directly, on identical seeded data — proving Compute isn't
// silently diverging from the established SP3/SP4 computations it wraps.
func TestCompute_ExposureAndDetectionMatchDirectCalls(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('a1', 'HOST-1')`)

		ctx := context.Background()
		snap, err := Compute(ctx, pool)
		if err != nil {
			t.Fatalf("Compute: %v", err)
		}
		if snap.AssetCount != 1 {
			t.Fatalf("AssetCount = %d, want 1 (one enrolled agent, no attack-path collections)", snap.AssetCount)
		}

		// Independently reproduce the same pipeline Compute wraps.
		g, s := attackpath.BuildGraphAndAnalyze(nil, nil)
		paths := pathcorrelation.DefaultPaths(g, s)
		wantCorr, err := pathcorrelation.Correlate(ctx, g, s, paths,
			pathcorrelation.DefaultEdgeTechniqueMapper{}, pathcorrelation.NewSQLRunLookup(pool), nil)
		if err != nil {
			t.Fatalf("pathcorrelation.Correlate: %v", err)
		}
		if snap.DetectionCoverage != wantCorr.Score {
			t.Errorf("DetectionCoverage = %d, want %d (direct pathcorrelation.Correlate call)", snap.DetectionCoverage, wantCorr.Score)
		}

		wantGraph, err := exposure.Build(ctx, g, s, wantCorr, nil,
			exposure.NewSQLCVEEnricher(pool), exposure.NewSQLFindingsLookup(pool),
			[]exposure.AgentRow{{AgentID: "a1", Hostname: "HOST-1"}})
		if err != nil {
			t.Fatalf("exposure.Build: %v", err)
		}
		wantSummaries := wantGraph.Summaries()
		if len(wantSummaries) != 1 {
			t.Fatalf("direct exposure.Build gave %d summaries, want 1", len(wantSummaries))
		}
		if snap.ExposureScore != wantSummaries[0].ExposureScore {
			t.Errorf("ExposureScore = %d, want %d (direct exposure.Build call)", snap.ExposureScore, wantSummaries[0].ExposureScore)
		}
	})
}
