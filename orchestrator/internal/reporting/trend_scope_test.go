package reporting

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/audspect/bas/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"
)

// seedTrendRun inserts one scored run.
func seedTrendRun(t *testing.T, pool *pgxpool.Pool, id, scenarioID, name, agent string, prevention float64, minutesAgo int) {
	t.Helper()
	ctx := context.Background()
	results := []models.SimulationResult{{
		ID: id + "-r1", Technique: models.AttackTechnique{ID: "T1059.004", Name: "Unix Shell", Tactic: "execution"},
		Result: models.ResultFail, Severity: "High",
	}}
	rj, _ := json.Marshal(results)
	sj, _ := json.Marshal(models.Score{PreventionScore: prevention, RiskScore: 50})
	if _, err := pool.Exec(ctx,
		`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, results, score, started_at)
		 VALUES ($1,$2,$3,$4,'completed',$5,$6, NOW() - make_interval(mins => $7))`,
		id, scenarioID, agent, name, rj, sj, minutesAgo); err != nil {
		t.Fatalf("seed run %s: %v", id, err)
	}
}

// A first run of a scenario must report Baseline, even when the endpoint has
// earlier runs of DIFFERENT scenarios.
//
// The trend query filtered only on agent_id, so "previous" was the endpoint's
// last run of ANY scenario. A Full Linux Sweep scoring 2% over 53 techniques
// was compared against an unrelated earlier scenario scoring 10% over a
// completely different technique set, and the report showed a -8.0 point
// "regression" that measured nothing. Prevention percentages are only
// comparable within the same technique set.
func TestBuildFromRun_TrendIgnoresOtherScenarios(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		e := NewEngine(pool)
		const agent = "agent-trend-scope"
		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id) VALUES ($1)`, agent); err != nil {
			t.Fatalf("seed agent: %v", err)
		}

		// An earlier, UNRELATED scenario on the same endpoint.
		seedTrendRun(t, pool, "tr-other", "scen-other", "Some Other Scenario", agent, 10.0, 60)
		// The run under report: first ever run of ITS scenario.
		seedTrendRun(t, pool, "tr-first", "scen-sweep", "Full Linux Sweep", agent, 2.0, 5)

		rep, err := e.BuildFromRun(ctx, "tr-first", "all")
		if err != nil {
			t.Fatalf("BuildFromRun: %v", err)
		}
		if rep.TrendAnalysis.HasPrevious {
			t.Errorf("first run of a scenario must be Baseline, but a trend was reported: %.1f%% -> %.1f%% (delta %.1f)",
				rep.TrendAnalysis.PreviousPrevention, rep.TrendAnalysis.CurrentPrevention, rep.TrendAnalysis.DeltaPrevention)
		}
	})
}

// A genuine prior run of the SAME scenario must still produce a trend, and the
// reported run must be the CURRENT point.
func TestBuildFromRun_TrendUsesSameScenarioAndAnchorsCurrent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		e := NewEngine(pool)
		const agent = "agent-trend-same"
		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id) VALUES ($1)`, agent); err != nil {
			t.Fatalf("seed agent: %v", err)
		}

		seedTrendRun(t, pool, "ts-old", "scen-sweep", "Full Linux Sweep", agent, 40.0, 120)
		seedTrendRun(t, pool, "ts-new", "scen-sweep", "Full Linux Sweep", agent, 55.0, 10)
		// A newer run of a DIFFERENT scenario must not become "current".
		seedTrendRun(t, pool, "ts-noise", "scen-other", "Other", agent, 99.0, 1)

		rep, err := e.BuildFromRun(ctx, "ts-new", "all")
		if err != nil {
			t.Fatalf("BuildFromRun: %v", err)
		}
		tr := rep.TrendAnalysis
		if !tr.HasPrevious {
			t.Fatal("a prior run of the same scenario exists; expected a trend")
		}
		if tr.CurrentPrevention != 55.0 {
			t.Errorf("CurrentPrevention = %.1f, want 55.0 — the trend must anchor on the run being reported, not the endpoint's newest run", tr.CurrentPrevention)
		}
		if tr.PreviousPrevention != 40.0 {
			t.Errorf("PreviousPrevention = %.1f, want 40.0 (the prior run of the SAME scenario)", tr.PreviousPrevention)
		}
		if tr.DeltaPrevention != 15.0 {
			t.Errorf("DeltaPrevention = %.1f, want +15.0", tr.DeltaPrevention)
		}
	})
}

// Re-rendering an OLDER run's report must not borrow a newer run's score as
// "current". buildTrendSummary treats the first element as current, and the
// query ordered by started_at DESC, so the endpoint's newest run won.
func TestBuildFromRun_TrendOnOlderRunDoesNotBorrowNewerScore(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		e := NewEngine(pool)
		const agent = "agent-trend-older"
		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id) VALUES ($1)`, agent); err != nil {
			t.Fatalf("seed agent: %v", err)
		}

		seedTrendRun(t, pool, "to-1", "scen-sweep", "Full Linux Sweep", agent, 30.0, 180)
		seedTrendRun(t, pool, "to-2", "scen-sweep", "Full Linux Sweep", agent, 60.0, 60) // reported
		seedTrendRun(t, pool, "to-3", "scen-sweep", "Full Linux Sweep", agent, 90.0, 5)  // newer

		rep, err := e.BuildFromRun(ctx, "to-2", "all")
		if err != nil {
			t.Fatalf("BuildFromRun: %v", err)
		}
		if got := rep.TrendAnalysis.CurrentPrevention; got != 60.0 {
			t.Errorf("CurrentPrevention = %.1f, want 60.0 — the report is about to-2, not the endpoint's newest run", got)
		}
		if got := rep.TrendAnalysis.PreviousPrevention; got != 30.0 {
			t.Errorf("PreviousPrevention = %.1f, want 30.0 — the run BEFORE the one being reported", got)
		}
	})
}

// The per-agent posture report has the same hazard: its run list is the
// endpoint's last 20 runs of ANY scenario, so the trend compared the top two
// regardless of whether they tested the same techniques.
//
// The rest of that report (heatmap, top findings, objective risks) is built
// from the LATEST run, so the trend must be scoped to that run's scenario for
// the page to be internally consistent.
func TestBuild_TrendIgnoresOtherScenarios(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		e := NewEngine(pool)
		const agent = "agent-trend-posture"
		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id) VALUES ($1)`, agent); err != nil {
			t.Fatalf("seed agent: %v", err)
		}

		seedTrendRun(t, pool, "tp-other", "scen-other", "Some Other Scenario", agent, 10.0, 60)
		seedTrendRun(t, pool, "tp-first", "scen-sweep", "Full Linux Sweep", agent, 2.0, 5)

		rep, err := e.Build(ctx, agent, "all")
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if rep.TrendAnalysis.HasPrevious {
			t.Errorf("latest run is the first of its scenario; expected Baseline, got %.1f%% -> %.1f%% (delta %.1f)",
				rep.TrendAnalysis.PreviousPrevention, rep.TrendAnalysis.CurrentPrevention, rep.TrendAnalysis.DeltaPrevention)
		}
	})
}
