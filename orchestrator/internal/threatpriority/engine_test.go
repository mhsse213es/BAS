package threatpriority

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
)

func mustExec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

func TestNewEngine_UsesDefaultFactors(t *testing.T) {
	e := NewEngine(nil, scenario.NewEngine(t.TempDir()), nil, nil)
	if len(e.factors) != 9 {
		t.Fatalf("got %d factors, want 9", len(e.factors))
	}
}

func TestScoreActor_ComputesCompositeFromRealFactors(t *testing.T) {
	// Exercises scoreActor directly with a hand-built sharedIndexes, bypassing
	// the DB (e.pool is nil, and previousScore is nil-pool-safe -- see
	// engine.go). Full ScoreAll/Score DB-backed behavior is covered by
	// history_test.go in Task 8, once threat_priority_history exists.
	e := &Engine{factors: DefaultFactors()}
	shared := &sharedIndexes{
		simulation: map[string]bool{"T1059": true},
		detection:  map[string]bool{"T1059": true},
		purple:     map[string]bool{},
		compliance: map[string]bool{},
	}
	profile := &ActorProfile{Name: "TEST-ACTOR-X", Confidence: "high"}

	// Name won't resolve against attackdata.GroupTechniqueIndex, so
	// scoreActor's own technique resolution yields nil TechniqueIDs --
	// exercise the "no known techniques" path deliberately here, and cover
	// the real-technique path via ScoreAll's DB-backed integration test in
	// Task 8/10 instead (technique resolution depends on real embedded
	// ATT&CK data, not something to fake in a unit test).
	ap, err := e.scoreActor(context.Background(), profile, shared)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ap.Tier == "" {
		t.Fatal("expected a non-empty tier")
	}
	if len(ap.Factors) != 9 {
		t.Fatalf("got %d factor results, want 9", len(ap.Factors))
	}
}

func TestLoadPreventionVerdicts_LatestWinsAndCarriesTimestamp(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		older := time.Now().UTC().Add(-48 * time.Hour)
		newer := time.Now().UTC().Add(-1 * time.Hour)
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('vt-a1', 'VT-HOST')`)
		mustExec(t, pool, `INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('vt-run-old', 'vt-scn', 'VT Old', 'vt-a1', 'completed', $1::jsonb, NOW())`,
			`[{"technique":{"id":"T1059"},"result":"fail","executedAt":"`+older.Format(time.RFC3339)+`"}]`)
		mustExec(t, pool, `INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('vt-run-new', 'vt-scn', 'VT New', 'vt-a1', 'completed', $1::jsonb, NOW())`,
			`[{"technique":{"id":"T1059"},"result":"pass","executedAt":"`+newer.Format(time.RFC3339)+`"}]`)

		verdicts, err := LoadPreventionVerdicts(ctx, pool)
		if err != nil {
			t.Fatalf("LoadPreventionVerdicts: %v", err)
		}
		v, ok := verdicts["T1059"]
		if !ok {
			t.Fatal("expected T1059 in the verdict map")
		}
		if v.Verdict != "pass" {
			t.Errorf("Verdict = %q, want %q (the later run)", v.Verdict, "pass")
		}
		if v.At.Sub(newer).Abs() > time.Second {
			t.Errorf("At = %v, want ~%v (the later run's executedAt)", v.At, newer)
		}
	})
}
