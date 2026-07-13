package api

import (
	"context"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"
)

// findingRow is the subset of the findings table these tests assert on.
type findingRow struct {
	Status          string
	ExposureState   string
	OccurrenceCount int
	ReopenedCount   int
	ResolvedAt      *time.Time
}

// queryFinding fetches the finding for (agentID, techID), regardless of
// control_class — every lifecycle test here seeds one technique per agent, so
// this stays decoupled from findings.ControlClass's own classification rules
// (separately unit-tested in internal/findings).
func queryFinding(t *testing.T, pool *pgxpool.Pool, agentID, techID string) (findingRow, bool) {
	t.Helper()
	var f findingRow
	err := pool.QueryRow(context.Background(),
		`SELECT status, exposure_state, occurrence_count, reopened_count, resolved_at
		   FROM findings WHERE agent_id=$1 AND technique_id=$2`,
		agentID, techID,
	).Scan(&f.Status, &f.ExposureState, &f.OccurrenceCount, &f.ReopenedCount, &f.ResolvedAt)
	if err != nil {
		return findingRow{}, false
	}
	return f, true
}

func countFindings(t *testing.T, pool *pgxpool.Pool, agentID string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM findings WHERE agent_id=$1`, agentID,
	).Scan(&n); err != nil {
		t.Fatalf("count findings: %v", err)
	}
	return n
}

// oneResult builds a single-result payload for seedReportableRun, keeping
// each lifecycle test's fixture obvious at the call site.
func oneResult(id, techID, result string, severity string, at time.Time) []models.SimulationResult {
	return []models.SimulationResult{{
		ID:         id,
		Technique:  models.AttackTechnique{ID: techID, Name: "Test Technique", Tactic: "execution"},
		Result:     models.CheckResult(result),
		Severity:   severity,
		ExecutedAt: at,
		StartedAt:  at,
	}}
}

// TestUpsertFindingsForRun_MissedCreatesFinding pins the base case: a FAIL
// result with no correlated detection creates an open finding with
// exposure_state=missed (T1059's data sources classify to "Endpoint" via
// findings.ControlClass — no identity/network/dns/cloud keywords).
func TestUpsertFindingsForRun_MissedCreatesFinding(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		at := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		seedReportableRun(t, pool, "uf-missed-run", "agent-uf-missed", reportRunOpts{
			Results: oneResult("r1", "T1059.001", "fail", "Critical", at),
		})
		h := newReportingHandler(t, pool, nil)
		h.upsertFindingsForRun(context.Background(), "uf-missed-run")

		f, ok := queryFinding(t, pool, "agent-uf-missed", "T1059.001")
		if !ok {
			t.Fatal("expected a finding to be created")
		}
		if f.Status != "open" || f.ExposureState != "missed" || f.OccurrenceCount != 1 {
			t.Fatalf("finding = %+v, want status=open exposure=missed occurrence=1", f)
		}
	})
}

// TestUpsertFindingsForRun_PreventedDoesNotCreateFinding pins Apply's Noop
// rule: a PASS observation against a non-existent finding creates nothing.
func TestUpsertFindingsForRun_PreventedDoesNotCreateFinding(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		at := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		seedReportableRun(t, pool, "uf-pass-run", "agent-uf-pass", reportRunOpts{
			Results: oneResult("r1", "T1547.001", "pass", "Medium", at),
		})
		h := newReportingHandler(t, pool, nil)
		h.upsertFindingsForRun(context.Background(), "uf-pass-run")

		if n := countFindings(t, pool, "agent-uf-pass"); n != 0 {
			t.Fatalf("expected 0 findings for an all-PASS run, got %d", n)
		}
	})
}

// TestUpsertFindingsForRun_NoResults_NoOp pins the len(results)==0 early
// return: a run with an empty results array must not error or create rows.
func TestUpsertFindingsForRun_NoResults_NoOp(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "uf-empty-run", "agent-uf-empty", reportRunOpts{Results: []models.SimulationResult{}})
		h := newReportingHandler(t, pool, nil)
		h.upsertFindingsForRun(context.Background(), "uf-empty-run")
		if n := countFindings(t, pool, "agent-uf-empty"); n != 0 {
			t.Fatalf("expected 0 findings, got %d", n)
		}
	})
}

// TestUpsertFindingsForRun_DetectedOnlyFromDetectionSummary pins the
// detected-vs-missed split: detectedTechs reads detection_summary.techniques
// (the agent's post-run alert sweep) — a FAIL whose technique is marked
// "detected" there becomes exposure_state=detected_only, not missed.
func TestUpsertFindingsForRun_DetectedOnlyFromDetectionSummary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		at := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		seedReportableRun(t, pool, "uf-det-run", "agent-uf-det", reportRunOpts{
			Results: oneResult("r1", "T1003.001", "fail", "High", at),
		})
		_, err := pool.Exec(context.Background(),
			`UPDATE scenario_runs SET detection_summary = $1 WHERE id = $2`,
			`{"techniques":[{"techniqueId":"T1003.001","verdict":"detected"}]}`, "uf-det-run")
		if err != nil {
			t.Fatalf("seed detection_summary: %v", err)
		}
		h := newReportingHandler(t, pool, nil)
		h.upsertFindingsForRun(context.Background(), "uf-det-run")

		f, ok := queryFinding(t, pool, "agent-uf-det", "T1003.001")
		if !ok {
			t.Fatal("expected a finding to be created")
		}
		if f.ExposureState != "detected_only" {
			t.Fatalf("exposure_state = %q, want detected_only", f.ExposureState)
		}
	})
}

// TestUpsertFindingsForRun_Idempotent pins the same-run refinement guard:
// calling upsertFindingsForRun twice for the SAME run must not double-count
// occurrence_count (Apply's same-run branch is Refined, which doesn't touch
// OccurrenceCount).
func TestUpsertFindingsForRun_Idempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		at := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		seedReportableRun(t, pool, "uf-idem-run", "agent-uf-idem", reportRunOpts{
			Results: oneResult("r1", "T1059.001", "fail", "Critical", at),
		})
		h := newReportingHandler(t, pool, nil)
		h.upsertFindingsForRun(context.Background(), "uf-idem-run")
		h.upsertFindingsForRun(context.Background(), "uf-idem-run")

		if n := countFindings(t, pool, "agent-uf-idem"); n != 1 {
			t.Fatalf("expected exactly 1 finding row after two calls, got %d", n)
		}
		f, ok := queryFinding(t, pool, "agent-uf-idem", "T1059.001")
		if !ok {
			t.Fatal("finding missing")
		}
		if f.OccurrenceCount != 1 {
			t.Fatalf("occurrence_count = %d, want 1 (re-running the same run must not double-count)", f.OccurrenceCount)
		}
	})
}

// TestUpsertFindingsForRun_RecurredHealedReopened walks the full lifecycle
// across three runs on the same agent/technique: missed (created) → missed
// again in a later run (recurred, occurrence bumps) → prevented in a later
// run (healed, resolved_at set) → missed again (reopened, resolved_at
// cleared, reopened_count bumps). Uses the shared handler across all three
// upserts, matching how the server calls this after every run completion.
func TestUpsertFindingsForRun_RecurredHealedReopened(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		agent := "agent-uf-lifecycle"
		t0 := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		h := newReportingHandler(t, pool, nil)

		seedReportableRun(t, pool, "uf-life-run1", agent, reportRunOpts{
			StartedAt: t0, Results: oneResult("r1", "T1059.001", "fail", "Critical", t0),
		})
		h.upsertFindingsForRun(context.Background(), "uf-life-run1")
		f, ok := queryFinding(t, pool, agent, "T1059.001")
		if !ok || f.Status != "open" || f.OccurrenceCount != 1 {
			t.Fatalf("after run1: finding = %+v (ok=%v), want open/occurrence=1", f, ok)
		}

		t1 := t0.Add(1 * time.Hour)
		seedReportableRun(t, pool, "uf-life-run2", agent, reportRunOpts{
			StartedAt: t1, Results: oneResult("r1", "T1059.001", "fail", "Critical", t1),
		})
		h.upsertFindingsForRun(context.Background(), "uf-life-run2")
		f, ok = queryFinding(t, pool, agent, "T1059.001")
		if !ok || f.Status != "open" || f.OccurrenceCount != 2 {
			t.Fatalf("after run2 (recur): finding = %+v (ok=%v), want open/occurrence=2", f, ok)
		}

		t2 := t1.Add(1 * time.Hour)
		seedReportableRun(t, pool, "uf-life-run3", agent, reportRunOpts{
			StartedAt: t2, Results: oneResult("r1", "T1059.001", "pass", "Critical", t2),
		})
		h.upsertFindingsForRun(context.Background(), "uf-life-run3")
		f, ok = queryFinding(t, pool, agent, "T1059.001")
		if !ok || f.Status != "remediated" || f.ResolvedAt == nil {
			t.Fatalf("after run3 (heal): finding = %+v (ok=%v), want remediated with resolved_at set", f, ok)
		}

		t3 := t2.Add(1 * time.Hour)
		seedReportableRun(t, pool, "uf-life-run4", agent, reportRunOpts{
			StartedAt: t3, Results: oneResult("r1", "T1059.001", "fail", "Critical", t3),
		})
		h.upsertFindingsForRun(context.Background(), "uf-life-run4")
		f, ok = queryFinding(t, pool, agent, "T1059.001")
		if !ok || f.Status != "open" || f.ResolvedAt != nil || f.ReopenedCount != 1 {
			t.Fatalf("after run4 (reopen): finding = %+v (ok=%v), want open/resolved_at=nil/reopened=1", f, ok)
		}
	})
}

// TestUpsertFindingsForRun_FrameworkNormalization pins the source_type
// derivation from step_meta.framework: "art" normalizes to "atomic",
// "caldera" passes through, anything else (including no step_meta entry at
// all) normalizes to "custom".
func TestUpsertFindingsForRun_FrameworkNormalization(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		at := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		results := []models.SimulationResult{
			{ID: "r1", Technique: models.AttackTechnique{ID: "T1059.001", Name: "x", Tactic: "execution"}, Result: models.ResultFail, Severity: "Critical", ExecutedAt: at, StartedAt: at},
			{ID: "r2", Technique: models.AttackTechnique{ID: "T1003.001", Name: "x", Tactic: "credential-access"}, Result: models.ResultFail, Severity: "High", ExecutedAt: at, StartedAt: at},
			{ID: "r3", Technique: models.AttackTechnique{ID: "T1547.001", Name: "x", Tactic: "persistence"}, Result: models.ResultFail, Severity: "Medium", ExecutedAt: at, StartedAt: at},
		}
		seedReportableRun(t, pool, "uf-fw-run", "agent-uf-fw", reportRunOpts{Results: results})
		_, err := pool.Exec(context.Background(),
			`UPDATE scenario_runs SET step_meta = $1 WHERE id = $2`,
			`{"s1":{"techniqueId":"T1059.001","framework":"art"},"s2":{"techniqueId":"T1003.001","framework":"caldera"}}`,
			"uf-fw-run")
		if err != nil {
			t.Fatalf("seed step_meta: %v", err)
		}
		h := newReportingHandler(t, pool, nil)
		h.upsertFindingsForRun(context.Background(), "uf-fw-run")

		cases := []struct{ tech, wantSource string }{
			{"T1059.001", "atomic"},
			{"T1003.001", "caldera"},
			{"T1547.001", "custom"}, // no step_meta entry at all
		}
		for _, c := range cases {
			var src string
			if err := pool.QueryRow(context.Background(),
				`SELECT source_type FROM findings WHERE agent_id='agent-uf-fw' AND technique_id=$1`, c.tech,
			).Scan(&src); err != nil {
				t.Fatalf("%s: query source_type: %v", c.tech, err)
			}
			if src != c.wantSource {
				t.Errorf("%s: source_type = %q, want %q", c.tech, src, c.wantSource)
			}
		}
	})
}

// TestUpsertFindingsForRun_ErrorAndSkippedExcluded pins the `default:
// continue` branch: ERROR and SKIPPED results never drive a finding, only
// PASS/BLOCKED/FAIL do.
func TestUpsertFindingsForRun_ErrorAndSkippedExcluded(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		at := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		results := []models.SimulationResult{
			{ID: "r1", Technique: models.AttackTechnique{ID: "T1059.001", Name: "x", Tactic: "execution"}, Result: models.ResultFail, Severity: "Critical", ExecutedAt: at, StartedAt: at},
			{ID: "r2", Technique: models.AttackTechnique{ID: "T1003.001", Name: "x", Tactic: "credential-access"}, Result: models.ResultError, Severity: "High", ExecutedAt: at, StartedAt: at},
			{ID: "r3", Technique: models.AttackTechnique{ID: "T1112", Name: "x", Tactic: "defense-evasion"}, Result: models.ResultSkipped, Severity: "Low", ExecutedAt: at, StartedAt: at},
		}
		seedReportableRun(t, pool, "uf-errskip-run", "agent-uf-errskip", reportRunOpts{Results: results})
		h := newReportingHandler(t, pool, nil)
		h.upsertFindingsForRun(context.Background(), "uf-errskip-run")

		if n := countFindings(t, pool, "agent-uf-errskip"); n != 1 {
			t.Fatalf("expected exactly 1 finding (only the FAIL), got %d", n)
		}
		if _, ok := queryFinding(t, pool, "agent-uf-errskip", "T1059.001"); !ok {
			t.Error("expected the FAIL technique's finding to exist")
		}
	})
}

// TestDispatchTicketing_NilTicketing_NoOp pins the documented guard: with no
// ticketing manager configured, dispatchTicketing must not panic or error.
func TestDispatchTicketing_NilTicketing_NoOp(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil) // no WithTicketing — h.ticketing stays nil
		h.dispatchTicketing(context.Background(), "agent-x", "T1059.001", "Endpoint", "created")
	})
}
