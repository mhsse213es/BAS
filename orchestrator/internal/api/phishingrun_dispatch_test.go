package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/phishingrun"
)

// dispatchEnv returns an env with a mail provider present, so preflight reaches its
// recipient and key checks. Nothing in these tests sends mail.
func dispatchEnv(pool *pgxpool.Pool) PhishingRunExecutorEnv {
	return PhishingRunExecutorEnv{Pool: pool, EmailGWProvider: emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil)}
}

func dispatchParams(key string, recipients ...string) map[string]any {
	return map[string]any{"idempotencyKey": key, "recipients": recipients}
}

func countPhishingRuns(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM phishing_runs`).Scan(&n); err != nil {
		t.Fatalf("count phishing runs: %v", err)
	}
	return n
}

// Each refusal is checked before anything is written. A refused dispatch creates no run.
func TestDispatch_RefusalsCreateNoRow(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		env := dispatchEnv(pool)
		exp, ok := emailgwefficacy.ExpectationByID(phishEmailGWExpectation["PH-BEC-001"])
		if !ok || exp.Recipient == "" {
			t.Fatalf("test prerequisite: EG expectation for PH-BEC-001 has no recipient")
		}
		cases := map[string]struct {
			scenario string
			params   map[string]any
			env      PhishingRunExecutorEnv
		}{
			"not EmailGW-backed":      {"PH-ID-001", dispatchParams("k1", exp.Recipient), env},
			"missing idempotency key": {"PH-BEC-001", map[string]any{"recipients": []string{exp.Recipient}}, env},
			"no recipients":           {"PH-BEC-001", map[string]any{"idempotencyKey": "k2"}, env},
			"wrong recipient":         {"PH-BEC-001", dispatchParams("k3", "someone-else@example.invalid"), env},
			"no EmailGW connector":    {"PH-BEC-001", dispatchParams("k4", exp.Recipient), PhishingRunExecutorEnv{Pool: pool}},
		}
		for name, c := range cases {
			t.Run(name, func(t *testing.T) {
				before := countPhishingRuns(t, pool)
				_, err := startPhishingDispatch(ctx, pool, c.env, PhishingRunRequest{ScenarioID: c.scenario, Parameters: c.params})
				if err == nil {
					t.Fatalf("dispatch was accepted; it must be refused before anything is sent")
				}
				if after := countPhishingRuns(t, pool); after != before {
					t.Errorf("refused dispatch wrote %d row(s)", after-before)
				}
			})
		}
	})
}

// A retry with the same key returns the run that already exists, and writes no second row.
func TestDispatch_DuplicateKeyReturnsExistingRun(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsurePhishingRunSchema(ctx, pool); err != nil {
			t.Fatalf("schema: %v", err)
		}
		exp, _ := emailgwefficacy.ExpectationByID(phishEmailGWExpectation["PH-BEC-001"])
		prior := map[string]any{"dispatch": map[string]any{"idempotencyKey": "dup-key", "emailGwRunId": "eg-prior"}}
		raw, _ := json.Marshal(prior)
		if _, err := pool.Exec(ctx,
			`INSERT INTO phishing_runs (id, scenario_id, status, result, error, initiated_by, started_at)
			 VALUES ('prior-run', 'PH-BEC-001', 'running', $1, '', 'u1', NOW())`, raw); err != nil {
			t.Fatalf("seed prior run: %v", err)
		}
		before := countPhishingRuns(t, pool)
		got, err := startPhishingDispatch(ctx, pool, dispatchEnv(pool), PhishingRunRequest{
			ScenarioID: "PH-BEC-001", Parameters: dispatchParams("dup-key", exp.Recipient), InitiatedBy: "u1",
		})
		if err != nil {
			t.Fatalf("retry with the same key: %v", err)
		}
		if got.ID != "prior-run" {
			t.Errorf("retry returned run %q, want the existing prior-run", got.ID)
		}
		if after := countPhishingRuns(t, pool); after != before {
			t.Errorf("retry wrote %d new row(s); a duplicate key must write none", after-before)
		}
	})
}

// A running dispatch stays running while its EmailGW run is still open.
func TestDispatch_RefreshLeavesOpenRunningAlone(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		seedDispatchedRun(t, pool, "open-run", "eg-open", "running", time.Now().UTC())
		got, err := refreshPhishingDispatch(ctx, pool, PhishingRunExecutorEnv{Pool: pool}, loadRunForTest(t, pool, "open-run"))
		if err != nil {
			t.Fatalf("refresh: %v", err)
		}
		if got.Status != phishingrun.StatusRunning {
			t.Errorf("open EmailGW run: status %q, want running", got.Status)
		}
	})
}

// An EmailGW run that failed or ended partial fails the phishing run. Nothing is graded.
func TestDispatch_FailedOrPartialEmailGWFailsPhishingRun(t *testing.T) {
	for _, egStatus := range []string{"failed", "partial"} {
		t.Run(egStatus, func(t *testing.T) {
			sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
				ctx := context.Background()
				id := "run-" + egStatus
				seedDispatchedRun(t, pool, id, "eg-"+egStatus, egStatus, time.Now().UTC())
				got, err := refreshPhishingDispatch(ctx, pool, PhishingRunExecutorEnv{Pool: pool}, loadRunForTest(t, pool, id))
				if err != nil {
					t.Fatalf("refresh: %v", err)
				}
				if got.Status != phishingrun.StatusFailed {
					t.Errorf("EmailGW %s: status %q, want failed", egStatus, got.Status)
				}
				if !strings.Contains(got.Error, egStatus) {
					t.Errorf("error %q does not name the EmailGW status", got.Error)
				}
			})
		})
	}
}

// A dispatch still open past the timeout fails with the reason. It is never left pending.
func TestDispatch_TimeoutFailsWithReason(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		seedDispatchedRun(t, pool, "stale-run", "eg-stale", "running", time.Now().UTC().Add(-phishDispatchTimeout-time.Hour))
		got, err := refreshPhishingDispatch(ctx, pool, PhishingRunExecutorEnv{Pool: pool}, loadRunForTest(t, pool, "stale-run"))
		if err != nil {
			t.Fatalf("refresh: %v", err)
		}
		if got.Status != phishingrun.StatusFailed || !strings.Contains(got.Error, "timed out") {
			t.Errorf("stale dispatch: status %q error %q, want failed with a timeout reason", got.Status, got.Error)
		}
	})
}

// If the EmailGW run row is gone, the phishing run fails. It is never left dangling.
func TestDispatch_MissingEmailGWRunFails(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		seedDispatchedRun(t, pool, "orphan-run", "eg-does-not-exist", "running", time.Now().UTC())
		if _, err := pool.Exec(ctx, `DELETE FROM email_gw_runs WHERE id = 'eg-does-not-exist'`); err != nil {
			t.Fatalf("setup: %v", err)
		}
		got, err := refreshPhishingDispatch(ctx, pool, PhishingRunExecutorEnv{Pool: pool}, loadRunForTest(t, pool, "orphan-run"))
		if err != nil {
			t.Fatalf("refresh: %v", err)
		}
		if got.Status != phishingrun.StatusFailed {
			t.Errorf("missing EmailGW run: status %q, want failed", got.Status)
		}
	})
}

// seedDispatchedRun writes a phishing run correlated to an EmailGW run, and that EmailGW
// run in the given state. dispatchedAt sets the age used by the timeout.
func seedDispatchedRun(t *testing.T, pool *pgxpool.Pool, phishID, egID, egStatus string, dispatchedAt time.Time) {
	t.Helper()
	ctx := context.Background()
	if err := db.EnsurePhishingRunSchema(ctx, pool); err != nil {
		t.Fatalf("schema: %v", err)
	}
	rec := dispatchResultEnvelope{Dispatch: dispatchRecord{
		IdempotencyKey: "key-" + phishID, EmailGWRunID: egID, EmailGWScenarioID: "EG-002.known-good",
		Environment: "lab", Recipient: "x@example.invalid", DispatchedAt: dispatchedAt,
	}}
	raw, _ := json.Marshal(rec)
	if _, err := pool.Exec(ctx,
		`INSERT INTO phishing_runs (id, scenario_id, status, result, error, initiated_by, started_at)
		 VALUES ($1, 'PH-BEC-001', 'running', $2, '', 'u1', NOW())`, phishID, raw); err != nil {
		t.Fatalf("seed phishing run: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO email_gw_runs (id, scenario_id, status) VALUES ($1, 'EG-002.known-good', $2)`, egID, egStatus); err != nil {
		t.Fatalf("seed EmailGW run: %v", err)
	}
}

func loadRunForTest(t *testing.T, pool *pgxpool.Pool, id string) *phishingrun.PhishingRun {
	t.Helper()
	var run phishingrun.PhishingRun
	var status string
	var result []byte
	if err := pool.QueryRow(context.Background(),
		`SELECT id, scenario_id, status, result, initiated_by, started_at FROM phishing_runs WHERE id = $1`, id,
	).Scan(&run.ID, &run.ScenarioID, &status, &result, &run.InitiatedBy, &run.StartedAt); err != nil {
		t.Fatalf("load run %s: %v", id, err)
	}
	run.Status = phishingrun.Status(status)
	run.Result = result
	return &run
}
