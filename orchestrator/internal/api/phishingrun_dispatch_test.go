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
	end := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	return map[string]any{"idempotencyKey": key, "recipients": recipients, "testWindowEnd": end}
}

// The operator's test window is an explicit instant inside the EmailGW dwell bounds.
// Anything outside is refused, never clamped, and a missing window is refused.
func TestDispatchTestWindow_Bounds(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }
	ok := []time.Duration{MinEmailGWDwellWindow, time.Hour, MaxEmailGWDwellWindow}
	for _, d := range ok {
		dwell, _, err := dispatchTestWindow(map[string]any{"testWindowEnd": at(d)}, now)
		if err != nil || dwell != d {
			t.Errorf("window %s: dwell=%s err=%v, want %s accepted", d, dwell, err, d)
		}
	}
	refused := map[string]map[string]any{
		"missing":      map[string]any{},
		"too short":    map[string]any{"testWindowEnd": at(MinEmailGWDwellWindow - time.Second)},
		"too long":     map[string]any{"testWindowEnd": at(MaxEmailGWDwellWindow + time.Second)},
		"in the past":  map[string]any{"testWindowEnd": at(-time.Minute)},
		"not RFC 3339": map[string]any{"testWindowEnd": "tomorrow"},
	}
	for name, params := range refused {
		if _, _, err := dispatchTestWindow(params, now); err == nil {
			t.Errorf("%s: accepted; it must be refused", name)
		}
	}
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

// When the EmailGW dispatch itself fails, the phishing run fails with that reason. It is
// never left running, and no EmailGW run is claimed as correlated. A zero injection
// target cannot send, so the inbound path refuses here without touching the network.
func TestDispatch_SendFailureFailsPhishingRun(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsurePhishingRunSchema(ctx, pool); err != nil {
			t.Fatalf("schema: %v", err)
		}
		exp, _ := emailgwefficacy.ExpectationByID(phishEmailGWExpectation["PH-BEC-001"])
		env := dispatchEnv(pool)
		run, err := startPhishingDispatch(ctx, pool, env, PhishingRunRequest{
			ScenarioID: "PH-BEC-001", Parameters: dispatchParams("send-fail-key", exp.Recipient), InitiatedBy: "u1",
		})
		if err == nil {
			t.Fatalf("a dispatch with no usable injection target was accepted")
		}
		if run == nil || run.Status != phishingrun.StatusFailed {
			t.Fatalf("run = %+v, want a failed phishing run", run)
		}
		if run.Error == "" {
			t.Errorf("failed run carries no reason")
		}
		reloaded := loadRunForTest(t, pool, run.ID)
		if reloaded.Status != phishingrun.StatusFailed {
			t.Errorf("stored status %q, want failed", reloaded.Status)
		}
	})
}

// A successful dispatch sends exactly once. A retry with the same key returns the same
// phishing run and does not send again. The phishing run stores the EmailGW run it
// created, so the correlation can be followed.
func TestDispatch_SuccessSendsOnceAndCorrelates(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsurePhishingRunSchema(ctx, pool); err != nil {
			t.Fatalf("schema: %v", err)
		}
		sends := 0
		orig := injectScenarioMessageFn
		injectScenarioMessageFn = func(_ context.Context, _ emailgwefficacy.InjectionTarget, _ emailgwefficacy.MailExpectation, _ emailgwefficacy.InjectableMessage) (emailgwefficacy.OriginDeliveryObservation, error) {
			sends++
			return emailgwefficacy.OriginDeliveryObservation{Timestamp: time.Now().UTC(), SenderPayloadHash: "hash-1"}, nil
		}
		t.Cleanup(func() {
			injectScenarioMessageFn = orig
			StopEmailGWWaiters()
		})

		exp, _ := emailgwefficacy.ExpectationByID(phishEmailGWExpectation["PH-BEC-001"])
		env := dispatchEnv(pool)
		env.EmailGWTarget = emailgwefficacy.InjectionTarget{HELODomain: "h.test", TargetMX: "mx.test", RelayHost: "relay.test"}
		params := dispatchParams("success-key", exp.Recipient)
		params["campaignId"] = "camp-7"
		req := PhishingRunRequest{ScenarioID: "PH-BEC-001", Parameters: params, InitiatedBy: "u1"}

		first, err := startPhishingDispatch(ctx, pool, env, req)
		if err != nil {
			t.Fatalf("first dispatch: %v", err)
		}
		if sends != 1 {
			t.Fatalf("sends = %d after first dispatch, want 1", sends)
		}
		if first.Status != phishingrun.StatusRunning {
			t.Errorf("status %q, want running while the EmailGW run is open", first.Status)
		}
		var env2 dispatchResultEnvelope
		if err := json.Unmarshal(first.Result, &env2); err != nil || env2.Dispatch.EmailGWRunID == "" {
			t.Fatalf("result carries no EmailGW run ID: %s (err %v)", first.Result, err)
		}
		if env2.Dispatch.CampaignID != "camp-7" || env2.Dispatch.TestWindowEnd.IsZero() {
			t.Errorf("correlation lost the campaign or test window: %+v", env2.Dispatch)
		}

		var egStatus string
		if err := pool.QueryRow(ctx, `SELECT status FROM email_gw_runs WHERE id = $1`, env2.Dispatch.EmailGWRunID).Scan(&egStatus); err != nil {
			t.Fatalf("correlated EmailGW run %s not found: %v", env2.Dispatch.EmailGWRunID, err)
		}

		second, err := startPhishingDispatch(ctx, pool, env, req)
		if err != nil {
			t.Fatalf("retry with the same key: %v", err)
		}
		if second.ID != first.ID {
			t.Errorf("retry returned run %q, want the original %q", second.ID, first.ID)
		}
		if sends != 1 {
			t.Errorf("sends = %d after a retry, want still 1: a duplicate key must not send again", sends)
		}
	})
}

// A dispatched run whose EmailGW run completed is graded through the read-back, and it
// settles as completed with provenance that names that EmailGW run.
func TestDispatch_CompletedEmailGWRunIsGraded(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		seedDispatchedRun(t, pool, "graded-run", "eg-graded", "completed", time.Now().UTC())
		exp, _ := emailgwefficacy.ExpectationByID("EG-002.known-good")
		result := emailgwefficacy.VerifyMailExpectation(exp, emailgwefficacy.OriginDeliveryObservation{},
			emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil), readbackScenarioWindow())
		raw, err := json.Marshal(result)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if _, err := pool.Exec(ctx, `UPDATE email_gw_runs SET result = $2 WHERE id = $1`, "eg-graded", raw); err != nil {
			t.Fatalf("attach result: %v", err)
		}

		got, err := refreshPhishingDispatch(ctx, pool, PhishingRunExecutorEnv{Pool: pool}, loadRunForTest(t, pool, "graded-run"))
		if err != nil {
			t.Fatalf("refresh: %v", err)
		}
		if got.Status != phishingrun.StatusCompleted {
			t.Fatalf("status %q, want completed", got.Status)
		}
		outcome, err := dispatchOutcomeFrom(got.Result)
		if err != nil {
			t.Fatalf("decode outcome: %v", err)
		}
		if outcome.Provenance == nil || outcome.Provenance.EmailGWRunID != "eg-graded" {
			t.Errorf("provenance = %+v, want the graded EmailGW run eg-graded", outcome.Provenance)
		}
	})
}

// The poller settles a dispatched run whose EmailGW run completed, with nobody reading
// the run. It also writes one settlement audit entry for it.
func TestDispatch_PollerSettlesUnreadRun(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		seedDispatchedRun(t, pool, "unread-run", "eg-unread", "completed", time.Now().UTC())
		exp, _ := emailgwefficacy.ExpectationByID("EG-002.known-good")
		result := emailgwefficacy.VerifyMailExpectation(exp, emailgwefficacy.OriginDeliveryObservation{},
			emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil), readbackScenarioWindow())
		raw, _ := json.Marshal(result)
		if _, err := pool.Exec(ctx, `UPDATE email_gw_runs SET result = $2 WHERE id = $1`, "eg-unread", raw); err != nil {
			t.Fatalf("attach result: %v", err)
		}

		if err := RefreshPhishingDispatches(ctx, pool, PhishingRunExecutorEnv{Pool: pool}); err != nil {
			t.Fatalf("poller refresh: %v", err)
		}
		got := loadRunForTest(t, pool, "unread-run")
		if got.Status != phishingrun.StatusCompleted {
			t.Errorf("unread dispatch: status %q after the poller, want completed", got.Status)
		}
		countAudits := func() int {
			var n int
			if err := pool.QueryRow(ctx,
				`SELECT COUNT(*) FROM audit_logs WHERE action = 'phishingrun.dispatch.settled' AND resource = 'unread-run'`,
			).Scan(&n); err != nil {
				t.Fatalf("count audit rows: %v", err)
			}
			return n
		}
		if n := countAudits(); n != 1 {
			t.Errorf("settlement audit rows = %d, want 1", n)
		}
		// A second pass finds nothing running, so it writes no second audit row.
		if err := RefreshPhishingDispatches(ctx, pool, PhishingRunExecutorEnv{Pool: pool}); err != nil {
			t.Fatalf("second poller pass: %v", err)
		}
		if n := countAudits(); n != 1 {
			t.Errorf("after a second pass, settlement audit rows = %d, want still 1", n)
		}
	})
}
