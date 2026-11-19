package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/aleef/campaign"
	"github.com/audspect/bas/internal/auth"
)

// Only an admin (aleef:authorize) creates engagements; the approver is the authenticated user and
// a body-supplied approver is refused. An analyst can start a run against the resulting engagement
// (the end-to-end test does so).
func TestEngagementApprovalIsServerSideAndAdminOnly(t *testing.T) {
	withAleefEnv(t, func(e *aleefEnv) {
		now := time.Now()
		body := aleefEngagementBody("http://127.0.0.1:9", "lab", now.Add(-time.Hour), now.Add(time.Hour))
		if rec := e.do(http.MethodPost, "/api/aleef/engagements", auth.RoleAnalyst, body); rec.Code != http.StatusForbidden {
			t.Fatalf("analyst create: %d", rec.Code)
		}
		if rec := e.do(http.MethodPost, "/api/aleef/engagements", auth.RoleViewer, body); rec.Code != http.StatusForbidden {
			t.Fatalf("viewer create: %d", rec.Code)
		}
		body["approver"] = "someone else"
		if rec := e.do(http.MethodPost, "/api/aleef/engagements", auth.RoleAdmin, body); rec.Code != http.StatusBadRequest {
			t.Fatalf("body approver: %d %s", rec.Code, rec.Body.String())
		}
		delete(body, "approver")
		rec := e.do(http.MethodPost, "/api/aleef/engagements", auth.RoleAdmin, body)
		if rec.Code != http.StatusCreated {
			t.Fatalf("admin create: %d %s", rec.Code, rec.Body.String())
		}
		got, err := e.store.GetEngagement(context.Background(), decodeMap(t, rec)["id"].(string))
		if err != nil {
			t.Fatal(err)
		}
		if got.Approver != "user:aleef-admin" {
			t.Fatalf("recorded approver %q, want the authenticated user", got.Approver)
		}
		var n int
		if err := e.pool.QueryRow(context.Background(), `SELECT count(*) FROM aleef_engagements`).Scan(&n); err != nil || n != 1 {
			t.Fatalf("engagements stored: %d %v", n, err)
		}
	})
}

// A finished run is persisted (status, report, finished_at); after the in-memory registry is
// cleared GET returns the persisted report.
func TestRunOutcomePersistedAndReadableAfterRegistryCleared(t *testing.T) {
	withAleefEnv(t, func(e *aleefEnv) {
		toy := newAleefToy()
		toy.readFlaw = true
		srv := httptest.NewServer(toy)
		defer srv.Close()
		runID := e.startRun(e.createEngagement(srv.URL), srv.URL)
		if final := e.waitRun(runID, 3*time.Minute); final["status"] != "completed" {
			t.Fatalf("status %v", final["status"])
		}
		rec, err := e.store.GetRunRecord(context.Background(), runID)
		if err != nil || rec.Status != "completed" || rec.FinishedAt == nil || len(rec.Report) == 0 {
			t.Fatalf("persisted record: %+v %v", rec, err)
		}
		e.state.mu.Lock()
		e.state.runs = map[string]*aleefRun{}
		e.state.mu.Unlock()
		m := decodeMap(t, e.do(http.MethodGet, "/api/aleef/runs/"+runID, auth.RoleAnalyst, nil))
		rep, _ := m["report"].(map[string]any)
		if m["status"] != "completed" || rep == nil || rep["RunID"] != runID || rep["Verified"].(float64) < 1 {
			t.Fatalf("GET after registry cleared: %v", m)
		}
	})
}

// A panic inside the campaign is persisted as failed and releases the engagement.
func TestPanicPathPersistedAsFailed(t *testing.T) {
	withAleefEnv(t, func(e *aleefEnv) {
		toy := newAleefToy()
		srv := httptest.NewServer(toy)
		defer srv.Close()
		e.state.runFn = func(context.Context, campaign.Config) (campaign.Report, error) { panic("boom") }
		engID := e.createEngagement(srv.URL)
		runID := e.startRun(engID, srv.URL)
		if final := e.waitRun(runID, time.Minute); final["status"] != "failed" {
			t.Fatalf("status %v", final["status"])
		}
		rec, err := e.store.GetRunRecord(context.Background(), runID)
		if err != nil || rec.Status != "failed" || !strings.Contains(rec.HaltedReason, "panicked") || rec.FinishedAt == nil {
			t.Fatalf("persisted record: %+v %v", rec, err)
		}
		e.state.runFn = func(context.Context, campaign.Config) (campaign.Report, error) { return campaign.Report{}, nil }
		e.startRun(engID, srv.URL) // the engagement was released
	})
}

// At startup, runs still 'running' become 'interrupted'; finished runs are untouched.
func TestStartupSweepMarksRunningInterrupted(t *testing.T) {
	withAleefEnv(t, func(e *aleefEnv) {
		ctx := context.Background()
		running, err := e.store.CreateRun(ctx, "")
		if err != nil {
			t.Fatal(err)
		}
		done, _ := e.store.CreateRun(ctx, "")
		if err := e.store.MarkRunFinished(ctx, done, "completed", "", []byte(`{"RunID":"x"}`), nil); err != nil {
			t.Fatal(err)
		}
		h := &Handler{aleef: e.state}
		if err := h.RecoverAleefRuns(ctx); err != nil {
			t.Fatal(err)
		}
		m := decodeMap(t, e.do(http.MethodGet, "/api/aleef/runs/"+running, auth.RoleAnalyst, nil))
		if m["status"] != "interrupted" || m["finished_at"] == nil {
			t.Fatalf("running run after sweep: %v", m)
		}
		if m2 := decodeMap(t, e.do(http.MethodGet, "/api/aleef/runs/"+done, auth.RoleAnalyst, nil)); m2["status"] != "completed" {
			t.Fatalf("finished run changed: %v", m2)
		}
		// a finished run is never overwritten by a late write
		if err := e.store.MarkRunFinished(ctx, running, "completed", "", nil, nil); err != nil {
			t.Fatal(err)
		}
		if rec, _ := e.store.GetRunRecord(ctx, running); rec.Status != "interrupted" {
			t.Fatalf("interrupted run overwritten: %s", rec.Status)
		}
	})
}

// Shutdown cancels a running campaign, waits for its cleanup sweep and refuses new runs.
func TestShutdownCancelsAndCleansUp(t *testing.T) {
	withAleefEnv(t, func(e *aleefEnv) {
		toy := newAleefToy()
		toy.readFlaw = true
		toy.delay = 15 * time.Millisecond
		srv := httptest.NewServer(toy)
		defer srv.Close()
		engID := e.createEngagement(srv.URL)
		runID := e.startRun(engID, srv.URL)
		time.Sleep(400 * time.Millisecond)
		e.state.shutdown(time.Minute)
		if toy.leftover() != 0 {
			t.Fatalf("shutdown left %d objects on the target", toy.leftover())
		}
		rec, err := e.store.GetRunRecord(context.Background(), runID)
		if err != nil || rec.Status != "halted" || !strings.Contains(rec.HaltedReason, "server shutdown") {
			t.Fatalf("persisted record after shutdown: %+v %v", rec, err)
		}
		if r := e.do(http.MethodPost, "/api/aleef/runs", auth.RoleAnalyst, aleefRunBody(engID, srv.URL)); r.Code != http.StatusServiceUnavailable {
			t.Fatalf("run after shutdown: %d", r.Code)
		}
	})
}

// Shutdown begins between CreateRun and registration: the request is refused with 503, nothing is
// registered, no goroutine starts, the run row is not left 'running' and wg stays usable.
func TestShutdownBetweenCreateRunAndRegistration(t *testing.T) {
	withAleefEnv(t, func(e *aleefEnv) {
		toy := newAleefToy()
		srv := httptest.NewServer(toy)
		defer srv.Close()
		engID := e.createEngagement(srv.URL)
		started := false
		e.state.runFn = func(context.Context, campaign.Config) (campaign.Report, error) {
			started = true
			return campaign.Report{}, nil
		}
		e.state.afterCreateRun = func() { e.state.shutdown(time.Minute) }
		rec := e.do(http.MethodPost, "/api/aleef/runs", auth.RoleAnalyst, aleefRunBody(engID, srv.URL))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status %d %s", rec.Code, rec.Body.String())
		}
		e.state.mu.Lock()
		nRuns, nActive := len(e.state.runs), len(e.state.active)
		e.state.mu.Unlock()
		if nRuns != 0 || nActive != 0 || started {
			t.Fatalf("registered=%d active=%d started=%v", nRuns, nActive, started)
		}
		var status, reason string
		if err := e.pool.QueryRow(context.Background(), `SELECT status, halted_reason FROM aleef_runs ORDER BY created_at DESC LIMIT 1`).Scan(&status, &reason); err != nil {
			t.Fatal(err)
		}
		if status != "halted" || reason != "server shutdown" {
			t.Fatalf("run row: %s %q", status, reason)
		}
		e.state.wg.Wait() // the counter is zero: no Add happened
		if toy.requests.Load() != 0 {
			t.Fatal("request reached the target")
		}
	})
}

// The approver key is refused in any letter case.
func TestEngagementApproverRefusedCaseInsensitively(t *testing.T) {
	withAleefEnv(t, func(e *aleefEnv) {
		now := time.Now()
		for _, k := range []string{"Approver", "APPROVER", "aPpRoVeR"} {
			body := aleefEngagementBody("http://127.0.0.1:9", "lab", now.Add(-time.Hour), now.Add(time.Hour))
			body[k] = "someone else"
			if rec := e.do(http.MethodPost, "/api/aleef/engagements", auth.RoleAdmin, body); rec.Code != http.StatusBadRequest {
				t.Fatalf("key %q: %d %s", k, rec.Code, rec.Body.String())
			}
		}
	})
}

// GET reports the database vocabulary for a stopped run and fills halted_reason from the report.
func TestRunStatusVocabularyAndHaltedReason(t *testing.T) {
	withAleefEnv(t, func(e *aleefEnv) {
		toy := newAleefToy()
		srv := httptest.NewServer(toy)
		defer srv.Close()
		e.state.runFn = func(context.Context, campaign.Config) (campaign.Report, error) {
			return campaign.Report{RunID: "x", Halted: "request budget exhausted"}, nil
		}
		runID := e.startRun(e.createEngagement(srv.URL), srv.URL)
		final := e.waitRun(runID, time.Minute)
		if final["status"] != "halted" || final["halted_reason"] != "request budget exhausted" {
			t.Fatalf("in memory: %v", final)
		}
		e.state.mu.Lock()
		e.state.runs = map[string]*aleefRun{}
		e.state.mu.Unlock()
		m := decodeMap(t, e.do(http.MethodGet, "/api/aleef/runs/"+runID, auth.RoleAnalyst, nil))
		if m["status"] != "halted" || m["halted_reason"] != "request budget exhausted" {
			t.Fatalf("from the database: %v", m)
		}
	})
}
