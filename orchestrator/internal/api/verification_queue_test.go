package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/verification"
	"github.com/audspect/bas/internal/ws"
)

// verificationScenario builds a scenario with one step carrying two
// expectations: "exp-manual" (provider microsoft_sentinel, a SIEM provider
// registered with Verifier: VerificationManual — off-host, belongs in the
// queue) and "exp-auto" (provider microsoft_defender, VerificationAutomatic —
// resolved on-host, must NEVER appear in the manual-verification queue).
func verificationScenario(t *testing.T, id string) (*scenario.Scenario, *scenario.Engine) {
	t.Helper()
	engine := scenario.NewEngine(t.TempDir())
	sc := &scenario.Scenario{
		ID:   id,
		Name: "Verification Test Scenario",
		Steps: []scenario.Step{
			{
				Name: "step-1", TechniqueID: "T1071.001", Framework: "custom", Command: "echo step-1",
				ExpectedDetections: []scenario.ExpectedDetection{
					{ID: "exp-manual", Provider: "microsoft_sentinel", Confidence: "required"},
					{ID: "exp-auto", Provider: "microsoft_defender", Confidence: "required"},
				},
			},
		},
	}
	if err := engine.SaveAs(context.Background(), sc, "user:test"); err != nil {
		t.Fatalf("save verification scenario: %v", err)
	}
	got, _ := engine.Get(id)
	return got, engine
}

func newVerificationHandler(t *testing.T, pool *pgxpool.Pool, engine *scenario.Engine) *Handler {
	t.Helper()
	return New(pool, ws.NewHub(), engine, "").WithVerificationStore(verification.NewStore(pool))
}

// seedRunForScenario inserts the minimal agent + scenario_runs row
// runScenario needs to resolve a run back to its scenario.
func seedRunForScenario(t *testing.T, pool *pgxpool.Pool, runID, agentID, scenarioID string) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx,
		`INSERT INTO agents (agent_id, hostname, state) VALUES ($1,'h','active') ON CONFLICT (agent_id) DO NOTHING`,
		agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO scenario_runs (id, scenario_id, agent_id) VALUES ($1,$2,$3)`,
		runID, scenarioID, agentID); err != nil {
		t.Fatalf("seed scenario_run: %v", err)
	}
}

// withURLParams sets multiple chi URL params on one request. withURLParam
// (event_handlers_test.go) builds a fresh chi.RouteContext per call, so
// chaining two calls silently drops the first param — routes with more than
// one path param (like /verifications/{runId}/history/{expectationId}) need
// this instead.
func withURLParams(r *http.Request, params map[string]string) *http.Request {
	rctx := chi.NewRouteContext()
	for k, v := range params {
		rctx.URLParams.Add(k, v)
	}
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func verificationsReq(runID, query string) *http.Request {
	path := "/api/scenarios/runs/" + runID + "/verifications"
	if query != "" {
		path += "?" + query
	}
	return withURLParam(httptest.NewRequest(http.MethodGet, path, nil), "runId", runID)
}

func TestListRunVerifications_NilStore503(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "") // no WithVerificationStore
		rec := httptest.NewRecorder()
		h.ListRunVerifications(rec, verificationsReq("r1", ""))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
	})
}

func TestListRunVerifications_RunOrScenarioNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newVerificationHandler(t, pool, scenario.NewEngine(t.TempDir()))
		rec := httptest.NewRecorder()
		h.ListRunVerifications(rec, verificationsReq("nope", ""))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestListRunVerifications_ExcludesAutomaticIncludesManual(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := verificationScenario(t, "lrv-auto-manual-sc")
		h := newVerificationHandler(t, pool, engine)
		seedRunForScenario(t, pool, "lrv-auto-manual-run", "lrv-agent", sc.ID)

		rec := httptest.NewRecorder()
		h.ListRunVerifications(rec, verificationsReq("lrv-auto-manual-run", ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Items []QueueItem `json:"items"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(out.Items) != 1 {
			t.Fatalf("items = %+v, want exactly 1 (the manual expectation)", out.Items)
		}
		if out.Items[0].ExpectationID != "exp-manual" {
			t.Fatalf("expectationId = %q, want exp-manual", out.Items[0].ExpectationID)
		}
		if out.Items[0].Status != "Pending" || out.Items[0].WorkflowState != verification.StatePending {
			t.Errorf("unattested item should read Pending, got status=%q workflow=%q", out.Items[0].Status, out.Items[0].WorkflowState)
		}
		if out.Items[0].Domain != "siem" {
			t.Errorf("domain = %q, want siem (microsoft_sentinel's DefaultDomain)", out.Items[0].Domain)
		}
	})
}

func TestListRunVerifications_DomainFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := verificationScenario(t, "lrv-domain-sc")
		h := newVerificationHandler(t, pool, engine)
		seedRunForScenario(t, pool, "lrv-domain-run", "lrv-domain-agent", sc.ID)

		rec := httptest.NewRecorder()
		h.ListRunVerifications(rec, verificationsReq("lrv-domain-run", "domain=identity"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var out struct {
			Items []QueueItem `json:"items"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out.Items) != 0 {
			t.Fatalf("domain=identity should exclude the siem expectation, got %+v", out.Items)
		}
	})
}

func createVerificationReq(t *testing.T, body map[string]any, role auth.Role, userID string) *http.Request {
	t.Helper()
	b, _ := json.Marshal(body)
	req := authedRequest(t, http.MethodPost, "/api/verifications", bytes.NewReader(b), role, userID)
	return req
}

func TestCreateVerification_NilStore503(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		uid := seedUser(t, pool, "cv-nilstore", "pw-Password1!", "admin", true)
		rec := callAuthed(h.CreateVerification, createVerificationReq(t, map[string]any{"runId": "r", "expectationId": "e", "result": "Detected"}, auth.RoleAdmin, uid))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
	})
}

func TestCreateVerification_ValidationErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newVerificationHandler(t, pool, scenario.NewEngine(t.TempDir()))
		uid := seedUser(t, pool, "cv-invalid", "pw-Password1!", "admin", true)
		cases := []struct {
			name string
			body map[string]any
		}{
			{"missing runId", map[string]any{"expectationId": "e", "result": "Detected"}},
			{"missing expectationId", map[string]any{"runId": "r", "result": "Detected"}},
			{"invalid result", map[string]any{"runId": "r", "expectationId": "e", "result": "Maybe"}},
			{"invalid workflowState", map[string]any{"runId": "r", "expectationId": "e", "result": "Detected", "workflowState": "Bogus"}},
		}
		for _, c := range cases {
			rec := callAuthed(h.CreateVerification, createVerificationReq(t, c.body, auth.RoleAdmin, uid))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s: status = %d, want 400", c.name, rec.Code)
			}
		}
	})
}

func TestCreateVerification_RunOrScenarioNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newVerificationHandler(t, pool, scenario.NewEngine(t.TempDir()))
		uid := seedUser(t, pool, "cv-notfound", "pw-Password1!", "admin", true)
		rec := callAuthed(h.CreateVerification, createVerificationReq(t, map[string]any{
			"runId": "nope", "expectationId": "e", "result": "Detected",
		}, auth.RoleAdmin, uid))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestCreateVerification_ExpectationNotFoundInScenario(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := verificationScenario(t, "cv-expnf-sc")
		h := newVerificationHandler(t, pool, engine)
		seedRunForScenario(t, pool, "cv-expnf-run", "cv-expnf-agent", sc.ID)
		uid := seedUser(t, pool, "cv-expnf-user", "pw-Password1!", "admin", true)

		rec := callAuthed(h.CreateVerification, createVerificationReq(t, map[string]any{
			"runId": "cv-expnf-run", "expectationId": "does-not-exist", "result": "Detected",
		}, auth.RoleAdmin, uid))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
		}
	})
}

// TestCreateVerification_ApprovedRequiresCanReview pins the in-handler gate:
// an empty workflowState defaults to Approved (verification_handlers.go),
// which requires CanReview regardless of whether the caller could otherwise
// reach this handler (both current roles with CanVerify — admin, analyst —
// also hold CanReview; this test exercises the handler's own conditional
// directly rather than the router's RequirePermission(CanVerify) gate, which
// is already exhaustively covered by rbac_matrix_test.go).
func TestCreateVerification_ApprovedRequiresCanReview(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := verificationScenario(t, "cv-review-sc")
		h := newVerificationHandler(t, pool, engine)
		seedRunForScenario(t, pool, "cv-review-run", "cv-review-agent", sc.ID)
		uid := seedUser(t, pool, "cv-review-user", "pw-Password1!", "viewer", true)

		rec := callAuthed(h.CreateVerification, createVerificationReq(t, map[string]any{
			"runId": "cv-review-run", "expectationId": "exp-manual", "result": "Detected",
		}, auth.RoleViewer, uid))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 (viewer lacks CanReview, default workflow is Approved), body = %s", rec.Code, rec.Body.String())
		}
	})
}

// TestCreateVerification_PendingDoesNotRequireCanReview is the negative
// counterpart: explicitly requesting workflowState=Pending never touches the
// CanReview gate.
func TestCreateVerification_PendingDoesNotRequireCanReview(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := verificationScenario(t, "cv-pending-sc")
		h := newVerificationHandler(t, pool, engine)
		seedRunForScenario(t, pool, "cv-pending-run", "cv-pending-agent", sc.ID)
		uid := seedUser(t, pool, "cv-pending-user", "pw-Password1!", "viewer", true)

		rec := callAuthed(h.CreateVerification, createVerificationReq(t, map[string]any{
			"runId": "cv-pending-run", "expectationId": "exp-manual", "result": "Detected", "workflowState": "Pending",
		}, auth.RoleViewer, uid))
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
		}
	})
}

// TestCreateVerification_SuccessPersistsAuditsAndAppearsInQueue is the full
// success path: 201 with the created record, server-resolved audit metadata
// (technique/domain/provider — NOT client-supplied), and the merged verdict
// then shows up correctly in ListRunVerifications.
func TestCreateVerification_SuccessPersistsAuditsAndAppearsInQueue(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := verificationScenario(t, "cv-success-sc")
		h := newVerificationHandler(t, pool, engine)
		seedRunForScenario(t, pool, "cv-success-run", "cv-success-agent", sc.ID)
		uid := seedUser(t, pool, "cv-success-user", "pw-Password1!", "admin", true)

		rec := callAuthed(h.CreateVerification, createVerificationReq(t, map[string]any{
			"runId": "cv-success-run", "expectationId": "exp-manual", "result": "Detected", "note": "confirmed via Sentinel",
		}, auth.RoleAdmin, uid))
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
		}
		var rec1 struct {
			ID          string `json:"id"`
			TechniqueID string `json:"techniqueId"`
			Domain      string `json:"domain"`
			Provider    string `json:"provider"`
			VerifiedBy  string `json:"verifiedBy"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &rec1); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if rec1.TechniqueID != "T1071.001" || rec1.Domain != "siem" || rec1.Provider != "microsoft_sentinel" {
			t.Fatalf("server-resolved metadata wrong: %+v", rec1)
		}
		if rec1.VerifiedBy != uid {
			t.Fatalf("verifiedBy = %q, want %q", rec1.VerifiedBy, uid)
		}

		queueRec := httptest.NewRecorder()
		h.ListRunVerifications(queueRec, verificationsReq("cv-success-run", ""))
		var out struct {
			Items []QueueItem `json:"items"`
		}
		json.Unmarshal(queueRec.Body.Bytes(), &out)
		if len(out.Items) != 1 || out.Items[0].Status != "Detected" || out.Items[0].VerificationID != rec1.ID {
			t.Fatalf("queue after create = %+v, want 1 item status=Detected verificationId=%s", out.Items, rec1.ID)
		}
	})
}

func TestGetVerificationHistory_NilStore503(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.GetVerificationHistory(rec, withURLParams(
			httptest.NewRequest(http.MethodGet, "/x", nil), map[string]string{"runId": "r", "expectationId": "e"}))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
	})
}

func TestGetVerificationHistory_ReflectsAttestationChain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := verificationScenario(t, "gvh-sc")
		h := newVerificationHandler(t, pool, engine)
		seedRunForScenario(t, pool, "gvh-run", "gvh-agent", sc.ID)
		uid := seedUser(t, pool, "gvh-user", "pw-Password1!", "admin", true)

		// First attestation, then a superseding second one.
		callAuthed(h.CreateVerification, createVerificationReq(t, map[string]any{
			"runId": "gvh-run", "expectationId": "exp-manual", "result": "NotDetected", "workflowState": "Pending",
		}, auth.RoleAdmin, uid))
		callAuthed(h.CreateVerification, createVerificationReq(t, map[string]any{
			"runId": "gvh-run", "expectationId": "exp-manual", "result": "Detected",
		}, auth.RoleAdmin, uid))

		rec := httptest.NewRecorder()
		h.GetVerificationHistory(rec, withURLParams(
			httptest.NewRequest(http.MethodGet, "/x", nil), map[string]string{"runId": "gvh-run", "expectationId": "exp-manual"}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			History []map[string]any `json:"history"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out.History) != 2 {
			t.Fatalf("history length = %d, want 2 (both attestations retained)", len(out.History))
		}
	})
}
