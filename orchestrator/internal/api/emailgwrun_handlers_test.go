package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/emailgwrun"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func triggerEmailGWRunReq(t *testing.T, pool *pgxpool.Pool, body map[string]any) *http.Request {
	t.Helper()
	userID := seedUser(t, pool, fmt.Sprintf("emailgwrun-op-%d", time.Now().UnixNano()), "pw12345678", string(auth.RoleAnalyst), true)
	b, _ := json.Marshal(body)
	return authedRequest(t, http.MethodPost, "/api/emailgw-runs", bytes.NewReader(b), auth.RoleAnalyst, userID)
}

// TestTriggerEmailGWRun_NotConfigured_Returns503 proves a deployment
// with no AUDSPECT_EMAILGW_DEFENDER_* credentials refuses clearly,
// same posture as GetCalderaAdversaries when CALDERA_URL is empty --
// never a 500, never a silent no-op injection.
func TestTriggerEmailGWRun_NotConfigured_Returns503(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req := triggerEmailGWRunReq(t, pool, map[string]any{"scenarioId": "EG-002.known-bad"})
		rec := callAuthed(h.TriggerEmailGWRun, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, body = %s, want %d", rec.Code, rec.Body.String(), http.StatusServiceUnavailable)
		}
	})
}

func TestTriggerEmailGWRun_MissingScenarioID_Returns400(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).
			WithEmailGWRun(emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil), emailgwefficacy.InjectionTarget{}, emailgwrun.EnvironmentLab)
		req := triggerEmailGWRunReq(t, pool, map[string]any{})
		rec := callAuthed(h.TriggerEmailGWRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want %d", rec.Code, rec.Body.String(), http.StatusBadRequest)
		}
	})
}

func TestTriggerEmailGWRun_NotWiredScenario_Returns400(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).
			WithEmailGWRun(emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil), emailgwefficacy.InjectionTarget{}, emailgwrun.EnvironmentLab)
		req := triggerEmailGWRunReq(t, pool, map[string]any{"scenarioId": "EG-004.known-good"}) // EICAR, needs a MIME attachment -- not wired
		rec := callAuthed(h.TriggerEmailGWRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want %d", rec.Code, rec.Body.String(), http.StatusBadRequest)
		}
	})
}

func TestTriggerEmailGWRun_Success_Returns201WithRunningStatus(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, addr := startEmailGWRunTestServer(t)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).
			WithEmailGWRun(emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil), emailgwefficacy.InjectionTarget{TargetMX: addr}, emailgwrun.EnvironmentLab)
		req := triggerEmailGWRunReq(t, pool, map[string]any{"scenarioId": "EG-002.known-bad"})
		rec := callAuthed(h.TriggerEmailGWRun, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s, want %d", rec.Code, rec.Body.String(), http.StatusCreated)
		}
		var run emailgwrun.EmailGWRun
		if err := json.Unmarshal(rec.Body.Bytes(), &run); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if run.ID == "" {
			t.Error("want non-empty run ID")
		}
		if run.Status != emailgwrun.StatusRunning {
			t.Errorf("Status = %q, want %q", run.Status, emailgwrun.StatusRunning)
		}
		if run.InitiatedBy == "" {
			t.Error("InitiatedBy should be set from the authenticated caller, never empty")
		}
	})
}

// TestTriggerEmailGWRun_InitiatedByIsServerControlled proves a caller
// can't spoof InitiatedBy through the request body -- same discipline
// TriggerCloudPlanRun's own InitiatedBy field enforces.
func TestTriggerEmailGWRun_InitiatedByIsServerControlled(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, addr := startEmailGWRunTestServer(t)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).
			WithEmailGWRun(emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil), emailgwefficacy.InjectionTarget{TargetMX: addr}, emailgwrun.EnvironmentLab)
		req := triggerEmailGWRunReq(t, pool, map[string]any{"scenarioId": "EG-002.known-bad", "initiatedBy": "spoofed-user"})
		rec := callAuthed(h.TriggerEmailGWRun, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var run emailgwrun.EmailGWRun
		_ = json.Unmarshal(rec.Body.Bytes(), &run)
		if run.InitiatedBy == "spoofed-user" {
			t.Error("InitiatedBy was taken from the request body -- it must always be the authenticated caller")
		}
	})
}

func TestListEmailGWRuns_ReturnsInsertedRun(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, addr := startEmailGWRunTestServer(t)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).
			WithEmailGWRun(emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil), emailgwefficacy.InjectionTarget{TargetMX: addr}, emailgwrun.EnvironmentLab)
		triggerRec := callAuthed(h.TriggerEmailGWRun, triggerEmailGWRunReq(t, pool, map[string]any{"scenarioId": "EG-002.known-bad"}))
		var triggered emailgwrun.EmailGWRun
		_ = json.Unmarshal(triggerRec.Body.Bytes(), &triggered)

		listReq := authedRequest(t, http.MethodGet, "/api/emailgw-runs", nil, auth.RoleAnalyst, "any-authenticated-user")
		rec := callAuthed(h.ListEmailGWRuns, listReq)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var runs []emailgwrun.EmailGWRun
		if err := json.Unmarshal(rec.Body.Bytes(), &runs); err != nil {
			t.Fatalf("decode: %v", err)
		}
		found := false
		for _, r := range runs {
			if r.ID == triggered.ID {
				found = true
			}
		}
		if !found {
			t.Errorf("ListEmailGWRuns did not include the just-triggered run %s", triggered.ID)
		}
	})
}

func TestGetEmailGWRun_NotFound_Returns404(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req := authedRequest(t, http.MethodGet, "/api/emailgw-runs/no-such-id", nil, auth.RoleAnalyst, "any-authenticated-user")
		req = withURLParam(req, "id", "no-such-id")
		rec := callAuthed(h.GetEmailGWRun, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, body = %s, want %d", rec.Code, rec.Body.String(), http.StatusNotFound)
		}
	})
}

func TestGetEmailGWRun_Found_ReturnsRun(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, addr := startEmailGWRunTestServer(t)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).
			WithEmailGWRun(emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil), emailgwefficacy.InjectionTarget{TargetMX: addr}, emailgwrun.EnvironmentLab)
		triggerRec := callAuthed(h.TriggerEmailGWRun, triggerEmailGWRunReq(t, pool, map[string]any{"scenarioId": "EG-002.known-bad"}))
		var triggered emailgwrun.EmailGWRun
		_ = json.Unmarshal(triggerRec.Body.Bytes(), &triggered)

		getReq := authedRequest(t, http.MethodGet, "/api/emailgw-runs/"+triggered.ID, nil, auth.RoleAnalyst, "any-authenticated-user")
		getReq = withURLParam(getReq, "id", triggered.ID)
		rec := callAuthed(h.GetEmailGWRun, getReq)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var got emailgwrun.EmailGWRun
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.ID != triggered.ID {
			t.Errorf("ID = %q, want %q", got.ID, triggered.ID)
		}
	})
}
