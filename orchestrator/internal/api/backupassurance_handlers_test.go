package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestTriggerBackupAssuranceAssessment_ReturnsSixCamelCaseResults(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodPost, "/api/backup-assurance/assessments", nil)
		rec := httptest.NewRecorder()

		h.TriggerBackupAssuranceAssessment(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		for _, key := range []string{`"assessmentId"`, `"results"`, `"check"`, `"verdict"`, `"simulated"`, `"observer"`} {
			if !strings.Contains(body, key) {
				t.Fatalf("response body missing camelCase key %s; got: %s", key, body)
			}
		}
		var got struct {
			AssessmentID string `json:"assessmentId"`
			Results      []struct {
				Check     string `json:"check"`
				Simulated bool   `json:"simulated"`
			} `json:"results"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.AssessmentID == "" {
			t.Fatal("assessmentId is empty")
		}
		if len(got.Results) != 6 {
			t.Fatalf("got %d results, want 6", len(got.Results))
		}
		for _, r := range got.Results {
			if !r.Simulated {
				t.Fatalf("check %s has simulated=false, want true", r.Check)
			}
		}
	})
}

func TestGetBackupAssuranceAssessment_RealAssessmentReturnsSixResults(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")

		triggerReq := httptest.NewRequest(http.MethodPost, "/api/backup-assurance/assessments", nil)
		triggerRec := httptest.NewRecorder()
		h.TriggerBackupAssuranceAssessment(triggerRec, triggerReq)
		var triggered struct {
			AssessmentID string `json:"assessmentId"`
		}
		if err := json.Unmarshal(triggerRec.Body.Bytes(), &triggered); err != nil {
			t.Fatalf("decode trigger response: %v", err)
		}

		getReq := httptest.NewRequest(http.MethodGet, "/api/backup-assurance/assessments/"+triggered.AssessmentID, nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("assessmentId", triggered.AssessmentID)
		getReq = getReq.WithContext(context.WithValue(getReq.Context(), chi.RouteCtxKey, rctx))
		getRec := httptest.NewRecorder()

		h.GetBackupAssuranceAssessment(getRec, getReq)

		if getRec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", getRec.Code, getRec.Body.String())
		}
	})
}

func TestGetBackupAssuranceAssessment_NonexistentIDReturns404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/api/backup-assurance/assessments/does-not-exist", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("assessmentId", "does-not-exist")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		rec := httptest.NewRecorder()

		h.GetBackupAssuranceAssessment(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestGetBackupAssuranceAssessment_IncompleteRowCountReturns500(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")

		triggerReq := httptest.NewRequest(http.MethodPost, "/api/backup-assurance/assessments", nil)
		triggerRec := httptest.NewRecorder()
		h.TriggerBackupAssuranceAssessment(triggerRec, triggerReq)
		var triggered struct {
			AssessmentID string `json:"assessmentId"`
		}
		if err := json.Unmarshal(triggerRec.Body.Bytes(), &triggered); err != nil {
			t.Fatalf("decode trigger response: %v", err)
		}
		if _, err := pool.Exec(context.Background(), `DELETE FROM backup_assurance_results WHERE assessment_id = $1 AND check_name = 'rpo_rto'`, triggered.AssessmentID); err != nil {
			t.Fatalf("corrupt: %v", err)
		}

		getReq := httptest.NewRequest(http.MethodGet, "/api/backup-assurance/assessments/"+triggered.AssessmentID, nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("assessmentId", triggered.AssessmentID)
		getReq = getReq.WithContext(context.WithValue(getReq.Context(), chi.RouteCtxKey, rctx))
		getRec := httptest.NewRecorder()

		h.GetBackupAssuranceAssessment(getRec, getReq)

		if getRec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500 for an incomplete (5-of-6) assessment", getRec.Code)
		}
	})
}
