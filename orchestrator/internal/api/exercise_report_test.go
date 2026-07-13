package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/exercise"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestGetExerciseReportJSON_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GetExerciseReportJSON(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", "nope"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestGetExerciseReportJSON_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		execID := launchedExecution(t, h, []exercise.PlanStep{minimalStep("a")})

		rec := httptest.NewRecorder()
		h.GetExerciseReportJSON(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", execID))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type = %q, want application/json", ct)
		}
		if !strings.Contains(rec.Body.String(), execID) {
			t.Error("expected the report JSON body to reference the execution ID")
		}
	})
}

func TestGetExerciseReportHTML_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		execID := launchedExecution(t, h, []exercise.PlanStep{minimalStep("a")})

		rec := httptest.NewRecorder()
		h.GetExerciseReportHTML(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", execID))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		if !strings.HasPrefix(strings.TrimSpace(rec.Body.String()), "<!") && !strings.Contains(rec.Body.String(), "<html") {
			t.Error("expected an HTML document body")
		}
	})
}

func TestGetExerciseReportCSV_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		execID := launchedExecution(t, h, []exercise.PlanStep{minimalStep("a")})

		rec := httptest.NewRecorder()
		h.GetExerciseReportCSV(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", execID))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		if ct := rec.Header().Get("Content-Type"); ct != "text/csv" {
			t.Errorf("content-type = %q, want text/csv", ct)
		}
	})
}

func TestGetExerciseReportPDF_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := exerciseHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GetExerciseReportPDF(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", "nope"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

// TestGetExerciseReportPDF_NoSidecarConfigured characterizes a real gap:
// unlike the full-report PDF path (Engine.PDFFromReport in
// internal/reporting/htmlpdf.go), reporting.ExerciseReportPDF has no fpdf
// fallback — it calls htmlToPDF directly and surfaces its error as a 500 when
// CHROME_WS_URL is unconfigured. This contradicts exercise.go's own package
// doc comment ("PDF (HTML→Chrome sidecar with fpdf fallback)"). Flagged, not
// fixed, per the "flag unrelated bugs, don't fix without asking" policy.
func TestGetExerciseReportPDF_NoSidecarConfigured(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		t.Setenv("CHROME_WS_URL", "")
		h := exerciseHandler(t, pool)
		execID := launchedExecution(t, h, []exercise.PlanStep{minimalStep("a")})

		rec := httptest.NewRecorder()
		h.GetExerciseReportPDF(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", execID))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500 (no fpdf fallback exists for exercise reports, unlike full reports)", rec.Code)
		}
	})
}
