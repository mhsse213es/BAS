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

// TestGetExerciseReportPDF_NoSidecarConfigured pins the fix: ExerciseReportPDF
// now falls back to a plain fpdf-rendered summary when the Chrome sidecar is
// unconfigured or unreachable (exerciseReportFallbackPDF in
// internal/reporting/exercise.go), mirroring the fallback the full-report PDF
// path already had (Engine.PDFFromReport in htmlpdf.go). The endpoint always
// returns a PDF now, matching exercise.go's own doc comment.
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
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		if rec.Header().Get("Content-Type") != "application/pdf" {
			t.Errorf("content-type = %q, want application/pdf", rec.Header().Get("Content-Type"))
		}
		if !strings.HasPrefix(rec.Body.String(), "%PDF") {
			t.Error("body is not a PDF")
		}
	})
}
