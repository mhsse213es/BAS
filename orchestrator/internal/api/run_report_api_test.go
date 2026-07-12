package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestGetRunReport_HTML(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "rr-html", "agent-rr-html", reportRunOpts{})
		h := newReportingHandler(t, pool, nil)
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/rr-html/report", nil), "runId", "rr-html")
		rec := httptest.NewRecorder()
		h.GetRunReport(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Fatalf("content-type = %q", ct)
		}
		if rec.Body.Len() == 0 {
			t.Fatal("empty body")
		}
		if !strings.Contains(rec.Body.String(), "T1059.001") {
			t.Fatalf("HTML report missing seeded technique T1059.001")
		}
	})
}

func TestGetRunReport_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/nope/report", nil), "runId", "nope")
		rec := httptest.NewRecorder()
		h.GetRunReport(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestGetRunReportData_Shape(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "rr-data", "agent-rr-data", reportRunOpts{})
		h := newReportingHandler(t, pool, nil)
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/rr-data/report.json", nil), "runId", "rr-data")
		rec := httptest.NewRecorder()
		h.GetRunReportData(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out["alertsTotal"].(float64) != 42 {
			t.Fatalf("alertsTotal = %v, want 42", out["alertsTotal"])
		}
		if out["noiseScore"].(float64) != 3.5 {
			t.Fatalf("noiseScore = %v, want 3.5", out["noiseScore"])
		}
		if _, ok := out["topFindings"]; !ok {
			t.Fatal("missing topFindings key")
		}
		if _, ok := out["killChain"]; !ok {
			t.Fatal("missing killChain key")
		}
	})
}

func TestGetRunReportData_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/nope/report.json", nil), "runId", "nope")
		rec := httptest.NewRecorder()
		h.GetRunReportData(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestGetRunPDF_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "rr-pdf", "agent-rr-pdf", reportRunOpts{})
		h := newReportingHandler(t, pool, nil)
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/rr-pdf/pdf", nil), "runId", "rr-pdf")
		rec := httptest.NewRecorder()
		h.GetRunPDF(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body len = %d", rec.Code, rec.Body.Len())
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/pdf" {
			t.Fatalf("content-type = %q", ct)
		}
		if rec.Body.Len() == 0 || !strings.HasPrefix(rec.Body.String(), "%PDF") {
			t.Fatalf("body is not a PDF (len=%d)", rec.Body.Len())
		}
		cd := rec.Header().Get("Content-Disposition")
		if !regexp.MustCompile(`filename="bas-report-.*\.pdf"`).MatchString(cd) {
			t.Fatalf("content-disposition = %q", cd)
		}
	})
}

func TestGetRunPDF_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/nope/pdf", nil), "runId", "nope")
		rec := httptest.NewRecorder()
		h.GetRunPDF(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestGetRunForensicCSV_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "rr-csv", "agent-rr-csv", reportRunOpts{})
		h := newReportingHandler(t, pool, nil)
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/rr-csv/forensic.csv", nil), "runId", "rr-csv")
		rec := httptest.NewRecorder()
		h.GetRunForensicCSV(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
			t.Fatalf("content-type = %q", ct)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "T1059.001") {
			t.Fatalf("CSV missing seeded technique T1059.001:\n%s", body)
		}
		if !regexp.MustCompile(`filename="bas-forensic-.*\.csv"`).MatchString(rec.Header().Get("Content-Disposition")) {
			t.Fatalf("content-disposition = %q", rec.Header().Get("Content-Disposition"))
		}
	})
}

func TestGetRunForensicCSV_FilterApplied(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "rr-csv-f", "agent-rr-csv-f", reportRunOpts{})
		h := newReportingHandler(t, pool, nil)
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/rr-csv-f/forensic.csv?filter=prevented", nil), "runId", "rr-csv-f")
		rec := httptest.NewRecorder()
		h.GetRunForensicCSV(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		// filter=prevented keeps only the single PASS result; the FAILs drop out.
		body := rec.Body.String()
		if strings.Contains(body, "T1059.001") {
			t.Fatalf("filter=prevented should have dropped the failing T1059.001 row:\n%s", body)
		}
		if !strings.Contains(body, "T1547.001") {
			t.Fatalf("filter=prevented should keep the passing T1547.001 row:\n%s", body)
		}
		if !strings.Contains(rec.Header().Get("Content-Disposition"), "-prevented-") {
			t.Fatalf("filename missing -prevented- suffix: %q", rec.Header().Get("Content-Disposition"))
		}
	})
}

func TestGetRunForensicCSV_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/nope/forensic.csv", nil), "runId", "nope")
		rec := httptest.NewRecorder()
		h.GetRunForensicCSV(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}
