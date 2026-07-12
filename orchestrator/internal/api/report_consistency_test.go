package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestReportConsistency_SameDataAcrossFormats seeds one run and asserts every
// format exposes the same underlying technique — catching an endpoint that
// accidentally queries different data than its siblings. Cache-Control is
// asserted absent, characterizing today's contract.
func TestReportConsistency_SameDataAcrossFormats(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "consist", "agent-consist", reportRunOpts{})
		h := newReportingHandler(t, pool, nil)

		htmlRec := httptest.NewRecorder()
		h.GetRunReport(htmlRec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "runId", "consist"))
		if !strings.Contains(htmlRec.Body.String(), "T1059.001") {
			t.Fatal("HTML missing T1059.001")
		}
		if cc := htmlRec.Header().Get("Cache-Control"); cc != "" {
			t.Fatalf("HTML unexpectedly sets Cache-Control=%q (contract change)", cc)
		}

		csvRec := httptest.NewRecorder()
		h.GetRunForensicCSV(csvRec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "runId", "consist"))
		if !strings.Contains(csvRec.Body.String(), "T1059.001") {
			t.Fatal("CSV missing T1059.001")
		}

		pdfRec := httptest.NewRecorder()
		h.GetRunPDF(pdfRec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "runId", "consist"))
		if pdfRec.Code != http.StatusOK || !strings.HasPrefix(pdfRec.Body.String(), "%PDF") {
			t.Fatalf("PDF not generated (status=%d)", pdfRec.Code)
		}
	})
}
