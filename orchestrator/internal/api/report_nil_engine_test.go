package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestReportHandlers_NilEngine503 covers every reporting-engine-dependent
// endpoint in 3d.1 scope with a Handler that has no reporting engine attached.
// Endpoints that do NOT touch the engine (GetRunForensicCSV, GetCampaignCSV,
// CreateReport, ListReports) are intentionally excluded — that exclusion itself
// documents which handlers depend on the engine.
func TestReportHandlers_NilEngine503(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		// No WithReporting — reportingEngine stays nil.
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		cases := []struct {
			name string
			fn   http.HandlerFunc
			req  *http.Request
		}{
			{"GetRunReport", h.GetRunReport, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "runId", "r")},
			{"GetRunReportData", h.GetRunReportData, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "runId", "r")},
			{"GetRunPDF", h.GetRunPDF, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "runId", "r")},
			{"GetFullReportHTML", h.GetFullReportHTML, httptest.NewRequest(http.MethodGet, "/x?agentId=a", nil)},
			{"GetFullReportPDF", h.GetFullReportPDF, httptest.NewRequest(http.MethodGet, "/x?agentId=a", nil)},
			{"GetFullReportCSV", h.GetFullReportCSV, httptest.NewRequest(http.MethodGet, "/x?agentId=a", nil)},
			{"GetAuditPack", h.GetAuditPack, httptest.NewRequest(http.MethodGet, "/x?agentId=a", nil)},
			{"GetCampaignReport", h.GetCampaignReport, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", "c")},
			{"GetCampaignPDF", h.GetCampaignPDF, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", "c")},
		}
		for _, c := range cases {
			rec := httptest.NewRecorder()
			c.fn(rec, c.req)
			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("%s: status = %d, want 503", c.name, rec.Code)
			}
		}
	})
}
