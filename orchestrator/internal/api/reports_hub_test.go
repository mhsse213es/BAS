package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/auth"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestReportDownloadPath_Table exhaustively covers the pure URL reconstructor.
func TestReportDownloadPath_Table(t *testing.T) {
	cases := []struct {
		name                             string
		rtype, format, agent, fw, filter string
		wantErr                          bool
		wantContains                     []string
	}{
		{"posture pdf", "posture", "pdf", "a1", "", "", false, []string{"/api/report/full/pdf", "agentId=a1"}},
		{"posture html", "posture", "html", "a1", "", "", false, []string{"/api/report/full/html"}},
		{"posture csv", "posture", "csv", "a1", "", "", false, []string{"/api/report/full/csv"}},
		{"posture default→pdf", "posture", "", "a1", "", "", false, []string{"/api/report/full/pdf"}},
		{"posture no agent", "posture", "pdf", "", "", "", true, nil},
		{"posture filter", "posture", "pdf", "a1", "", "failed", false, []string{"filter=failed"}},
		{"posture filter=all omitted", "posture", "pdf", "a1", "", "all", false, []string{"/api/report/full/pdf"}},
		{"audit", "audit", "", "a1", "", "", false, []string{"/api/report/audit-pack", "agentId=a1"}},
		{"audit filter", "audit", "", "a1", "", "failed", false, []string{"/api/report/audit-pack", "filter=failed"}},
		{"audit no agent", "audit", "", "", "", "", true, nil},
		{"compliance", "compliance", "json", "a1", "SEBI_CSCRF", "", false, []string{"/api/compliance/report", "framework=SEBI_CSCRF", "format=json"}},
		{"compliance filter", "compliance", "json", "a1", "SEBI_CSCRF", "failed", false, []string{"/api/compliance/report", "filter=failed"}},
		{"compliance default format", "compliance", "", "a1", "SEBI_CSCRF", "", false, []string{"format=html"}},
		{"compliance no fw", "compliance", "json", "a1", "", "", true, nil},
		{"compliance no agent", "compliance", "json", "", "SEBI_CSCRF", "", true, nil},
		{"invalid type", "bogus", "", "a1", "", "", true, nil},
		{"escaping", "compliance", "json", "a b", "F&W", "", false, []string{"agentId=a+b", "framework=F%26W"}},
	}
	for _, c := range cases {
		got, err := reportDownloadPath(c.rtype, c.format, c.agent, c.fw, c.filter)
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: expected error, got path %q", c.name, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: unexpected error %v", c.name, err)
			continue
		}
		for _, sub := range c.wantContains {
			if !strings.Contains(got, sub) {
				t.Errorf("%s: path %q missing %q", c.name, got, sub)
			}
		}
	}
}

func TestCreateReport_PersistsAndReturnsPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		uid := seedUser(t, pool, "reporter", "pw-Password1!", "admin", true)
		h := newReportingHandler(t, pool, nil)
		body := `{"reportType":"posture","format":"pdf","agentId":"agent-x"}`
		req := authedRequest(t, http.MethodPost, "/api/reports", strings.NewReader(body), auth.RoleAdmin, uid)
		rec := callAuthed(h.CreateReport, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !strings.Contains(out["downloadPath"].(string), "/api/report/full/pdf") {
			t.Fatalf("downloadPath = %v", out["downloadPath"])
		}
		var rtype, source, status, by string
		if err := pool.QueryRow(context.Background(),
			`SELECT report_type, source, status, COALESCE(generated_by,'') FROM report_log WHERE id=$1`,
			out["id"],
		).Scan(&rtype, &source, &status, &by); err != nil {
			t.Fatalf("report_log row not found: %v", err)
		}
		if rtype != "posture" || source != "reports_hub" || status != "generated" {
			t.Fatalf("row mismatch: type=%q source=%q status=%q", rtype, source, status)
		}
		if by != uid {
			t.Fatalf("generated_by = %q, want %q", by, uid)
		}
	})
}

func TestCreateReport_InvalidType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		req := httptest.NewRequest(http.MethodPost, "/api/reports", strings.NewReader(`{"reportType":"bogus"}`))
		rec := httptest.NewRecorder()
		h.CreateReport(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

func TestCreateReport_MalformedJSON(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		req := httptest.NewRequest(http.MethodPost, "/api/reports", strings.NewReader(`{"reportType":`))
		rec := httptest.NewRecorder()
		h.CreateReport(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		var n int
		_ = pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM report_log`).Scan(&n)
		if n != 0 {
			t.Fatalf("malformed body should not persist a report_log row, found %d", n)
		}
	})
}

func TestListReports_ReconstructsPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		uid := seedUser(t, pool, "lister", "pw-Password1!", "admin", true)
		h := newReportingHandler(t, pool, nil)
		// Create a report via the real handler so the row shape is authentic.
		createReq := authedRequest(t, http.MethodPost, "/api/reports", strings.NewReader(`{"reportType":"compliance","format":"csv","agentId":"a9","framework":"SEBI_CSCRF"}`), auth.RoleAdmin, uid)
		if rec := callAuthed(h.CreateReport, createReq); rec.Code != http.StatusOK {
			t.Fatalf("seed create status = %d", rec.Code)
		}
		listRec := httptest.NewRecorder()
		h.ListReports(listRec, httptest.NewRequest(http.MethodGet, "/api/reports", nil))
		if listRec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", listRec.Code)
		}
		var out []map[string]any
		if err := json.Unmarshal(listRec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(out) == 0 {
			t.Fatal("expected at least one report row")
		}
		dp, _ := out[0]["downloadPath"].(string)
		if !strings.Contains(dp, "/api/compliance/report") || !strings.Contains(dp, "framework=SEBI_CSCRF") {
			t.Fatalf("reconstructed downloadPath = %q", dp)
		}
	})
}
