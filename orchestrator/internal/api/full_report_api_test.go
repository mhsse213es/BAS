package api

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func newReqCtx() context.Context { return context.Background() }

func fullReq(path, agentID string) *http.Request {
	if agentID != "" {
		path += "?agentId=" + agentID
	}
	return httptest.NewRequest(http.MethodGet, path, nil)
}

func TestGetFullReportHTML_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "fr-html", "agent-fr-html", reportRunOpts{})
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetFullReportHTML(rec, fullReq("/api/report/full/html", "agent-fr-html"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		if !strings.Contains(body, "T1059.001") {
			t.Fatal("full HTML report missing seeded technique")
		}
		// Compliance summary rows present because a mapper is attached — at least
		// one known framework name string should appear.
		if !strings.Contains(body, "SEBI") && !strings.Contains(body, "NIST") && !strings.Contains(body, "ISO") {
			t.Fatalf("expected compliance summary rows in full HTML report")
		}
	})
}

func TestGetFullReportHTML_NoMapper(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "fr-nomap", "agent-fr-nomap", reportRunOpts{})
		// Handler WITHOUT WithCompliance — complianceRows returns nil, report still renders.
		t.Setenv("CHROME_WS_URL", "")
		engine := scenario.NewEngine(t.TempDir())
		h := New(pool, ws.NewHub(), engine, "").
			WithReporting(reporting.NewEngine(pool).WithScenarios(engine))
		rec := httptest.NewRecorder()
		h.GetFullReportHTML(rec, fullReq("/api/report/full/html", "agent-fr-nomap"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (report should render without a mapper)", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "T1059.001") {
			t.Fatal("report body missing seeded technique")
		}
	})
}

func TestFullReport_MissingAgentID_Matrix(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		cases := []struct {
			name string
			fn   http.HandlerFunc
			path string
		}{
			{"html", h.GetFullReportHTML, "/api/report/full/html"},
			{"pdf", h.GetFullReportPDF, "/api/report/full/pdf"},
			{"csv", h.GetFullReportCSV, "/api/report/full/csv"},
			{"auditpack", h.GetAuditPack, "/api/report/audit-pack"},
		}
		for _, c := range cases {
			rec := httptest.NewRecorder()
			c.fn(rec, fullReq(c.path, "")) // no agentId
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s: status = %d, want 400", c.name, rec.Code)
			}
		}
	})
}

func TestGetFullReportPDF_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "fr-pdf", "agent-fr-pdf", reportRunOpts{})
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetFullReportPDF(rec, fullReq("/api/report/full/pdf", "agent-fr-pdf"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if rec.Header().Get("Content-Type") != "application/pdf" {
			t.Fatalf("content-type = %q", rec.Header().Get("Content-Type"))
		}
		if !strings.HasPrefix(rec.Body.String(), "%PDF") {
			t.Fatal("body is not a PDF")
		}
		if !regexp.MustCompile(`filename="bas-report-.*\.pdf"`).MatchString(rec.Header().Get("Content-Disposition")) {
			t.Fatalf("content-disposition = %q", rec.Header().Get("Content-Disposition"))
		}
	})
}

// TestGetFullReportCSV_LatestRunOnly pins that the agent-level CSV reflects only
// the LATEST completed/partial run, not older ones (business logic, not
// rendering). The older run carries T1003.001; the newer carries only the
// override technique — the CSV must contain the newer, not the older.
func TestGetFullReportCSV_LatestRunOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		agentID := "agent-fr-latest"
		older := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
		newer := time.Date(2026, 6, 2, 9, 0, 0, 0, time.UTC)
		seedReportableRun(t, pool, "fr-old", agentID, reportRunOpts{StartedAt: older, TechniqueOverride: "T1003.001"})
		seedReportableRun(t, pool, "fr-new", agentID, reportRunOpts{StartedAt: newer, TechniqueOverride: "T1218.011"})
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetFullReportCSV(rec, fullReq("/api/report/full/csv", agentID))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "T1218.011") {
			t.Fatalf("CSV should contain the latest run's technique T1218.011:\n%s", body)
		}
		if strings.Contains(body, "T1003.001") {
			t.Fatalf("CSV should NOT contain the older run's technique T1003.001 (latest-only):\n%s", body)
		}
	})
}

func TestGetFullReportCSV_NoCompletedRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		// Agent exists (seeded via a running-only run) but no completed/partial run.
		seedReportableRun(t, pool, "fr-running", "agent-fr-none", reportRunOpts{Status: "running"})
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetFullReportCSV(rec, fullReq("/api/report/full/csv", "agent-fr-none"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestGetAuditPack_ZeroRunsGuard(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "ap-running", "agent-ap-none", reportRunOpts{Status: "running"})
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetAuditPack(rec, fullReq("/api/report/audit-pack", "agent-ap-none"))
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422", rec.Code)
		}
	})
}

func TestGetAuditPack_ZIPStructure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		// Run IDs must be realistic length (>=8 chars): auditpack.go:163 slices
		// runID[:8] unguarded. Production IDs are hex-nanos (~15) or UUIDs (36).
		seedReportableRun(t, pool, "ap-ok-run-0001", "agent-ap-ok", reportRunOpts{})
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetAuditPack(rec, fullReq("/api/report/audit-pack", "agent-ap-ok"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if rec.Header().Get("Content-Type") != "application/zip" {
			t.Fatalf("content-type = %q", rec.Header().Get("Content-Type"))
		}
		raw := rec.Body.Bytes()
		zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
		if err != nil {
			t.Fatalf("not a valid zip: %v", err)
		}
		// Audit-pack entries carry a "bas-audit-pack-<host>-<date>/" directory
		// prefix, so match by suffix rather than exact name.
		hasSuffix := func(suffix string) bool {
			for _, f := range zr.File {
				if strings.HasSuffix(f.Name, suffix) {
					return true
				}
			}
			return false
		}
		var runEntry string
		for _, f := range zr.File {
			if strings.Contains(f.Name, "/runs/") {
				runEntry = f.Name
			}
		}
		for _, want := range []string{"/README.txt", "/summary.json", "/executive-report.html", "/agent-inventory.json", "/MANIFEST.txt"} {
			if !hasSuffix(want) {
				var have []string
				for _, f := range zr.File {
					have = append(have, f.Name)
				}
				t.Fatalf("audit pack missing entry *%q; have %v", want, have)
			}
		}
		if len(zr.File) < 6 {
			t.Fatalf("audit pack entry count = %d, want >= 6", len(zr.File))
		}
		if runEntry == "" {
			t.Fatal("audit pack has no runs/*.json entry")
		}
		// One entry contains seeded content.
		rf, err := zr.Open(runEntry)
		if err != nil {
			t.Fatalf("open run entry: %v", err)
		}
		defer rf.Close()
		content, _ := io.ReadAll(rf)
		if !strings.Contains(string(content), "T1059.001") {
			t.Fatalf("run entry %q missing seeded technique T1059.001", runEntry)
		}
	})
}

// TestGetAuditPack_ShortRunID_NoPanic regression-tests auditpack.go:163, which
// used to slice runID[:8] unconditionally and panicked (slice bounds out of
// range) whenever a run ID was under 8 characters. Production IDs are always
// long enough (hex-nanos ~15 chars, or 36-char UUIDs) that this was never
// reachable in prod, but the slice was still an unguarded landmine — this
// pins the len(runID) guard added alongside it.
func TestGetAuditPack_ShortRunID_NoPanic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "ap5", "agent-ap-short", reportRunOpts{})
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetAuditPack(rec, fullReq("/api/report/audit-pack", "agent-ap-short"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		raw := rec.Body.Bytes()
		zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
		if err != nil {
			t.Fatalf("not a valid zip: %v", err)
		}
		var found bool
		for _, f := range zr.File {
			if strings.Contains(f.Name, "/runs/") && strings.HasSuffix(f.Name, "-ap5.json") {
				found = true
			}
		}
		if !found {
			var have []string
			for _, f := range zr.File {
				have = append(have, f.Name)
			}
			t.Fatalf("expected a runs/*-ap5.json entry (short ID used as-is); have %v", have)
		}
	})
}

// TestAggregateAgentResults_DedupAndUnion pins the dedup-by-result-ID and
// union-across-completed/partial business logic (white-box call).
func TestAggregateAgentResults_DedupAndUnion(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		agentID := "agent-agg"
		shared := models.SimulationResult{ID: "shared-id", Technique: models.AttackTechnique{ID: "T1000"}, Result: models.ResultFail}
		uniqA := models.SimulationResult{ID: "uniq-a", Technique: models.AttackTechnique{ID: "T1001"}, Result: models.ResultPass}
		uniqB := models.SimulationResult{ID: "uniq-b", Technique: models.AttackTechnique{ID: "T1002"}, Result: models.ResultPass}
		seedReportableRun(t, pool, "agg-1", agentID, reportRunOpts{Status: "completed", Results: []models.SimulationResult{shared, uniqA}})
		seedReportableRun(t, pool, "agg-2", agentID, reportRunOpts{Status: "partial", Results: []models.SimulationResult{shared, uniqB}})
		seedReportableRun(t, pool, "agg-run", agentID, reportRunOpts{Status: "running", Results: []models.SimulationResult{{ID: "excluded", Result: models.ResultFail}}})
		h := newReportingHandler(t, pool, nil)
		got := h.aggregateAgentResults(newReqCtx(), agentID)
		ids := map[string]int{}
		for _, r := range got {
			ids[r.ID]++
		}
		if ids["shared-id"] != 1 {
			t.Fatalf("shared-id count = %d, want exactly 1 (dedup)", ids["shared-id"])
		}
		if ids["uniq-a"] != 1 || ids["uniq-b"] != 1 {
			t.Fatalf("expected both unique results present: %v", ids)
		}
		if ids["excluded"] != 0 {
			t.Fatal("running-status run's results must be excluded from aggregate")
		}
		if len(got) != 3 {
			t.Fatalf("aggregate len = %d, want 3", len(got))
		}
	})
}

func TestComplianceRows_AggregatesAllRuns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "cr-1", "agent-cr", reportRunOpts{})
		h := newReportingHandler(t, pool, nil)
		rows := h.complianceRows(newReqCtx(), "agent-cr", "")
		if len(rows) == 0 {
			t.Fatal("expected compliance summary rows for every mapper framework")
		}
		if len(rows) != len(h.complianceMapper.Frameworks()) {
			t.Fatalf("row count = %d, want one per framework (%d)", len(rows), len(h.complianceMapper.Frameworks()))
		}
	})
}

func TestSanitizeFilename_Table(t *testing.T) {
	cases := []struct{ in, want string }{
		{"clean-name_1", "clean-name_1"},
		{"has spaces", "has_spaces"},
		{"a/b\\c", "a_b_c"},
		{"a:b*c?d\"e<f>g|h", "a_b_c_d_e_f_g_h"},
		{"dot.name", "dot_name"},
		{"", ""},
		{"café", "caf__"}, // é is 2 UTF-8 bytes → 2 underscores
	}
	for _, c := range cases {
		if got := sanitizeFilename(c.in); got != c.want {
			t.Errorf("sanitizeFilename(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// 32-char cap.
	long := strings.Repeat("x", 40)
	if got := sanitizeFilename(long); len(got) != 32 {
		t.Errorf("cap: len = %d, want 32", len(got))
	}
	exactly32 := strings.Repeat("y", 32)
	if got := sanitizeFilename(exactly32); got != exactly32 {
		t.Errorf("exactly-32 mangled: %q", got)
	}
}
