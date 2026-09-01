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

// complianceReq builds a GET request for a compliance endpoint from a raw,
// already-encoded query string (e.g. "framework=SEBI_CSCRF&agentId=a1").
func complianceReq(path, query string) *http.Request {
	if query != "" {
		path += "?" + query
	}
	return httptest.NewRequest(http.MethodGet, path, nil)
}

// TestListComplianceFrameworks_Success pins the 7 bundled frameworks
// (internal/compliance/mappings/*.yaml) and their sort-by-ID order.
func TestListComplianceFrameworks_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.ListComplianceFrameworks(rec, complianceReq("/api/compliance/frameworks", ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out []struct {
			ID            string `json:"id"`
			TotalControls int    `json:"totalControls"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		wantIDs := []string{"CERT_IN", "IRDAI_CSF", "ISO_27001_2022", "NIST_CSF_2", "PCI_DSS_V4", "RBI_CSF", "SEBI_CSCRF"}
		if len(out) != len(wantIDs) {
			t.Fatalf("framework count = %d, want %d", len(out), len(wantIDs))
		}
		for i, want := range wantIDs {
			if out[i].ID != want {
				t.Errorf("frameworks[%d].id = %q, want %q (sorted by ID)", i, out[i].ID, want)
			}
			if out[i].TotalControls == 0 {
				t.Errorf("frameworks[%d] (%s) has 0 totalControls", i, out[i].ID)
			}
		}
	})
}

func TestGetComplianceReport_MissingFramework(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetComplianceReport(rec, complianceReq("/api/compliance/report", "agentId=a1"))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

func TestGetComplianceReport_MissingAgentAndRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetComplianceReport(rec, complianceReq("/api/compliance/report", "framework=SEBI_CSCRF"))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

func TestGetComplianceReport_UnknownFramework(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "cr-unknown-fw-run", "agent-cr-unknown-fw", reportRunOpts{})
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetComplianceReport(rec, complianceReq("/api/compliance/report", "framework=NOT_A_FRAMEWORK&agentId=agent-cr-unknown-fw"))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestGetComplianceReport_RunNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetComplianceReport(rec, complianceReq("/api/compliance/report", "framework=SEBI_CSCRF&runId=nope"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestGetComplianceReport_AgentNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetComplianceReport(rec, complianceReq("/api/compliance/report", "framework=SEBI_CSCRF&agentId=nope"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

// TestGetComplianceReport_ByRunID_Single pins the single-run path: the
// scenario name comes straight from the seeded run, not the "Aggregated
// across N run(s)" synthetic label used by the agentId (no runId) path.
func TestGetComplianceReport_ByRunID_Single(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "cr-single-run", "agent-cr-single", reportRunOpts{Name: "Single Run Compliance Check"})
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetComplianceReport(rec, complianceReq("/api/compliance/report", "framework=SEBI_CSCRF&runId=cr-single-run"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			AgentID      string `json:"agentId"`
			RunID        string `json:"runId"`
			ScenarioName string `json:"scenarioName"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out.RunID != "cr-single-run" || out.AgentID != "agent-cr-single" {
			t.Fatalf("runId/agentId = %q/%q", out.RunID, out.AgentID)
		}
		if out.ScenarioName != "Single Run Compliance Check" {
			t.Fatalf("scenarioName = %q, want the seeded run name (not aggregated)", out.ScenarioName)
		}
	})
}

// TestGetComplianceReport_ByAgentID_Aggregate pins the multi-run aggregation
// path: two runs with distinct techniques must both surface as evidence in
// the resulting report, and the scenario name becomes the synthetic
// "Aggregated across N run(s)" label.
func TestGetComplianceReport_ByAgentID_Aggregate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "cr-agg-run-1", "agent-cr-agg", reportRunOpts{TechniqueOverride: "T1059.002"})
		seedReportableRun(t, pool, "cr-agg-run-2", "agent-cr-agg", reportRunOpts{TechniqueOverride: "T1003.002"})
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetComplianceReport(rec, complianceReq("/api/compliance/report", "framework=SEBI_CSCRF&agentId=agent-cr-agg"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		if !strings.Contains(body, "Aggregated across 2 run(s)") {
			t.Errorf("scenarioName should be the aggregated label; body = %s", body)
		}
		if !strings.Contains(body, "T1059.002") || !strings.Contains(body, "T1003.002") {
			t.Errorf("aggregated report should surface evidence from both runs; body = %s", body)
		}
	})
}

func TestGetComplianceReport_FormatCSV(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "cr-csv-run", "agent-cr-csv", reportRunOpts{})
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetComplianceReport(rec, complianceReq("/api/compliance/report", "framework=SEBI_CSCRF&agentId=agent-cr-csv&format=csv"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if rec.Header().Get("Content-Type") != "text/csv; charset=utf-8" {
			t.Fatalf("content-type = %q", rec.Header().Get("Content-Type"))
		}
		if !regexp.MustCompile(`filename="Audspect_Compliance_Report_.*\.csv"`).MatchString(rec.Header().Get("Content-Disposition")) {
			t.Fatalf("content-disposition = %q", rec.Header().Get("Content-Disposition"))
		}
		if !strings.HasPrefix(rec.Body.String(), "Framework,Version,Control ID,Control Name,Domain,Category,Validation,Status,Tested,Passed,Failed,Failing Techniques") {
			t.Fatalf("csv header row missing; body starts: %.100s", rec.Body.String())
		}
	})
}

func TestGetComplianceReport_FormatJSON(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "cr-json-run", "agent-cr-json", reportRunOpts{})
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetComplianceReport(rec, complianceReq("/api/compliance/report", "framework=SEBI_CSCRF&agentId=agent-cr-json&format=json"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if rec.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("content-type = %q", rec.Header().Get("Content-Type"))
		}
		if !regexp.MustCompile(`filename="Audspect_Compliance_Report_.*\.json"`).MatchString(rec.Header().Get("Content-Disposition")) {
			t.Fatalf("content-disposition = %q", rec.Header().Get("Content-Disposition"))
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("body is not valid JSON: %v", err)
		}
		if out["agentId"] != "agent-cr-json" {
			t.Fatalf("agentId = %v", out["agentId"])
		}
	})
}

func TestGetComplianceReport_DefaultFormat_NoAttachmentHeader(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "cr-default-run", "agent-cr-default", reportRunOpts{})
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetComplianceReport(rec, complianceReq("/api/compliance/report", "framework=SEBI_CSCRF&agentId=agent-cr-default"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if rec.Header().Get("Content-Disposition") != "" {
			t.Errorf("default format should not set an attachment header, got %q", rec.Header().Get("Content-Disposition"))
		}
	})
}

// TestGetComplianceReport_FilterApplied pins that `filter` is applied to the
// underlying results BEFORE scoring: canonicalResults has two FAIL results
// mapped into SEBI_CSCRF controls (T1059.001, T1003.001 both fall under
// techIndex base entries), so the unfiltered report must show failing
// controls, while filter=prevented (keeps only PASS/BLOCKED results) must
// not.
func TestGetComplianceReport_FilterApplied(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "cr-filter-run", "agent-cr-filter", reportRunOpts{})
		h := newReportingHandler(t, pool, nil)

		unfiltered := httptest.NewRecorder()
		h.GetComplianceReport(unfiltered, complianceReq("/api/compliance/report", "framework=SEBI_CSCRF&agentId=agent-cr-filter"))
		var un struct {
			Summary struct {
				FailingControls int `json:"failingControls"`
			} `json:"summary"`
		}
		if err := json.Unmarshal(unfiltered.Body.Bytes(), &un); err != nil {
			t.Fatalf("decode unfiltered: %v", err)
		}
		if un.Summary.FailingControls == 0 {
			t.Fatal("unfiltered report should have failing controls from canonicalResults' FAIL techniques")
		}

		filtered := httptest.NewRecorder()
		h.GetComplianceReport(filtered, complianceReq("/api/compliance/report", "framework=SEBI_CSCRF&agentId=agent-cr-filter&filter=prevented"))
		var f struct {
			Summary struct {
				FailingControls int `json:"failingControls"`
			} `json:"summary"`
		}
		if err := json.Unmarshal(filtered.Body.Bytes(), &f); err != nil {
			t.Fatalf("decode filtered: %v", err)
		}
		if f.Summary.FailingControls != 0 {
			t.Fatalf("filter=prevented should leave zero failing controls (only PASS results survive), got %d", f.Summary.FailingControls)
		}
	})
}

func TestGetComplianceDashboardScores_PerAgent_ZeroState(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetComplianceDashboardScores(rec, complianceReq("/api/compliance/scores", "agentId=agent-no-snapshots"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var out []struct {
			FrameworkID    string `json:"frameworkId"`
			FrameworkName  string `json:"frameworkName"`
			ShortName      string `json:"shortName"`
			Regulator      string `json:"regulator"`
			TestedControls int    `json:"testedControls"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(out) != 7 {
			t.Fatalf("zero-state should still return all 7 frameworks, got %d", len(out))
		}
		for _, s := range out {
			if s.FrameworkName == "" || s.ShortName == "" {
				t.Errorf("%s: missing enrichment (name=%q shortName=%q)", s.FrameworkID, s.FrameworkName, s.ShortName)
			}
			if s.TestedControls != 0 {
				t.Errorf("%s: zero-state should have 0 tested controls, got %d", s.FrameworkID, s.TestedControls)
			}
		}
	})
}

func TestGetComplianceDashboardScores_PerAgent_WithSnapshot(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "cds-snap-run", "agent-cds-snap", reportRunOpts{})
		h := newReportingHandler(t, pool, nil)
		h.refreshComplianceSnapshots(newReqCtx(), "agent-cds-snap")

		rec := httptest.NewRecorder()
		h.GetComplianceDashboardScores(rec, complianceReq("/api/compliance/scores", "agentId=agent-cds-snap"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var out []struct {
			FrameworkID    string `json:"frameworkId"`
			TestedControls int    `json:"testedControls"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		var sebi *int
		for _, s := range out {
			if s.FrameworkID == "SEBI_CSCRF" {
				tc := s.TestedControls
				sebi = &tc
			}
		}
		if sebi == nil {
			t.Fatal("SEBI_CSCRF entry missing from scores response")
		}
		if *sebi == 0 {
			t.Fatal("SEBI_CSCRF should show tested controls after refreshComplianceSnapshots ran against canonicalResults")
		}
	})
}

func TestGetComplianceDashboardScores_Fleet_NoAgentID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "cds-fleet-run-1", "agent-cds-fleet-1", reportRunOpts{})
		seedReportableRun(t, pool, "cds-fleet-run-2", "agent-cds-fleet-2", reportRunOpts{})
		h := newReportingHandler(t, pool, nil)
		h.refreshComplianceSnapshots(newReqCtx(), "agent-cds-fleet-1")
		h.refreshComplianceSnapshots(newReqCtx(), "agent-cds-fleet-2")

		rec := httptest.NewRecorder()
		h.GetComplianceDashboardScores(rec, complianceReq("/api/compliance/scores", ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var out []struct {
			FrameworkID    string `json:"frameworkId"`
			TestedControls int    `json:"testedControls"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(out) != 7 {
			t.Fatalf("fleet view should return all 7 frameworks, got %d", len(out))
		}
		var sebi *int
		for _, s := range out {
			if s.FrameworkID == "SEBI_CSCRF" {
				tc := s.TestedControls
				sebi = &tc
			}
		}
		if sebi == nil || *sebi == 0 {
			t.Fatal("fleet-wide SEBI_CSCRF entry should aggregate tested controls across both agents")
		}
	})
}

// TestComplianceShortName_Table exhaustively covers the pure display-label
// mapping: all 7 bundled framework IDs plus an unknown-ID passthrough.
func TestComplianceShortName_Table(t *testing.T) {
	cases := []struct{ id, want string }{
		{"SEBI_CSCRF", "SEBI CSCRF"},
		{"RBI_CSF", "RBI CSF"},
		{"CERT_IN", "CERT-In"},
		{"IRDAI_CSF", "IRDAI"},
		{"ISO_27001_2022", "ISO 27001"},
		{"NIST_CSF_2", "NIST CSF"},
		{"PCI_DSS_V4", "PCI DSS v4"},
		{"UNKNOWN_FW", "UNKNOWN_FW"},
	}
	for _, c := range cases {
		if got := complianceShortName(c.id); got != c.want {
			t.Errorf("complianceShortName(%q) = %q, want %q", c.id, got, c.want)
		}
	}
}
