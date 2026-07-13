package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/auth"
	"github.com/jackc/pgx/v5/pgxpool"
)

func findingsReq(path, query string) *http.Request {
	if query != "" {
		path += "?" + query
	}
	return httptest.NewRequest(http.MethodGet, path, nil)
}

func TestListFindings_Empty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.ListFindings(rec, findingsReq("/api/findings", ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if strings.TrimSpace(rec.Body.String()) != "[]" {
			t.Fatalf("body = %q, want empty JSON array", rec.Body.String())
		}
	})
}

// TestListFindings_FiltersAndOrdering seeds a Critical/missed finding and a
// Medium/prevented-then-open finding on two agents, then pins: status filter,
// severity filter, agentId filter, and severity-then-recency ordering
// (Critical sorts before Medium regardless of insertion order).
func TestListFindings_FiltersAndOrdering(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		t0 := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		h := newReportingHandler(t, pool, nil)

		// Medium/open finding seeded first...
		seedReportableRun(t, pool, "lf-med-run", "agent-lf-a", reportRunOpts{
			StartedAt: t0, Results: oneResult("r1", "T1547.001", "fail", "Medium", t0),
		})
		h.upsertFindingsForRun(context.Background(), "lf-med-run")

		// ...Critical/open finding seeded second, on a different agent.
		t1 := t0.Add(1 * time.Hour)
		seedReportableRun(t, pool, "lf-crit-run", "agent-lf-b", reportRunOpts{
			StartedAt: t1, Results: oneResult("r1", "T1059.001", "fail", "Critical", t1),
		})
		h.upsertFindingsForRun(context.Background(), "lf-crit-run")

		// Unfiltered: Critical must sort before Medium despite later insertion.
		rec := httptest.NewRecorder()
		h.ListFindings(rec, findingsReq("/api/findings", ""))
		var all []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &all); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(all) < 2 {
			t.Fatalf("expected at least 2 findings, got %d", len(all))
		}
		if all[0]["severity"] != "Critical" {
			t.Fatalf("first finding severity = %v, want Critical (severity-first ordering)", all[0]["severity"])
		}

		// severity filter
		rec = httptest.NewRecorder()
		h.ListFindings(rec, findingsReq("/api/findings", "severity=Medium"))
		var bySev []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &bySev)
		for _, f := range bySev {
			if f["severity"] != "Medium" {
				t.Errorf("severity filter leaked a %v row", f["severity"])
			}
		}
		if len(bySev) == 0 {
			t.Error("severity=Medium filter returned no rows")
		}

		// agentId filter
		rec = httptest.NewRecorder()
		h.ListFindings(rec, findingsReq("/api/findings", "agentId=agent-lf-a"))
		var byAgent []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &byAgent)
		for _, f := range byAgent {
			if f["agentId"] != "agent-lf-a" {
				t.Errorf("agentId filter leaked a row for %v", f["agentId"])
			}
		}
		if len(byAgent) == 0 {
			t.Error("agentId filter returned no rows")
		}

		// status filter (both are "open" — sanity check it doesn't over-exclude)
		rec = httptest.NewRecorder()
		h.ListFindings(rec, findingsReq("/api/findings", "status=open"))
		var byStatus []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &byStatus)
		if len(byStatus) < 2 {
			t.Errorf("status=open should include both seeded findings, got %d", len(byStatus))
		}
	})
}

func TestGetFinding_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		at := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		seedReportableRun(t, pool, "gf-run", "agent-gf", reportRunOpts{
			Results: oneResult("r1", "T1059.001", "fail", "Critical", at),
		})
		h := newReportingHandler(t, pool, nil)
		h.upsertFindingsForRun(context.Background(), "gf-run")

		var id string
		if err := pool.QueryRow(context.Background(),
			`SELECT id FROM findings WHERE agent_id='agent-gf' AND technique_id='T1059.001'`,
		).Scan(&id); err != nil {
			t.Fatalf("lookup seeded finding id: %v", err)
		}

		rec := httptest.NewRecorder()
		h.GetFinding(rec, withURLParam(findingsReq("/api/findings/"+id, ""), "id", id))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out["techniqueId"] != "T1059.001" {
			t.Fatalf("techniqueId = %v", out["techniqueId"])
		}
		if out["enrichment"] == nil {
			t.Error("expected ATT&CK enrichment to be attached")
		}
		if _, ok := out["productSnapshot"]; !ok {
			t.Error("expected productSnapshot key")
		}
		if _, ok := out["dataSources"]; !ok {
			t.Error("expected dataSources key")
		}
	})
}

func TestGetFinding_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.GetFinding(rec, withURLParam(findingsReq("/api/findings/nope", ""), "id", "nope"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestSetFindingStatus_InvalidStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		uid := seedUser(t, pool, "sfs-invalid", "pw-Password1!", "admin", true)
		req := authedRequest(t, http.MethodPost, "/api/findings/x/status", strings.NewReader(`{"status":"bogus"}`), auth.RoleAdmin, uid)
		req = withURLParam(req, "id", "x")
		rec := callAuthed(h.SetFindingStatus, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

func TestSetFindingStatus_MalformedBody(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		uid := seedUser(t, pool, "sfs-malformed", "pw-Password1!", "admin", true)
		req := authedRequest(t, http.MethodPost, "/api/findings/x/status", strings.NewReader(`{"status":`), auth.RoleAdmin, uid)
		req = withURLParam(req, "id", "x")
		rec := callAuthed(h.SetFindingStatus, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

func TestSetFindingStatus_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		uid := seedUser(t, pool, "sfs-notfound", "pw-Password1!", "admin", true)
		req := authedRequest(t, http.MethodPost, "/api/findings/nope/status", strings.NewReader(`{"status":"triaged"}`), auth.RoleAdmin, uid)
		req = withURLParam(req, "id", "nope")
		rec := callAuthed(h.SetFindingStatus, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

// TestSetFindingStatus_ValidTransitions pins: remediated stamps resolved_at,
// the other three valid statuses do not, and resolved_by is populated from
// the authenticated caller's claims (auth.ClaimsFrom, via the real JWT
// middleware — see callAuthed).
func TestSetFindingStatus_ValidTransitions(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		at := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		h := newReportingHandler(t, pool, nil)
		uid := seedUser(t, pool, "sfs-valid", "pw-Password1!", "analyst", true)

		cases := []struct {
			status       string
			wantResolved bool
		}{
			{"triaged", false},
			{"remediated", true},
			{"risk_accepted", false},
			{"open", false},
		}
		for i, c := range cases {
			runID := "sfs-run-" + c.status
			agentID := "agent-sfs-" + c.status
			techID := "T1059.001"
			seedReportableRun(t, pool, runID, agentID, reportRunOpts{
				StartedAt: at.Add(time.Duration(i) * time.Minute),
				Results:   oneResult("r1", techID, "fail", "Critical", at.Add(time.Duration(i)*time.Minute)),
			})
			h.upsertFindingsForRun(context.Background(), runID)

			var id string
			if err := pool.QueryRow(context.Background(),
				`SELECT id FROM findings WHERE agent_id=$1 AND technique_id=$2`, agentID, techID,
			).Scan(&id); err != nil {
				t.Fatalf("%s: lookup finding: %v", c.status, err)
			}

			body := `{"status":"` + c.status + `","reason":"test"}`
			req := authedRequest(t, http.MethodPost, "/api/findings/"+id+"/status", strings.NewReader(body), auth.RoleAnalyst, uid)
			req = withURLParam(req, "id", id)
			rec := callAuthed(h.SetFindingStatus, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s: status = %d, want 200, body = %s", c.status, rec.Code, rec.Body.String())
			}

			var dbStatus, resolvedBy string
			var resolvedAt *time.Time
			if err := pool.QueryRow(context.Background(),
				`SELECT status, COALESCE(resolved_by,''), resolved_at FROM findings WHERE id=$1`, id,
			).Scan(&dbStatus, &resolvedBy, &resolvedAt); err != nil {
				t.Fatalf("%s: query updated row: %v", c.status, err)
			}
			if dbStatus != c.status {
				t.Errorf("%s: db status = %q", c.status, dbStatus)
			}
			if (resolvedAt != nil) != c.wantResolved {
				t.Errorf("%s: resolved_at set = %v, want %v", c.status, resolvedAt != nil, c.wantResolved)
			}
			if resolvedBy != uid {
				t.Errorf("%s: resolved_by = %q, want %q", c.status, resolvedBy, uid)
			}
		}
	})
}

func TestListRemediations_GroupsOpenFindingsAndExcludesResolved(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		at := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		h := newReportingHandler(t, pool, nil)

		// Two open findings for the SAME technique on different agents.
		seedReportableRun(t, pool, "lr-run-a", "agent-lr-a", reportRunOpts{
			StartedAt: at, Results: oneResult("r1", "T1059.001", "fail", "Critical", at),
		})
		h.upsertFindingsForRun(context.Background(), "lr-run-a")
		t1 := at.Add(1 * time.Minute)
		seedReportableRun(t, pool, "lr-run-b", "agent-lr-b", reportRunOpts{
			StartedAt: t1, Results: oneResult("r1", "T1059.001", "fail", "Critical", t1),
		})
		h.upsertFindingsForRun(context.Background(), "lr-run-b")

		// A remediated finding for a DIFFERENT technique — must not appear.
		t2 := t1.Add(1 * time.Minute)
		seedReportableRun(t, pool, "lr-run-resolved", "agent-lr-c", reportRunOpts{
			StartedAt: t2, Results: oneResult("r1", "T1547.001", "fail", "Medium", t2),
		})
		h.upsertFindingsForRun(context.Background(), "lr-run-resolved")
		var resolvedID string
		pool.QueryRow(context.Background(),
			`SELECT id FROM findings WHERE agent_id='agent-lr-c' AND technique_id='T1547.001'`).Scan(&resolvedID)
		pool.Exec(context.Background(), `UPDATE findings SET status='remediated' WHERE id=$1`, resolvedID)

		rec := httptest.NewRecorder()
		h.ListRemediations(rec, findingsReq("/api/remediations", ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var out []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		var t1059 map[string]any
		for _, rem := range out {
			if rem["techniqueId"] == "T1059.001" {
				t1059 = rem
			}
			if rem["techniqueId"] == "T1547.001" {
				t.Error("remediated finding's technique should not appear in remediations")
			}
		}
		if t1059 == nil {
			t.Fatal("expected a T1059.001 remediation group")
		}
		if fc, _ := t1059["findingCount"].(float64); fc != 2 {
			t.Errorf("findingCount = %v, want 2", t1059["findingCount"])
		}
		if ac, _ := t1059["agentCount"].(float64); ac != 2 {
			t.Errorf("agentCount = %v, want 2", t1059["agentCount"])
		}
	})
}

// TestListFindings_IncludesOptionalFields pins scanFindings' three
// pointer-guarded columns: lastCampaignId (only set when the finding's
// originating run carried a campaign_id) and resolvedReason/resolvedAt (only
// set once a status change has stamped them).
func TestListFindings_IncludesOptionalFields(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		at := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		seedCampaign(t, pool, "lf-opt-camp", "Optional Fields Campaign")
		seedReportableRun(t, pool, "lf-opt-run", "agent-lf-opt", reportRunOpts{
			CampaignID: "lf-opt-camp",
			Results:    oneResult("r1", "T1059.001", "fail", "Critical", at),
		})
		h := newReportingHandler(t, pool, nil)
		h.upsertFindingsForRun(context.Background(), "lf-opt-run")

		var id string
		if err := pool.QueryRow(context.Background(),
			`SELECT id FROM findings WHERE agent_id='agent-lf-opt' AND technique_id='T1059.001'`,
		).Scan(&id); err != nil {
			t.Fatalf("lookup finding: %v", err)
		}

		uid := seedUser(t, pool, "lf-opt-user", "pw-Password1!", "analyst", true)
		req := authedRequest(t, http.MethodPost, "/api/findings/"+id+"/status",
			strings.NewReader(`{"status":"triaged","reason":"confirmed exposure"}`), auth.RoleAnalyst, uid)
		req = withURLParam(req, "id", id)
		if rec := callAuthed(h.SetFindingStatus, req); rec.Code != http.StatusOK {
			t.Fatalf("SetFindingStatus: status = %d, body = %s", rec.Code, rec.Body.String())
		}
		// remediated stamps resolved_at; do a second change to also exercise that.
		req2 := authedRequest(t, http.MethodPost, "/api/findings/"+id+"/status",
			strings.NewReader(`{"status":"remediated","reason":"control fixed"}`), auth.RoleAnalyst, uid)
		req2 = withURLParam(req2, "id", id)
		if rec := callAuthed(h.SetFindingStatus, req2); rec.Code != http.StatusOK {
			t.Fatalf("SetFindingStatus (remediated): status = %d, body = %s", rec.Code, rec.Body.String())
		}

		rec := httptest.NewRecorder()
		h.ListFindings(rec, findingsReq("/api/findings", "agentId=agent-lf-opt"))
		var out []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(out) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(out))
		}
		f := out[0]
		if f["lastCampaignId"] != "lf-opt-camp" {
			t.Errorf("lastCampaignId = %v, want lf-opt-camp", f["lastCampaignId"])
		}
		if f["resolvedReason"] != "control fixed" {
			t.Errorf("resolvedReason = %v, want %q", f["resolvedReason"], "control fixed")
		}
		if f["resolvedAt"] == nil {
			t.Error("resolvedAt should be set after transitioning to remediated")
		}
	})
}

func TestListRemediations_Empty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newReportingHandler(t, pool, nil)
		rec := httptest.NewRecorder()
		h.ListRemediations(rec, findingsReq("/api/remediations", ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if strings.TrimSpace(rec.Body.String()) != "[]" {
			t.Fatalf("body = %q, want empty JSON array", rec.Body.String())
		}
	})
}
