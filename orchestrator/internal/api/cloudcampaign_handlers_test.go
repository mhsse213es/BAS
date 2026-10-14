package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/cloudrun"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestBucketCloudRunStatus_EveryBranch(t *testing.T) {
	cases := []struct {
		name string
		run  *cloudrun.CloudRun
		want string
	}{
		{"nil run (InsertCloudRun itself never persisted a row)", nil, "failed"},
		{"completed", &cloudrun.CloudRun{Status: cloudrun.StatusCompleted}, "completed"},
		{"partial", &cloudrun.CloudRun{Status: cloudrun.StatusPartial}, "partial"},
		{"failed", &cloudrun.CloudRun{Status: cloudrun.StatusFailed}, "failed"},
		{"running (UpdateCloudRunStatus itself failed -- never confirmed terminal)", &cloudrun.CloudRun{Status: cloudrun.StatusRunning}, "failed"},
		{"pending", &cloudrun.CloudRun{Status: cloudrun.StatusPending}, "failed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := bucketCloudRunStatus(c.run); got != c.want {
				t.Errorf("bucketCloudRunStatus: got %q want %q", got, c.want)
			}
		})
	}
}

func createCloudCampaignReq(t *testing.T, pool *pgxpool.Pool, body map[string]any) (*http.Request, string) {
	t.Helper()
	userID := seedUser(t, pool, fmt.Sprintf("cloudcampaign-op-%d", time.Now().UnixNano()), "pw12345678", string(auth.RoleAnalyst), true)
	b, _ := json.Marshal(body)
	req := authedRequest(t, http.MethodPost, "/api/cloud-campaigns", bytes.NewReader(b), auth.RoleAnalyst, userID)
	return req, userID
}

func oneCloudCampaignRun(scenarioID, accountID, target string) map[string]any {
	return map[string]any{
		"scenarioId": scenarioID,
		"account":    map[string]any{"provider": "aws", "accountId": accountID},
		"edges": []map[string]any{
			{
				"source": map[string]any{"canonicalId": "arn:aws:iam::" + accountID + ":user/alice", "kind": "iam-user"},
				"target": map[string]any{"canonicalId": target, "kind": "iam-role"},
				"action": "sts:AssumeRole", "sourceType": "identity-policy",
				"attributes": map[string]any{"policy_document": `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole"}]}`},
			},
		},
		"held":   []string{"arn:aws:iam::" + accountID + ":user/alice"},
		"target": target,
	}
}

func TestCreateCloudCampaign_ThreeAccountsAllComplete(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := map[string]any{
			"name": "Three Account Sweep",
			"runs": []map[string]any{
				oneCloudCampaignRun("s1", "111", "arn:aws:iam::111:role/admin"),
				oneCloudCampaignRun("s2", "222", "arn:aws:iam::222:role/admin"),
				oneCloudCampaignRun("s3", "333", "arn:aws:iam::333:role/admin"),
			},
		}
		req, _ := createCloudCampaignReq(t, pool, body)
		rec := callAuthed(h.CreateCloudCampaign, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			CampaignID string                                            `json:"campaignId"`
			Summary    struct{ Total, Completed, Partial, Failed int }   `json:"summary"`
			Results    []map[string]any                                 `json:"results"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.CampaignID == "" {
			t.Fatal("want non-empty campaignId")
		}
		if resp.Summary.Total != 3 || resp.Summary.Completed != 3 || resp.Summary.Failed != 0 {
			t.Fatalf("summary = %+v, want total:3 completed:3 failed:0", resp.Summary)
		}
		if len(resp.Results) != 3 {
			t.Fatalf("results: got %d want 3", len(resp.Results))
		}
	})
}

func TestCreateCloudCampaign_OneMalformedSubRequestRejectsWholeRequest(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		goodRun := oneCloudCampaignRun("s1", "111", "arn:aws:iam::111:role/admin")
		badRun := oneCloudCampaignRun("s2", "222", "arn:aws:iam::222:role/admin")
		delete(badRun, "target") // malformed: missing required field
		body := map[string]any{"name": "Rejected Campaign", "runs": []map[string]any{goodRun, badRun}}
		req, _ := createCloudCampaignReq(t, pool, body)
		rec := callAuthed(h.CreateCloudCampaign, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var campaignCount, runCount int
		_ = pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM cloud_campaigns WHERE name = 'Rejected Campaign'`).Scan(&campaignCount)
		_ = pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM cloud_runs WHERE scenario_id IN ('s1','s2')`).Scan(&runCount)
		if campaignCount != 0 || runCount != 0 {
			t.Fatalf("campaignCount=%d runCount=%d, want 0 and 0 -- nothing should persist when any sub-request is invalid", campaignCount, runCount)
		}
	})
}

// TestCreateCloudCampaign_OversizedBodyRejectedBeforeFullDecode proves the
// request body is bounded (http.MaxBytesReader) before JSON decoding, not
// just after -- the 25-account/500-edge caps only run on an already-decoded
// req, so without this guard an oversized payload is fully materialized
// into memory before either cap gets a chance to reject it.
func TestCreateCloudCampaign_OversizedBodyRejectedBeforeFullDecode(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		// An oversized JSON *string* value, not a bare number -- the decoder
		// must scan through to a closing quote that never arrives within the
		// byte budget, forcing it to keep reading (and so hit the
		// MaxBytesReader limit) rather than erroring out early on invalid
		// number syntax.
		oversized := []byte(`{"name":"` + strings.Repeat("x", maxCloudCampaignRequestBytes+1) + `"}`)
		req := authedRequest(t, http.MethodPost, "/api/cloud-campaigns", bytes.NewReader(oversized), auth.RoleAnalyst, "any-user")
		rec := callAuthed(h.CreateCloudCampaign, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "too large") {
			t.Fatalf("expected a body-too-large error, got: %s", rec.Body.String())
		}
	})
}

func TestCreateCloudCampaign_TooManyAccountsRejectsWholeRequest(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		runs := make([]map[string]any, 26)
		for i := range runs {
			runs[i] = oneCloudCampaignRun(fmt.Sprintf("s%d", i), fmt.Sprintf("%d", 100+i), "arn:aws:iam::999:role/admin")
		}
		body := map[string]any{"name": "Too Many", "runs": runs}
		req, _ := createCloudCampaignReq(t, pool, body)
		rec := callAuthed(h.CreateCloudCampaign, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var campaignCount int
		_ = pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM cloud_campaigns WHERE name = 'Too Many'`).Scan(&campaignCount)
		if campaignCount != 0 {
			t.Fatalf("campaignCount=%d, want 0", campaignCount)
		}
	})
}

func TestCreateCloudCampaign_TooManyEdgesOnOneSubRequestRejectsWholeRequest(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		goodRun := oneCloudCampaignRun("s1", "111", "arn:aws:iam::111:role/admin")
		heavyRun := oneCloudCampaignRun("s2", "222", "arn:aws:iam::222:role/admin")
		edges := make([]map[string]any, 501)
		for i := range edges {
			edges[i] = map[string]any{
				"source": map[string]any{"canonicalId": fmt.Sprintf("arn:aws:iam::222:user/u%d", i), "kind": "iam-user"},
				"target": map[string]any{"canonicalId": "arn:aws:iam::222:role/admin", "kind": "iam-role"},
				"action": "sts:AssumeRole",
			}
		}
		heavyRun["edges"] = edges
		body := map[string]any{"name": "Too Many Edges", "runs": []map[string]any{goodRun, heavyRun}}
		req, _ := createCloudCampaignReq(t, pool, body)
		rec := callAuthed(h.CreateCloudCampaign, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var campaignCount, runCount int
		_ = pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM cloud_campaigns WHERE name = 'Too Many Edges'`).Scan(&campaignCount)
		_ = pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM cloud_runs WHERE scenario_id IN ('s1','s2')`).Scan(&runCount)
		if campaignCount != 0 || runCount != 0 {
			t.Fatalf("campaignCount=%d runCount=%d, want 0 and 0 -- the valid sibling sub-request must not be dispatched either", campaignCount, runCount)
		}
	})
}

func TestCreateCloudCampaign_OneAccountMismatchDoesNotAffectOthers(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		goodRun1 := oneCloudCampaignRun("s1", "111", "arn:aws:iam::111:role/admin")
		mismatchRun := map[string]any{
			"scenarioId": "mismatch-scenario",
			"account":    map[string]any{"provider": "aws", "accountId": "222"},
			"edges": []map[string]any{
				{
					"source": map[string]any{"canonicalId": "arn:aws:iam::222:user/alice", "kind": "iam-user"},
					"target": map[string]any{
						"canonicalId": "arn:azure:role/admin", "kind": "iam-role",
						"accountScope": map[string]any{"provider": "azure"},
					},
					"action": "sts:AssumeRole",
				},
			},
			"held":   []string{"arn:aws:iam::222:user/alice"},
			"target": "arn:azure:role/admin",
		}
		goodRun2 := oneCloudCampaignRun("s3", "333", "arn:aws:iam::333:role/admin")
		body := map[string]any{"name": "Isolation Test", "runs": []map[string]any{goodRun1, mismatchRun, goodRun2}}
		req, _ := createCloudCampaignReq(t, pool, body)
		rec := callAuthed(h.CreateCloudCampaign, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s -- a per-account mismatch must not fail the whole campaign request", rec.Code, rec.Body.String())
		}
		var resp struct {
			Summary struct{ Total, Completed, Partial, Failed int } `json:"summary"`
			Results []struct {
				RunID  string `json:"runId"`
				Status string `json:"status"`
				Error  string `json:"error"`
			} `json:"results"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.Summary.Total != 3 || resp.Summary.Completed != 2 || resp.Summary.Failed != 1 {
			t.Fatalf("summary = %+v, want total:3 completed:2 failed:1", resp.Summary)
		}
		failedCount, completedCount := 0, 0
		for _, r := range resp.Results {
			if r.Status == "failed" {
				failedCount++
				if r.RunID == "" || r.Error == "" {
					t.Fatalf("failed result missing runId or error: %+v", r)
				}
			}
			if r.Status == "completed" {
				completedCount++
			}
		}
		if failedCount != 1 || completedCount != 2 {
			t.Fatalf("failedCount=%d completedCount=%d, want 1 and 2 -- other accounts must still complete despite one mismatch", failedCount, completedCount)
		}
	})
}

func TestCreateCloudCampaign_InitiatedByAndCampaignIDAreServerControlled(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		run1 := oneCloudCampaignRun("s1", "111", "arn:aws:iam::111:role/admin")
		run1["initiatedBy"] = "spoofed-user-1"
		run2 := oneCloudCampaignRun("s2", "222", "arn:aws:iam::222:role/admin")
		run2["initiatedBy"] = "spoofed-user-2"
		body := map[string]any{"name": "Spoof Test", "runs": []map[string]any{run1, run2}}
		req, userID := createCloudCampaignReq(t, pool, body)
		rec := callAuthed(h.CreateCloudCampaign, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			CampaignID string                      `json:"campaignId"`
			Results    []struct{ RunID string `json:"runId"` } `json:"results"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		for _, r := range resp.Results {
			var initiatedBy, campaignID string
			if err := pool.QueryRow(context.Background(),
				`SELECT initiated_by, campaign_id FROM cloud_runs WHERE id = $1`, r.RunID,
			).Scan(&initiatedBy, &campaignID); err != nil {
				t.Fatalf("query row %s: %v", r.RunID, err)
			}
			if initiatedBy != userID {
				t.Fatalf("initiated_by: got %q want %q (authenticated caller, not the spoofed body value)", initiatedBy, userID)
			}
			if campaignID != resp.CampaignID {
				t.Fatalf("campaign_id: got %q want %q", campaignID, resp.CampaignID)
			}
		}
	})
}

func TestCreateCloudCampaign_AuditsOkEvenWhenSomeAccountsFail(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		goodRun := oneCloudCampaignRun("s1", "111", "arn:aws:iam::111:role/admin")
		mismatchRun := map[string]any{
			"scenarioId": "mismatch-scenario-audit",
			"account":    map[string]any{"provider": "aws", "accountId": "222"},
			"edges": []map[string]any{
				{
					"source": map[string]any{"canonicalId": "arn:aws:iam::222:user/alice", "kind": "iam-user"},
					"target": map[string]any{
						"canonicalId": "arn:azure:role/admin", "kind": "iam-role",
						"accountScope": map[string]any{"provider": "azure"},
					},
					"action": "sts:AssumeRole",
				},
			},
			"held":   []string{"arn:aws:iam::222:user/alice"},
			"target": "arn:azure:role/admin",
		}
		body := map[string]any{"name": "Audit Ok Despite Failure", "runs": []map[string]any{goodRun, mismatchRun}}
		req, _ := createCloudCampaignReq(t, pool, body)
		rec := callAuthed(h.CreateCloudCampaign, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct{ CampaignID string `json:"campaignId"` }
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)

		ctx := context.Background()
		deadline := time.Now().Add(2 * time.Second)
		for {
			var n int
			_ = pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'cloudcampaign.create' AND resource = $1 AND outcome = 'ok'`, resp.CampaignID).Scan(&n)
			if n == 1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("audit rows for resource=%s outcome=ok = %d, want 1 -- outcome must be ok even though one sub-request failed", resp.CampaignID, n)
			}
			time.Sleep(50 * time.Millisecond)
		}
	})
}

func TestGetCloudCampaign_RoundTripsARealCampaign(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := map[string]any{
			"name": "Round Trip Test",
			"runs": []map[string]any{
				oneCloudCampaignRun("s1", "111", "arn:aws:iam::111:role/admin"),
				oneCloudCampaignRun("s2", "222", "arn:aws:iam::222:role/admin"),
			},
		}
		createReq, _ := createCloudCampaignReq(t, pool, body)
		createRec := callAuthed(h.CreateCloudCampaign, createReq)
		if createRec.Code != http.StatusCreated {
			t.Fatalf("setup create failed: status = %d, body = %s", createRec.Code, createRec.Body.String())
		}
		var created struct{ CampaignID string `json:"campaignId"` }
		_ = json.Unmarshal(createRec.Body.Bytes(), &created)

		getReq := authedRequest(t, http.MethodGet, "/api/cloud-campaigns/"+created.CampaignID, nil, auth.RoleAnalyst, "any-authenticated-user")
		getReq = withURLParam(getReq, "id", created.CampaignID)
		rec := callAuthed(h.GetCloudCampaign, getReq)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			ID      string                                          `json:"id"`
			Summary struct{ Total, Completed, Partial, Failed int } `json:"summary"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.ID != created.CampaignID {
			t.Fatalf("ID: got %q want %q", resp.ID, created.CampaignID)
		}
		if resp.Summary.Total != 2 || resp.Summary.Completed != 2 {
			t.Fatalf("summary = %+v, want total:2 completed:2", resp.Summary)
		}
	})
}

func TestGetCloudCampaign_NonexistentIDReturns404(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		getReq := authedRequest(t, http.MethodGet, "/api/cloud-campaigns/nonexistent-id", nil, auth.RoleAnalyst, "any-authenticated-user")
		getReq = withURLParam(getReq, "id", "nonexistent-id")
		rec := callAuthed(h.GetCloudCampaign, getReq)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

// TestGetCloudCampaign_RollupIsRecomputedIndependentlyOfPostTime proves the
// weaker, directly testable half of the spec's documented POST-vs-GET
// accounting distinction: GET recomputes its rollup from cloud_runs rather
// than trusting POST's in-memory result, and the two agree when nothing
// failed to persist. Forcing the InsertCloudRun-failure asymmetry itself
// is not reachable through integration, matching sub-project #3's own
// documented, accepted gap for that branch.
func TestGetCloudCampaign_RollupIsRecomputedIndependentlyOfPostTime(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := map[string]any{
			"name": "Recompute Test",
			"runs": []map[string]any{oneCloudCampaignRun("s1", "111", "arn:aws:iam::111:role/admin")},
		}
		createReq, _ := createCloudCampaignReq(t, pool, body)
		createRec := callAuthed(h.CreateCloudCampaign, createReq)
		var created struct {
			CampaignID string                             `json:"campaignId"`
			Summary    struct{ Total, Completed int }     `json:"summary"`
		}
		_ = json.Unmarshal(createRec.Body.Bytes(), &created)

		getReq := authedRequest(t, http.MethodGet, "/api/cloud-campaigns/"+created.CampaignID, nil, auth.RoleAnalyst, "any-authenticated-user")
		getReq = withURLParam(getReq, "id", created.CampaignID)
		rec := callAuthed(h.GetCloudCampaign, getReq)
		var resp struct{ Summary struct{ Total, Completed int } `json:"summary"` }
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if resp.Summary.Total != created.Summary.Total || resp.Summary.Completed != created.Summary.Completed {
			t.Fatalf("GET summary %+v should match POST summary %+v when nothing failed to persist", resp.Summary, created.Summary)
		}
	})
}

func TestListCloudCampaigns_LimitBoundaryValues(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		for i := 0; i < 3; i++ {
			body := map[string]any{"name": fmt.Sprintf("Limit Test %d", i), "runs": []map[string]any{oneCloudCampaignRun("s1", "111", "arn:aws:iam::111:role/admin")}}
			req, _ := createCloudCampaignReq(t, pool, body)
			if rec := callAuthed(h.CreateCloudCampaign, req); rec.Code != http.StatusCreated {
				t.Fatalf("seed campaign %d failed: status = %d, body = %s", i, rec.Code, rec.Body.String())
			}
		}

		cases := []struct {
			name        string
			limitParam  string
			wantMaxRows int // 0 means "don't check row count, only status"
		}{
			{"malformed", "not-a-number", 0},
			{"zero", "0", 0},
			{"negative", "-1", 0},
			{"justOverMax", "101", 0},
			{"exactlyMax", "100", 0},
			{"validSmall", "1", 1},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				listReq := authedRequest(t, http.MethodGet, "/api/cloud-campaigns?limit="+c.limitParam, nil, auth.RoleAnalyst, "any-authenticated-user")
				rec := callAuthed(h.ListCloudCampaigns, listReq)
				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, body = %s (an invalid limit must silently fall back to the default, never 400)", rec.Code, rec.Body.String())
				}
				if c.wantMaxRows > 0 {
					var list []map[string]any
					if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
						t.Fatalf("decode: %v", err)
					}
					if len(list) != c.wantMaxRows {
						t.Fatalf("rows: got %d want exactly %d", len(list), c.wantMaxRows)
					}
				}
			})
		}
	})
}
