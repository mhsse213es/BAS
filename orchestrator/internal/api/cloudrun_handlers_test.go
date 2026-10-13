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

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/cloudrun"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func triggerCloudPlanRunReq(t *testing.T, pool *pgxpool.Pool, body map[string]any) (*http.Request, string) {
	t.Helper()
	userID := seedUser(t, pool, fmt.Sprintf("cloudrun-op-%d", time.Now().UnixNano()), "pw12345678", string(auth.RoleAnalyst), true)
	b, _ := json.Marshal(body)
	req := authedRequest(t, http.MethodPost, "/api/cloud-runs", bytes.NewReader(b), auth.RoleAnalyst, userID)
	return req, userID
}

func validCloudPlanRunBody() map[string]any {
	return map[string]any{
		"scenarioId": "test-scenario",
		"account":    map[string]any{"provider": "aws", "accountId": "111"},
		"edges": []map[string]any{
			{
				"source": map[string]any{"canonicalId": "arn:aws:iam::111:user/alice", "kind": "iam-user"},
				"target": map[string]any{"canonicalId": "arn:aws:iam::111:role/admin", "kind": "iam-role"},
				"action": "sts:AssumeRole", "sourceType": "identity-policy",
				"attributes": map[string]any{"policy_document": `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole"}]}`},
			},
		},
		"held":    []string{"arn:aws:iam::111:user/alice"},
		"target":  "arn:aws:iam::111:role/admin",
		"maxHops": 3,
	}
}

func TestTriggerCloudPlanRun_Success(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req, _ := triggerCloudPlanRunReq(t, pool, validCloudPlanRunBody())
		rec := callAuthed(h.TriggerCloudPlanRun, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var run cloudrun.CloudRun
		if err := json.Unmarshal(rec.Body.Bytes(), &run); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if run.ID == "" {
			t.Fatal("want non-empty run ID")
		}
		if run.Status != cloudrun.StatusCompleted && run.Status != cloudrun.StatusPartial {
			t.Fatalf("status: got %s want completed or partial", run.Status)
		}
	})
}

func TestTriggerCloudPlanRun_MissingScenarioID(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validCloudPlanRunBody()
		delete(body, "scenarioId")
		req, _ := triggerCloudPlanRunReq(t, pool, body)
		rec := callAuthed(h.TriggerCloudPlanRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestTriggerCloudPlanRun_MissingTarget(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validCloudPlanRunBody()
		delete(body, "target")
		req, _ := triggerCloudPlanRunReq(t, pool, body)
		rec := callAuthed(h.TriggerCloudPlanRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestTriggerCloudPlanRun_InvalidProvider(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validCloudPlanRunBody()
		body["account"] = map[string]any{"provider": "not-a-real-provider", "accountId": "111"}
		req, _ := triggerCloudPlanRunReq(t, pool, body)
		rec := callAuthed(h.TriggerCloudPlanRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var count int
		_ = pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM cloud_runs WHERE scenario_id = 'test-scenario'`).Scan(&count)
		if count != 0 {
			t.Fatalf("rows created: got %d want 0 (the handler's pre-check must run before any insert)", count)
		}
	})
}

func TestTriggerCloudPlanRun_InitiatedByIsAlwaysServerControlled(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validCloudPlanRunBody()
		body["initiatedBy"] = "someone-else-entirely"
		req, userID := triggerCloudPlanRunReq(t, pool, body)
		rec := callAuthed(h.TriggerCloudPlanRun, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var run cloudrun.CloudRun
		if err := json.Unmarshal(rec.Body.Bytes(), &run); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if run.InitiatedBy != userID {
			t.Fatalf("InitiatedBy: got %q want %q (the authenticated caller, not the request body's spoofed value)", run.InitiatedBy, userID)
		}
	})
}

func TestTriggerCloudPlanRun_MismatchFailsWith500AndAuditsTheRealRowID(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := map[string]any{
			"scenarioId": "mismatch-scenario",
			"account":    map[string]any{"provider": "aws", "accountId": "111"},
			"edges": []map[string]any{
				{
					"source": map[string]any{"canonicalId": "arn:aws:iam::111:user/alice", "kind": "iam-user"},
					"target": map[string]any{
						"canonicalId": "arn:azure:role/admin", "kind": "iam-role",
						"accountScope": map[string]any{"provider": "azure"},
					},
					"action": "sts:AssumeRole",
				},
			},
			"held":   []string{"arn:aws:iam::111:user/alice"},
			"target": "arn:azure:role/admin",
		}
		req, _ := triggerCloudPlanRunReq(t, pool, body)
		rec := callAuthed(h.TriggerCloudPlanRun, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var errBody struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil {
			t.Fatalf("decode error body: %v", err)
		}
		if errBody.Error == "" {
			t.Fatal("want a non-empty error message in the response body")
		}
		var runID string
		var status string
		ctx := context.Background()
		if err := pool.QueryRow(ctx, `SELECT id, status FROM cloud_runs WHERE scenario_id = 'mismatch-scenario'`).Scan(&runID, &status); err != nil {
			t.Fatalf("query row: %v", err)
		}
		if status != string(cloudrun.StatusFailed) {
			t.Fatalf("status: got %s want failed", status)
		}
		if !strings.Contains(errBody.Error, runID) {
			t.Fatalf("response error %q does not mention the real run ID %s -- Task 1's error-wrapping must reach the HTTP response", errBody.Error, runID)
		}
		deadline := time.Now().Add(2 * time.Second)
		for {
			var n int
			_ = pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'cloudrun.plan.run' AND resource = $1 AND outcome = 'error'`, runID).Scan(&n)
			if n == 1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("audit rows for resource=%s = %d, want 1 (the handler must pass the real row ID through to the audit log on failure)", runID, n)
			}
			time.Sleep(50 * time.Millisecond)
		}
	})
}

func TestTriggerCloudPlanRun_SuccessAudits(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req, _ := triggerCloudPlanRunReq(t, pool, validCloudPlanRunBody())
		rec := callAuthed(h.TriggerCloudPlanRun, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var run cloudrun.CloudRun
		if err := json.Unmarshal(rec.Body.Bytes(), &run); err != nil {
			t.Fatalf("decode: %v", err)
		}
		ctx := context.Background()
		deadline := time.Now().Add(2 * time.Second)
		for {
			var n int
			_ = pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'cloudrun.plan.run' AND resource = $1 AND outcome = 'ok'`, run.ID).Scan(&n)
			if n == 1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("audit rows for resource=%s = %d, want 1", run.ID, n)
			}
			time.Sleep(50 * time.Millisecond)
		}
	})
}
