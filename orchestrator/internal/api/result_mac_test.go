package api

// Replay of a byte-identical, valid-MAC submission is intentionally NOT a
// rejection case: the handler's REPLACE semantics make duplicate deliveries
// idempotent by design (agents retry until the response lands). The
// idempotency itself is covered in submit_scenario_result_test.go
// (TestSubmitScenarioResult_REPLACENotAppend) — this file only owns the
// authentication/tamper boundary.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSubmitScenarioResult_MAC_Matrix(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		engine := scenario.NewEngine(t.TempDir())
		seedRunRow(t, pool, "mac-matrix-run", "sc-mac", "agent-mac", "running")
		validBody := rawResultBody(t, scenario.RawRunResult{RunID: "mac-matrix-run", ScenarioID: "sc-mac", AgentID: "agent-mac"})
		otherBody := rawResultBody(t, scenario.RawRunResult{RunID: "mac-matrix-run", ScenarioID: "sc-mac", AgentID: "agent-mac", Partial: true})
		bodyCompact := []byte(`{"runId":"mac-matrix-run","scenarioId":"sc-mac","agentId":"agent-mac"}`)
		bodySpaced := []byte(`{"agentId": "agent-mac", "runId":  "mac-matrix-run", "scenarioId": "sc-mac"}`)

		cases := []struct {
			name       string
			secret     string // handler's configured agentSecret; "" = intentional bypass
			token      string
			mac        string
			body       []byte
			wantStatus int
		}{
			{"valid MAC accepted", "s3cr3t", "s3cr3t", signResultMAC("s3cr3t", validBody), validBody, http.StatusOK},
			{"missing MAC header rejected", "s3cr3t", "s3cr3t", "", validBody, http.StatusUnauthorized},
			{"wrong MAC rejected", "s3cr3t", "s3cr3t", strings.Repeat("0", 64), validBody, http.StatusUnauthorized},
			{"malformed hex rejected", "s3cr3t", "s3cr3t", "not-hex-garbage!!", validBody, http.StatusUnauthorized},
			{"MAC from a different secret rejected", "s3cr3t", "s3cr3t", signResultMAC("other-secret", validBody), validBody, http.StatusUnauthorized},
			{"MAC computed for a different body is rejected (tamper detection)", "s3cr3t", "s3cr3t", signResultMAC("s3cr3t", otherBody), validBody, http.StatusUnauthorized},
			{"MAC boundary is raw bytes, not parsed JSON (reordered/whitespace body rejected)", "s3cr3t", "s3cr3t", signResultMAC("s3cr3t", bodyCompact), bodySpaced, http.StatusUnauthorized},
			{"empty secret configured bypasses MAC entirely", "", "", "", validBody, http.StatusOK},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				h := New(pool, ws.NewHub(), engine, "").WithAgentSecret(tc.secret)
				req := submitResultReq(tc.token, tc.mac, tc.body)
				rec := httptest.NewRecorder()
				h.SubmitScenarioResult(rec, req)
				if rec.Code != tc.wantStatus {
					t.Fatalf("status = %d, want %d, body = %s", rec.Code, tc.wantStatus, rec.Body.String())
				}
			})
		}
	})
}

// The agent-token gate (validateAgentAuth) is a separate, earlier trust
// boundary than the MAC: it runs first and rejects before the body is even
// read. The MAC matrix always passes a matching token, so this test owns the
// wrong-token path and confirms it rejects before any run mutation.
func TestSubmitScenarioResult_AgentTokenRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		engine := scenario.NewEngine(t.TempDir())
		h := New(pool, ws.NewHub(), engine, "").WithAgentSecret("s3cr3t")
		seedRunRow(t, pool, "token-guard-run", "sc-token-guard", "agent-token-guard", "running")

		body := rawResultBody(t, scenario.RawRunResult{
			RunID: "token-guard-run", ScenarioID: "sc-token-guard", AgentID: "agent-token-guard",
			Results: []scenario.ExecResult{{TaskID: "t0", ExitCode: 0, Stdout: "PASS: should never persist"}},
		})
		// Wrong X-Agent-Token; MAC would be valid, but the token gate runs first.
		req := submitResultReq("wrong-token", signResultMAC("s3cr3t", body), body)
		rec := httptest.NewRecorder()
		h.SubmitScenarioResult(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}

		var status string
		var completedAt *time.Time
		if err := pool.QueryRow(context.Background(),
			`SELECT status, completed_at FROM scenario_runs WHERE id = $1`, "token-guard-run",
		).Scan(&status, &completedAt); err != nil {
			t.Fatalf("read run: %v", err)
		}
		if status != "running" || completedAt != nil {
			t.Fatalf("run was mutated despite agent-token rejection: status=%q completedAt=%v", status, completedAt)
		}
	})
}

func TestSubmitScenarioResult_MAC_RejectionPrecedesMutation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		engine := scenario.NewEngine(t.TempDir())
		h := New(pool, ws.NewHub(), engine, "").WithAgentSecret("s3cr3t")
		seedRunRow(t, pool, "mac-guard-run", "sc-mac-guard", "agent-mac-guard", "running")

		body := rawResultBody(t, scenario.RawRunResult{
			RunID: "mac-guard-run", ScenarioID: "sc-mac-guard", AgentID: "agent-mac-guard",
			Results: []scenario.ExecResult{{TaskID: "t0", ExitCode: 0, Stdout: "PASS: should never persist"}},
		})
		req := submitResultReq("s3cr3t", strings.Repeat("0", 64), body) // valid token, wrong MAC
		rec := httptest.NewRecorder()
		h.SubmitScenarioResult(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}

		var status string
		var completedAt *time.Time
		if err := pool.QueryRow(context.Background(),
			`SELECT status, completed_at FROM scenario_runs WHERE id = $1`, "mac-guard-run",
		).Scan(&status, &completedAt); err != nil {
			t.Fatalf("read run: %v", err)
		}
		if status != "running" || completedAt != nil {
			t.Fatalf("run was mutated despite MAC rejection: status=%q completedAt=%v", status, completedAt)
		}
	})
}
