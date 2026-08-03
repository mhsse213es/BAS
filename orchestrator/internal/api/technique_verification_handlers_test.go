package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestVerifyTechnique_NotCompleted_Conflict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('tv-h1', 'TV-H1', 'windows')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
			VALUES ('rr-tvh-1', 'enable_windows_firewall', 'tv-h1', 'windows-firewall-enabled', 1, 'dispatched', 'user-1', 'test')`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "requestId", "rr-tvh-1")
		w := httptest.NewRecorder()
		h.VerifyTechnique(w, req)
		if w.Code != http.StatusConflict {
			t.Errorf("status = %d, want 409 (not Completed)", w.Code)
		}
	})
}

func TestVerifyTechnique_NotEligible_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('tv-h2', 'TV-H2', 'windows')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
			VALUES ('rr-tvh-2', 'enable_bitlocker', 'tv-h2', 'windows-bitlocker-enabled', 4, 'completed', 'user-1', 'test')`)

		// Written under <dir>/custom/ and loaded via Load(), not Save() --
		// Save() would reject a step with no technique_id via Validate().
		dir := t.TempDir()
		customDir := filepath.Join(dir, "custom")
		if err := os.MkdirAll(customDir, 0o755); err != nil {
			t.Fatalf("mkdir custom dir: %v", err)
		}
		content := "id: fixture-no-technique-2\n" +
			"name: Fixture No Technique 2\n" +
			"local_check: true\n" +
			"steps:\n" +
			"  - name: \"BitLocker Check\"\n" +
			"    check_id: windows-bitlocker-enabled\n" +
			"    framework: custom\n" +
			"    executor: local\n" +
			"    command: \"echo PASS\"\n" +
			"    timeout_sec: 10\n"
		if err := os.WriteFile(filepath.Join(customDir, "fixture-no-technique-2.yaml"), []byte(content), 0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		eng := scenario.NewEngine(dir)
		if err := eng.Load(); err != nil {
			t.Fatalf("engine.Load: %v", err)
		}

		h := New(pool, ws.NewHub(), eng, "")
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "requestId", "rr-tvh-2")
		w := httptest.NewRecorder()
		h.VerifyTechnique(w, req)
		if w.Code != http.StatusUnprocessableEntity {
			t.Errorf("status = %d, want 422 (windows-bitlocker-enabled has no technique_id)", w.Code)
		}
	})
}

func TestVerifyTechnique_AlreadyRequested_Conflict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('tv-h3', 'TV-H3', 'windows')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
			VALUES ('rr-tvh-3', 'enable_windows_firewall', 'tv-h3', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test')`)
		mustExecAPI(t, pool, `
			INSERT INTO technique_verification_runs (id, request_id, agent_id, check_id, technique_id, status, requested_by)
			VALUES ('tvr-h3', 'rr-tvh-3', 'tv-h3', 'windows-firewall-enabled', 'T1562.004', 'requested', 'user-1')`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		registerFixtureScenario(t, h.engine, "windows-firewall-enabled")

		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "requestId", "rr-tvh-3")
		w := httptest.NewRecorder()
		h.VerifyTechnique(w, req)
		if w.Code != http.StatusConflict {
			t.Errorf("status = %d, want 409 (a technique_verification_runs row already exists)", w.Code)
		}
	})
}

func TestVerifyTechnique_Eligible_Dispatches(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('tv-h4', 'TV-H4', 'windows')`)
		mustExecAPI(t, pool, `
			INSERT INTO remediation_requests (id, remediation_id, agent_id, check_id, tier, status, requested_by, reason)
			VALUES ('rr-tvh-4', 'enable_windows_firewall', 'tv-h4', 'windows-firewall-enabled', 1, 'completed', 'user-1', 'test')`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		registerFixtureScenario(t, h.engine, "windows-firewall-enabled")
		fake := startFakeAgent(t, h.hub, "tv-h4")
		defer fake.Disconnect(t)

		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "requestId", "rr-tvh-4")
		w := httptest.NewRecorder()
		h.VerifyTechnique(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
	})
}
