package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/vexsweep"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func setAgentEnvLabel(t *testing.T, pool *pgxpool.Pool, agentID, label string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `UPDATE agents SET env_label = $2 WHERE agent_id = $1`, agentID, label); err != nil {
		t.Fatalf("set env label: %v", err)
	}
}

func postSweep(t *testing.T, h *Handler, pool *pgxpool.Pool, agentID string) *httptest.ResponseRecorder {
	t.Helper()
	userID := seedUser(t, pool, "sweep-prod-"+agentID, "password123", "admin", true)
	body, _ := json.Marshal(map[string]string{"agentId": agentID, "mode": "sequential"})
	req := authedRequest(t, http.MethodPost, "/api/vex/sweeps", bytes.NewReader(body), auth.RoleAdmin, userID)
	return callAuthed(h.CreateVexSweep, req)
}

// A full sweep runs every ART technique on one endpoint. It is blocked on an endpoint labelled Production.
func TestCreateVexSweep_ProductionEndpoint_Blocked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret).WithVexSweep(vexsweep.NewStore(pool), testVexSweepDispatcher(vexsweep.NewStore(pool)))
		seedActiveAgent(t, pool, "sweep-prod-win", "Windows Server 2022")
		setAgentEnvLabel(t, pool, "sweep-prod-win", "Production")
		rec := postSweep(t, h, pool, "sweep-prod-win")
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403, body: %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "production") {
			t.Errorf("error should say why, body: %s", rec.Body.String())
		}
	})
}

// The label is free text set by the installer, so "PRODUCTION " in any case is still production.
func TestCreateVexSweep_ProductionLabelIgnoresCaseAndSpaces(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret).WithVexSweep(vexsweep.NewStore(pool), testVexSweepDispatcher(vexsweep.NewStore(pool)))
		seedActiveAgent(t, pool, "sweep-prod-case", "Windows Server 2022")
		setAgentEnvLabel(t, pool, "sweep-prod-case", " PRODUCTION ")
		if rec := postSweep(t, h, pool, "sweep-prod-case"); rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
	})
}

// A non-production endpoint still gets through the policy check.
func TestCreateVexSweep_LabEndpoint_NotBlockedByPolicy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret).WithVexSweep(vexsweep.NewStore(pool), testVexSweepDispatcher(vexsweep.NewStore(pool)))
		seedActiveAgent(t, pool, "sweep-lab-win", "Windows Server 2022")
		setAgentEnvLabel(t, pool, "sweep-lab-win", "Lab")
		if rec := postSweep(t, h, pool, "sweep-lab-win"); rec.Code == http.StatusForbidden {
			t.Fatalf("status = 403 for a Lab endpoint, body: %s", rec.Body.String())
		}
	})
}
