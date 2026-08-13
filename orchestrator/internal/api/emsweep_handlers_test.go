package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/emsweep"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testEMSweepDispatcher(store *emsweep.Store) *emsweep.Dispatcher {
	return emsweep.NewDispatcher(store, func(ctx context.Context, scenarioRunID string) (string, error) {
		return "running", nil
	})
}

func TestCreateEMSweep_DispatchesFirstLayerEventually(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, engine := minimalPostureScenario(t, "em-01-control-validation")
		store := emsweep.NewStore(pool)
		h := New(pool, ws.NewHub(), engine, testJWTSecret).WithEMSweep(store, testEMSweepDispatcher(store))
		agentID := "em-create-agent"
		seedActiveAgent(t, pool, agentID, "Windows")
		uid := seedUser(t, pool, "em-create-user", "pw-Password1!", "admin", true)

		body, _ := json.Marshal(map[string]any{"agentId": agentID})
		req := authedRequest(t, http.MethodPost, "/api/em/sweeps", bytes.NewReader(body), auth.RoleAdmin, uid)
		rec := callAuthed(h.CreateEMSweep, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201, body = %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out["agentId"] != agentID {
			t.Fatalf("response agentId = %v, want %v", out["agentId"], agentID)
		}
		layers, _ := out["layers"].([]any)
		if len(layers) != 1 || layers[0] != "em-01-control-validation" {
			t.Fatalf("expected exactly the one registered EM layer, got %v", layers)
		}
	})
}

func TestCreateEMSweep_RejectsSecondSweepSameAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, engine := minimalPostureScenario(t, "em-01-control-validation")
		store := emsweep.NewStore(pool)
		h := New(pool, ws.NewHub(), engine, testJWTSecret).WithEMSweep(store, testEMSweepDispatcher(store))
		agentID := "em-conflict-agent"
		seedActiveAgent(t, pool, agentID, "Windows")
		uid := seedUser(t, pool, "em-conflict-user", "pw-Password1!", "admin", true)
		body, _ := json.Marshal(map[string]any{"agentId": agentID})

		req1 := authedRequest(t, http.MethodPost, "/api/em/sweeps", bytes.NewReader(body), auth.RoleAdmin, uid)
		if rec := callAuthed(h.CreateEMSweep, req1); rec.Code != http.StatusCreated {
			t.Fatalf("first create: status = %d, body = %s", rec.Code, rec.Body.String())
		}
		req2 := authedRequest(t, http.MethodPost, "/api/em/sweeps", bytes.NewReader(body), auth.RoleAdmin, uid)
		rec2 := callAuthed(h.CreateEMSweep, req2)
		if rec2.Code != http.StatusConflict {
			t.Fatalf("second create: status = %d, want 409, body = %s", rec2.Code, rec2.Body.String())
		}
	})
}

func TestGetActiveEMSweep_404WhenNoneRunning(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := emsweep.NewStore(pool)
		h := New(pool, ws.NewHub(), nil, testJWTSecret).WithEMSweep(store, testEMSweepDispatcher(store))
		uid := seedUser(t, pool, "em-active-user", "pw-Password1!", "viewer", true)
		req := authedRequest(t, http.MethodGet, "/api/em/sweeps/active?agentId=em-no-sweep-agent", nil, auth.RoleViewer, uid)
		rec := callAuthed(h.GetActiveEMSweep, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestGetEMSweepRuns_ReturnsSweepAndItsRuns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, engine := minimalPostureScenario(t, "em-01-control-validation")
		store := emsweep.NewStore(pool)
		h := New(pool, ws.NewHub(), engine, testJWTSecret).WithEMSweep(store, testEMSweepDispatcher(store))
		agentID := "em-runs-agent"
		seedActiveAgent(t, pool, agentID, "Windows")
		uid := seedUser(t, pool, "em-runs-user", "pw-Password1!", "admin", true)

		body, _ := json.Marshal(map[string]any{"agentId": agentID})
		createReq := authedRequest(t, http.MethodPost, "/api/em/sweeps", bytes.NewReader(body), auth.RoleAdmin, uid)
		createRec := callAuthed(h.CreateEMSweep, createReq)
		var created map[string]any
		json.Unmarshal(createRec.Body.Bytes(), &created)
		sweepID, _ := created["id"].(string)
		if sweepID == "" {
			t.Fatalf("no sweep id in create response: %s", createRec.Body.String())
		}

		runsReq := withURLParam(authedRequest(t, http.MethodGet, "/api/em/sweeps/"+sweepID+"/runs", nil, auth.RoleAdmin, uid), "id", sweepID)
		runsRec := callAuthed(h.GetEMSweepRuns, runsReq)
		if runsRec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", runsRec.Code, runsRec.Body.String())
		}
		var out map[string]any
		json.Unmarshal(runsRec.Body.Bytes(), &out)
		if _, ok := out["sweep"]; !ok {
			t.Fatalf("expected a 'sweep' key in response: %s", runsRec.Body.String())
		}
		if _, ok := out["runs"]; !ok {
			t.Fatalf("expected a 'runs' key in response: %s", runsRec.Body.String())
		}
	})
}

func TestCancelEMSweep_StopsSweepAndCancelsCurrentRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, engine := minimalPostureScenario(t, "em-01-control-validation")
		store := emsweep.NewStore(pool)
		h := New(pool, ws.NewHub(), engine, testJWTSecret).WithEMSweep(store, testEMSweepDispatcher(store))
		agentID := "em-cancel-agent"
		seedActiveAgent(t, pool, agentID, "Windows")
		uid := seedUser(t, pool, "em-cancel-user", "pw-Password1!", "admin", true)

		body, _ := json.Marshal(map[string]any{"agentId": agentID})
		createReq := authedRequest(t, http.MethodPost, "/api/em/sweeps", bytes.NewReader(body), auth.RoleAdmin, uid)
		createRec := callAuthed(h.CreateEMSweep, createReq)
		var created map[string]any
		json.Unmarshal(createRec.Body.Bytes(), &created)
		sweepID, _ := created["id"].(string)
		if sweepID == "" {
			t.Fatalf("no sweep id in create response: %s", createRec.Body.String())
		}

		cancelReq := withURLParam(authedRequest(t, http.MethodPost, "/api/em/sweeps/"+sweepID+"/cancel", nil, auth.RoleAdmin, uid), "id", sweepID)
		cancelRec := callAuthed(h.CancelEMSweep, cancelReq)
		if cancelRec.Code != http.StatusOK {
			t.Fatalf("cancel status = %d, want 200, body = %s", cancelRec.Code, cancelRec.Body.String())
		}

		var status string
		if err := pool.QueryRow(context.Background(), `SELECT status FROM em_sweeps WHERE id = $1`, sweepID).Scan(&status); err != nil {
			t.Fatalf("query status: %v", err)
		}
		if status != "stopped" {
			t.Fatalf("status = %q, want stopped", status)
		}
	})
}

func TestListEMSweeps_ReturnsRunningByDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, engine := minimalPostureScenario(t, "em-01-control-validation")
		store := emsweep.NewStore(pool)
		h := New(pool, ws.NewHub(), engine, testJWTSecret).WithEMSweep(store, testEMSweepDispatcher(store))
		agentID := "em-list-agent"
		seedActiveAgent(t, pool, agentID, "Windows")
		uid := seedUser(t, pool, "em-list-user", "pw-Password1!", "admin", true)

		body, _ := json.Marshal(map[string]any{"agentId": agentID})
		createReq := authedRequest(t, http.MethodPost, "/api/em/sweeps", bytes.NewReader(body), auth.RoleAdmin, uid)
		if rec := callAuthed(h.CreateEMSweep, createReq); rec.Code != http.StatusCreated {
			t.Fatalf("create: status = %d, body = %s", rec.Code, rec.Body.String())
		}

		listReq := authedRequest(t, http.MethodGet, "/api/em/sweeps", nil, auth.RoleAdmin, uid)
		listRec := callAuthed(h.ListEMSweeps, listReq)
		if listRec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", listRec.Code, listRec.Body.String())
		}
		var out []map[string]any
		json.Unmarshal(listRec.Body.Bytes(), &out)
		if len(out) != 1 || out[0]["agentId"] != agentID {
			t.Fatalf("ListEMSweeps = %+v, want exactly one sweep for %q", out, agentID)
		}
	})
}
