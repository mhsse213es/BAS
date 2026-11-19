package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/ws"
)

// trayPolicyEnv enrols one agent and returns helpers to drive the tray-icon endpoints and read back what the
// agent would be told on its next heartbeat.
type trayPolicyEnv struct {
	t       *testing.T
	h       *Handler
	pool    *pgxpool.Pool
	agentID string
}

func newTrayPolicyEnv(t *testing.T, pool *pgxpool.Pool, agentID string) *trayPolicyEnv {
	t.Helper()
	h := New(pool, ws.NewHub(), nil, "")
	rec := httptest.NewRecorder()
	h.EnrollAgent(rec, httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))
	if rec.Code != http.StatusOK {
		t.Fatalf("seed enroll: status = %d", rec.Code)
	}
	return &trayPolicyEnv{t: t, h: h, pool: pool, agentID: agentID}
}

func (e *trayPolicyEnv) setAgent(body string) *httptest.ResponseRecorder {
	req := withURLParam(httptest.NewRequest(http.MethodPut, "/api/agents/"+e.agentID+"/tray-icon", bytes.NewReader([]byte(body))), "agentId", e.agentID)
	rec := httptest.NewRecorder()
	e.h.SetAgentTrayIcon(rec, req)
	return rec
}

func (e *trayPolicyEnv) setFleet(body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	e.h.SetFleetTrayIcon(rec, httptest.NewRequest(http.MethodPut, "/api/fleet/tray-icon", bytes.NewReader([]byte(body))))
	return rec
}

// hidden is what the agent is told on its next heartbeat.
func (e *trayPolicyEnv) hidden() bool {
	e.t.Helper()
	rec := httptest.NewRecorder()
	e.h.Heartbeat(rec, httptest.NewRequest(http.MethodPost, "/api/heartbeat", bytes.NewReader(heartbeatBody(e.agentID))))
	if rec.Code != http.StatusOK {
		e.t.Fatalf("heartbeat: status = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Policy map[string]any `json:"policy"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		e.t.Fatalf("decode heartbeat: %v", err)
	}
	v, ok := resp.Policy["hideTrayIcon"]
	if !ok {
		e.t.Fatalf("heartbeat policy has no hideTrayIcon field: %s", rec.Body.String())
	}
	b, isBool := v.(bool)
	if !isBool {
		e.t.Fatalf("hideTrayIcon = %v, want a bool", v)
	}
	return b
}

func TestTrayIconPolicy_DefaultsToVisible(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e := newTrayPolicyEnv(t, pool, "agent-tray-default")
		if e.hidden() {
			t.Fatal("a new agent with no fleet setting and no override must keep its tray icon")
		}
	})
}

// Fleet default applies to agents with no override; a per-agent override beats it in either direction; clearing
// the override (null) returns the agent to the fleet default.
func TestTrayIconPolicy_FleetDefaultAndAgentOverridePrecedence(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e := newTrayPolicyEnv(t, pool, "agent-tray-prec")

		if rec := e.setFleet(`{"hidden":true}`); rec.Code != http.StatusOK {
			t.Fatalf("set fleet: %d %s", rec.Code, rec.Body.String())
		}
		if !e.hidden() {
			t.Error("fleet hide=true, no override: want hidden")
		}

		if rec := e.setAgent(`{"hidden":false}`); rec.Code != http.StatusOK {
			t.Fatalf("set agent show: %d %s", rec.Code, rec.Body.String())
		}
		if e.hidden() {
			t.Error("fleet hide=true but this agent is overridden to show: want visible")
		}

		if rec := e.setFleet(`{"hidden":false}`); rec.Code != http.StatusOK {
			t.Fatalf("clear fleet: %d", rec.Code)
		}
		if rec := e.setAgent(`{"hidden":true}`); rec.Code != http.StatusOK {
			t.Fatalf("set agent hide: %d", rec.Code)
		}
		if !e.hidden() {
			t.Error("fleet visible but this agent is overridden to hide: want hidden")
		}

		if rec := e.setAgent(`{"hidden":null}`); rec.Code != http.StatusOK {
			t.Fatalf("clear override: %d %s", rec.Code, rec.Body.String())
		}
		if e.hidden() {
			t.Error("override cleared and fleet visible: want visible")
		}
	})
}

// Re-enrolling rewrites policy_json; the stored override must survive it.
func TestTrayIconPolicy_OverrideSurvivesReEnroll(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e := newTrayPolicyEnv(t, pool, "agent-tray-reenroll")
		if rec := e.setAgent(`{"hidden":true}`); rec.Code != http.StatusOK {
			t.Fatalf("set agent: %d", rec.Code)
		}
		rec := httptest.NewRecorder()
		e.h.EnrollAgent(rec, httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(e.agentID, nil))))
		if rec.Code != http.StatusOK {
			t.Fatalf("re-enroll: %d", rec.Code)
		}
		if !e.hidden() {
			t.Fatal("re-enrolling reset the per-agent tray override")
		}
	})
}

func TestTrayIconPolicy_Validation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e := newTrayPolicyEnv(t, pool, "agent-tray-valid")
		for name, body := range map[string]string{"not json": "{nope", "missing field": `{}`, "string value": `{"hidden":"yes"}`} {
			if rec := e.setAgent(body); rec.Code != http.StatusBadRequest {
				t.Errorf("agent %s: status = %d, want 400", name, rec.Code)
			}
		}
		// The fleet default is a plain on/off: null (inherit) is not meaningful there.
		for name, body := range map[string]string{"not json": "{nope", "missing field": `{}`, "null": `{"hidden":null}`, "string value": `{"hidden":"yes"}`} {
			if rec := e.setFleet(body); rec.Code != http.StatusBadRequest {
				t.Errorf("fleet %s: status = %d, want 400", name, rec.Code)
			}
		}
		unknown := withURLParam(httptest.NewRequest(http.MethodPut, "/api/agents/nope/tray-icon", bytes.NewReader([]byte(`{"hidden":true}`))), "agentId", "nope")
		rec := httptest.NewRecorder()
		e.h.SetAgentTrayIcon(rec, unknown)
		if rec.Code != http.StatusNotFound {
			t.Errorf("unknown agent: status = %d, want 404", rec.Code)
		}
		if e.hidden() {
			t.Error("rejected requests must not change the policy")
		}
	})
}

// The agent list exposes each agent's override (null = inherits) and GET returns the fleet default, so the console
// can label its buttons correctly.
func TestTrayIconPolicy_ListAndGetReflectState(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e := newTrayPolicyEnv(t, pool, "agent-tray-list")

		rec := httptest.NewRecorder()
		e.h.GetFleetTrayIcon(rec, httptest.NewRequest(http.MethodGet, "/api/fleet/tray-icon", nil))
		var fleet struct {
			Hidden bool `json:"hidden"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &fleet)
		if rec.Code != http.StatusOK || fleet.Hidden {
			t.Fatalf("GET fleet default: %d %s, want 200 hidden=false", rec.Code, rec.Body.String())
		}

		trayHidden := func() *bool {
			rec := httptest.NewRecorder()
			e.h.GetAgents(rec, httptest.NewRequest(http.MethodGet, "/api/agents", nil))
			var list []struct {
				AgentID    string `json:"agentId"`
				TrayHidden *bool  `json:"trayHidden"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
				t.Fatalf("decode agents: %v (%s)", err, rec.Body.String())
			}
			for _, a := range list {
				if a.AgentID == e.agentID {
					return a.TrayHidden
				}
			}
			t.Fatalf("agent %s not in list", e.agentID)
			return nil
		}
		if trayHidden() != nil {
			t.Error("a new agent inherits the fleet default, so trayHidden must be null")
		}
		e.setAgent(`{"hidden":true}`)
		if v := trayHidden(); v == nil || !*v {
			t.Errorf("after hide override trayHidden = %v, want true", v)
		}
		e.setAgent(`{"hidden":false}`)
		if v := trayHidden(); v == nil || *v {
			t.Errorf("after show override trayHidden = %v, want false (explicit override, not inherit)", v)
		}

		e.setFleet(`{"hidden":true}`)
		rec = httptest.NewRecorder()
		e.h.GetFleetTrayIcon(rec, httptest.NewRequest(http.MethodGet, "/api/fleet/tray-icon", nil))
		_ = json.Unmarshal(rec.Body.Bytes(), &fleet)
		if !fleet.Hidden {
			t.Error("GET fleet default after set: want hidden=true")
		}
	})
}

// Hiding the tray removes the endpoint user's only visible sign of the agent, so every change is audited.
func TestTrayIconPolicy_ChangesAreAudited(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e := newTrayPolicyEnv(t, pool, "agent-tray-audit")
		e.setAgent(`{"hidden":true}`)
		e.setFleet(`{"hidden":true}`)
		for _, action := range []string{"agent.tray_icon", "fleet.tray_icon"} {
			var n int
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM audit_logs WHERE action = $1`, action).Scan(&n); err == nil && n > 0 {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			if n == 0 {
				t.Errorf("no audit_logs row for %q", action)
			}
		}
	})
}
