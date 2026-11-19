package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/ws"
)

// An administrator's Force Remove is permanent. These tests pin that, and pin that an agent which merely
// retired itself (its own local --uninstall, which a reinstall also runs) is NOT locked.

type forceRemoveEnv struct {
	t    *testing.T
	h    *Handler
	pool *pgxpool.Pool
}

func newForceRemoveEnv(t *testing.T, pool *pgxpool.Pool, agentIDs ...string) *forceRemoveEnv {
	t.Helper()
	h := New(pool, ws.NewHub(), nil, "")
	for _, id := range agentIDs {
		rec := httptest.NewRecorder()
		h.EnrollAgent(rec, httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(id, nil))))
		if rec.Code != http.StatusOK {
			t.Fatalf("seed enroll %s: status = %d", id, rec.Code)
		}
	}
	return &forceRemoveEnv{t: t, h: h, pool: pool}
}

func (e *forceRemoveEnv) call(fn http.HandlerFunc, method, agentID, body string) *httptest.ResponseRecorder {
	req := withURLParam(httptest.NewRequest(method, "/api/agents/"+agentID, bytes.NewReader([]byte(body))), "agentId", agentID)
	rec := httptest.NewRecorder()
	fn(rec, req)
	return rec
}

func (e *forceRemoveEnv) state(agentID string) string {
	e.t.Helper()
	var s string
	if err := e.pool.QueryRow(context.Background(), `SELECT COALESCE(state,'') FROM agents WHERE agent_id=$1`, agentID).Scan(&s); err != nil {
		e.t.Fatalf("read state of %s: %v", agentID, err)
	}
	return s
}

func TestForceRemove_CannotBeReactivatedThroughTheStateEndpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e := newForceRemoveEnv(t, pool, "fr-state")
		if rec := e.call(e.h.RemoveAgent, http.MethodPost, "fr-state", `{"reason":"decommissioned"}`); rec.Code != http.StatusOK {
			t.Fatalf("force remove: %d %s", rec.Code, rec.Body.String())
		}
		for _, target := range []string{"active", "restricted", "quarantined"} {
			rec := e.call(e.h.SetAgentState, http.MethodPut, "fr-state", `{"state":"`+target+`"}`)
			if rec.Code != http.StatusConflict {
				t.Errorf("setting a force-removed agent to %q: status = %d, want 409", target, rec.Code)
			}
		}
		if got := e.state("fr-state"); got != "retired" {
			t.Fatalf("state after the refused changes = %q, want retired", got)
		}
	})
}

// The state endpoint is not the only way back: revoke -> reinstate and uninstall -> reinstall both end at
// "active". The database refuses the change itself, so no code path can do it, present or future.
func TestForceRemove_DatabaseRefusesAnyWayBack(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e := newForceRemoveEnv(t, pool, "fr-db")
		e.call(e.h.RemoveAgent, http.MethodPost, "fr-db", `{"reason":"decommissioned"}`)

		for name, sql := range map[string]string{
			"direct activate":  `UPDATE agents SET state='active' WHERE agent_id='fr-db'`,
			"revoke":           `UPDATE agents SET state='revoked' WHERE agent_id='fr-db'`,
			"uninstalled":      `UPDATE agents SET state='uninstalled' WHERE agent_id='fr-db'`,
			"clear the marker": `UPDATE agents SET force_removed_at=NULL WHERE agent_id='fr-db'`,
			"both at once":     `UPDATE agents SET state='active', force_removed_at=NULL WHERE agent_id='fr-db'`,
		} {
			if _, err := pool.Exec(context.Background(), sql); err == nil {
				t.Errorf("%s: the database allowed it", name)
			}
		}
		if got := e.state("fr-db"); got != "retired" {
			t.Fatalf("state = %q, want retired", got)
		}
	})
}

func TestForceRemove_RevokeAndUninstallAreRefusedWithAClearError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e := newForceRemoveEnv(t, pool, "fr-paths")
		e.call(e.h.RemoveAgent, http.MethodPost, "fr-paths", `{"reason":"decommissioned"}`)
		if rec := e.call(e.h.RevokeAgent, http.MethodPost, "fr-paths", `{"reason":"x"}`); rec.Code != http.StatusConflict {
			t.Errorf("revoke: status = %d, want 409", rec.Code)
		}
		if rec := e.call(e.h.UninstallAgent, http.MethodPost, "fr-paths", `{"reason":"x"}`); rec.Code != http.StatusConflict {
			t.Errorf("uninstall: status = %d, want 409", rec.Code)
		}
	})
}

// An agent that retired itself (agent --uninstall -> /api/agents/unenroll) can still be reactivated: the Linux
// installer runs -uninstall on every reinstall, so locking that would strand the host forever.
func TestSelfRetiredAgentCanStillBeReactivated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e := newForceRemoveEnv(t, pool, "fr-self")
		if _, err := pool.Exec(context.Background(), `UPDATE agents SET state='retired' WHERE agent_id='fr-self'`); err != nil {
			t.Fatalf("self-retire: %v", err)
		}
		if rec := e.call(e.h.SetAgentState, http.MethodPut, "fr-self", `{"state":"active"}`); rec.Code != http.StatusOK {
			t.Fatalf("reactivating a self-retired agent: status = %d %s, want 200", rec.Code, rec.Body.String())
		}
		if got := e.state("fr-self"); got != "active" {
			t.Fatalf("state = %q, want active", got)
		}
	})
}

// An agent that is already retired (it uninstalled itself) and is then force-removed becomes permanent too.
func TestForceRemoveAfterSelfRetireIsStillPermanent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e := newForceRemoveEnv(t, pool, "fr-both")
		pool.Exec(context.Background(), `UPDATE agents SET state='retired' WHERE agent_id='fr-both'`)
		e.call(e.h.RemoveAgent, http.MethodPost, "fr-both", `{"reason":"decommissioned"}`)
		if rec := e.call(e.h.SetAgentState, http.MethodPut, "fr-both", `{"state":"active"}`); rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409", rec.Code)
		}
	})
}
