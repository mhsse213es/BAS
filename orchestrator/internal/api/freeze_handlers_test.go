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

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestCreateAgentFreeze_AdminCreates(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		from := time.Now().UTC()
		to := from.Add(48 * time.Hour)
		body, _ := json.Marshal(map[string]any{
			"fromAt": from.Format(time.RFC3339),
			"toAt":   to.Format(time.RFC3339),
			"reason": "Q3 audit change-freeze",
		})
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body)), "agentId", "freeze-h-a1")
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "admin-1", Role: auth.RoleAdmin}))
		w := httptest.NewRecorder()
		h.CreateAgentFreeze(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}

		frozen, reason, err := jobsStore.IsAgentFrozen(context.Background(), "freeze-h-a1")
		if err != nil {
			t.Fatalf("IsAgentFrozen: %v", err)
		}
		if !frozen || reason != "Q3 audit change-freeze" {
			t.Errorf("frozen=%v reason=%q, want true/'Q3 audit change-freeze'", frozen, reason)
		}
	})
}

func TestCreateAgentFreeze_ToBeforeFrom_BadRequest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		jobsStore := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))

		from := time.Now().UTC()
		to := from.Add(-1 * time.Hour) // before from
		body, _ := json.Marshal(map[string]any{"fromAt": from.Format(time.RFC3339), "toAt": to.Format(time.RFC3339), "reason": "test"})
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body)), "agentId", "freeze-h-a3")
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "admin-1", Role: auth.RoleAdmin}))
		w := httptest.NewRecorder()
		h.CreateAgentFreeze(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400 (toAt before fromAt)", w.Code)
		}
	})
}

func TestListAgentFreezes_ReturnsCreated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		jobsStore := jobs.NewStore(pool)
		created, err := jobsStore.CreateFreeze(context.Background(), jobs.AgentFreeze{
			AgentID: "freeze-h-a4", FromAt: time.Now().UTC(), ToAt: time.Now().UTC().Add(1 * time.Hour), Reason: "test",
		})
		if err != nil {
			t.Fatalf("CreateFreeze: %v", err)
		}

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "agentId", "freeze-h-a4")
		w := httptest.NewRecorder()
		h.ListAgentFreezes(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var resp struct {
			Freezes []jobs.AgentFreeze `json:"freezes"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(resp.Freezes) != 1 || resp.Freezes[0].ID != created.ID {
			t.Errorf("resp.Freezes = %+v, want 1 row matching %s", resp.Freezes, created.ID)
		}
	})
}

func TestDeleteAgentFreeze_AdminLiftsEarly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		jobsStore := jobs.NewStore(pool)
		created, err := jobsStore.CreateFreeze(context.Background(), jobs.AgentFreeze{
			AgentID: "freeze-h-a5", FromAt: time.Now().UTC(), ToAt: time.Now().UTC().Add(1 * time.Hour), Reason: "test",
		})
		if err != nil {
			t.Fatalf("CreateFreeze: %v", err)
		}

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").
			WithJobsDispatcher(jobsStore, jobs.NewDispatcher(jobsStore))
		req := withURLParam(httptest.NewRequest(http.MethodDelete, "/x", nil), "freezeId", created.ID)
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "admin-1", Role: auth.RoleAdmin}))
		w := httptest.NewRecorder()
		h.DeleteAgentFreeze(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		frozen, _, err := jobsStore.IsAgentFrozen(context.Background(), "freeze-h-a5")
		if err != nil {
			t.Fatalf("IsAgentFrozen: %v", err)
		}
		if frozen {
			t.Error("frozen = true, want false after DELETE")
		}
	})
}
