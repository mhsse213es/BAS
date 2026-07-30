package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/vexsweep"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDispatchVariantForSweep_NoARTStoreReturnsError(t *testing.T) {
	// h.artStore is nil in this bare Handler (no WithART/WithContentSeed
	// called) -- resolveTemplates' ART-fallback path must surface a clear
	// error, not panic, so the dispatcher can mark the sweep failed cleanly.
	// A real pool is required here (not nil) since resolveTemplates queries
	// payload_families before ever reaching the ART-store check.
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret)
		_, _, _, err := h.dispatchVariantForSweep(context.Background(), "agent-1", "T1059.001", "sequential", false)
		if err == nil {
			t.Fatal("dispatchVariantForSweep() with no ART store loaded, want an error, got nil")
		}
	})
}

func TestHandler_WithVexSweep_StoresReference(t *testing.T) {
	store := vexsweep.NewStore(nil)
	h := New(nil, ws.NewHub(), nil, testJWTSecret).WithVexSweep(store, testVexSweepDispatcher(store))
	if h.vexSweep != store {
		t.Fatal("WithVexSweep did not store the given *vexsweep.Store on the Handler")
	}
}

func TestRunVariants_RejectsWhenAgentHasRunningSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := vexsweep.NewStore(pool)
		if _, err := store.Create(ctx, vexsweep.Sweep{
			AgentID: "agent-blocks-adhoc", Mode: "sequential",
			Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{33}, TotalVariants: 33,
		}); err != nil {
			t.Fatalf("Create sweep: %v", err)
		}

		h := New(pool, ws.NewHub(), nil, testJWTSecret).WithVexSweep(store, testVexSweepDispatcher(store))
		userID := seedUser(t, pool, "adhoc-blocked-user", "password123", "admin", true)
		body, _ := json.Marshal(map[string]string{"agentId": "agent-blocks-adhoc", "techniqueId": "T1059.003"})
		req := authedRequest(t, http.MethodPost, "/api/variants/run", bytes.NewReader(body), auth.RoleAdmin, userID)
		rec := callAuthed(h.RunVariants, req)
		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409, body: %s", rec.Code, rec.Body.String())
		}
	})
}
