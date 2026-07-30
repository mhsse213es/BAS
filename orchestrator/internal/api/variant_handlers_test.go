package api

import (
	"context"
	"testing"

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
	h := New(nil, ws.NewHub(), nil, testJWTSecret).WithVexSweep(store)
	if h.vexSweep != store {
		t.Fatal("WithVexSweep did not store the given *vexsweep.Store on the Handler")
	}
}
