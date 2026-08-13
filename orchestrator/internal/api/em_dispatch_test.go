package api

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/emsweep"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestHandler_WithEMSweep_StoresReference(t *testing.T) {
	h := New(nil, ws.NewHub(), nil, testJWTSecret)
	store := emsweep.NewStore(nil)
	dispatcher := emsweep.NewDispatcher(store, func(ctx context.Context, id string) (string, error) { return "", nil })
	h.WithEMSweep(store, dispatcher)
	if h.emSweep != store {
		t.Fatal("WithEMSweep did not store the emsweep.Store reference on the Handler")
	}
}

func TestDispatchEMLayer_DispatchesAndTagsRunWithSweepID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalPostureScenario(t, "em-dispatch-sc")
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "em-dispatch-agent"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		// A real em_sweeps row must exist first -- em_sweep_id is a real FK,
		// same as vex_sweeps' sweep_id.
		sw, err := emsweep.NewStore(pool).Create(context.Background(), emsweep.Sweep{
			AgentID: agentID, Layers: []string{sc.ID}, TotalLayers: 1,
		})
		if err != nil {
			t.Fatalf("seed em_sweeps row: %v", err)
		}

		runID, err := h.dispatchEMLayer(context.Background(), sw.ID, agentID, sc.ID)
		if err != nil {
			t.Fatalf("dispatchEMLayer: %v", err)
		}
		if runID == "" {
			t.Fatal("expected a non-empty scenario_run id")
		}

		var emSweepID string
		if err := pool.QueryRow(context.Background(),
			`SELECT em_sweep_id FROM scenario_runs WHERE id = $1`, runID,
		).Scan(&emSweepID); err != nil {
			t.Fatalf("query em_sweep_id: %v", err)
		}
		if emSweepID != sw.ID {
			t.Fatalf("em_sweep_id = %q, want %q", emSweepID, sw.ID)
		}
	})
}

func TestDispatchEMLayer_UnknownScenario_ReturnsError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, engine := minimalPostureScenario(t, "em-dispatch-other-sc")
		h := New(pool, ws.NewHub(), engine, "")
		_, err := h.dispatchEMLayer(context.Background(), "sweep-1", "some-agent", "does-not-exist")
		if err == nil {
			t.Fatal("expected an error for an unknown scenario id")
		}
	})
}
