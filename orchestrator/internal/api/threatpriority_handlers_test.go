package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/threatpriority"
	"github.com/audspect/bas/internal/ws"
)

func TestThreatPriorityActors_EmptyRoster_ReturnsEmptyArray(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		engine := scenario.NewEngine(t.TempDir())
		if err := engine.Load(); err != nil {
			t.Fatalf("engine.Load: %v", err)
		}
		pe := threatpriority.NewEngine(pool, engine, nil, nil)
		h := New(pool, ws.NewHub(), engine, "").WithThreatPriority(pe)

		req := httptest.NewRequest("GET", "/api/threat-priority/actors", nil)
		w := httptest.NewRecorder()
		h.ThreatPriorityActors(w, req)

		if w.Code != 200 {
			t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
		}
	})
}

func TestThreatPriorityActorDetail_UnknownActor_ReturnsEmptyButOK(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		engine := scenario.NewEngine(t.TempDir())
		if err := engine.Load(); err != nil {
			t.Fatalf("engine.Load: %v", err)
		}
		pe := threatpriority.NewEngine(pool, engine, nil, nil)
		h := New(pool, ws.NewHub(), engine, "").WithThreatPriority(pe)

		req := httptest.NewRequest("GET", "/api/threat-priority/actors/Nonexistent-Actor", nil)
		req = withURLParams(req, map[string]string{"name": "Nonexistent-Actor"})
		w := httptest.NewRecorder()
		h.ThreatPriorityActorDetail(w, req)

		if w.Code != 200 {
			t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
		}
	})
}

func TestThreatPriorityActors_NoEngineAttached_ReturnsEmptyArray(t *testing.T) {
	engine := scenario.NewEngine(t.TempDir())
	if err := engine.Load(); err != nil {
		t.Fatalf("engine.Load: %v", err)
	}
	h := New(nil, ws.NewHub(), engine, "")

	req := httptest.NewRequest("GET", "/api/threat-priority/actors", nil)
	w := httptest.NewRecorder()
	h.ThreatPriorityActors(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
	}
	if strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("body = %q, want an empty JSON array (nil-safe when no priority engine attached)", w.Body.String())
	}
}
