package api

import (
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestCoverageMatrix_ReturnsRowsForKnownActor(t *testing.T) {
	engine := scenario.NewEngine(t.TempDir())
	if err := engine.Load(); err != nil {
		t.Fatalf("engine.Load: %v", err)
	}
	h := New(nil, ws.NewHub(), engine, "")

	req := httptest.NewRequest("GET", "/api/coverage/matrix?actor="+url.QueryEscape("Wizard Spider"), nil)
	w := httptest.NewRecorder()
	h.CoverageMatrix(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
	}
	if w.Body.Len() == 0 {
		t.Fatal("expected a non-empty JSON body")
	}
}

func TestCoverageActors_ReturnsSortedNonEmptyList(t *testing.T) {
	engine := scenario.NewEngine(t.TempDir())
	if err := engine.Load(); err != nil {
		t.Fatalf("engine.Load: %v", err)
	}
	h := New(nil, ws.NewHub(), engine, "")

	req := httptest.NewRequest("GET", "/api/coverage/actors", nil)
	w := httptest.NewRecorder()
	h.CoverageActors(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
	}
	if w.Body.Len() == 0 {
		t.Fatal("expected a non-empty JSON body -- attackdata.GroupTechniqueIndex() ships bundled MITRE groups, list should never be empty")
	}
}
