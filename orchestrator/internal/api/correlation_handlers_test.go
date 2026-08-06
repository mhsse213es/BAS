package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/correlation"
	"github.com/audspect/bas/internal/reporting/attackdata"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func correlationHandler(t *testing.T, pool *pgxpool.Pool) *Handler {
	t.Helper()
	eng := scenario.NewEngine(t.TempDir())
	return New(pool, ws.NewHub(), eng, "").WithCorrelation(correlation.NewEngine(pool, eng))
}

func TestCorrelateTechniqueHandler_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	want := attackdata.Lookup("T1059.001")
	if want == nil {
		t.Fatal("test fixture assumption broken: T1059.001 not bundled")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := correlationHandler(t, pool)
		rec := httptest.NewRecorder()
		h.CorrelateTechnique(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/api/correlation/technique/T1059.001", nil), "id", "T1059.001"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var out correlation.TechniqueCorrelation
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out.Technique.Name != want.Name {
			t.Errorf("Technique.Name = %q, want %q", out.Technique.Name, want.Name)
		}
	})
}

func TestCorrelateActorHandler_UnknownActor_Returns200Empty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := correlationHandler(t, pool)
		rec := httptest.NewRecorder()
		h.CorrelateActor(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/api/correlation/actor/NoSuchActor", nil), "name", "NoSuchActor"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (unknown actor is an empty correlation, not an error)", rec.Code)
		}
		var out correlation.ActorCorrelation
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(out.Techniques) != 0 {
			t.Errorf("Techniques = %+v, want empty", out.Techniques)
		}
	})
}

func TestCorrelateIOCHandler_UnknownID_Returns200Empty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := correlationHandler(t, pool)
		rec := httptest.NewRecorder()
		h.CorrelateIOC(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/api/correlation/ioc/does-not-exist", nil), "id", "does-not-exist"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})
}
