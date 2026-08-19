package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestGetARTAtomics_ReturnsOneRowPerAtomicNotPerTechnique proves the new
// endpoint's whole point: a technique with multiple atomics produces
// multiple rows, unlike GetARTTechniques' one-row-per-technique aggregate.
// Powers the read-only "Detailed view" for the art_all_windows Full Sweep
// scenario.
func TestGetARTAtomics_ReturnsOneRowPerAtomicNotPerTechnique(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO techniques (technique_id, name, tactic) VALUES ('T1059','Command and Scripting Interpreter','execution')
			 ON CONFLICT (technique_id) DO NOTHING`); err != nil {
			t.Fatalf("seed technique: %v", err)
		}
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO art_atomic_tests (technique_id, test_index, name, executor, command, platform)
			 VALUES ('T1059', 0, 'exec ps', 'powershell', 'whoami', 'windows'),
			        ('T1059', 1, 'exec cmd', 'cmd', 'whoami', 'windows')`); err != nil {
			t.Fatalf("seed art_atomic_tests: %v", err)
		}
		store, err := scenario.NewARTStoreFromDB(context.Background(), pool, nil)
		if err != nil {
			t.Fatalf("NewARTStoreFromDB: %v", err)
		}

		h := variantHandler(t, pool).WithART(store)
		rec := httptest.NewRecorder()
		h.GetARTAtomics(rec, httptest.NewRequest(http.MethodGet, "/api/art/atomics?platform=windows", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var atoms []scenario.AtomicMeta
		if err := json.Unmarshal(rec.Body.Bytes(), &atoms); err != nil {
			t.Fatalf("decode: %v", err)
		}
		count := 0
		for _, a := range atoms {
			if a.TechniqueID == "T1059" {
				count++
			}
		}
		if count != 2 {
			t.Errorf("T1059 atoms = %d, want 2 (exec ps + exec cmd) -- endpoint must return per-atomic rows, not per-technique", count)
		}
	})
}

func TestGetARTAtomics_NilStoreReturnsEmptyArray(t *testing.T) {
	h := New(nil, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
	rec := httptest.NewRecorder()
	h.GetARTAtomics(rec, httptest.NewRequest(http.MethodGet, "/api/art/atomics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 even with no ART store loaded", rec.Code)
	}
	var atoms []scenario.AtomicMeta
	if err := json.Unmarshal(rec.Body.Bytes(), &atoms); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(atoms) != 0 {
		t.Errorf("atoms = %v, want empty", atoms)
	}
}
