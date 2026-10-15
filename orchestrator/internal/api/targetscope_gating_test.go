package api

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// TestResolveTargetScopeImport_Omitted_NoImportsExist_FailsOpen pins
// the only case where target-scope gating is legitimately skipped:
// no target-scope import has ever been created, so there is nothing
// to check a target against.
func TestResolveTargetScopeImport_Omitted_NoImportsExist_FailsOpen(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/", nil)
		scope, ok := h.resolveTargetScopeImport(rec, req, "")
		if !ok {
			t.Fatalf("ok = false, body = %s, want true", rec.Body.String())
		}
		if scope != nil {
			t.Errorf("scope = %+v, want nil -- nothing has ever been imported", scope)
		}
	})
}

func TestResolveTargetScopeImport_Omitted_ImportExists_ResolvesLatest(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		_ = createTestTargetScopeImport(t, h, pool, map[string]any{
			"sourceType":        "manual",
			"authorizedTargets": []map[string]any{{"cidr": "10.0.1.0/24"}},
			"limitations":       []string{"x"},
		})
		newerID := createTestTargetScopeImport(t, h, pool, map[string]any{
			"sourceType":        "manual",
			"authorizedTargets": []map[string]any{{"cidr": "10.0.2.0/24"}},
			"limitations":       []string{"x"},
		})

		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/", nil)
		scope, ok := h.resolveTargetScopeImport(rec, req, "")
		if !ok {
			t.Fatalf("ok = false, body = %s, want true", rec.Body.String())
		}
		if scope == nil || scope.ID != newerID {
			t.Errorf("scope.ID = %v, want the newest import %q", scope, newerID)
		}
	})
}

func TestResolveTargetScopeImport_ExplicitID_PinsSpecificImport_NotLatest(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		olderID := createTestTargetScopeImport(t, h, pool, map[string]any{
			"sourceType":        "manual",
			"authorizedTargets": []map[string]any{{"cidr": "10.0.1.0/24"}},
			"limitations":       []string{"x"},
		})
		_ = createTestTargetScopeImport(t, h, pool, map[string]any{
			"sourceType":        "manual",
			"authorizedTargets": []map[string]any{{"cidr": "10.0.2.0/24"}},
			"limitations":       []string{"x"},
		})

		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/", nil)
		scope, ok := h.resolveTargetScopeImport(rec, req, olderID)
		if !ok {
			t.Fatalf("ok = false, body = %s, want true", rec.Body.String())
		}
		if scope == nil || scope.ID != olderID {
			t.Errorf("scope.ID = %v, want the explicitly-pinned import %q", scope, olderID)
		}
	})
}

func TestResolveTargetScopeImport_LookupFailure_FailsClosed(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/", nil)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		req = req.WithContext(ctx)
		scope, ok := h.resolveTargetScopeImport(rec, req, "")
		if ok {
			t.Fatalf("ok = true, want false -- a lookup failure must fail closed")
		}
		if rec.Code < 500 {
			t.Errorf("status = %d, want a 5xx", rec.Code)
		}
		if scope != nil {
			t.Errorf("scope = %+v, want nil on failure", scope)
		}
	})
}
