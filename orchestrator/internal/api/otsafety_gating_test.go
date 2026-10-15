package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func createTestOTSafetyImport(t *testing.T, h *Handler, pool *pgxpool.Pool, body map[string]any) string {
	t.Helper()
	userID := seedUser(t, pool, fmt.Sprintf("otsafety-gating-op-%d", time.Now().UnixNano()), "pw12345678", string(auth.RoleAnalyst), true)
	b, _ := json.Marshal(body)
	req := authedRequest(t, http.MethodPost, "/api/ot-safety-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
	rec := callAuthed(h.CreateOTSafetyImport, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create ot safety import: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created ot safety import: %v", err)
	}
	return created.ID
}

// TestResolveOTSafetyGatingContext_BothOmitted_NoImportsExist_FailOpen pins
// the only case where safety gating is legitimately skipped: neither a
// topology nor an ot-safety import has ever been created, so there is
// nothing to resolve a target's zone against.
func TestResolveOTSafetyGatingContext_BothOmitted_NoImportsExist_FailOpen(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/x", nil)

		topo, safety, ok := h.resolveOTSafetyGatingContext(rec, req, "", "")
		if !ok {
			t.Fatalf("ok = false, body = %s, want true (nothing declared, nothing to fail on)", rec.Body.String())
		}
		if topo != nil || safety != nil {
			t.Errorf("topo = %v, safety = %v, want both nil when nothing was ever imported", topo, safety)
		}
	})
}

// TestResolveOTSafetyGatingContext_BothOmitted_ImportsExist_ResolvesLatest
// is the core fix: omitting both ids must not silently skip the gate when
// imports actually exist -- it must resolve the most recently created one
// of each type.
func TestResolveOTSafetyGatingContext_BothOmitted_ImportsExist_ResolvesLatest(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)

		olderTopoID := createTestTopologyImport(t, h, pool, map[string]any{
			"sourceType": "manual",
			"zones":      []map[string]any{{"name": "older-zone", "cidrs": []string{"10.0.1.0/24"}}},
			"edges":      []map[string]any{},
		})
		newerTopoID := createTestTopologyImport(t, h, pool, map[string]any{
			"sourceType": "manual",
			"zones":      []map[string]any{{"name": "newer-zone", "cidrs": []string{"10.0.2.0/24"}}},
			"edges":      []map[string]any{},
		})
		newerSafetyID := createTestOTSafetyImport(t, h, pool, map[string]any{
			"sourceType":     "manual",
			"sensitiveZones": []map[string]any{{"zoneName": "newer-zone", "tier": "ot"}},
			"limitations":    []string{"zone names are not cross-validated against a real network-topology import"},
		})

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		topo, safety, ok := h.resolveOTSafetyGatingContext(rec, req, "", "")
		if !ok {
			t.Fatalf("ok = false, body = %s, want true", rec.Body.String())
		}
		if topo == nil || topo.ID != newerTopoID {
			t.Errorf("resolved topology import = %v, want the newest one (%s), not the older one (%s)", topo, newerTopoID, olderTopoID)
		}
		if safety == nil || safety.ID != newerSafetyID {
			t.Errorf("resolved ot safety import = %v, want %s", safety, newerSafetyID)
		}
	})
}

// TestResolveOTSafetyGatingContext_ExplicitIDs_PinSpecificImport_NotLatest
// proves an explicit id always wins over auto-resolution, even when a
// newer import of that type exists.
func TestResolveOTSafetyGatingContext_ExplicitIDs_PinSpecificImport_NotLatest(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)

		olderTopoID := createTestTopologyImport(t, h, pool, map[string]any{
			"sourceType": "manual",
			"zones":      []map[string]any{{"name": "older-zone", "cidrs": []string{"10.0.1.0/24"}}},
			"edges":      []map[string]any{},
		})
		_ = createTestTopologyImport(t, h, pool, map[string]any{
			"sourceType": "manual",
			"zones":      []map[string]any{{"name": "newer-zone", "cidrs": []string{"10.0.2.0/24"}}},
			"edges":      []map[string]any{},
		})
		olderSafetyID := createTestOTSafetyImport(t, h, pool, map[string]any{
			"sourceType":     "manual",
			"sensitiveZones": []map[string]any{{"zoneName": "older-zone", "tier": "ot"}},
			"limitations":    []string{"zone names are not cross-validated against a real network-topology import"},
		})
		_ = createTestOTSafetyImport(t, h, pool, map[string]any{
			"sourceType":     "manual",
			"sensitiveZones": []map[string]any{{"zoneName": "newer-zone", "tier": "ot"}},
			"limitations":    []string{"zone names are not cross-validated against a real network-topology import"},
		})

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		topo, safety, ok := h.resolveOTSafetyGatingContext(rec, req, olderTopoID, olderSafetyID)
		if !ok {
			t.Fatalf("ok = false, body = %s, want true", rec.Body.String())
		}
		if topo == nil || topo.ID != olderTopoID {
			t.Errorf("resolved topology import = %v, want the explicitly-pinned older one (%s)", topo, olderTopoID)
		}
		if safety == nil || safety.ID != olderSafetyID {
			t.Errorf("resolved ot safety import = %v, want the explicitly-pinned older one (%s)", safety, olderSafetyID)
		}
	})
}

// TestResolveOTSafetyGatingContext_LookupFailure_FailsClosed proves a
// genuine lookup failure (here: a context already canceled before the
// query runs) is never treated as "nothing was imported" -- it must
// write an error response and return ok=false so the caller rejects the
// request instead of probing unguarded.
func TestResolveOTSafetyGatingContext_LookupFailure_FailsClosed(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		req := httptest.NewRequest(http.MethodPost, "/x", nil).WithContext(ctx)
		rec := httptest.NewRecorder()

		topo, safety, ok := h.resolveOTSafetyGatingContext(rec, req, "", "")
		if ok {
			t.Fatalf("ok = true, want false -- a canceled-context lookup failure must fail closed, not proceed as if nothing was imported")
		}
		if topo != nil || safety != nil {
			t.Errorf("topo = %v, safety = %v, want both nil on a failed lookup", topo, safety)
		}
		if rec.Code < 500 {
			t.Errorf("status = %d, want a 5xx -- a lookup failure is a server-side problem, not a caller error", rec.Code)
		}
	})
}
