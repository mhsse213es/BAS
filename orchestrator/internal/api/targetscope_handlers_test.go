package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// createTestTargetScopeImport mirrors createTestOTSafetyImport's shape
// exactly -- a shared creation helper other test files (gating tests)
// also use.
func createTestTargetScopeImport(t *testing.T, h *Handler, pool *pgxpool.Pool, body map[string]any) string {
	t.Helper()
	userID := seedUser(t, pool, fmt.Sprintf("targetscope-op-%d", time.Now().UnixNano()), "pw12345678", string(auth.RoleAnalyst), true)
	b, _ := json.Marshal(body)
	req := authedRequest(t, http.MethodPost, "/api/target-scope-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
	rec := callAuthed(h.CreateTargetScopeImport, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create target scope import: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created target scope import: %v", err)
	}
	return created.ID
}

func validTargetScopeBody() map[string]any {
	return map[string]any{
		"sourceType":        "manual",
		"authorizedTargets": []map[string]any{{"cidr": "10.0.1.0/24", "note": "pentest lab"}},
		"limitations":       []string{"not cross-validated against a real network-topology import"},
	}
}

func TestCreateTargetScopeImport_Valid_Returns201(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "targetscope-op-create", "pw12345678", string(auth.RoleAnalyst), true)
		b, _ := json.Marshal(validTargetScopeBody())
		req := authedRequest(t, http.MethodPost, "/api/target-scope-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateTargetScopeImport, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s, want 201", rec.Code, rec.Body.String())
		}
		var created struct {
			ID                string `json:"id"`
			AuthorizedTargets []struct {
				CIDR string `json:"cidr"`
			} `json:"authorizedTargets"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if created.ID == "" || len(created.AuthorizedTargets) != 1 || created.AuthorizedTargets[0].CIDR != "10.0.1.0/24" {
			t.Errorf("unexpected created body: %s", rec.Body.String())
		}
	})
}

func TestCreateTargetScopeImport_AuthorizedTargetsWithoutLimitations_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "targetscope-op-nolimit", "pw12345678", string(auth.RoleAnalyst), true)
		body := map[string]any{
			"sourceType":        "manual",
			"authorizedTargets": []map[string]any{{"cidr": "10.0.1.0/24"}},
		}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/target-scope-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateTargetScopeImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400 -- limitations must be required whenever any authorized target is declared", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateTargetScopeImport_EntryWithBothCIDRAndHost_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "targetscope-op-both", "pw12345678", string(auth.RoleAnalyst), true)
		body := map[string]any{
			"sourceType":        "manual",
			"authorizedTargets": []map[string]any{{"cidr": "10.0.1.0/24", "host": "approved.example"}},
			"limitations":       []string{"x"},
		}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/target-scope-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateTargetScopeImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400 -- an entry must declare exactly one of cidr/host", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateTargetScopeImport_EntryWithNeitherCIDRNorHost_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "targetscope-op-neither", "pw12345678", string(auth.RoleAnalyst), true)
		body := map[string]any{
			"sourceType":        "manual",
			"authorizedTargets": []map[string]any{{"note": "oops"}},
			"limitations":       []string{"x"},
		}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/target-scope-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateTargetScopeImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400 -- an entry must declare exactly one of cidr/host", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateTargetScopeImport_InvalidCIDR_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "targetscope-op-badcidr", "pw12345678", string(auth.RoleAnalyst), true)
		body := map[string]any{
			"sourceType":        "manual",
			"authorizedTargets": []map[string]any{{"cidr": "not-a-cidr"}},
			"limitations":       []string{"x"},
		}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/target-scope-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateTargetScopeImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400 -- an unparseable cidr must be rejected", rec.Code, rec.Body.String())
		}
	})
}

func TestListAndGetTargetScopeImport(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		id := createTestTargetScopeImport(t, h, pool, validTargetScopeBody())

		userID := seedUser(t, pool, "targetscope-op-list", "pw12345678", string(auth.RoleViewer), true)
		listReq := authedRequest(t, http.MethodGet, "/api/target-scope-imports", nil, auth.RoleViewer, userID)
		listRec := callAuthed(h.ListTargetScopeImports, listReq)
		if listRec.Code != http.StatusOK {
			t.Fatalf("list status = %d, body = %s", listRec.Code, listRec.Body.String())
		}

		getReq := authedRequest(t, http.MethodGet, "/api/target-scope-imports/"+id, nil, auth.RoleViewer, userID)
		getReq = withURLParam(getReq, "id", id)
		getRec := callAuthed(h.GetTargetScopeImport, getReq)
		if getRec.Code != http.StatusOK {
			t.Fatalf("get status = %d, body = %s", getRec.Code, getRec.Body.String())
		}
	})
}

func TestGetTargetScopeImport_NotFound_Returns404(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "targetscope-op-404", "pw12345678", string(auth.RoleViewer), true)
		req := authedRequest(t, http.MethodGet, "/api/target-scope-imports/nonexistent", nil, auth.RoleViewer, userID)
		req = withURLParam(req, "id", "nonexistent")
		rec := callAuthed(h.GetTargetScopeImport, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, body = %s, want 404", rec.Code, rec.Body.String())
		}
	})
}
