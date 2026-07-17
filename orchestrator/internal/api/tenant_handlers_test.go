package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func tenantHandler(t *testing.T, pool *pgxpool.Pool) *Handler {
	t.Helper()
	return New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
}

func TestCreateTenant_ThenListTenants(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := tenantHandler(t, pool)

		body := `{"name":"Acme Bank","slug":"acme"}`
		rec := httptest.NewRecorder()
		h.CreateTenant(rec, httptest.NewRequest(http.MethodPost, "/api/tenants", strings.NewReader(body)))
		if rec.Code != http.StatusOK {
			t.Fatalf("CreateTenant status = %d, body=%s", rec.Code, rec.Body.String())
		}

		rec = httptest.NewRecorder()
		h.ListTenants(rec, httptest.NewRequest(http.MethodGet, "/api/tenants", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("ListTenants status = %d, body=%s", rec.Code, rec.Body.String())
		}
		var got []Tenant
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		// 'default' (from the schema bootstrap row) plus the one just created.
		if len(got) != 2 {
			t.Fatalf("ListTenants returned %d tenants, want 2 (default + acme): %+v", len(got), got)
		}
		foundAcme := false
		for _, tn := range got {
			if tn.Slug == "acme" && tn.Name == "Acme Bank" && tn.Status == "active" {
				foundAcme = true
			}
		}
		if !foundAcme {
			t.Errorf("did not find the created acme tenant in %+v", got)
		}
	})
}

func TestCreateTenant_DuplicateSlugConflict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := tenantHandler(t, pool)
		body := `{"name":"First","slug":"dupe"}`
		rec := httptest.NewRecorder()
		h.CreateTenant(rec, httptest.NewRequest(http.MethodPost, "/api/tenants", strings.NewReader(body)))
		if rec.Code != http.StatusOK {
			t.Fatalf("first create status = %d", rec.Code)
		}

		rec = httptest.NewRecorder()
		h.CreateTenant(rec, httptest.NewRequest(http.MethodPost, "/api/tenants", strings.NewReader(body)))
		if rec.Code != http.StatusConflict {
			t.Fatalf("duplicate slug status = %d, want 409", rec.Code)
		}
	})
}

func TestUpdateTenant_SuspendAndRename(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := tenantHandler(t, pool)
		var id string
		if err := pool.QueryRow(t.Context(), `INSERT INTO tenants (name, slug) VALUES ('Old Name', 'update-me') RETURNING id`).Scan(&id); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}

		body := `{"name":"New Name","status":"suspended"}`
		req := httptest.NewRequest(http.MethodPatch, "/api/tenants/"+id, strings.NewReader(body))
		req = withURLParam(req, "id", id) // existing helper, event_handlers_test.go
		rec := httptest.NewRecorder()
		h.UpdateTenant(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("UpdateTenant status = %d, body=%s", rec.Code, rec.Body.String())
		}

		var name, status string
		if err := pool.QueryRow(t.Context(), `SELECT name, status FROM tenants WHERE id = $1`, id).Scan(&name, &status); err != nil {
			t.Fatalf("verify: %v", err)
		}
		if name != "New Name" || status != "suspended" {
			t.Errorf("name=%q status=%q, want New Name/suspended", name, status)
		}
	})
}
