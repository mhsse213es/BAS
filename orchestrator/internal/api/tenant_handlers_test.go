package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
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

func TestCreateUser_PlatformAdminMustSpecifyTenant(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := tenantHandler(t, pool)
		platformAdminTok, _ := auth.GenerateTenantToken("pa-1", auth.RoleAdmin, nil, true, testJWTSecret, time.Hour)

		body := `{"username":"noTenant","password":"correcthorsebatterystaple","role":"viewer"}`
		req := httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+platformAdminTok)
		req = withClaims(t, req, testJWTSecret)
		rec := httptest.NewRecorder()
		h.CreateUser(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("platform-admin CreateUser with no tenantId status = %d, want 400", rec.Code)
		}
	})
}

func TestCreateUser_TenantAdminIgnoresRequestedTenantId(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := tenantHandler(t, pool)
		var otherTenantID string
		if err := pool.QueryRow(t.Context(), `INSERT INTO tenants (name, slug) VALUES ('Other', 'other') RETURNING id`).Scan(&otherTenantID); err != nil {
			t.Fatalf("seed other tenant: %v", err)
		}
		defaultTenant := "default"
		tenantAdminTok, _ := auth.GenerateTenantToken("ta-1", auth.RoleAdmin, &defaultTenant, false, testJWTSecret, time.Hour)

		body := `{"username":"sneaky","password":"correcthorsebatterystaple","role":"viewer","tenantId":"` + otherTenantID + `"}`
		req := httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tenantAdminTok)
		req = withClaims(t, req, testJWTSecret)
		rec := httptest.NewRecorder()
		h.CreateUser(rec, req)
		if rec.Code != http.StatusCreated { // CreateUser's established success code
			t.Fatalf("CreateUser status = %d, body=%s", rec.Code, rec.Body.String())
		}

		var gotTenant string
		if err := pool.QueryRow(t.Context(), `SELECT tenant_id FROM users WHERE username = 'sneaky'`).Scan(&gotTenant); err != nil {
			t.Fatalf("verify: %v", err)
		}
		if gotTenant != "default" {
			t.Errorf("created user's tenant_id = %q, want default (the caller's own tenant, not the requested other)", gotTenant)
		}
	})
}

// withClaims puts the request's own bearer token's claims into its context,
// the way auth.Middleware would in the real router — CreateUser reads
// caller identity via auth.ClaimsFrom, and these tests call the handler
// directly (bypassing Mount's middleware chain), so this must be done by hand.
func withClaims(t *testing.T, req *http.Request, secret string) *http.Request {
	t.Helper()
	tok := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
	claims, err := auth.ValidateToken(tok, secret)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	return req.WithContext(auth.ContextWithClaims(req.Context(), claims))
}
