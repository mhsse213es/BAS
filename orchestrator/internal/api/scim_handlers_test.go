package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scim"
)

func seedSCIMConfig(t *testing.T, pool *pgxpool.Pool, tenantID, token, defaultRole string, enabled bool) string {
	t.Helper()
	var id string
	err := pool.QueryRow(t.Context(),
		`INSERT INTO scim_configs (tenant_id, token_hash, default_role, enabled) VALUES ($1,$2,$3,$4) RETURNING id`,
		tenantID, hashSCIMToken(token), defaultRole, enabled,
	).Scan(&id)
	if err != nil {
		t.Fatalf("seedSCIMConfig: %v", err)
	}
	return id
}

func TestSCIMAuth_MissingWrongDisabledToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		seedSCIMConfig(t, pool, "default", "good-token", "viewer", true)
		seedSCIMConfig(t, pool, mustSeedTenant(t, pool, "disabled-tenant"), "disabled-token", "viewer", false)

		cases := []struct {
			name  string
			token string
		}{
			{"missing", ""},
			{"wrong", "no-such-token"},
			{"disabled config", "disabled-token"},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
				if c.token != "" {
					req.Header.Set("Authorization", "Bearer "+c.token)
				}
				rec := httptest.NewRecorder()
				h.scimAuth(http.HandlerFunc(h.SCIMListUsers)).ServeHTTP(rec, req)
				if rec.Code != http.StatusUnauthorized {
					t.Errorf("status = %d, want 401", rec.Code)
				}
			})
		}
	})
}

func TestSCIMCreateUser_JITDefaultRoleAndAuthSource(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		seedSCIMConfig(t, pool, "default", "good-token", "analyst", true)

		body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"newhire@example.com","active":true}`
		req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer good-token")
		rec := httptest.NewRecorder()
		h.scimAuth(http.HandlerFunc(h.SCIMCreateUser)).ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
		}

		var role, authSource string
		var isActive bool
		err := pool.QueryRow(t.Context(), `SELECT role, auth_source, is_active FROM users WHERE username='newhire@example.com'`).
			Scan(&role, &authSource, &isActive)
		if err != nil {
			t.Fatalf("provisioned user not found: %v", err)
		}
		if role != "analyst" || authSource != "sso" || !isActive {
			t.Errorf("role=%q authSource=%q isActive=%v, want analyst/sso/true", role, authSource, isActive)
		}
	})
}

func TestSCIMCreateUser_DuplicateUserNameConflicts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		seedSCIMConfig(t, pool, "default", "good-token", "viewer", true)
		body := `{"userName":"dup@example.com"}`

		req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer good-token")
		rec := httptest.NewRecorder()
		h.scimAuth(http.HandlerFunc(h.SCIMCreateUser)).ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("first create status = %d", rec.Code)
		}

		req = httptest.NewRequest(http.MethodPost, "/scim/v2/Users", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer good-token")
		rec = httptest.NewRecorder()
		h.scimAuth(http.HandlerFunc(h.SCIMCreateUser)).ServeHTTP(rec, req)
		if rec.Code != http.StatusConflict {
			t.Fatalf("duplicate create status = %d, want 409", rec.Code)
		}
	})
}

func TestSCIMListUsers_FilterByUserName(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		seedSCIMConfig(t, pool, "default", "good-token", "viewer", true)
		seedUser(t, pool, "alice@example.com", "pw", "viewer", true)
		seedUser(t, pool, "bob@example.com", "pw", "viewer", true)
		pool.Exec(t.Context(), `UPDATE users SET tenant_id='default' WHERE username IN ('alice@example.com','bob@example.com')`)

		req := httptest.NewRequest(http.MethodGet, `/scim/v2/Users?filter=`+`userName+eq+%22alice%40example.com%22`, nil)
		req.Header.Set("Authorization", "Bearer good-token")
		rec := httptest.NewRecorder()
		h.scimAuth(http.HandlerFunc(h.SCIMListUsers)).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
		}
		var got scim.ListResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.TotalResults != 1 || len(got.Resources) != 1 || got.Resources[0].UserName != "alice@example.com" {
			t.Errorf("got %+v", got)
		}
	})
}

func TestSCIMPatchUser_ActiveFalseDeactivates(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		seedSCIMConfig(t, pool, "default", "good-token", "viewer", true)
		userID := seedUser(t, pool, "person@example.com", "pw", "viewer", true)
		pool.Exec(t.Context(), `UPDATE users SET tenant_id='default' WHERE id=$1`, userID)

		body := `{"Operations":[{"op":"replace","path":"active","value":false}]}`
		req := httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/"+userID, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer good-token")
		req = withURLParam(req, "id", userID)
		rec := httptest.NewRecorder()
		h.scimAuth(http.HandlerFunc(h.SCIMPatchUser)).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
		}

		var isActive bool
		pool.QueryRow(t.Context(), `SELECT is_active FROM users WHERE id=$1`, userID).Scan(&isActive)
		if isActive {
			t.Error("user still active after PATCH active:false")
		}
		var n int
		pool.QueryRow(t.Context(), `SELECT COUNT(*) FROM users WHERE id=$1`, userID).Scan(&n)
		if n != 1 {
			t.Error("row was removed — PATCH must deactivate, never delete")
		}
	})
}

func TestSCIMDeleteUser_DeactivatesNeverHardDeletes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		seedSCIMConfig(t, pool, "default", "good-token", "viewer", true)
		userID := seedUser(t, pool, "leaving@example.com", "pw", "viewer", true)
		pool.Exec(t.Context(), `UPDATE users SET tenant_id='default' WHERE id=$1`, userID)

		req := httptest.NewRequest(http.MethodDelete, "/scim/v2/Users/"+userID, nil)
		req.Header.Set("Authorization", "Bearer good-token")
		req = withURLParam(req, "id", userID)
		rec := httptest.NewRecorder()
		h.scimAuth(http.HandlerFunc(h.SCIMDeleteUser)).ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204, body=%s", rec.Code, rec.Body.String())
		}

		var isActive bool
		var n int
		pool.QueryRow(t.Context(), `SELECT COUNT(*) FROM users WHERE id=$1`, userID).Scan(&n)
		if n != 1 {
			t.Fatal("row was hard-deleted — must only soft-deactivate")
		}
		pool.QueryRow(t.Context(), `SELECT is_active FROM users WHERE id=$1`, userID).Scan(&isActive)
		if isActive {
			t.Error("user still active after DELETE")
		}
	})
}

func TestSCIMUsers_CrossTenantIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		otherTenantID := mustSeedTenant(t, pool, "other-scim-users")
		seedSCIMConfig(t, pool, "default", "default-token", "viewer", true)
		seedSCIMConfig(t, pool, otherTenantID, "other-token", "viewer", true)
		otherUserID := seedUser(t, pool, "other-tenant-user@example.com", "pw", "viewer", true)
		pool.Exec(t.Context(), `UPDATE users SET tenant_id=$1 WHERE id=$2`, otherTenantID, otherUserID)

		req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users/"+otherUserID, nil)
		req.Header.Set("Authorization", "Bearer default-token")
		req = withURLParam(req, "id", otherUserID)
		rec := httptest.NewRecorder()
		h.scimAuth(http.HandlerFunc(h.SCIMGetUser)).ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("cross-tenant GET status = %d, want 404", rec.Code)
		}
	})
}

func TestSCIMServiceProviderConfig_DiscoveryEndpoints(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		seedSCIMConfig(t, pool, "default", "good-token", "viewer", true)

		for _, tc := range []struct {
			path    string
			handler http.HandlerFunc
		}{
			{"/scim/v2/ServiceProviderConfig", h.SCIMServiceProviderConfig},
			{"/scim/v2/ResourceTypes", h.SCIMResourceTypes},
			{"/scim/v2/Schemas", h.SCIMSchemas},
		} {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.Header.Set("Authorization", "Bearer good-token")
			rec := httptest.NewRecorder()
			h.scimAuth(tc.handler).ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("%s status = %d, body=%s", tc.path, rec.Code, rec.Body.String())
			}
			var probe any
			if err := json.Unmarshal(rec.Body.Bytes(), &probe); err != nil {
				t.Errorf("%s: invalid JSON: %v", tc.path, err)
			}
		}
	})
}

// mustSeedTenant inserts a tenant row for tests that need a second tenant
// beyond the bootstrap "default" one.
func mustSeedTenant(t *testing.T, pool *pgxpool.Pool, slug string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(t.Context(), `INSERT INTO tenants (name, slug) VALUES ($1, $1) RETURNING id`, slug).Scan(&id); err != nil {
		t.Fatalf("mustSeedTenant: %v", err)
	}
	return id
}
