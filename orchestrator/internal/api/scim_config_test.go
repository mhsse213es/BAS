package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCreateSCIMConfig_ReturnsTokenOnceThenGetOmitsIt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		tok := tenantAdminToken(t, "default")

		body := `{"defaultRole":"analyst"}`
		req := httptest.NewRequest(http.MethodPost, "/api/scim/config", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		req = withClaims(t, req, testJWTSecret)
		rec := httptest.NewRecorder()
		h.CreateSCIMConfig(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("CreateSCIMConfig status = %d, body=%s", rec.Code, rec.Body.String())
		}
		var created struct {
			ID    string `json:"id"`
			Token string `json:"token"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if created.Token == "" {
			t.Fatal("expected a cleartext token in the create response")
		}

		req = httptest.NewRequest(http.MethodGet, "/api/scim/config", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		req = withClaims(t, req, testJWTSecret)
		rec = httptest.NewRecorder()
		h.GetSCIMConfig(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GetSCIMConfig status = %d, body=%s", rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), created.Token) {
			t.Fatal("GetSCIMConfig must never return the token again")
		}
	})
}

func TestCreateSCIMConfig_DuplicateForSameTenantConflicts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		tok := tenantAdminToken(t, "default")

		req := httptest.NewRequest(http.MethodPost, "/api/scim/config", strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer "+tok)
		req = withClaims(t, req, testJWTSecret)
		rec := httptest.NewRecorder()
		h.CreateSCIMConfig(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("first create status = %d", rec.Code)
		}

		req = httptest.NewRequest(http.MethodPost, "/api/scim/config", strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer "+tok)
		req = withClaims(t, req, testJWTSecret)
		rec = httptest.NewRecorder()
		h.CreateSCIMConfig(rec, req)
		if rec.Code != http.StatusConflict {
			t.Fatalf("duplicate create status = %d, want 409", rec.Code)
		}
	})
}

func TestRotateSCIMConfig_InvalidatesOldTokenHash(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		tok := tenantAdminToken(t, "default")
		var id string
		if err := pool.QueryRow(t.Context(),
			`INSERT INTO scim_configs (tenant_id, token_hash) VALUES ('default', $1) RETURNING id`,
			hashSCIMToken("old-token"),
		).Scan(&id); err != nil {
			t.Fatalf("seed: %v", err)
		}

		req := httptest.NewRequest(http.MethodPost, "/api/scim/config/"+id+"/rotate", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		req = withURLParam(req, "id", id)
		req = withClaims(t, req, testJWTSecret)
		rec := httptest.NewRecorder()
		h.RotateSCIMConfig(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("RotateSCIMConfig status = %d, body=%s", rec.Code, rec.Body.String())
		}
		var got struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.Token == "" || got.Token == "old-token" {
			t.Fatalf("expected a fresh token, got %q", got.Token)
		}
		var hash string
		pool.QueryRow(t.Context(), `SELECT token_hash FROM scim_configs WHERE id=$1`, id).Scan(&hash)
		if hash == hashSCIMToken("old-token") {
			t.Error("old token's hash is still stored after rotation")
		}
		if hash != hashSCIMToken(got.Token) {
			t.Error("stored hash does not match the newly issued token")
		}
	})
}

func TestUpdateSCIMConfig_ChangesRoleAndEnabled(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		tok := tenantAdminToken(t, "default")
		var id string
		if err := pool.QueryRow(t.Context(),
			`INSERT INTO scim_configs (tenant_id, token_hash, default_role, enabled) VALUES ('default', $1, 'viewer', true) RETURNING id`,
			hashSCIMToken("tok"),
		).Scan(&id); err != nil {
			t.Fatalf("seed: %v", err)
		}

		req := httptest.NewRequest(http.MethodPut, "/api/scim/config/"+id, strings.NewReader(`{"defaultRole":"analyst","enabled":false}`))
		req.Header.Set("Authorization", "Bearer "+tok)
		req = withURLParam(req, "id", id)
		req = withClaims(t, req, testJWTSecret)
		rec := httptest.NewRecorder()
		h.UpdateSCIMConfig(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("UpdateSCIMConfig status = %d, body=%s", rec.Code, rec.Body.String())
		}
		var role string
		var enabled bool
		pool.QueryRow(t.Context(), `SELECT default_role, enabled FROM scim_configs WHERE id=$1`, id).Scan(&role, &enabled)
		if role != "analyst" || enabled {
			t.Errorf("role=%q enabled=%v, want analyst/false", role, enabled)
		}
	})
}

func TestDeleteSCIMConfig_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		tok := tenantAdminToken(t, "default")
		var id string
		if err := pool.QueryRow(t.Context(),
			`INSERT INTO scim_configs (tenant_id, token_hash) VALUES ('default', $1) RETURNING id`,
			hashSCIMToken("tok"),
		).Scan(&id); err != nil {
			t.Fatalf("seed: %v", err)
		}
		req := httptest.NewRequest(http.MethodDelete, "/api/scim/config/"+id, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		req = withURLParam(req, "id", id)
		req = withClaims(t, req, testJWTSecret)
		rec := httptest.NewRecorder()
		h.DeleteSCIMConfig(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("DeleteSCIMConfig status = %d, body=%s", rec.Code, rec.Body.String())
		}
		var n int
		pool.QueryRow(t.Context(), `SELECT COUNT(*) FROM scim_configs WHERE id=$1`, id).Scan(&n)
		if n != 0 {
			t.Error("row still present after delete")
		}
	})
}

func TestSCIMConfig_CrossTenantIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		var otherTenantID string
		if err := pool.QueryRow(t.Context(), `INSERT INTO tenants (name, slug) VALUES ('Other', 'other-scim') RETURNING id`).Scan(&otherTenantID); err != nil {
			t.Fatalf("seed other tenant: %v", err)
		}
		var otherConfigID string
		if err := pool.QueryRow(t.Context(),
			`INSERT INTO scim_configs (tenant_id, token_hash) VALUES ($1, $2) RETURNING id`,
			otherTenantID, hashSCIMToken("other-tok"),
		).Scan(&otherConfigID); err != nil {
			t.Fatalf("seed other config: %v", err)
		}

		defaultTok := tenantAdminToken(t, "default")

		req := httptest.NewRequest(http.MethodGet, "/api/scim/config", nil)
		req.Header.Set("Authorization", "Bearer "+defaultTok)
		req = withClaims(t, req, testJWTSecret)
		rec := httptest.NewRecorder()
		h.GetSCIMConfig(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("GetSCIMConfig cross-tenant status = %d, want 404", rec.Code)
		}

		req = httptest.NewRequest(http.MethodDelete, "/api/scim/config/"+otherConfigID, nil)
		req.Header.Set("Authorization", "Bearer "+defaultTok)
		req = withURLParam(req, "id", otherConfigID)
		req = withClaims(t, req, testJWTSecret)
		rec = httptest.NewRecorder()
		h.DeleteSCIMConfig(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("DeleteSCIMConfig cross-tenant status = %d, want 404", rec.Code)
		}
		var n int
		pool.QueryRow(t.Context(), `SELECT COUNT(*) FROM scim_configs WHERE id=$1`, otherConfigID).Scan(&n)
		if n != 1 {
			t.Error("other tenant's config was deleted cross-tenant — isolation failed")
		}
	})
}
