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

func ssoHandler(t *testing.T, pool *pgxpool.Pool) *Handler {
	t.Helper()
	return New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
}

func tenantAdminToken(t *testing.T, tenantID string) string {
	t.Helper()
	tok, err := auth.GenerateTenantToken("ta-1", auth.RoleAdmin, &tenantID, false, testJWTSecret, time.Hour)
	if err != nil {
		t.Fatalf("GenerateTenantToken: %v", err)
	}
	return tok
}

func TestCreateSSOConfig_ThenGet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		tok := tenantAdminToken(t, "default")

		body := `{"issuerUrl":"https://idp.example.com","clientId":"c1","clientSecret":"s1","defaultRole":"analyst","enabled":true}`
		req := httptest.NewRequest(http.MethodPost, "/api/sso/config", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		req = withClaims(t, req, testJWTSecret)
		rec := httptest.NewRecorder()
		h.CreateSSOConfig(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("CreateSSOConfig status = %d, body=%s", rec.Code, rec.Body.String())
		}

		req = httptest.NewRequest(http.MethodGet, "/api/sso/config", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		req = withClaims(t, req, testJWTSecret)
		rec = httptest.NewRecorder()
		h.GetSSOConfig(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GetSSOConfig status = %d, body=%s", rec.Code, rec.Body.String())
		}
		var got SSOConfig
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.IssuerURL != "https://idp.example.com" || got.DefaultRole != "analyst" || !got.Enabled {
			t.Errorf("got %+v", got)
		}
	})
}

func TestCreateSSOConfig_DuplicateForSameTenantConflicts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		tok := tenantAdminToken(t, "default")
		body := `{"issuerUrl":"https://idp.example.com","clientId":"c1","clientSecret":"s1"}`

		req := httptest.NewRequest(http.MethodPost, "/api/sso/config", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		req = withClaims(t, req, testJWTSecret)
		rec := httptest.NewRecorder()
		h.CreateSSOConfig(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("first create status = %d", rec.Code)
		}

		req = httptest.NewRequest(http.MethodPost, "/api/sso/config", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		req = withClaims(t, req, testJWTSecret)
		rec = httptest.NewRecorder()
		h.CreateSSOConfig(rec, req)
		if rec.Code != http.StatusConflict {
			t.Fatalf("duplicate create status = %d, want 409", rec.Code)
		}
	})
}

func TestUpdateSSOConfig_MaskedSecretPreservesExisting(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		tok := tenantAdminToken(t, "default")
		var id string
		if err := pool.QueryRow(t.Context(),
			`INSERT INTO sso_configs (tenant_id, issuer_url, client_id, client_secret) VALUES ('default','https://idp.example.com','c1','real-secret') RETURNING id`,
		).Scan(&id); err != nil {
			t.Fatalf("seed: %v", err)
		}

		body := `{"issuerUrl":"https://idp2.example.com","clientId":"c1","clientSecret":"***","defaultRole":"viewer","enabled":true}`
		req := httptest.NewRequest(http.MethodPut, "/api/sso/config/"+id, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		req = withURLParam(req, "id", id)
		req = withClaims(t, req, testJWTSecret)
		rec := httptest.NewRecorder()
		h.UpdateSSOConfig(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("UpdateSSOConfig status = %d, body=%s", rec.Code, rec.Body.String())
		}

		var secret string
		if err := pool.QueryRow(t.Context(), `SELECT client_secret FROM sso_configs WHERE id=$1`, id).Scan(&secret); err != nil {
			t.Fatalf("verify: %v", err)
		}
		if secret != "real-secret" {
			t.Errorf("client_secret = %q, want unchanged real-secret", secret)
		}
	})
}

func TestDeleteSSOConfig_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		tok := tenantAdminToken(t, "default")
		var id string
		if err := pool.QueryRow(t.Context(),
			`INSERT INTO sso_configs (tenant_id, issuer_url, client_id, client_secret) VALUES ('default','https://idp.example.com','c1','s1') RETURNING id`,
		).Scan(&id); err != nil {
			t.Fatalf("seed: %v", err)
		}
		req := httptest.NewRequest(http.MethodDelete, "/api/sso/config/"+id, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		req = withURLParam(req, "id", id)
		req = withClaims(t, req, testJWTSecret)
		rec := httptest.NewRecorder()
		h.DeleteSSOConfig(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("DeleteSSOConfig status = %d, body=%s", rec.Code, rec.Body.String())
		}
		var n int
		pool.QueryRow(t.Context(), `SELECT COUNT(*) FROM sso_configs WHERE id=$1`, id).Scan(&n)
		if n != 0 {
			t.Errorf("row still present after delete")
		}
	})
}

func TestSSOConfig_CrossTenantIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		var otherTenantID string
		if err := pool.QueryRow(t.Context(), `INSERT INTO tenants (name, slug) VALUES ('Other', 'other') RETURNING id`).Scan(&otherTenantID); err != nil {
			t.Fatalf("seed other tenant: %v", err)
		}
		var otherConfigID string
		if err := pool.QueryRow(t.Context(),
			`INSERT INTO sso_configs (tenant_id, issuer_url, client_id, client_secret) VALUES ($1,'https://other-idp.example.com','c1','s1') RETURNING id`,
			otherTenantID,
		).Scan(&otherConfigID); err != nil {
			t.Fatalf("seed other config: %v", err)
		}

		defaultTok := tenantAdminToken(t, "default")

		// GET returns 404 for a tenant with no config of its own — it must
		// never see the other tenant's row.
		req := httptest.NewRequest(http.MethodGet, "/api/sso/config", nil)
		req.Header.Set("Authorization", "Bearer "+defaultTok)
		req = withClaims(t, req, testJWTSecret)
		rec := httptest.NewRecorder()
		h.GetSSOConfig(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("GetSSOConfig cross-tenant status = %d, want 404", rec.Code)
		}

		// DELETE by the other tenant's config ID must not succeed from the
		// "default" tenant's admin token.
		req = httptest.NewRequest(http.MethodDelete, "/api/sso/config/"+otherConfigID, nil)
		req.Header.Set("Authorization", "Bearer "+defaultTok)
		req = withURLParam(req, "id", otherConfigID)
		req = withClaims(t, req, testJWTSecret)
		rec = httptest.NewRecorder()
		h.DeleteSSOConfig(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("DeleteSSOConfig cross-tenant status = %d, want 404", rec.Code)
		}
		var n int
		pool.QueryRow(t.Context(), `SELECT COUNT(*) FROM sso_configs WHERE id=$1`, otherConfigID).Scan(&n)
		if n != 1 {
			t.Errorf("other tenant's config was deleted cross-tenant — isolation failed")
		}
	})
}
