package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/auth"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestPrivilegeEscalation_NonAdminBlockedFromEveryAdminRoute cross-references
// routeMatrix (from rbac_matrix_test.go) rather than re-enumerating admin
// routes by hand, so it can never silently drift from the matrix that
// drives the main RBAC test.
func TestPrivilegeEscalation_NonAdminBlockedFromEveryAdminRoute(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := mountTestRouter(t)
		for _, rc := range routeMatrix {
			if rc.tier != tierAdminOnly {
				continue
			}
			for _, role := range []auth.Role{auth.RoleViewer, auth.RoleAnalyst} {
				t.Run(string(role)+" "+rc.method+" "+rc.path, func(t *testing.T) {
					tok, _ := auth.GenerateToken("escalate-"+string(role), role, testJWTSecret, time.Hour)
					req := httptest.NewRequest(rc.method, concretePath(rc.path), nil)
					req.Header.Set("Authorization", "Bearer "+tok)
					rec := httptest.NewRecorder()
					router.ServeHTTP(rec, req)
					if rec.Code != http.StatusForbidden {
						t.Fatalf("%s on admin-only %s %s: status = %d, want 403", role, rc.method, rc.path, rec.Code)
					}
				})
			}
		}
	})
}

func TestPrivilegeEscalation_ViewerCannotUpdateOwnAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := mountTestRouter(t)
		viewerID := seedUser(t, pool, "quinn", "password123", "viewer", true)
		tok, _ := auth.GenerateToken(viewerID, auth.RoleViewer, testJWTSecret, time.Hour)

		body, _ := json.Marshal(map[string]any{"role": "admin"})
		req := httptest.NewRequest(http.MethodPut, "/api/users/"+viewerID, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("viewer self-update: status = %d, want 403 (blocked by the outer admin-only route group, before any handler-level self-protection logic runs)", rec.Code)
		}
	})
}

func TestPrivilegeEscalation_ForgedRoleClaimRejectedAtAuthentication(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := mountTestRouter(t)

		// A token claiming role=admin, signed with a secret the server does
		// not recognize (the attacker doesn't know testJWTSecret). Must be
		// rejected at authentication (401), never reach the role check.
		forged, err := auth.GenerateToken("attacker", auth.RoleAdmin, "attacker-controlled-secret", time.Hour)
		if err != nil {
			t.Fatalf("mint forged token: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
		req.Header.Set("Authorization", "Bearer "+forged)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("forged-secret admin token: status = %d, want 401", rec.Code)
		}
	})
}

func TestPrivilegeEscalation_MissingRoleClaimDenied(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := mountTestRouter(t)

		claims := auth.Claims{
			UserID: "no-role-user",
			// Role deliberately left as the zero value "".
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		}
		tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testJWTSecret))
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("empty-role token on admin-only route: status = %d, want 403", rec.Code)
		}
	})
}

func TestPrivilegeEscalation_ExtraneousFieldsIgnored(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := mountTestRouter(t)
		adminID := seedUser(t, pool, "rex", "password123", "admin", true)
		tok, _ := auth.GenerateToken(adminID, auth.RoleAdmin, testJWTSecret, time.Hour)

		body, _ := json.Marshal(map[string]any{
			"username": "sam",
			"password": "password123",
			"role":     "viewer",
			"isAdmin":  true,
			"id":       "attacker-chosen-id",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create with extraneous fields: status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var created map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &created)
		if created["role"] != "viewer" {
			t.Fatalf("role = %q, want viewer (isAdmin field must be ignored, not bound anywhere)", created["role"])
		}
		if created["id"] == "attacker-chosen-id" {
			t.Fatal("server accepted a client-supplied id via the full HTTP stack")
		}
	})
}
