package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/cigate"
	"github.com/audspect/bas/internal/license"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func ciGateRouter(t *testing.T, pool *pgxpool.Pool) http.Handler {
	t.Helper()
	h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
	// No factory lab agent: a request that clears CI auth then answers 503, which tells it apart from a 401.
	h.SetCIGate(cigate.NewHandler(cigate.NewService(pool, nil, nil, ""), cigate.NewStore(pool)))
	prev := license.Current()
	license.SetInitial(license.Info{State: license.StateValid, Tier: license.TierEnterprise})
	t.Cleanup(func() { license.SetInitial(prev) })
	return Mount(h, ws.NewHub(), testJWTSecret, "", http.NotFoundHandler(), 0, 0)
}

func ciDo(router http.Handler, method, path, bearer, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// A CI token opens the CI routes and nothing else; a user session is not a CI credential; only an admin issues tokens;
// and a revoked token stops working at once.
func TestCIGate_TokenLifecycleThroughTheRealRoutes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		router := ciGateRouter(t, pool)
		tenant := "default"
		jwt := func(role auth.Role) string {
			tok, err := auth.GenerateTenantToken("ci-"+string(role), role, &tenant, false, testJWTSecret, time.Hour)
			if err != nil {
				t.Fatalf("mint %s token: %v", role, err)
			}
			return tok
		}
		admin, analyst := jwt(auth.RoleAdmin), jwt(auth.RoleAnalyst)

		if c := ciDo(router, http.MethodPost, "/api/ci-tokens", analyst, `{"name":"p"}`).Code; c != http.StatusForbidden {
			t.Fatalf("analyst issuing a CI token: status %d, want 403", c)
		}
		rec := ciDo(router, http.MethodPost, "/api/ci-tokens", admin, `{"name":"pipeline"}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("admin issuing a CI token: status %d, body %s", rec.Code, rec.Body.String())
		}
		var created struct {
			Token string `json:"token"`
			Info  struct {
				ID string `json:"id"`
			} `json:"info"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || !cigate.IsCIToken(created.Token) || created.Info.ID == "" {
			t.Fatalf("issue response not usable: %v, %s", err, rec.Body.String())
		}

		start := `{"contentId":"x"}`
		if c := ciDo(router, http.MethodPost, "/api/ci/validations", "", start).Code; c != http.StatusUnauthorized {
			t.Errorf("no credential on the CI route: status %d, want 401", c)
		}
		if c := ciDo(router, http.MethodPost, "/api/ci/validations", admin, start).Code; c != http.StatusUnauthorized {
			t.Errorf("an admin session on the CI route: status %d, want 401", c)
		}
		if c := ciDo(router, http.MethodPost, "/api/ci/validations", created.Token, start).Code; c != http.StatusServiceUnavailable {
			t.Errorf("a CI token on the CI route: status %d, want 503 (past auth, no lab agent)", c)
		}
		if c := ciDo(router, http.MethodGet, "/api/agents", created.Token, "").Code; c != http.StatusUnauthorized {
			t.Errorf("a CI token on a user route: status %d, want 401", c)
		}
		if c := ciDo(router, http.MethodGet, "/api/ci-tokens", created.Token, "").Code; c != http.StatusUnauthorized {
			t.Errorf("a CI token managing tokens: status %d, want 401", c)
		}

		if c := ciDo(router, http.MethodDelete, "/api/ci-tokens/"+created.Info.ID, admin, "").Code; c != http.StatusOK {
			t.Fatalf("revoke: status %d, want 200", c)
		}
		if c := ciDo(router, http.MethodPost, "/api/ci/validations", created.Token, start).Code; c != http.StatusUnauthorized {
			t.Errorf("a revoked CI token: status %d, want 401", c)
		}

		// Issuing and revoking a credential must leave a trail. The audit insert is asynchronous, so poll for it.
		for _, action := range []string{"ci.token_created", "ci.token_revoked"} {
			var n int
			for i := 0; i < 50 && n == 0; i++ {
				_ = pool.QueryRow(context.Background(),
					`SELECT count(*) FROM audit_logs WHERE action = $1 AND resource = $2`, action, created.Info.ID).Scan(&n)
				if n == 0 {
					time.Sleep(100 * time.Millisecond)
				}
			}
			if n != 1 {
				t.Errorf("audit rows for %s on token %s = %d, want 1", action, created.Info.ID, n)
			}
		}
	})
}
