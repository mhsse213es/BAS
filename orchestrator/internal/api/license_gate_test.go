package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/license"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestLicenseGate_AllowlistPassesThroughWhenLocked(t *testing.T) {
	license.SetInitial(license.Info{State: license.StateLocked})
	defer license.SetInitial(license.Info{}) // reset for other tests in this package

	allowlisted := []string{"/health", "/api/license/status"}
	for _, path := range allowlisted {
		called := false
		gated := LicenseGate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		}))
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		gated.ServeHTTP(rec, req)
		if !called {
			t.Errorf("path %q: handler was not called, want it to pass through the gate when locked", path)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("path %q: status = %d, want %d", path, rec.Code, http.StatusOK)
		}
	}
}

func TestLicenseGate_StaticShellPassesThroughWhenLocked(t *testing.T) {
	license.SetInitial(license.Info{State: license.StateLocked})
	defer license.SetInitial(license.Info{})

	called := false
	gated := LicenseGate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	req := httptest.NewRequest(http.MethodGet, "/index.html", nil)
	rec := httptest.NewRecorder()
	gated.ServeHTTP(rec, req)
	if !called {
		t.Error("static asset path was blocked when locked, want it to pass through so the lockout screen can load")
	}
	_ = rec
}

func TestLicenseGate_BlocksAPIRoutesWhenLocked(t *testing.T) {
	license.SetInitial(license.Info{State: license.StateLocked})
	defer license.SetInitial(license.Info{})

	blocked := []string{"/api/auth/login", "/api/agents", "/ws/agent", "/scim/v2/Users"}
	for _, path := range blocked {
		called := false
		gated := LicenseGate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		gated.ServeHTTP(rec, req)
		if called {
			t.Errorf("path %q: handler was called, want it blocked when locked", path)
		}
		if rec.Code != http.StatusPaymentRequired {
			t.Errorf("path %q: status = %d, want %d", path, rec.Code, http.StatusPaymentRequired)
		}
	}
}

func TestLicenseGate_PassesThroughWhenValidOrGrace(t *testing.T) {
	for _, state := range []license.State{license.StateValid, license.StateGrace} {
		license.SetInitial(license.Info{State: state})
		called := false
		gated := LicenseGate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		}))
		req := httptest.NewRequest(http.MethodGet, "/api/agents", nil)
		rec := httptest.NewRecorder()
		gated.ServeHTTP(rec, req)
		if !called {
			t.Errorf("state %q: handler was not called, want normal pass-through", state)
		}
	}
	license.SetInitial(license.Info{}) // reset
}

func TestWSUpgrade_RejectedWhenLocked(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		router := Mount(h, ws.NewHub(), testJWTSecret, "", http.NotFoundHandler(), 0, 0)

		license.SetInitial(license.Info{State: license.StateLocked})
		defer license.SetInitial(license.Info{})

		req := httptest.NewRequest(http.MethodGet, "/ws/agent?agentId=test-agent", nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusPaymentRequired {
			t.Errorf("/ws/agent when locked: status = %d, want %d", rec.Code, http.StatusPaymentRequired)
		}
	})
}
