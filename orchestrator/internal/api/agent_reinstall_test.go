package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Reinstalling an agent on a host the server already knows. The server must not let the shared secret take over a
// live host (audit F-03), but it must let a host come back after it was uninstalled or removed, or when an
// administrator issued a token for it.

func setAgentState(t *testing.T, pool *pgxpool.Pool, agentID, state string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO agents (agent_id, hostname, state) VALUES ($1, 'h', $2)
		 ON CONFLICT (agent_id) DO UPDATE SET state = EXCLUDED.state`, agentID, state); err != nil {
		t.Fatal(err)
	}
}

func agentStateOf(t *testing.T, pool *pgxpool.Pool, agentID string) string {
	t.Helper()
	var s string
	if err := pool.QueryRow(context.Background(), `SELECT state FROM agents WHERE agent_id = $1`, agentID).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func liveCerts(t *testing.T, pool *pgxpool.Pool, agentID string) int {
	t.Helper()
	var n int
	pool.QueryRow(context.Background(),
		`SELECT count(*) FROM agent_certificates WHERE agent_id = $1 AND revoked = false AND expires_at > NOW()`, agentID).Scan(&n)
	return n
}

func TestReinstall_SecretCannotTakeOverALiveHost(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h, _ := newTestHandlerWithPKI(t, pool)
		if _, st := enrollForTest(t, h, revAgentA); st != http.StatusOK {
			t.Fatalf("first enrolment = %d", st)
		}
		setAgentState(t, pool, revAgentA, "active")
		if _, st := enrollForTest(t, h, revAgentA); st != http.StatusConflict {
			t.Errorf("secret re-bootstrap of an active host = %d, want 409", st)
		}
		if n := liveCerts(t, pool, revAgentA); n != 1 {
			t.Errorf("live certificates = %d, want the original 1", n)
		}
	})
}

func TestReinstall_UninstalledHostEnrolsAgainAndComesBackActive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h, _ := newTestHandlerWithPKI(t, pool)
		enrollForTest(t, h, revAgentA)
		setAgentState(t, pool, revAgentA, "uninstalled")
		if _, st := enrollForTest(t, h, revAgentA); st != http.StatusOK {
			t.Fatalf("re-enrolment of an uninstalled host = %d, want 200", st)
		}
		if n := liveCerts(t, pool, revAgentA); n != 1 {
			t.Errorf("live certificates = %d, want exactly the new one", n)
		}
		if s := agentStateOf(t, pool, revAgentA); s != "active" {
			t.Errorf("state after re-enrolment = %q, want active", s)
		}
	})
}

func TestReinstall_RemovedHostGetsACertificateButStaysRetired(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h, _ := newTestHandlerWithPKI(t, pool)
		enrollForTest(t, h, revAgentA)
		setAgentState(t, pool, revAgentA, "retired")
		if _, st := enrollForTest(t, h, revAgentA); st != http.StatusOK {
			t.Fatalf("re-enrolment of a removed host = %d, want 200", st)
		}
		if n := liveCerts(t, pool, revAgentA); n != 1 {
			t.Errorf("live certificates = %d, want exactly the new one", n)
		}
		if s := agentStateOf(t, pool, revAgentA); s != "retired" {
			t.Errorf("an administrator's removal must stay in force until restored; state = %q", s)
		}
	})
}

func TestReinstall_RevokedHostStaysBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h, _ := newTestHandlerWithPKI(t, pool)
		enrollForTest(t, h, revAgentA)
		setAgentState(t, pool, revAgentA, AgentStateRevoked)
		if _, st := enrollForTest(t, h, revAgentA); st != http.StatusForbidden {
			t.Errorf("revoked host = %d, want 403", st)
		}
	})
}

func TestReinstall_TokenReplacesTheCertificatesOfAnActiveHost(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := tokenHandler(t, pool)
		first, _ := issueToken(t, h, map[string]any{"agentId": revAgentA})
		if c := enrollWith(t, h, revAgentA, first.Token, ""); c != http.StatusOK {
			t.Fatalf("first enrolment = %d", c)
		}
		setAgentState(t, pool, revAgentA, "active")

		// A wrong token must not touch the existing certificate.
		if c := enrollWith(t, h, revAgentA, "bas_enr_wrong", ""); c != http.StatusUnauthorized {
			t.Errorf("wrong token = %d, want 401", c)
		}
		if n := liveCerts(t, pool, revAgentA); n != 1 {
			t.Fatalf("a refused attempt changed the certificates (%d live)", n)
		}

		second, _ := issueToken(t, h, map[string]any{"agentId": revAgentA})
		if c := enrollWith(t, h, revAgentA, second.Token, ""); c != http.StatusOK {
			t.Fatalf("enrolment with a fresh token for an active host = %d, want 200", c)
		}
		if n := liveCerts(t, pool, revAgentA); n != 1 {
			t.Errorf("live certificates = %d, want exactly the new one", n)
		}
	})
}

func reinstallRouter(h *Handler) http.Handler {
	r := chi.NewRouter()
	r.Post("/api/agents/{agentId}/allow-reinstall", h.AllowAgentReinstall)
	return r
}

func TestAllowReinstall_AdminApprovalLetsTheSecretReplaceAnActiveHostOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h, _ := newTestHandlerWithPKI(t, pool)
		enrollForTest(t, h, revAgentA)
		enrollForTest(t, h, revAgentB)
		setAgentState(t, pool, revAgentA, "active")
		setAgentState(t, pool, revAgentB, "active")

		// Not approved yet: still refused.
		if _, st := enrollForTest(t, h, revAgentA); st != http.StatusConflict {
			t.Fatalf("before approval = %d, want 409", st)
		}
		rec := postJSON(reinstallRouter(h), "/api/agents/"+revAgentA+"/allow-reinstall", map[string]any{"reason": "disk was reimaged"})
		if rec.Code != http.StatusOK {
			t.Fatalf("allow-reinstall = %d: %s", rec.Code, rec.Body.String())
		}
		// Approval for A does nothing for B.
		if _, st := enrollForTest(t, h, revAgentB); st != http.StatusConflict {
			t.Errorf("another host after A was approved = %d, want 409", st)
		}
		if _, st := enrollForTest(t, h, revAgentA); st != http.StatusOK {
			t.Fatalf("approved reinstall = %d, want 200", st)
		}
		if n := liveCerts(t, pool, revAgentA); n != 1 {
			t.Errorf("live certificates = %d, want exactly the new one", n)
		}
		if s := agentStateOf(t, pool, revAgentA); s != "active" {
			t.Errorf("state = %q, want active", s)
		}
		// One use only.
		if _, st := enrollForTest(t, h, revAgentA); st != http.StatusConflict {
			t.Errorf("second reinstall on the same approval = %d, want 409", st)
		}
	})
}

func TestAllowReinstall_ExpiredApprovalIsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h, _ := newTestHandlerWithPKI(t, pool)
		enrollForTest(t, h, revAgentA)
		setAgentState(t, pool, revAgentA, "active")
		if rec := postJSON(reinstallRouter(h), "/api/agents/"+revAgentA+"/allow-reinstall", map[string]any{"reason": "x"}); rec.Code != http.StatusOK {
			t.Fatalf("allow-reinstall = %d", rec.Code)
		}
		pool.Exec(context.Background(), `UPDATE agents SET reinstall_allowed_until = NOW() - interval '1 minute' WHERE agent_id = $1`, revAgentA)
		if _, st := enrollForTest(t, h, revAgentA); st != http.StatusConflict {
			t.Errorf("after the approval expired = %d, want 409", st)
		}
	})
}

func TestAllowReinstall_Validation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h, _ := newTestHandlerWithPKI(t, pool)
		setAgentState(t, pool, revAgentA, "active")
		rt := reinstallRouter(h)
		if rec := postJSON(rt, "/api/agents/"+revAgentA+"/allow-reinstall", map[string]any{"reason": "  "}); rec.Code != http.StatusBadRequest {
			t.Errorf("no reason = %d, want 400", rec.Code)
		}
		if rec := postJSON(rt, "/api/agents/"+revAgentB+"/allow-reinstall", map[string]any{"reason": "x"}); rec.Code != http.StatusNotFound {
			t.Errorf("unknown agent = %d, want 404", rec.Code)
		}
		if rec := postJSON(rt, "/api/agents/"+revAgentA+"/allow-reinstall", map[string]any{"reason": "x", "hours": 500}); rec.Code != http.StatusBadRequest {
			t.Errorf("hours out of range = %d, want 400", rec.Code)
		}
		setAgentState(t, pool, revAgentA, AgentStateRevoked)
		if rec := postJSON(rt, "/api/agents/"+revAgentA+"/allow-reinstall", map[string]any{"reason": "x"}); rec.Code != http.StatusConflict {
			t.Errorf("revoked host = %d, want 409 (reinstate it first)", rec.Code)
		}
	})
}
