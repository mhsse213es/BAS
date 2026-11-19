package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Force Remove is permanent against the console (the Active toggle, revoke/reinstate, uninstall/reinstall from the
// console are all refused). A fresh INSTALL on the machine is different: the agent's ID is derived from the
// hostname, so a reinstall always lands on the same record, and an administrator who runs the installer (with the
// secret or a one-time token) has decided the machine is back. That install lifts the removal. A certificate
// RENEWAL by an agent that is still running does not: it was not an install.

func markForceRemoved(t *testing.T, pool *pgxpool.Pool, agentID string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO agents (agent_id, hostname, state, force_removed_at) VALUES ($1, 'h', 'retired', NOW())
		 ON CONFLICT (agent_id) DO UPDATE SET state = 'retired', force_removed_at = NOW()`, agentID); err != nil {
		t.Fatal(err)
	}
}

func forceRemovedAtIsSet(t *testing.T, pool *pgxpool.Pool, agentID string) bool {
	t.Helper()
	var set bool
	if err := pool.QueryRow(context.Background(),
		`SELECT force_removed_at IS NOT NULL FROM agents WHERE agent_id = $1`, agentID).Scan(&set); err != nil {
		t.Fatal(err)
	}
	return set
}

func liftAuditCount(t *testing.T, pool *pgxpool.Pool, agentID string) int {
	t.Helper()
	var n int
	pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_logs WHERE action = 'agent.force_removal_lifted' AND resource = $1`, agentID).Scan(&n)
	return n
}

func TestForceRemoved_FreshInstallBySecretBringsTheMachineBackActive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h, _ := newTestHandlerWithPKI(t, pool)
		markForceRemoved(t, pool, revAgentA)
		if _, st := enrollForTest(t, h, revAgentA); st != http.StatusOK {
			t.Fatalf("install of a force-removed machine = %d, want 200", st)
		}
		if s := agentStateOf(t, pool, revAgentA); s != "active" {
			t.Errorf("state after the install = %q, want active", s)
		}
		if forceRemovedAtIsSet(t, pool, revAgentA) {
			t.Error("force_removed_at is still set after an install")
		}
		if n := liveCerts(t, pool, revAgentA); n != 1 {
			t.Errorf("live certificates = %d, want the new one", n)
		}
		if n := liftAuditCount(t, pool, revAgentA); n != 1 {
			t.Errorf("audit entries for the lifted removal = %d, want 1", n)
		}
	})
}

func TestForceRemoved_FreshInstallByAdminTokenBringsTheMachineBackActive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := tokenHandler(t, pool)
		markForceRemoved(t, pool, revAgentA)
		tok, code := issueToken(t, h, map[string]any{"agentId": revAgentA})
		if code != http.StatusOK {
			t.Fatalf("issue token = %d", code)
		}
		if c := enrollWith(t, h, revAgentA, tok.Token, ""); c != http.StatusOK {
			t.Fatalf("install with a token = %d, want 200", c)
		}
		if s := agentStateOf(t, pool, revAgentA); s != "active" || forceRemovedAtIsSet(t, pool, revAgentA) {
			t.Errorf("state = %q, force_removed_at set = %v; want active and cleared", s, forceRemovedAtIsSet(t, pool, revAgentA))
		}
	})
}

func TestForceRemoved_ARefusedInstallLeavesTheRemovalInForce(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := tokenHandler(t, pool)
		markForceRemoved(t, pool, revAgentA)
		// Token mode: the shared secret alone enrols nobody, so a refused install must not lift anything.
		if c := enrollWith(t, h, revAgentA, "", "test-bootstrap-secret"); c != http.StatusUnauthorized {
			t.Fatalf("secret in token mode = %d, want 401", c)
		}
		if s := agentStateOf(t, pool, revAgentA); s != "retired" || !forceRemovedAtIsSet(t, pool, revAgentA) {
			t.Errorf("a refused install changed the record: state=%q forceRemovedSet=%v", s, forceRemovedAtIsSet(t, pool, revAgentA))
		}
	})
}

func TestForceRemoved_ACertificateRenewalByARunningAgentDoesNotLiftIt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h, ca := newTestHandlerWithPKI(t, pool)
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		clientCert, _ := bootstrapForTest(t, h, key, renewalTestAgentID)
		markForceRemoved(t, pool, renewalTestAgentID)
		srv := newMTLSEnrollServer(t, h, ca)

		resp := postRenewal(t, mtlsClient(ca, clientCert), srv.URL, renewalTestAgentID, csrForKey(t, key, renewalTestAgentID))
		resp.Body.Close()
		if s := agentStateOf(t, pool, renewalTestAgentID); s != "retired" || !forceRemovedAtIsSet(t, pool, renewalTestAgentID) {
			t.Errorf("a renewal lifted the removal: state=%q forceRemovedSet=%v", s, forceRemovedAtIsSet(t, pool, renewalTestAgentID))
		}
		if n := liftAuditCount(t, pool, renewalTestAgentID); n != 0 {
			t.Errorf("audit entries for a lifted removal = %d, want 0", n)
		}
	})
}

// The lift is not a loophole: after it, a new Force Remove locks the machine again, and the console still cannot
// reactivate it.
func TestForceRemoved_AfterAnInstallAFreshForceRemoveLocksAgain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h, _ := newTestHandlerWithPKI(t, pool)
		markForceRemoved(t, pool, revAgentA)
		enrollForTest(t, h, revAgentA)
		markForceRemoved(t, pool, revAgentA)
		if _, err := pool.Exec(context.Background(), `UPDATE agents SET state = 'active' WHERE agent_id = $1`, revAgentA); err == nil {
			t.Error("the database let a re-removed machine be reactivated")
		}
	})
}
