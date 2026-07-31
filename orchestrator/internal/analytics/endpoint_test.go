package analytics

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func seedAgent(t *testing.T, pool *pgxpool.Pool, id, status, state string, binaryTrusted bool, lastUpdateAgo string) {
	t.Helper()
	mustExec(t, pool, `
		INSERT INTO agents (agent_id, hostname, status, state, binary_trusted, last_update)
		VALUES ($1, $2, $3, $4, $5, NOW() - $6::interval)`,
		id, id+"-host", status, state, binaryTrusted, lastUpdateAgo)
}

func TestEndpointPosture_TalliesConnectivityAndLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedAgent(t, pool, "a1", "idle", "active", true, "10 seconds")
		seedAgent(t, pool, "a2", "scanning", "active", true, "5 minutes") // stale -> offline
		seedAgent(t, pool, "a3", "idle", "restricted", true, "0 seconds")
		seedAgent(t, pool, "a4", "idle", "quarantined", true, "0 seconds")
		seedAgent(t, pool, "a5", "idle", "retired", true, "0 seconds")

		got, err := EndpointPosture(context.Background(), pool)
		if err != nil {
			t.Fatalf("EndpointPosture: %v", err)
		}
		if got.TotalAgents != 5 {
			t.Errorf("TotalAgents = %d, want 5", got.TotalAgents)
		}
		if got.OnlineAgents != 4 {
			t.Errorf("OnlineAgents = %d, want 4 (a2 is stale)", got.OnlineAgents)
		}
		if got.OfflineAgents != 1 {
			t.Errorf("OfflineAgents = %d, want 1 (a2)", got.OfflineAgents)
		}
		if got.ActiveAgents != 2 {
			t.Errorf("ActiveAgents = %d, want 2 (a1, a2)", got.ActiveAgents)
		}
		if got.RestrictedAgents != 1 || got.QuarantinedAgents != 1 || got.RetiredAgents != 1 {
			t.Errorf("lifecycle tallies = restricted:%d quarantined:%d retired:%d, want 1/1/1",
				got.RestrictedAgents, got.QuarantinedAgents, got.RetiredAgents)
		}
	})
}

func TestEndpointPosture_UntrustedBinaryCount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedAgent(t, pool, "b1", "idle", "active", true, "0 seconds")
		seedAgent(t, pool, "b2", "idle", "active", false, "0 seconds")
		seedAgent(t, pool, "b3", "idle", "active", false, "0 seconds")

		got, err := EndpointPosture(context.Background(), pool)
		if err != nil {
			t.Fatalf("EndpointPosture: %v", err)
		}
		if got.UntrustedBinaryCount != 2 {
			t.Errorf("UntrustedBinaryCount = %d, want 2 (b2, b3)", got.UntrustedBinaryCount)
		}
	})
}

func TestEndpointPosture_CurrentlyIsolated_UsesLatestActionPerHost(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedAgent(t, pool, "c1", "idle", "active", true, "0 seconds")
		seedAgent(t, pool, "c2", "idle", "active", true, "0 seconds")
		seedAgent(t, pool, "c3", "idle", "active", true, "0 seconds")

		// c1: bare completed isolate -> currently isolated.
		mustExec(t, pool, `
			INSERT INTO action_requests (type, target_type, target_identifier, connector_id, status, requested_at)
			VALUES ('endpoint.isolate', 'hostname', 'c1-host', 'conn-1', 'completed', NOW() - interval '1 hour')`)

		// c2: isolate then a later completed release -> NOT currently isolated.
		mustExec(t, pool, `
			INSERT INTO action_requests (type, target_type, target_identifier, connector_id, status, requested_at)
			VALUES ('endpoint.isolate', 'hostname', 'c2-host', 'conn-1', 'completed', NOW() - interval '2 hours')`)
		mustExec(t, pool, `
			INSERT INTO action_requests (type, target_type, target_identifier, connector_id, status, requested_at)
			VALUES ('endpoint.release', 'hostname', 'c2-host', 'conn-1', 'completed', NOW() - interval '1 hour')`)

		// c3: isolate attempt FAILED -> NOT currently isolated.
		mustExec(t, pool, `
			INSERT INTO action_requests (type, target_type, target_identifier, connector_id, status, requested_at)
			VALUES ('endpoint.isolate', 'hostname', 'c3-host', 'conn-1', 'failed', NOW() - interval '1 hour')`)

		got, err := EndpointPosture(context.Background(), pool)
		if err != nil {
			t.Fatalf("EndpointPosture: %v", err)
		}
		if got.CurrentlyIsolated != 1 {
			t.Errorf("CurrentlyIsolated = %d, want 1 (only c1)", got.CurrentlyIsolated)
		}
	})
}

func TestEndpointPosture_NoAgents_ReturnsZeroSummary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		got, err := EndpointPosture(context.Background(), pool)
		if err != nil {
			t.Fatalf("EndpointPosture: %v", err)
		}
		if got.TotalAgents != 0 || got.CurrentlyIsolated != 0 {
			t.Errorf("got %+v, want all zero", got)
		}
	})
}
