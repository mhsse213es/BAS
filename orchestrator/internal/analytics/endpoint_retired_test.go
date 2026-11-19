package analytics

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Phase 2: a retired agent must not reach total, online, offline or untrusted-binary counts,
// even when it is stale, untrusted, or still marked online. It appears only as retired.
func TestEndpointPosture_RetiredAgentsExcludedFromLiveCounts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedAgent(t, pool, "live1", "idle", "active", true, "10 seconds")
		seedAgent(t, pool, "gone-stale-untrusted", "idle", "retired", false, "10 days")
		seedAgent(t, pool, "gone-fresh", "idle", "retired", true, "0 seconds")

		got, err := EndpointPosture(context.Background(), pool)
		if err != nil {
			t.Fatalf("EndpointPosture: %v", err)
		}
		if got.TotalAgents != 1 || got.OnlineAgents != 1 || got.OfflineAgents != 0 {
			t.Errorf("live total/online/offline = %d/%d/%d, want 1/1/0 (retired excluded)",
				got.TotalAgents, got.OnlineAgents, got.OfflineAgents)
		}
		if got.UntrustedBinaryCount != 0 {
			t.Errorf("UntrustedBinaryCount = %d, want 0 (the untrusted agent is retired)", got.UntrustedBinaryCount)
		}
		if got.RetiredAgents != 2 {
			t.Errorf("RetiredAgents = %d, want 2 (shown in the lifecycle breakdown)", got.RetiredAgents)
		}
	})
}
