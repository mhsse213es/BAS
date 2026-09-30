package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestLegacyMigrationStatus_NoTrafficEver_Eligible(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := &Handler{db: pool}

		req := httptest.NewRequest(http.MethodGet, "/api/agents/legacy-migration-status", nil)
		rec := httptest.NewRecorder()
		h.GetLegacyMigrationStatus(rec, req)

		var body legacyMigrationStatusResponse
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if !body.Eligible {
			t.Error("expected eligible=true when no legacy traffic has ever been recorded")
		}
		if body.LastLegacySeenAt != nil {
			t.Errorf("expected LastLegacySeenAt nil with no traffic, got %v", body.LastLegacySeenAt)
		}
	})
}

func TestLegacyMigrationStatus_ExactlyAtThirtyDayBoundary(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := &Handler{db: pool}
		ctx := context.Background()

		// Exactly 30 days ago, to the second -- the actual boundary an operator
		// will hit in practice, not a comfortably-inside/outside case.
		exactlyThirtyDaysAgo := time.Now().UTC().Add(-30 * 24 * time.Hour)
		_, err := pool.Exec(ctx,
			`INSERT INTO legacy_transport_log (agent_id, day, last_seen_at, endpoint) VALUES ($1, $2, $3, $4)`,
			"boundary-agent", exactlyThirtyDaysAgo.Truncate(24*time.Hour), exactlyThirtyDaysAgo, "/api/heartbeat")
		if err != nil {
			t.Fatalf("seed: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/api/agents/legacy-migration-status", nil)
		rec := httptest.NewRecorder()
		h.GetLegacyMigrationStatus(rec, req)

		var body legacyMigrationStatusResponse
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if !body.Eligible {
			t.Error("expected eligible=true at exactly 30 days since last legacy traffic (>= 30 days is the rule)")
		}
	})
}

func TestLegacyMigrationStatus_TwentyNineDaysNotEligible(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := &Handler{db: pool}
		ctx := context.Background()

		recentEnough := time.Now().UTC().Add(-29*24*time.Hour - 23*time.Hour) // 29d23h ago -- just short
		_, err := pool.Exec(ctx,
			`INSERT INTO legacy_transport_log (agent_id, day, last_seen_at, endpoint) VALUES ($1, $2, $3, $4)`,
			"almost-agent", recentEnough.Truncate(24*time.Hour), recentEnough, "/api/heartbeat")
		if err != nil {
			t.Fatalf("seed: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/api/agents/legacy-migration-status", nil)
		rec := httptest.NewRecorder()
		h.GetLegacyMigrationStatus(rec, req)

		var body legacyMigrationStatusResponse
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if body.Eligible {
			t.Error("expected eligible=false at 29 days 23 hours since last legacy traffic -- still inside the 30-day window")
		}
		if len(body.BlockingAgents) != 1 || body.BlockingAgents[0].AgentID != "almost-agent" {
			t.Errorf("expected almost-agent in BlockingAgents, got %+v", body.BlockingAgents)
		}
	})
}

func TestLegacyMigrationStatus_QueryErrorFailsClosedNotEligible(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := &Handler{db: pool}

		// A cancelled context forces the eligibility queries to error --
		// simulating a DB timeout, pool exhaustion, or a permissions problem.
		// The handler must never report "eligible" when it couldn't actually
		// determine that; that would be exactly the false "clear" the spec
		// says must never happen.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		req := httptest.NewRequest(http.MethodGet, "/api/agents/legacy-migration-status", nil).WithContext(ctx)
		rec := httptest.NewRecorder()
		h.GetLegacyMigrationStatus(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 when the eligibility query fails (fail-closed), got %d with body %q -- a query error must never silently report eligible=true", rec.Code, rec.Body.String())
		}
	})
}

func TestLegacyMigrationStatus_UnattributedTrafficBlocksEligibility(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := &Handler{db: pool}
		ctx := context.Background()

		recent := time.Now().UTC().Add(-1 * time.Hour)
		_, err := pool.Exec(ctx,
			`INSERT INTO legacy_transport_unattributed (day, last_seen_at, request_count) VALUES ($1, $2, $3)`,
			recent.Truncate(24*time.Hour), recent, 3)
		if err != nil {
			t.Fatalf("seed: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/api/agents/legacy-migration-status", nil)
		rec := httptest.NewRecorder()
		h.GetLegacyMigrationStatus(rec, req)

		var body legacyMigrationStatusResponse
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if body.Eligible {
			t.Error("expected eligible=false when unattributed legacy traffic exists inside the window, even with zero named blocking agents")
		}
		if body.UnattributedRequests == nil || body.UnattributedRequests.Count != 3 {
			t.Errorf("expected UnattributedRequests.Count=3, got %+v", body.UnattributedRequests)
		}
	})
}
