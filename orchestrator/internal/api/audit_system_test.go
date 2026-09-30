package api

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAuditLogSystem_WritesWithSystemActor(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := &Handler{db: pool}
		ctx := context.Background()

		h.AuditLogSystem(ctx, "legacy_listener.disabled", "", map[string]any{"reason": "operator retirement"}, "ok")
		waitForAsyncWrite(t, pool, "audit_logs", "action = 'legacy_listener.disabled'")

		var actorID, outcome string
		err := pool.QueryRow(ctx,
			`SELECT actor_id, outcome FROM audit_logs WHERE action = 'legacy_listener.disabled'`,
		).Scan(&actorID, &outcome)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		if actorID != "" {
			t.Errorf("expected empty actor_id for a system/startup event (renders as 'system' per the existing COALESCE in GetAuditLogs), got %q", actorID)
		}
		if outcome != "ok" {
			t.Errorf("expected outcome 'ok', got %q", outcome)
		}
	})
}
