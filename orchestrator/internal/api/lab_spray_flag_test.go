package api

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func seedSprayFlag(t *testing.T, pool *pgxpool.Pool, agentID string, flag bool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO agents (agent_id, hostname, is_spray_lab) VALUES ($1, 'h', $2)
		   ON CONFLICT (agent_id) DO UPDATE SET is_spray_lab = EXCLUDED.is_spray_lab`,
		agentID, flag); err != nil {
		t.Fatalf("seed %s: %v", agentID, err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM agents WHERE agent_id = $1`, agentID)
	})
}

func readSprayFlag(t *testing.T, pool *pgxpool.Pool, agentID string) bool {
	t.Helper()
	var flag bool
	if err := pool.QueryRow(context.Background(),
		`SELECT is_spray_lab FROM agents WHERE agent_id = $1`, agentID).Scan(&flag); err != nil {
		t.Fatalf("read %s: %v", agentID, err)
	}
	return flag
}

// The configured agent becomes the one spray-lab agent and any previously flagged
// agent is cleared; an empty ID clears every flag.
func TestEnsureSoleSprayLabAgent(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		seedSprayFlag(t, pool, "spray-flag-old-0001", true)
		seedSprayFlag(t, pool, "spray-flag-new-0002", false)
		if err := EnsureSoleSprayLabAgent(ctx, pool, "spray-flag-new-0002"); err != nil {
			t.Fatal(err)
		}
		if readSprayFlag(t, pool, "spray-flag-old-0001") {
			t.Fatal("previously flagged agent was not cleared")
		}
		if !readSprayFlag(t, pool, "spray-flag-new-0002") {
			t.Fatal("configured agent was not flagged")
		}
		if err := EnsureSoleSprayLabAgent(ctx, pool, ""); err != nil {
			t.Fatal(err)
		}
		if readSprayFlag(t, pool, "spray-flag-new-0002") {
			t.Fatal("empty setting did not clear the flag")
		}
	})
}
