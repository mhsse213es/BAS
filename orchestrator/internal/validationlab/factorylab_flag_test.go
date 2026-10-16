package validationlab

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// seedAgentFlag inserts one agent row with a given is_factory_lab value and
// registers cleanup. IDs are distinctive so this never collides with other
// agents seeded on the shared test DB.
func seedAgentFlag(t *testing.T, pool *pgxpool.Pool, agentID string, labFlag bool) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx,
		`INSERT INTO agents (agent_id, hostname, is_factory_lab) VALUES ($1, 'h', $2)
		   ON CONFLICT (agent_id) DO UPDATE SET is_factory_lab = EXCLUDED.is_factory_lab`,
		agentID, labFlag); err != nil {
		t.Fatalf("seed agent %s: %v", agentID, err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM agents WHERE agent_id = $1`, agentID)
	})
}

func readFactoryLabFlag(t *testing.T, pool *pgxpool.Pool, agentID string) bool {
	t.Helper()
	var flag bool
	if err := pool.QueryRow(context.Background(),
		`SELECT is_factory_lab FROM agents WHERE agent_id = $1`, agentID).Scan(&flag); err != nil {
		t.Fatalf("read is_factory_lab for %s: %v", agentID, err)
	}
	return flag
}

// TestEnsureSoleFactoryLabAgent_FlagsConfiguredAndClearsStale is the core
// property: the configured lab agent becomes the one and only factory lab --
// it is flagged true and any previously-flagged agent is cleared -- so a fresh
// install never needs a manual "UPDATE agents SET is_factory_lab" by hand.
func TestEnsureSoleFactoryLabAgent_FlagsConfiguredAndClearsStale(t *testing.T) {
	pool := sharedDB.Pool
	ctx := context.Background()
	seedAgentFlag(t, pool, "labflag-configured", false) // the lab agent, enrolled but not yet flagged
	seedAgentFlag(t, pool, "labflag-stale", true)        // a previously-designated lab agent

	if err := EnsureSoleFactoryLabAgent(ctx, pool, "labflag-configured"); err != nil {
		t.Fatalf("EnsureSoleFactoryLabAgent: %v", err)
	}

	if !readFactoryLabFlag(t, pool, "labflag-configured") {
		t.Error("configured lab agent must be flagged is_factory_lab=true")
	}
	if readFactoryLabFlag(t, pool, "labflag-stale") {
		t.Error("an agent that is no longer the configured lab must have its flag cleared")
	}
}

// TestEnsureSoleFactoryLabAgent_Idempotent confirms the every-restart case:
// calling it again on already-correct state leaves the flag set and errors not.
func TestEnsureSoleFactoryLabAgent_Idempotent(t *testing.T) {
	pool := sharedDB.Pool
	ctx := context.Background()
	seedAgentFlag(t, pool, "labflag-idem", true)

	for i := 0; i < 2; i++ {
		if err := EnsureSoleFactoryLabAgent(ctx, pool, "labflag-idem"); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if !readFactoryLabFlag(t, pool, "labflag-idem") {
		t.Error("flag must remain true after repeated calls")
	}
}

// TestEnsureSoleFactoryLabAgent_NotYetEnrolled confirms a configured ID with no
// agent row yet is not an error (install.sh --upgrade can boot with the ID set
// a moment before the agent's row exists), and any stale flag is still cleared.
func TestEnsureSoleFactoryLabAgent_NotYetEnrolled(t *testing.T) {
	pool := sharedDB.Pool
	ctx := context.Background()
	seedAgentFlag(t, pool, "labflag-orphan-stale", true)

	if err := EnsureSoleFactoryLabAgent(ctx, pool, "labflag-not-enrolled-yet"); err != nil {
		t.Fatalf("EnsureSoleFactoryLabAgent with no matching row: %v", err)
	}
	if readFactoryLabFlag(t, pool, "labflag-orphan-stale") {
		t.Error("stale flag must be cleared even when the configured agent has not enrolled yet")
	}
}
