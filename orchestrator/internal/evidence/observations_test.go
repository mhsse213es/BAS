package evidence

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// seedThreat creates a resolved actor + its Threat directly, bypassing the
// resolver (this package tests evidence recording, not identity
// resolution, which internal/threatidentity already covers).
func seedThreat(t *testing.T, pool *pgxpool.Pool, name string) string {
	t.Helper()
	ctx := context.Background()
	var actorID string
	if err := pool.QueryRow(ctx, `INSERT INTO threat_actor_profiles (name, aliases) VALUES ($1, '{}') RETURNING id`,
		name).Scan(&actorID); err != nil {
		t.Fatal(err)
	}
	var threatID string
	if err := pool.QueryRow(ctx, `INSERT INTO threats (id, subject_type, subject_id, actor_id, title)
		VALUES ('thr-' || gen_random_uuid()::text, 'actor', $1, $1, $2) RETURNING id`,
		actorID, name).Scan(&threatID); err != nil {
		t.Fatal(err)
	}
	return threatID
}

func TestRecordObservationAndLinkThreatSource(t *testing.T) {
	ctx := context.Background()
	store := NewStore(sharedDB.Pool)
	instanceID := "misp-obs-test-1"
	if err := store.EnsureSourceInstance(ctx, instanceID, "misp", "Test", ModeSnapshot, TrustTrusted); err != nil {
		t.Fatal(err)
	}
	syncID, _, err := store.RecordSync(ctx, instanceID, ModeSnapshot, time.Now(), "succeeded", Complete, "")
	if err != nil {
		t.Fatal(err)
	}
	_, trustVersionID, err := store.CurrentTrust(ctx, instanceID)
	if err != nil {
		t.Fatal(err)
	}

	obsID, err := store.RecordObservation(ctx, syncID, instanceID, "evt-1", "APT29", "hash-abc",
		time.Now(), map[string]any{"name": "APT29"}, trustVersionID)
	if err != nil {
		t.Fatal(err)
	}
	if obsID == "" {
		t.Fatal("observation id must be set")
	}

	threatID := seedThreat(t, sharedDB.Pool, "APT29-obs-test")
	conf := 85
	if err := store.LinkThreatSource(ctx, threatID, obsID, "misp", "evt-1", time.Now(), &conf, "hash-abc", "resolver", ""); err != nil {
		t.Fatal(err)
	}

	var count int
	if err := sharedDB.Pool.QueryRow(ctx, `SELECT count(*) FROM threat_sources WHERE threat_id = $1`, threatID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("threat_sources rows = %d, want 1", count)
	}

	// A second link attempt for the SAME observation is refused -- an
	// observation is evidence for exactly one threat (UNIQUE(observation_id)).
	if err := store.LinkThreatSource(ctx, threatID, obsID, "misp", "evt-1", time.Now(), &conf, "hash-abc", "resolver", ""); err == nil {
		t.Fatal("expected an error linking the same observation twice")
	}
}
