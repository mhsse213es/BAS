package tcv

import (
	"context"
	"testing"
	"time"
)

func seedThreat(t *testing.T, name string) string {
	t.Helper()
	ctx := context.Background()
	var actorID string
	if err := sharedDB.Pool.QueryRow(ctx, `INSERT INTO threat_actor_profiles (name, aliases) VALUES ($1, '{}') RETURNING id`,
		name).Scan(&actorID); err != nil {
		t.Fatal(err)
	}
	var threatID string
	if err := sharedDB.Pool.QueryRow(ctx, `INSERT INTO threats (id, subject_type, subject_id, actor_id, title)
		VALUES ('thr-' || gen_random_uuid()::text, 'actor', $1, $1, $2) RETURNING id`,
		actorID, name).Scan(&threatID); err != nil {
		t.Fatal(err)
	}
	return threatID
}

func TestRecordThreatClockStart_WriteOnceNeverMoved(t *testing.T) {
	ctx := context.Background()
	threatID := seedThreat(t, "APT-clock-threat")
	first := time.Now().Add(-48 * time.Hour)
	later := time.Now()

	if err := RecordThreatClockStart(ctx, sharedDB.Pool, threatID, first, "sync-1"); err != nil {
		t.Fatal(err)
	}
	// A second, later call must not move the already-written start.
	if err := RecordThreatClockStart(ctx, sharedDB.Pool, threatID, later, "sync-2"); err != nil {
		t.Fatal(err)
	}

	var startedAt time.Time
	var sourceRef string
	if err := sharedDB.Pool.QueryRow(ctx, `SELECT started_at, source_ref FROM threat_clock_starts WHERE threat_id = $1 AND clock = 'threat'`,
		threatID).Scan(&startedAt, &sourceRef); err != nil {
		t.Fatal(err)
	}
	if diff := startedAt.Sub(first); diff < -time.Second || diff > time.Second {
		t.Fatalf("started_at = %v, want the first call's time %v (write-once)", startedAt, first)
	}
	if sourceRef != "sync-1" {
		t.Fatalf("source_ref = %q, want %q (first call wins)", sourceRef, "sync-1")
	}
}

func TestRecordIntelligenceClockStart_SeparateFromThreatClock(t *testing.T) {
	ctx := context.Background()
	threatID := seedThreat(t, "APT-clock-intel")
	threatStart := time.Now().Add(-24 * time.Hour)
	intelStart := time.Now()

	if err := RecordThreatClockStart(ctx, sharedDB.Pool, threatID, threatStart, "sync-t"); err != nil {
		t.Fatal(err)
	}
	if err := RecordIntelligenceClockStart(ctx, sharedDB.Pool, threatID, intelStart, "sync-i"); err != nil {
		t.Fatal(err)
	}

	var count int
	if err := sharedDB.Pool.QueryRow(ctx, `SELECT count(*) FROM threat_clock_starts WHERE threat_id = $1`, threatID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("threat_clock_starts rows = %d, want 2 (threat and intelligence are independent clocks)", count)
	}
}
