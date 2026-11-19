package connector

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/evidence"
	"github.com/audspect/bas/internal/threatidentity"
)

// threat_observed fires once, from the trusted-claim path, with the same
// event_time as the Phase-2C threat clock start (spec §14 "mirror 2C").
func TestThreatObserved_WrittenOnceFromTrustedClaim(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		observedAt := time.Now().Add(-6 * time.Hour)
		src := &stubEvidenceSource{
			name: "misp",
			actors: []ThreatActor{
				{Name: "APT-obs-evt", Source: "misp", SourceID: "evt-1",
					Techniques: []TechniqueRef{{ID: "T1059"}, {ID: "T1055"}}},
			},
			claims: []evidence.RawClaim{
				{ActorName: "APT-obs-evt", TechniqueID: "T1059", ExternalID: "evt-1", ObservedAt: observedAt, RawConfidence: "high"},
			},
		}
		s := &Scheduler{pool: pool, sources: []Source{src}, generator: NewGenerator(t.TempDir(), nil, nil, nil), engine: scenarioEngineForTest(t)}
		s.WithIdentityStore(threatidentity.NewStore(pool))
		s.WithEvidenceStore(evidence.NewStore(pool))

		s.sync()

		var threatID string
		if err := pool.QueryRow(ctx, `SELECT t.id FROM threats t JOIN threat_actor_profiles p ON p.id = t.actor_id
			WHERE p.name = 'APT-obs-evt'`).Scan(&threatID); err != nil {
			t.Fatalf("resolved threat not found: %v", err)
		}

		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM tcf_pipeline_events WHERE threat_id=$1 AND event_type='threat_observed'`, threatID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("threat_observed events = %d, want 1", count)
		}

		var eventTime, clockStart time.Time
		if err := pool.QueryRow(ctx, `SELECT event_time FROM tcf_pipeline_events WHERE threat_id=$1 AND event_type='threat_observed'`, threatID).Scan(&eventTime); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT started_at FROM threat_clock_starts WHERE threat_id=$1 AND clock='threat'`, threatID).Scan(&clockStart); err != nil {
			t.Fatal(err)
		}
		if !eventTime.Equal(clockStart) {
			t.Errorf("threat_observed event_time %v != threat clock start %v (must mirror 2C)", eventTime, clockStart)
		}

		// A second sync must not add a duplicate.
		s.sync()
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM tcf_pipeline_events WHERE threat_id=$1 AND event_type='threat_observed'`, threatID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("after second sync, threat_observed events = %d, want 1", count)
		}
	})
}

// Acceptance test 1: threat_eligible is written once, on the first cycle a
// threat clears minTechniques, and never again.
func TestThreatEligible_FirstClearOnly(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		idStore := threatidentity.NewStore(pool)
		resolved, err := idStore.ResolveAndPersist(ctx, threatidentity.Incoming{Name: "APT-elig"}, threatidentity.ProfileFields{})
		if err != nil {
			t.Fatal(err)
		}
		seedActiveTechnique(t, pool, resolved.ThreatID, "T1059")
		seedActiveTechnique(t, pool, resolved.ThreatID, "T1053")

		store := evidence.NewStore(pool)
		g := NewGenerator(t.TempDir(), nil, nil, nil).WithRegistrar(&dedupRegistrar{}).WithEvidenceStore(store).WithActiveTechniqueProjection()
		a := ThreatActor{Name: "APT-elig", ThreatID: resolved.ThreatID, Source: "misp"}

		if _, err := g.Write([]ThreatActor{a}); err != nil {
			t.Fatalf("first Write: %v", err)
		}
		if _, err := g.Write([]ThreatActor{a}); err != nil {
			t.Fatalf("second Write: %v", err)
		}

		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM tcf_pipeline_events WHERE threat_id=$1 AND event_type='threat_eligible'`, resolved.ThreatID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("threat_eligible events = %d, want 1 (write-once across cycles)", count)
		}
	})
}

// Acceptance test 2: a threat below minTechniques gets no threat_eligible
// event (its queue stage stays open).
func TestThreatEligible_NotWrittenBelowThreshold(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		idStore := threatidentity.NewStore(pool)
		resolved, err := idStore.ResolveAndPersist(ctx, threatidentity.Incoming{Name: "APT-subthresh"}, threatidentity.ProfileFields{})
		if err != nil {
			t.Fatal(err)
		}
		seedActiveTechnique(t, pool, resolved.ThreatID, "T1059") // only one, below minTechniques=2

		store := evidence.NewStore(pool)
		g := NewGenerator(t.TempDir(), nil, nil, nil).WithRegistrar(&dedupRegistrar{}).WithEvidenceStore(store).WithActiveTechniqueProjection()
		a := ThreatActor{Name: "APT-subthresh", ThreatID: resolved.ThreatID, Source: "misp"}
		if _, err := g.Write([]ThreatActor{a}); err != nil {
			t.Fatalf("Write: %v", err)
		}

		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM tcf_pipeline_events WHERE threat_id=$1 AND event_type='threat_eligible'`, resolved.ThreatID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("threat_eligible events = %d, want 0 (below minTechniques)", count)
		}
	})
}
