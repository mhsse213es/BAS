package connector

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/evidence"
	"github.com/audspect/bas/internal/threatidentity"
)

func seedActiveTechnique(t *testing.T, pool *pgxpool.Pool, threatID, techniqueID string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `INSERT INTO threat_techniques
		(threat_id, technique_id, last_seen_at, status, status_reason)
		VALUES ($1, $2, NOW(), 'active', 'supported')`, threatID, techniqueID); err != nil {
		t.Fatal(err)
	}
}

func TestGenerator_Write_WithProjection_UsesActiveTechniqueSet(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		idStore := threatidentity.NewStore(pool)
		resolved, err := idStore.ResolveAndPersist(ctx, threatidentity.Incoming{Name: "APT-gen-active-set"}, threatidentity.ProfileFields{})
		if err != nil {
			t.Fatal(err)
		}
		// Two active techniques recorded by the evidence layer, even though
		// this actor's OWN merged Techniques list below is empty. With the
		// active-technique projection opted in, Write must consult the active
		// set, not actor.Techniques, for the generation-policy threshold
		// (spec §6.2, §8).
		seedActiveTechnique(t, pool, resolved.ThreatID, "T1059")
		seedActiveTechnique(t, pool, resolved.ThreatID, "T1055")

		g := NewGenerator(t.TempDir(), nil, nil, nil).
			WithEvidenceStore(evidence.NewStore(pool)).
			WithActiveTechniqueProjection().
			WithRegistrar(&recRegistrar{})
		res, err := g.Write([]ThreatActor{{Name: "APT-gen-active-set", ThreatID: resolved.ThreatID, Source: "misp"}})
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		if res.Created != 1 {
			t.Fatalf("GenerateResult = %+v, want Created=1", res)
		}

		var genCount int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM content_generations WHERE threat_id = $1`,
			resolved.ThreatID).Scan(&genCount); err != nil {
			t.Fatal(err)
		}
		if genCount != 1 {
			t.Fatalf("content_generations rows = %d, want 1", genCount)
		}
	})
}

// Option B: the evidence store is wired for observability (Phase 9) but the
// active-technique projection is NOT opted in. Generation must keep reading
// actor.Techniques and must NOT consult the active set -- so an actor with an
// empty Techniques list is skipped even when the active set is non-empty.
func TestGenerator_Write_EvidenceWithoutProjection_IgnoresActiveSet(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		idStore := threatidentity.NewStore(pool)
		resolved, err := idStore.ResolveAndPersist(ctx, threatidentity.Incoming{Name: "APT-no-projection"}, threatidentity.ProfileFields{})
		if err != nil {
			t.Fatal(err)
		}
		seedActiveTechnique(t, pool, resolved.ThreatID, "T1059")
		seedActiveTechnique(t, pool, resolved.ThreatID, "T1055")

		g := NewGenerator(t.TempDir(), nil, nil, nil).
			WithEvidenceStore(evidence.NewStore(pool)). // recording only, no projection
			WithRegistrar(&recRegistrar{})
		res, err := g.Write([]ThreatActor{{Name: "APT-no-projection", ThreatID: resolved.ThreatID, Source: "misp"}})
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		if res.Created != 0 || res.Skipped != 1 {
			t.Fatalf("GenerateResult = %+v, want Created=0 Skipped=1 (actor.Techniques empty, active set must be ignored)", res)
		}

		// Phase 9 observability still records the skip even without projection.
		var skippedAttempts int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM content_generation_attempts WHERE threat_id = $1 AND outcome = 'skipped'`,
			resolved.ThreatID).Scan(&skippedAttempts); err != nil {
			t.Fatal(err)
		}
		if skippedAttempts != 1 {
			t.Fatalf("skipped generation-attempt rows = %d, want 1 (observability records without projection)", skippedAttempts)
		}
	})
}

// Option B, the positive case: with the evidence store wired but no projection,
// an actor that carries its own techniques generates from actor.Techniques
// (NOT from the active set, which is empty here) AND the attempt is recorded.
func TestGenerator_Write_EvidenceWithoutProjection_RecordsFromActorTechniques(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		idStore := threatidentity.NewStore(pool)
		resolved, err := idStore.ResolveAndPersist(ctx, threatidentity.Incoming{Name: "APT-actor-techniques"}, threatidentity.ProfileFields{})
		if err != nil {
			t.Fatal(err)
		}
		// Deliberately NO seedActiveTechnique: the active set is empty. If
		// generation consulted it, the actor would be skipped. It must instead
		// use actor.Techniques below.
		g := NewGenerator(t.TempDir(), nil, nil, nil).
			WithEvidenceStore(evidence.NewStore(pool)).
			WithRegistrar(&recRegistrar{})
		res, err := g.Write([]ThreatActor{{
			Name: "APT-actor-techniques", ThreatID: resolved.ThreatID, Source: "misp",
			Techniques: []TechniqueRef{{ID: "T1059"}, {ID: "T1055"}},
		}})
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		if res.Created != 1 {
			t.Fatalf("GenerateResult = %+v, want Created=1 (generated from actor.Techniques)", res)
		}

		var createdAttempts int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM content_generation_attempts WHERE threat_id = $1 AND outcome = 'created'`,
			resolved.ThreatID).Scan(&createdAttempts); err != nil {
			t.Fatal(err)
		}
		if createdAttempts != 1 {
			t.Fatalf("created generation-attempt rows = %d, want 1 (Phase 9 recorded)", createdAttempts)
		}
		var genCount int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM content_generations WHERE threat_id = $1`,
			resolved.ThreatID).Scan(&genCount); err != nil {
			t.Fatal(err)
		}
		if genCount != 1 {
			t.Fatalf("content_generations rows = %d, want 1", genCount)
		}
	})
}
