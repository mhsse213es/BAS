package connector

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/contentregistry"
	"github.com/audspect/bas/internal/evidence"
	"github.com/audspect/bas/internal/threatidentity"
)

// Acceptance test 3: a failed attempt records generation_attempted +
// generation_failed and no content_created; a later successful attempt records
// content_created carrying the new content_version_id.
func TestGenerationEvents_AttemptFailThenCreate(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		idStore := threatidentity.NewStore(pool)
		resolved, err := idStore.ResolveAndPersist(ctx, threatidentity.Incoming{Name: "APT-genevt"}, threatidentity.ProfileFields{})
		if err != nil {
			t.Fatal(err)
		}
		seedActiveTechnique(t, pool, resolved.ThreatID, "T1059")
		seedActiveTechnique(t, pool, resolved.ThreatID, "T1053")
		store := evidence.NewStore(pool)
		a := ThreatActor{Name: "APT-genevt", ThreatID: resolved.ThreatID, Source: "misp"}

		// A registrar that always fails -> the attempt is recorded as failed.
		gFail := NewGenerator(t.TempDir(), nil, nil, nil).
			WithRegistrar(collisionRegistrar{err: contentregistry.ErrSourceCollision}).
			WithEvidenceStore(store).WithActiveTechniqueProjection()
		if _, err := gFail.Write([]ThreatActor{a}); err != nil {
			t.Fatalf("failed Write: %v", err)
		}

		var attempted, failed, created int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM tcf_pipeline_events WHERE threat_id=$1 AND event_type='generation_attempted'`, resolved.ThreatID).Scan(&attempted); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM tcf_pipeline_events WHERE threat_id=$1 AND event_type='generation_failed'`, resolved.ThreatID).Scan(&failed); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM tcf_pipeline_events WHERE threat_id=$1 AND event_type='content_created'`, resolved.ThreatID).Scan(&created); err != nil {
			t.Fatal(err)
		}
		if attempted < 1 || failed != 1 || created != 0 {
			t.Fatalf("after failed Write: attempted=%d failed=%d created=%d, want >=1/1/0", attempted, failed, created)
		}

		// A registrar that creates a version -> content_created with its id.
		gOK := NewGenerator(t.TempDir(), nil, nil, nil).
			WithRegistrar(&dedupRegistrar{}).
			WithEvidenceStore(store).WithActiveTechniqueProjection()
		if _, err := gOK.Write([]ThreatActor{a}); err != nil {
			t.Fatalf("successful Write: %v", err)
		}

		var cvID string
		if err := pool.QueryRow(ctx, `SELECT count(*), coalesce(max(content_version_id),'') FROM tcf_pipeline_events WHERE threat_id=$1 AND event_type='content_created'`, resolved.ThreatID).Scan(&created, &cvID); err != nil {
			t.Fatal(err)
		}
		if created != 1 || cvID == "" {
			t.Fatalf("after create Write: content_created=%d content_version_id=%q, want 1/non-empty", created, cvID)
		}
	})
}
