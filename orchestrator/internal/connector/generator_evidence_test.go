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

func TestGenerator_Write_UsesActiveTechniqueSetNotMergedActorList(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		idStore := threatidentity.NewStore(pool)
		resolved, err := idStore.ResolveAndPersist(ctx, threatidentity.Incoming{Name: "APT-gen-active-set"}, threatidentity.ProfileFields{})
		if err != nil {
			t.Fatal(err)
		}
		// Two active techniques recorded by the evidence layer, even though
		// this actor's OWN merged Techniques list below is empty -- Write
		// must consult the active set, not actor.Techniques, for the
		// generation-policy threshold (spec §6.2, §8).
		seedActiveTechnique(t, pool, resolved.ThreatID, "T1059")
		seedActiveTechnique(t, pool, resolved.ThreatID, "T1055")

		g := NewGenerator(t.TempDir(), nil, nil, nil).WithEvidenceStore(evidence.NewStore(pool)).WithRegistrar(&recRegistrar{})
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
