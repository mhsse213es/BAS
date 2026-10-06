package connector

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/threatidentity"
)

// TCF Phase 2A: sync resolves every merged actor before persistence; an
// ambiguous actor gets no profile write, no source rows and no identity,
// and a resolved one carries its stored display name downstream.
func TestScheduler_ResolveActorsSetsIdentityAndSkipsAmbiguous(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `INSERT INTO threat_actor_profiles (name, aliases) VALUES
			('Alpha', '{Panda}'), ('Bravo', '{Panda}'), ('APT29', '{}')`); err != nil {
			t.Fatal(err)
		}
		s := &Scheduler{pool: pool}
		s.WithIdentityStore(threatidentity.NewStore(pool))
		raw := []ThreatActor{
			{Name: "Panda", Source: "misp", SourceID: "evt-1"},
			{Name: "apt-29", Source: "opencti", SourceID: "oc-1"},
		}
		merged := []ThreatActor{raw[0], raw[1]}
		groups := [][]int{{0}, {1}}
		out := s.resolveActors(raw, merged, groups)
		if out[0].ActorID != "" || out[0].ThreatID != "" {
			t.Fatalf("ambiguous actor resolved: %+v", out[0])
		}
		if out[1].ActorID == "" || out[1].ThreatID == "" || out[1].Name != "APT29" {
			t.Fatalf("resolved actor: %+v", out[1])
		}
		s.upsertActorSources(raw, out, groups)
		var n int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM threat_actor_sources`).Scan(&n)
		if n != 1 {
			t.Fatalf("threat_actor_sources rows = %d, want 1 (ambiguous skipped)", n)
		}
		var cands int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM actor_resolution_candidates WHERE status = 'unresolved'`).Scan(&cands)
		if cands != 1 {
			t.Fatalf("candidates = %d", cands)
		}
	})
}
