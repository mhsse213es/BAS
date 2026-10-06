package connector

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/threatidentity"
)

// Final review Important 1: activity signals go through identity, never
// around it. A signal naming an unresolved merged actor is dropped; one
// naming a known actor attaches to its display name without rewriting the
// profile; a new name gets a profile and a Threat; nothing becomes a stub
// outside the resolver.
func TestScheduler_ActivitySignalsResolveThroughIdentity(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `INSERT INTO threat_actor_profiles (name, aliases, sectors) VALUES
			('Alpha', '{Panda}', '{}'), ('Bravo', '{Panda}', '{}'), ('APT29', '{Cozy Bear}', '{gov}')`); err != nil {
			t.Fatal(err)
		}
		s := &Scheduler{pool: pool}
		s.WithIdentityStore(threatidentity.NewStore(pool))
		merged := []ThreatActor{{Name: "Panda", Source: "misp", SourceID: "evt-1"}} // unresolved: ActorID ""
		now := time.Now()
		s.upsertActivitySignals("otx", []ActivitySignal{
			{ActorName: "Panda", PulseCount: 3, FirstObserved: now, LastObserved: now},
			{ActorName: "Cozy Bear", PulseCount: 2, FirstObserved: now, LastObserved: now},
			{ActorName: "Brand New", PulseCount: 1, FirstObserved: now, LastObserved: now},
		}, merged)

		var stubs int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM threat_actor_profiles WHERE name IN ('Panda', 'Cozy Bear')`).Scan(&stubs)
		if stubs != 0 {
			t.Fatalf("%d stub profile(s) created outside the resolver", stubs)
		}
		var act string
		_ = pool.QueryRow(ctx, `SELECT string_agg(actor_name, ',' ORDER BY actor_name) FROM threat_actor_activity`).Scan(&act)
		if act != "APT29,Brand New" {
			t.Fatalf("activity attached to %q, want APT29,Brand New", act)
		}
		var sectors []string
		_ = pool.QueryRow(ctx, `SELECT sectors FROM threat_actor_profiles WHERE name = 'APT29'`).Scan(&sectors)
		if len(sectors) != 1 {
			t.Fatalf("APT29 profile rewritten: sectors=%v", sectors)
		}
		var threat bool
		_ = pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM threats t JOIN threat_actor_profiles p ON p.id = t.actor_id
			WHERE p.name = 'Brand New')`).Scan(&threat)
		if !threat {
			t.Fatal("new activity actor has no Threat")
		}
	})
}

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
