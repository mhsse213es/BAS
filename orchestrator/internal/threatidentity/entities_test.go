package threatidentity

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func seedCampaign(t *testing.T, pool *pgxpool.Pool, id string, actors ...string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `INSERT INTO intelligence_campaigns (id, name, actor_ids, source_provider)
		VALUES ($1, $1, $2, 'misp')`, id, actors); err != nil {
		t.Fatal(err)
	}
}

func TestLinkEntityActors_RenamedActorRelationSurvives(t *testing.T) { // acceptance 6
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		s := NewStore(pool)
		a := mustResolve(t, s, Incoming{Name: "APT29", CanonicalGroupID: "G0016", Sources: misp("APT29", "e1")})
		seedCampaign(t, pool, "camp-1", "APT29")
		if r, err := s.LinkEntityActors(ctx, EntityCampaign, "camp-1", "misp", []string{"APT29"}); err != nil || r.Linked != 1 {
			t.Fatalf("%+v %v", r, err)
		}
		// The source now calls it something else; identity must not move.
		mustResolve(t, s, Incoming{Name: "Midnight Blizzard", CanonicalGroupID: "G0016", Sources: misp("Midnight Blizzard", "e2")})
		var actor string
		if err := pool.QueryRow(ctx, `SELECT actor_id FROM campaign_actors WHERE campaign_id = 'camp-1'`).Scan(&actor); err != nil || actor != a.ActorID {
			t.Fatalf("actor=%q err=%v", actor, err)
		}
	})
}

func TestLinkEntityActors_AmbiguousNameQueuedOnce(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		seedProfile(t, pool, "A", "Panda")
		seedProfile(t, pool, "B", "Panda")
		s := NewStore(pool)
		seedCampaign(t, pool, "camp-2", "Panda")
		for i := 0; i < 2; i++ {
			r, err := s.LinkEntityActors(ctx, EntityCampaign, "camp-2", "misp", []string{"Panda"})
			if err != nil || r.Linked != 0 {
				t.Fatalf("%+v %v", r, err)
			}
		}
		var n int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM actor_resolution_candidates WHERE kind = 'campaign_ref'`).Scan(&n)
		if n != 1 {
			t.Fatalf("candidates = %d", n)
		}
	})
}

func TestLinkEntityActors_UnmatchedNameCreatesNothing(t *testing.T) { // Review Focus 5
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		s := NewStore(pool)
		seedCampaign(t, pool, "camp-3", "Filtered Out Actor")
		r, err := s.LinkEntityActors(ctx, EntityCampaign, "camp-3", "misp", []string{"Filtered Out Actor"})
		if err != nil || r.Unmatched != 1 || r.Linked != 0 || r.Queued != 0 {
			t.Fatalf("%+v %v", r, err)
		}
		var profiles, cands int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM threat_actor_profiles`).Scan(&profiles)
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM actor_resolution_candidates`).Scan(&cands)
		if profiles != 0 || cands != 0 {
			t.Fatalf("profiles=%d candidates=%d", profiles, cands)
		}
	})
}

func TestBackfill_ThreatsForLegacyProfilesAndCampaignLinks(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		seedProfile(t, pool, "Lazarus Group")
		seedProfile(t, pool, "Turla")
		seedCampaign(t, pool, "camp-4", "Lazarus Group")
		s := NewStore(pool)
		r, err := s.Backfill(ctx)
		if err != nil || r.Threats != 2 || r.Links.Linked != 1 {
			t.Fatalf("%+v %v", r, err)
		}
		r2, err := s.Backfill(ctx) // idempotent
		if err != nil || r2.Threats != 0 || r2.Links.Linked != 0 {
			t.Fatalf("second run %+v %v", r2, err)
		}
	})
}
