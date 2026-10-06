package threatidentity

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ambiguousCandidate seeds two actors sharing alias "Panda" and returns
// (candidate id, actor A id).
func ambiguousCandidate(t *testing.T, pool *pgxpool.Pool, s *Store) (string, string) {
	t.Helper()
	a := seedProfile(t, pool, "A", "Panda")
	seedProfile(t, pool, "B", "Panda")
	r := mustResolve(t, s, Incoming{Name: "Panda", Sources: KeysFor("opencti", "oc-7", "Panda")})
	if r.CandidateID == "" {
		t.Fatal("no candidate")
	}
	return r.CandidateID, a
}

func TestDecide_LinkMapsSourceAndIsTerminal(t *testing.T) { // acceptance 12
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		s := NewStore(pool)
		cid, actorA := ambiguousCandidate(t, pool, s)
		c, err := s.Decide(ctx, cid, ActionLink, actorA, "analyst confirmed", "user:1")
		if err != nil || c.Status != "linked" || c.DecidedActorID == nil || *c.DecidedActorID != actorA {
			t.Fatalf("%+v %v", c, err)
		}
		// Future syncs of the same record resolve without re-queueing.
		r := mustResolve(t, s, Incoming{Name: "Panda", Sources: KeysFor("opencti", "oc-7", "Panda")})
		if r.Outcome != OutcomeExisting || r.ActorID != actorA {
			t.Fatalf("%+v", r)
		}
		if _, err := s.Decide(ctx, cid, ActionDismiss, "", "changed my mind", "user:2"); !errors.Is(err, ErrAlreadyDecided) {
			t.Fatalf("second decision: %v", err)
		}
	})
}

func TestDecide_NewCreatesActorAndThreat(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		s := NewStore(pool)
		cid, _ := ambiguousCandidate(t, pool, s)
		c, err := s.Decide(ctx, cid, ActionNew, "", "distinct group", "user:1")
		if err != nil || c.Status != "new_actor" || c.DecidedActorID == nil {
			t.Fatalf("%+v %v", c, err)
		}
		var name string
		if err := pool.QueryRow(ctx, `SELECT p.name FROM threats t JOIN threat_actor_profiles p ON p.id = t.actor_id
			WHERE p.id = $1`, *c.DecidedActorID).Scan(&name); err != nil || name != "Panda" {
			t.Fatalf("name=%q err=%v", name, err)
		}
	})
}

func TestDecide_DismissCreatesNothing(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		s := NewStore(pool)
		cid, _ := ambiguousCandidate(t, pool, s)
		var before int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM threats`).Scan(&before)
		if c, err := s.Decide(ctx, cid, ActionDismiss, "", "noise", "user:1"); err != nil || c.Status != "dismissed" {
			t.Fatalf("%+v %v", c, err)
		}
		var after, ids int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM threats`).Scan(&after)
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM actor_source_identities WHERE source = 'opencti'`).Scan(&ids)
		if after != before || ids != 0 {
			t.Fatalf("threats %d->%d, identities %d", before, after, ids)
		}
	})
}

func TestDecide_Validation(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		s := NewStore(pool)
		cid, _ := ambiguousCandidate(t, pool, s)
		cases := []struct {
			action        Action
			actor, reason string
			want          error
		}{
			{ActionLink, "", "r", ErrBadDecision},
			{ActionLink, "act-missing", "r", ErrActorNotFound},
			{ActionDismiss, "", "", ErrBadDecision},
			{Action("merge"), "", "r", ErrBadDecision},
		}
		for _, c := range cases {
			if _, err := s.Decide(ctx, cid, c.action, c.actor, c.reason, "user:1"); !errors.Is(err, c.want) {
				t.Fatalf("%v: err=%v want %v", c, err, c.want)
			}
		}
		if _, err := s.Decide(ctx, "arc-missing", ActionDismiss, "", "r", "user:1"); !errors.Is(err, ErrCandidateNotFound) {
			t.Fatalf("missing: %v", err)
		}
	})
}

func TestDecide_NewNameTaken(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		s := NewStore(pool)
		cid, _ := ambiguousCandidate(t, pool, s)
		seedProfile(t, pool, "Panda")
		if _, err := s.Decide(ctx, cid, ActionNew, "", "distinct", "user:1"); !errors.Is(err, ErrNameTaken) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestDecide_RefLinksEntity(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		a := seedProfile(t, pool, "A", "Panda")
		seedProfile(t, pool, "B", "Panda")
		seedCampaign(t, pool, "camp-9", "Panda")
		s := NewStore(pool)
		if _, err := s.LinkEntityActors(ctx, EntityCampaign, "camp-9", "misp", []string{"Panda"}); err != nil {
			t.Fatal(err)
		}
		var cid string
		if err := pool.QueryRow(ctx, `SELECT id FROM actor_resolution_candidates WHERE kind = 'campaign_ref'`).Scan(&cid); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Decide(ctx, cid, ActionLink, a, "campaign is A's", "user:1"); err != nil {
			t.Fatal(err)
		}
		var actor string
		if err := pool.QueryRow(ctx, `SELECT actor_id FROM campaign_actors WHERE campaign_id = 'camp-9'`).Scan(&actor); err != nil || actor != a {
			t.Fatalf("actor=%q err=%v", actor, err)
		}
	})
}

func TestDecide_ConcurrentOnlyOneWins(t *testing.T) { // Review Focus 3
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		s := NewStore(pool)
		cid, actorA := ambiguousCandidate(t, pool, s)
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i := range errs {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, errs[i] = s.Decide(ctx, cid, ActionLink, actorA, "race", "user:1")
			}(i)
		}
		wg.Wait()
		ok, already := 0, 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, ErrAlreadyDecided):
				already++
			default:
				t.Fatalf("unexpected: %v", err)
			}
		}
		if ok != 1 || already != 1 {
			t.Fatalf("ok=%d already=%d", ok, already)
		}
	})
}
