package threatidentity

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func mustExec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// Final review Important 2: an admin decision outranks conflicting source
// mappings (spec §3.3 rule 1, §3.4 "mapped for future syncs").
func TestResolve_AdminOverrideOutranksSourceMappings(t *testing.T) {
	misp := SourceKey{Source: "misp", ID: "evt-1"}
	oc := SourceKey{Source: "opencti", ID: "oc-1"}
	snap := Snapshot{
		Actors:           []KnownActor{{ID: "act-a", Name: "A"}, {ID: "act-b", Name: "B"}},
		SourceIdentities: map[SourceKey]string{misp: "act-a", oc: "act-b"},
	}
	in := Incoming{Name: "X", Sources: []SourceKey{misp, oc}}
	if d := Resolve(in, snap); d.Outcome != OutcomeAmbiguous {
		t.Fatalf("precondition: %+v", d)
	}
	snap.AdminOverrides = map[SourceKey]string{oc: "act-a"}
	if d := Resolve(in, snap); d.Outcome != OutcomeExisting || d.ActorID != "act-a" || d.Rule != "admin_decision" {
		t.Fatalf("override ignored: %+v", d)
	}
	snap.AdminOverrides = map[SourceKey]string{misp: "act-a", oc: "act-b"}
	if d := Resolve(in, snap); d.Outcome != OutcomeAmbiguous || d.Rule != "admin_decision" {
		t.Fatalf("disagreeing overrides must be ambiguous: %+v", d)
	}
}

func TestDecide_LinkHoldsAgainstConflictingSourceMappings(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		s := NewStore(pool)
		a := seedProfile(t, pool, "A")
		b := seedProfile(t, pool, "B")
		mustExec(t, pool, `INSERT INTO actor_source_identities (source, source_id, actor_id, linked_by) VALUES
			('misp','evt-1',$1,'resolver'), ('opencti','oc-1',$2,'resolver')`, a, b)
		in := Incoming{Name: "X", Sources: []SourceKey{{Source: "misp", ID: "evt-1"}, {Source: "opencti", ID: "oc-1"}}}
		r := mustResolve(t, s, in)
		if r.Outcome != OutcomeAmbiguous || r.CandidateID == "" {
			t.Fatalf("precondition: %+v", r)
		}
		if _, err := s.Decide(ctx, r.CandidateID, ActionLink, a, "same group", "user:1"); err != nil {
			t.Fatal(err)
		}
		r = mustResolve(t, s, in)
		if r.Outcome != OutcomeExisting || r.ActorID != a {
			t.Fatalf("after link: %+v", r)
		}
		var open int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM actor_resolution_candidates WHERE status = 'unresolved'`).Scan(&open)
		if open != 0 {
			t.Fatalf("re-queued %d candidate(s) after an admin link", open)
		}
	})
}

// Final review Important 1: evidence-only callers (OTX activity) resolve
// through the store but never rewrite an existing profile's columns.
func TestResolveAndPersist_KeepExistingLeavesProfileColumns(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		s := NewStore(pool)
		a := seedProfile(t, pool, "APT29", "Cozy Bear")
		mustExec(t, pool, `UPDATE threat_actor_profiles SET sectors = '{gov}', techniques = '{T1059}' WHERE id = $1`, a)
		r, err := s.ResolveAndPersist(ctx, Incoming{Name: "Cozy Bear", Sources: KeysFor("otx", "", "Cozy Bear")},
			ProfileFields{KeepExisting: true})
		if err != nil || r.Outcome != OutcomeExisting || r.ActorID != a || r.DisplayName != "APT29" {
			t.Fatalf("%+v %v", r, err)
		}
		var sectors, techniques []string
		_ = pool.QueryRow(ctx, `SELECT sectors, techniques FROM threat_actor_profiles WHERE id = $1`, a).Scan(&sectors, &techniques)
		if len(sectors) != 1 || len(techniques) != 1 {
			t.Fatalf("profile clobbered: sectors=%v techniques=%v", sectors, techniques)
		}
	})
}
