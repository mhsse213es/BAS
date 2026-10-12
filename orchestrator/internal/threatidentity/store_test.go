package threatidentity

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func misp(name, id string) []SourceKey { return KeysFor("misp", id, name) }

func mustResolve(t *testing.T, s *Store, in Incoming) Resolved {
	t.Helper()
	r, err := s.ResolveAndPersist(context.Background(), in, ProfileFields{Source: in.Sources[0].Source})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestResolveAndPersist_NewActorGetsIDAndThreat(t *testing.T) { // acceptance 5, 8
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := NewStore(pool)
		r := mustResolve(t, s, Incoming{Name: "Akira", Sources: misp("Akira", "evt-1")})
		if r.Outcome != OutcomeNew || r.ActorID == "" || r.ThreatID == "" || r.DisplayName != "Akira" {
			t.Fatalf("%+v", r)
		}
		var subj, gid string
		if err := pool.QueryRow(context.Background(),
			`SELECT t.subject_id, p.canonical_group_id FROM threats t JOIN threat_actor_profiles p ON p.id = t.actor_id WHERE t.id = $1`,
			r.ThreatID).Scan(&subj, &gid); err != nil || subj != r.ActorID || gid != "" {
			t.Fatalf("threat row: subj=%q gid=%q err=%v", subj, gid, err)
		}
	})
}

func TestResolveAndPersist_RenameKeepsIDAndThreat(t *testing.T) { // acceptance 1
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := NewStore(pool)
		first := mustResolve(t, s, Incoming{Name: "APT29", CanonicalGroupID: "G0016", Sources: misp("APT29", "evt-1")})
		again := mustResolve(t, s, Incoming{Name: "Midnight Blizzard", CanonicalGroupID: "G0016", Sources: misp("Midnight Blizzard", "evt-2")})
		if again.Outcome != OutcomeExisting || again.ActorID != first.ActorID || again.ThreatID != first.ThreatID {
			t.Fatalf("first=%+v again=%+v", first, again)
		}
		if again.DisplayName != "APT29" {
			t.Fatalf("display name changed to %q", again.DisplayName)
		}
		var aliases []string
		if err := pool.QueryRow(context.Background(), `SELECT aliases FROM threat_actor_profiles WHERE id = $1`, first.ActorID).Scan(&aliases); err != nil {
			t.Fatal(err)
		}
		if !contains(aliases, "Midnight Blizzard") {
			t.Fatalf("aliases %v", aliases)
		}
	})
}

func TestResolveAndPersist_SameActorFromTwoSourcesOneThreat(t *testing.T) { // acceptance 4
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := NewStore(pool)
		a := mustResolve(t, s, Incoming{Name: "Volt Typhoon", CanonicalGroupID: "G1017", Sources: misp("Volt Typhoon", "evt-1")})
		b := mustResolve(t, s, Incoming{Name: "Bronze Silhouette", CanonicalGroupID: "G1017",
			Sources: KeysFor("opencti", "oc-9", "Bronze Silhouette")})
		if a.ThreatID != b.ThreatID {
			t.Fatalf("two threats: %q %q", a.ThreatID, b.ThreatID)
		}
		var n int
		_ = pool.QueryRow(context.Background(), `SELECT count(*) FROM threats`).Scan(&n)
		if n != 1 {
			t.Fatalf("threats = %d", n)
		}
	})
}

func TestResolveAndPersist_GroupIDChangeKeepsActorID(t *testing.T) { // acceptance 9
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := NewStore(pool)
		a := mustResolve(t, s, Incoming{Name: "Turla", CanonicalGroupID: "G0010", Sources: misp("Turla", "evt-1")})
		b := mustResolve(t, s, Incoming{Name: "Turla", CanonicalGroupID: "G9999", Sources: misp("Turla", "evt-1")})
		if b.ActorID != a.ActorID {
			t.Fatalf("id changed %q -> %q", a.ActorID, b.ActorID)
		}
		var gid string
		_ = pool.QueryRow(context.Background(), `SELECT canonical_group_id FROM threat_actor_profiles WHERE id=$1`, a.ActorID).Scan(&gid)
		if gid != "G9999" {
			t.Fatalf("group id = %q", gid)
		}
	})
}

func TestResolveAndPersist_AmbiguousCreatesCandidateNoThreat(t *testing.T) { // acceptance 3
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		seedProfile(t, pool, "A", "Panda Group")
		seedProfile(t, pool, "B", "Panda Group")
		s := NewStore(pool)
		r := mustResolve(t, s, Incoming{Name: "Panda Group", Sources: KeysFor("opencti", "oc-1", "Panda Group")})
		if r.Outcome != OutcomeAmbiguous || r.CandidateID == "" || r.ActorID != "" || r.ThreatID != "" {
			t.Fatalf("%+v", r)
		}
		var threats, profiles int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM threats`).Scan(&threats)
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM threat_actor_profiles`).Scan(&profiles)
		if threats != 0 || profiles != 2 {
			t.Fatalf("threats=%d profiles=%d", threats, profiles)
		}
		var ext, src string
		_ = pool.QueryRow(ctx, `SELECT source, external_id FROM actor_resolution_candidates WHERE id=$1`, r.CandidateID).Scan(&src, &ext)
		if src != "opencti" || ext != "oc-1" {
			t.Fatalf("candidate keyed %s/%s", src, ext)
		}
	})
}

func TestResolveAndPersist_AmbiguousDedupedAcrossSyncs(t *testing.T) { // Review Focus 1
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		seedProfile(t, pool, "APT29", "Cozy Bear")
		seedProfile(t, pool, "The Dukes", "Cozy Bear")
		s := NewStore(pool)
		in := Incoming{Name: "Cozy Bear", Sources: misp("Cozy Bear", "evt-5")}
		a := mustResolve(t, s, in)
		b := mustResolve(t, s, in)
		if a.CandidateID == "" || a.CandidateID != b.CandidateID {
			t.Fatalf("a=%+v b=%+v", a, b)
		}
		var n int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM actor_resolution_candidates`).Scan(&n)
		if n != 1 {
			t.Fatalf("candidates = %d", n)
		}
	})
}

func TestResolveAndPersist_AliasWithConflictingGroupQueued(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		// Same display name, contradictory ATT&CK group: queued, no write.
		if _, err := pool.Exec(ctx, `INSERT INTO threat_actor_profiles (name, canonical_group_id) VALUES ('Ember Bear', 'G1003')`); err != nil {
			t.Fatal(err)
		}
		s := NewStore(pool)
		r := mustResolve(t, s, Incoming{Name: "Ember Bear", CanonicalGroupID: "G9000", Sources: misp("Ember Bear", "e1")})
		if r.Outcome != OutcomeAmbiguous || r.CandidateID == "" {
			t.Fatalf("%+v", r)
		}
		var gid string
		_ = pool.QueryRow(ctx, `SELECT canonical_group_id FROM threat_actor_profiles WHERE name = 'Ember Bear'`).Scan(&gid)
		if gid != "G1003" {
			t.Fatalf("profile written: gid=%q", gid)
		}
	})
}

func TestResolveAndPersist_NameConflictBecomesCandidate(t *testing.T) { // Review Focus 2
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		seedProfile(t, pool, "Collide")
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		id, conflict, err := insertProfile(ctx, tx, "Collide", ProfileFields{})
		if err != nil || !conflict || id != "" {
			t.Fatalf("id=%q conflict=%v err=%v", id, conflict, err)
		}
		if _, err := tx.Exec(ctx, `SELECT 1`); err != nil {
			t.Fatalf("tx poisoned: %v", err)
		}
	})
}

func TestResolveAndPersist_DismissedIsNotRequeued(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		seedProfile(t, pool, "A", "P")
		seedProfile(t, pool, "B", "P")
		s := NewStore(pool)
		in := Incoming{Name: "P", Sources: misp("P", "e3")}
		r := mustResolve(t, s, in)
		if _, err := pool.Exec(ctx, `UPDATE actor_resolution_candidates SET status='dismissed', decided_by='user:1',
			decided_at=NOW(), decision_reason='noise' WHERE id=$1`, r.CandidateID); err != nil {
			t.Fatal(err)
		}
		again := mustResolve(t, s, in)
		if again.Outcome != OutcomeAmbiguous || again.CandidateID != "" {
			t.Fatalf("%+v", again)
		}
		var open int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM actor_resolution_candidates WHERE status='unresolved'`).Scan(&open)
		if open != 0 {
			t.Fatalf("requeued: %d open", open)
		}
	})
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
