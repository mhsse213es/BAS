package contentregistry

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

// seedThreat inserts an actor + its Threat and returns the threat id.
func seedThreat(t *testing.T, pool *pgxpool.Pool, name string) string {
	t.Helper()
	ctx := context.Background()
	var actor, threat string
	if err := pool.QueryRow(ctx, `INSERT INTO threat_actor_profiles (name) VALUES ($1)
		ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id`, name).Scan(&actor); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO threats (id, subject_type, subject_id, actor_id, title)
		VALUES ('thr-' || gen_random_uuid()::text, 'actor', $1, $1, $2) RETURNING id`, actor, name).Scan(&threat); err != nil {
		t.Fatal(err)
	}
	return threat
}

func TestRegisterGenerated_WritesGeneratedForLink(t *testing.T) { // spec §4.3, §9.1
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		thr := seedThreat(t, pool, "RansomHub")
		r := New(pool, testutil.DevVerifier())
		art := []byte("id: intel-link1\nname: RansomHub\nart_techniques: [T1059.001, T1082]\n")
		vid, created, err := r.RegisterGenerated(ctx, GeneratedCandidate{ContentID: "intel-link1", Artifact: art,
			GenerationKey: "k1", GenerationRef: "k1", ThreatID: thr})
		if err != nil || !created {
			t.Fatalf("register: %v", err)
		}
		var kind, prov, ref string
		if err := pool.QueryRow(ctx, `SELECT relationship_kind, provenance_type, provenance_ref FROM content_version_threats
			WHERE content_version_id = $1 AND threat_id = $2`, vid, thr).Scan(&kind, &prov, &ref); err != nil {
			t.Fatal(err)
		}
		if kind != "generated_for" || prov != "generator" || ref != "k1" {
			t.Fatalf("link %s/%s/%s", kind, prov, ref)
		}
	})
}

func TestRegisterGenerated_CollisionWithOtherThreatFailsClosed(t *testing.T) { // acceptance 11
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		a, b := seedThreat(t, pool, "A"), seedThreat(t, pool, "B")
		r := New(pool, testutil.DevVerifier())
		mk := func(name string) []byte {
			return []byte("id: intel-same\nname: " + name + "\nart_techniques: [T1059.001, T1082]\n")
		}
		if _, _, err := r.RegisterGenerated(ctx, GeneratedCandidate{ContentID: "intel-same", Artifact: mk("A"), ThreatID: a}); err != nil {
			t.Fatal(err)
		}
		_, _, err := r.RegisterGenerated(ctx, GeneratedCandidate{ContentID: "intel-same", Artifact: mk("B"), ThreatID: b})
		if !errors.Is(err, ErrThreatCollision) {
			t.Fatalf("err = %v", err)
		}
		var n int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM content_versions WHERE content_id = 'intel-same'`).Scan(&n)
		if n != 1 {
			t.Fatalf("versions = %d", n)
		}
	})
}

func TestRegisterGenerated_RequiresThreat(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		r := New(pool, testutil.DevVerifier())
		_, _, err := r.RegisterGenerated(context.Background(), GeneratedCandidate{ContentID: "intel-x",
			Artifact: []byte("id: intel-x\nname: X\nart_techniques: [T1059.001, T1082]\n")})
		if err == nil {
			t.Fatal("candidate without a threat accepted")
		}
	})
}
