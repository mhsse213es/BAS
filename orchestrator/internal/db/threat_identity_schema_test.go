package db_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
)

func TestEnsureThreatIdentitySchema_IdempotentAndIDKeyed(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		// testutil already ran it once; further boots must be no-ops.
		for i := 0; i < 2; i++ {
			if err := db.EnsureThreatIdentitySchema(ctx, pool); err != nil {
				t.Fatalf("run %d: %v", i, err)
			}
		}
		var pk string
		if err := pool.QueryRow(ctx, `
			SELECT string_agg(a.attname, ',') FROM pg_constraint c
			  JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey)
			 WHERE c.conrelid = 'threat_actor_profiles'::regclass AND c.contype = 'p'`).Scan(&pk); err != nil {
			t.Fatal(err)
		}
		if pk != "id" {
			t.Fatalf("primary key = %q, want id", pk)
		}
		var id string
		if err := pool.QueryRow(ctx, `INSERT INTO threat_actor_profiles (name) VALUES ('APT29') RETURNING id`).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(id, "act-") || len(id) != len("act-")+36 {
			t.Fatalf("id = %q", id)
		}
	})
}

func TestEnsureThreatIdentitySchema_RenameCascadesToChildren(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		mustExec(t, pool, `INSERT INTO threat_actor_profiles (name) VALUES ('Cozy Bear')`)
		mustExec(t, pool, `INSERT INTO threat_actor_sources (actor_name, source, name) VALUES ('Cozy Bear','misp','Cozy Bear')`)
		mustExec(t, pool, `INSERT INTO threat_actor_activity (actor_name, source) VALUES ('Cozy Bear','otx')`)
		mustExec(t, pool, `INSERT INTO technique_evidence (actor_name, technique_id, source) VALUES ('Cozy Bear','T1059','opencti')`)
		mustExec(t, pool, `UPDATE threat_actor_profiles SET name = 'APT29' WHERE name = 'Cozy Bear'`)
		for _, tbl := range []string{"threat_actor_sources", "threat_actor_activity", "technique_evidence"} {
			var n int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+tbl+` WHERE actor_name = 'APT29'`).Scan(&n); err != nil || n != 1 {
				t.Fatalf("%s after rename: n=%d err=%v", tbl, n, err)
			}
		}
	})
}

func TestEnsureThreatIdentitySchema_DeclarativeGuards(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		var actor string
		if err := pool.QueryRow(ctx, `INSERT INTO threat_actor_profiles (name) VALUES ('Akira') RETURNING id`).Scan(&actor); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO threats (id, subject_type, subject_id, actor_id, title)
			VALUES ('thr-x','actor',$1,NULL,'Akira')`, actor); err == nil {
			t.Fatal("actor threat without actor_id accepted")
		}
		mustExec(t, pool, `INSERT INTO threats (id, subject_type, subject_id, actor_id, title) VALUES ('thr-1','actor',$1,$1,'Akira')`, actor)
		if _, err := pool.Exec(ctx, `INSERT INTO threats (id, subject_type, subject_id, actor_id, title)
			VALUES ('thr-2','actor',$1,$1,'dup')`, actor); err == nil {
			t.Fatal("second Threat for the same subject accepted")
		}
		if _, err := pool.Exec(ctx, `INSERT INTO actor_resolution_candidates
			(kind, source, raw_name, reason, resolver_context, resolver_context_hash, status, decided_at)
			VALUES ('source_record','misp','X','ambiguous','{}','h','unresolved',NOW())`); err == nil {
			t.Fatal("unresolved candidate with decided_at accepted")
		}
		if _, err := pool.Exec(ctx, `INSERT INTO actor_resolution_candidates
			(kind, source, raw_name, reason, resolver_context, resolver_context_hash, status, decided_by, decided_at)
			VALUES ('source_record','misp','X','ambiguous','{}','h','dismissed','user:1',NOW())`); err == nil {
			t.Fatal("decision without a reason accepted")
		}
		if _, err := pool.Exec(ctx, `INSERT INTO content_version_threats
			(content_version_id, threat_id, relationship_kind, provenance_type, provenance_ref)
			VALUES ('v','thr-1','generated_for','admin','a')`); err == nil {
			t.Fatal("generated_for with admin provenance accepted")
		}
	})
}

// TestEnsureAppRole_ThreatIdentityGrants pins the spec §12 least-privilege
// rules as bas_app actually sees them.
func TestEnsureAppRole_ThreatIdentityGrants(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureAppRole(ctx, pool, testAppPassword); err != nil {
			t.Fatal(err)
		}
		var actor string
		if err := pool.QueryRow(ctx, `INSERT INTO threat_actor_profiles (name) VALUES ('Turla') RETURNING id`).Scan(&actor); err != nil {
			t.Fatal(err)
		}
		mustExec(t, pool, `INSERT INTO threats (id, subject_type, subject_id, actor_id, title) VALUES ('thr-g','actor',$1,$1,'Turla')`, actor)
		mustExec(t, pool, `INSERT INTO actor_source_identities (source, source_id, actor_id, linked_by) VALUES ('misp','e1',$1,'resolver')`, actor)
		mustExec(t, pool, `INSERT INTO actor_resolution_candidates (kind, source, raw_name, reason, resolver_context, resolver_context_hash)
			VALUES ('source_record','misp','X','ambiguous','{}','h')`)
		app := appConnectedPool(t, pool)
		denied := []string{
			`UPDATE threat_actor_profiles SET id = 'x'`,
			`DELETE FROM threat_actor_profiles`,
			`DELETE FROM threats`,
			`UPDATE actor_source_identities SET actor_id = actor_id`,
			`DELETE FROM actor_source_identities`,
			`UPDATE actor_identity_overrides SET actor_id = actor_id`,
			`DELETE FROM actor_identity_overrides`,
			`UPDATE actor_resolution_candidates SET reason = reason`,
			`DELETE FROM actor_resolution_candidates`,
			`UPDATE content_version_threats SET provenance_ref = provenance_ref`,
			`UPDATE content_generation_owners SET threat_id = threat_id`,
			`UPDATE campaign_actors SET actor_id = actor_id`,
		}
		for _, s := range denied {
			if _, err := app.Exec(ctx, s); err == nil || !strings.Contains(err.Error(), "permission denied") {
				t.Errorf("bas_app %q: err=%v, want permission denied", s, err)
			}
		}
		allowed := []string{
			`UPDATE threat_actor_profiles SET name = name, aliases = aliases`,
			`UPDATE threats SET title = title, last_seen_at = last_seen_at`,
			`UPDATE actor_resolution_candidates SET status = status WHERE false`,
		}
		for _, s := range allowed {
			if _, err := app.Exec(ctx, s); err != nil {
				t.Errorf("bas_app %q: %v", s, err)
			}
		}
	})
}
