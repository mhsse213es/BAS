package db_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestThreatIdentitySchema_IDKeyed(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
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

func TestThreatIdentitySchema_RenameCascadesToChildren(t *testing.T) {
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

func TestThreatIdentitySchema_DeclarativeGuards(t *testing.T) {
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
