package migrate_test

// Ported from TCF's internal/db content_registry_schema_test.go
// (TestContentVersions_AppRoleCannotRewriteOrDelete) and
// threat_identity_schema_test.go (TestEnsureAppRole_ThreatIdentityGrants),
// which exercised the pre-H1 db.EnsureAppRole. bas_app's grants are now set
// by migrate up's role step.

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func mustAdmin(t *testing.T, c *pgx.Conn, sql string, args ...any) {
	t.Helper()
	if _, err := c.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func wantDenied(t *testing.T, app *pgx.Conn, stmts []string) {
	t.Helper()
	for _, s := range stmts {
		if _, err := app.Exec(context.Background(), s); err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("bas_app %q: want permission denied, got %v", s, err)
		}
	}
}

func TestRoleGrants_ContentRegistryImmutable(t *testing.T) { // TCF Phase 1 §4.2 (A3, DB half)
	ctx := context.Background()
	admin, app, _ := provisioned(t)
	art := []byte("id: imm\n")
	mustAdmin(t, admin, `INSERT INTO scenarios (scenario_id, origin) VALUES ('imm','LOCAL')`)
	mustAdmin(t, admin, `INSERT INTO content_versions (content_id, origin, version, artifact_sha256, artifact_size, artifact_bytes,
		   signature_bytes, trust_level, lifecycle, intake_source, schema_version, created_by)
		 VALUES ('imm','LOCAL',1,$1,$2,$3,NULL,'UNTRUSTED','DRAFT','builtin',1,'test')`, fmt.Sprintf("%064d", 1), len(art), art)
	var vid string
	if err := admin.QueryRow(ctx, `SELECT id FROM content_versions WHERE content_id='imm'`).Scan(&vid); err != nil {
		t.Fatal(err)
	}
	mustAdmin(t, admin, `INSERT INTO content_validations (content_version_id, level, outcome, validator, validator_version)
		VALUES ($1,'STRUCTURAL','PASS','test','1')`, vid)
	mustAdmin(t, admin, `INSERT INTO content_registry_state (id) VALUES (1)`)

	wantDenied(t, app, []string{
		`UPDATE content_versions SET artifact_bytes = 'x' WHERE content_id='imm'`,
		`UPDATE content_versions SET artifact_sha256 = 'x' WHERE content_id='imm'`,
		`UPDATE content_versions SET version = 9 WHERE content_id='imm'`,
		`DELETE FROM content_versions WHERE content_id='imm'`,
		`DELETE FROM scenarios WHERE scenario_id='imm'`,
		`UPDATE content_version_events SET actor='x'`,
		`DELETE FROM content_version_events`,
		`UPDATE content_version_sources SET role='primary'`,
		`DELETE FROM content_version_sources`,
		`UPDATE content_safety_verdicts SET verdict='x'`,
		`DELETE FROM content_safety_verdicts`,
		`UPDATE content_validations SET outcome='FAIL'`,
		`DELETE FROM content_validations`,
		`UPDATE content_registry_state SET inventory='{}'`,
		`DELETE FROM content_registry_state`,
	})
	// INSERT stays allowed (CompleteMigration writes the marker row).
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO content_registry_state (id) VALUES (1) ON CONFLICT DO NOTHING`); err != nil {
		t.Errorf("bas_app must be able to INSERT content_registry_state: %v", err)
	}
	_ = tx.Rollback(ctx)
	// The three mutable columns.
	if _, err := app.Exec(ctx, `UPDATE content_versions SET lifecycle='VALIDATING', trust_level=trust_level, signature_bytes=signature_bytes WHERE content_id='imm'`); err != nil {
		t.Errorf("bas_app lifecycle/trust/signature update must be allowed: %v", err)
	}
}

func TestRoleGrants_ThreatIdentity(t *testing.T) { // TCF Phase 2A spec §12
	ctx := context.Background()
	admin, app, _ := provisioned(t)
	var actor string
	if err := admin.QueryRow(ctx, `INSERT INTO threat_actor_profiles (name) VALUES ('Turla') RETURNING id`).Scan(&actor); err != nil {
		t.Fatal(err)
	}
	mustAdmin(t, admin, `INSERT INTO threats (id, subject_type, subject_id, actor_id, title) VALUES ('thr-g','actor',$1,$1,'Turla')`, actor)
	mustAdmin(t, admin, `INSERT INTO actor_source_identities (source, source_id, actor_id, linked_by) VALUES ('misp','e1',$1,'resolver')`, actor)
	mustAdmin(t, admin, `INSERT INTO actor_resolution_candidates (kind, source, raw_name, reason, resolver_context, resolver_context_hash)
		VALUES ('source_record','misp','X','ambiguous','{}','h')`)

	wantDenied(t, app, []string{
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
		`DELETE FROM content_version_threats`,
		`UPDATE content_generation_owners SET threat_id = threat_id`,
		`DELETE FROM content_generation_owners`,
		`UPDATE campaign_actors SET actor_id = actor_id`,
		`DELETE FROM campaign_actors`,
		`UPDATE malware_actors SET actor_id = actor_id`,
		`DELETE FROM malware_actors`,
		`UPDATE tool_actors SET actor_id = actor_id`,
		`DELETE FROM tool_actors`,
	})
	for _, s := range []string{
		`UPDATE threat_actor_profiles SET name = name, aliases = aliases`,
		`UPDATE threats SET title = title, last_seen_at = last_seen_at`,
		`UPDATE actor_resolution_candidates SET status = status WHERE false`,
	} {
		if _, err := app.Exec(ctx, s); err != nil {
			t.Errorf("bas_app %q: %v", s, err)
		}
	}
}
