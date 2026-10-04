package db_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
)

func TestContentRegistrySchema_Idempotent(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		for i := 0; i < 2; i++ {
			if err := db.EnsureContentRegistrySchema(ctx, pool); err != nil {
				t.Fatalf("ensure #%d: %v", i+1, err)
			}
		}
		for _, tbl := range []string{"content_versions", "content_version_events", "content_version_sources",
			"content_safety_verdicts", "content_validations", "content_registry_state"} {
			var n int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_name=$1`, tbl).Scan(&n); err != nil || n != 1 {
				t.Fatalf("table %s missing (n=%d err=%v)", tbl, n, err)
			}
		}
	})
}

// TestContentRegistrySchema_RefusesUnexpectedScenarioRows runs the guard
// against an isolated schema whose `scenarios` table has a row but no origin
// column -- the state a deployment would be in if something had ever written
// the (historically dead) table.
func TestContentRegistrySchema_RefusesUnexpectedScenarioRows(t *testing.T) {
	ctx := context.Background()
	admin := sharedDB.Pool
	if _, err := admin.Exec(ctx, `DROP SCHEMA IF EXISTS cr_guard CASCADE; CREATE SCHEMA cr_guard;
		CREATE TABLE cr_guard.scenarios (scenario_id text PRIMARY KEY, name text NOT NULL DEFAULT '');
		INSERT INTO cr_guard.scenarios (scenario_id) VALUES ('stray')`); err != nil {
		t.Fatalf("setup: %v", err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), `DROP SCHEMA IF EXISTS cr_guard CASCADE`) })
	cfg := admin.Config().Copy()
	cfg.ConnConfig.RuntimeParams["search_path"] = "cr_guard"
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer p.Close()
	err = db.EnsureContentRegistrySchema(ctx, p)
	if err == nil || !strings.Contains(err.Error(), "unexpected row") {
		t.Fatalf("want unexpected-row refusal, got %v", err)
	}
}

// insertIdentity / insertVersion bypass the Go layer on purpose: these tests
// prove the DATABASE rejects illegal states on its own.
func insertIdentity(t *testing.T, pool *pgxpool.Pool, id, origin string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO scenarios (scenario_id, origin) VALUES ($1,$2)`, id, origin); err != nil {
		t.Fatalf("insert identity %s/%s: %v", id, origin, err)
	}
}

func insertVersion(pool *pgxpool.Pool, id, origin, trust, lifecycle string, sig []byte, version int) error {
	art := []byte("id: " + id + "\n")
	_, err := pool.Exec(context.Background(),
		`INSERT INTO content_versions (content_id, origin, version, artifact_sha256, artifact_size, artifact_bytes,
		   signature_bytes, trust_level, lifecycle, intake_source, schema_version, created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'builtin',1,'test')`,
		id, origin, version, fmt.Sprintf("%064d", version), len(art), art, sig, trust, lifecycle)
	return err
}

func TestContentVersions_ImpossibleStatesRejectedByDB(t *testing.T) { // A4
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		origins := []string{"VENDOR", "LOCAL"}
		trusts := []string{"VENDOR_SIGNED", "LOCAL_TRUSTED", "UNTRUSTED"}
		lifecycles := []string{"DRAFT", "VALIDATING", "VALIDATED", "APPROVED", "PUBLISHED", "PUBLISHED_LOCAL", "RETIRED", "REJECTED"}
		legal := func(o, tr, lc string, signed bool) bool {
			if tr == "VENDOR_SIGNED" && !(o == "VENDOR" && signed) {
				return false
			}
			if tr == "LOCAL_TRUSTED" && o != "LOCAL" {
				return false
			}
			if lc == "PUBLISHED" && o != "VENDOR" {
				return false
			}
			if lc == "PUBLISHED_LOCAL" && o != "LOCAL" {
				return false
			}
			return true
		}
		n := 0
		for _, o := range origins {
			for _, tr := range trusts {
				for _, lc := range lifecycles {
					for _, signed := range []bool{false, true} {
						n++
						id := fmt.Sprintf("a4-%d", n)
						insertIdentity(t, pool, id, o)
						var sig []byte
						if signed {
							sig = []byte("sig")
						}
						err := insertVersion(pool, id, o, tr, lc, sig, 1)
						if got, want := err == nil, legal(o, tr, lc, signed); got != want {
							t.Errorf("%s+%s+%s signed=%v: accepted=%v want %v (err=%v)", o, tr, lc, signed, got, want, err)
						}
					}
				}
			}
		}
		// Named spot checks from the spec.
		insertIdentity(t, pool, "spot-local", "LOCAL")
		if insertVersion(pool, "spot-local", "LOCAL", "VENDOR_SIGNED", "PUBLISHED", []byte("s"), 1) == nil {
			t.Fatal("LOCAL+VENDOR_SIGNED+PUBLISHED must be impossible")
		}
		// Composite FK: a LOCAL version can never hang off a VENDOR identity.
		insertIdentity(t, pool, "spot-vendor", "VENDOR")
		if insertVersion(pool, "spot-vendor", "LOCAL", "UNTRUSTED", "DRAFT", nil, 1) == nil {
			t.Fatal("origin mismatch with identity must violate the composite FK")
		}
	})
}

func TestContentVersions_AppRoleCannotRewriteOrDelete(t *testing.T) { // A3 (DB half)
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureAppRole(ctx, pool, testAppPassword); err != nil {
			t.Fatalf("EnsureAppRole: %v", err)
		}
		insertIdentity(t, pool, "imm", "LOCAL")
		if err := insertVersion(pool, "imm", "LOCAL", "UNTRUSTED", "DRAFT", nil, 1); err != nil {
			t.Fatalf("seed: %v", err)
		}
		app := appConnectedPool(t, pool)
		for _, stmt := range []string{
			`UPDATE content_versions SET artifact_bytes = 'x' WHERE content_id='imm'`,
			`UPDATE content_versions SET artifact_sha256 = 'x' WHERE content_id='imm'`,
			`UPDATE content_versions SET version = 9 WHERE content_id='imm'`,
			`DELETE FROM content_versions WHERE content_id='imm'`,
			`DELETE FROM scenarios WHERE scenario_id='imm'`,
			`UPDATE content_version_events SET actor='x'`,
			`DELETE FROM content_version_events`,
		} {
			if _, err := app.Exec(ctx, stmt); err == nil || !strings.Contains(err.Error(), "permission denied") {
				t.Errorf("bas_app %q: want permission denied, got %v", stmt, err)
			}
		}
		if _, err := app.Exec(ctx, `UPDATE content_versions SET lifecycle='VALIDATING' WHERE content_id='imm'`); err != nil {
			t.Fatalf("bas_app lifecycle update must be allowed: %v", err)
		}
	})
}

func TestContentVersionEvents_ApprovalRequiresHumanActor(t *testing.T) { // A17 (DB half)
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		insertIdentity(t, pool, "ev", "LOCAL")
		if err := insertVersion(pool, "ev", "LOCAL", "UNTRUSTED", "DRAFT", nil, 1); err != nil {
			t.Fatalf("seed: %v", err)
		}
		var vid string
		_ = pool.QueryRow(ctx, `SELECT id FROM content_versions WHERE content_id='ev'`).Scan(&vid)
		ins := func(to, actor string) error {
			_, err := pool.Exec(ctx, `INSERT INTO content_version_events (content_version_id, to_lifecycle, to_trust, actor) VALUES ($1,$2,'UNTRUSTED',$3)`, vid, to, actor)
			return err
		}
		for _, to := range []string{"APPROVED", "PUBLISHED_LOCAL", "REJECTED"} {
			if ins(to, "intake") == nil {
				t.Errorf("%s by non-human actor must be rejected", to)
			}
			if err := ins(to, "user:u1"); err != nil {
				t.Errorf("%s by user: %v", to, err)
			}
		}
		if err := ins("PUBLISHED_LOCAL", "migration:pre-registry"); err != nil {
			t.Errorf("migration actor must be allowed: %v", err)
		}
	})
}

func TestScenarioRuns_ContentKindRequiresVersion(t *testing.T) { // A8 (DB half)
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id, hostname) VALUES ('a8','h')`); err != nil {
			t.Fatalf("agent: %v", err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO scenario_runs (scenario_id, agent_id, execution_kind) VALUES ('x','a8','content')`); err == nil {
			t.Fatal("content run without content_version_id must be rejected")
		}
		if _, err := pool.Exec(ctx, `INSERT INTO scenario_runs (scenario_id, agent_id, execution_kind) VALUES ('x','a8','bogus')`); err == nil {
			t.Fatal("unknown execution_kind must be rejected")
		}
		var kind string
		if err := pool.QueryRow(ctx, `INSERT INTO scenario_runs (scenario_id, agent_id) VALUES ('x','a8') RETURNING execution_kind`).Scan(&kind); err != nil || kind != "legacy" {
			t.Fatalf("default kind: got %q err=%v, want legacy", kind, err)
		}
	})
}
