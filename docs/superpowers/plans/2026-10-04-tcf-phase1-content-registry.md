# TCF Phase 1 — Content Registry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put a governed, immutable, provenance-carrying Content Registry between threat intelligence and executable scenarios. Every content run must be pinned to an exact content version, and every unapproved or unsigned version must be refused at dispatch.

**Architecture:** A new package `internal/contentregistry` owns the registry tables (Postgres, DB-enforced invariants). The scenario engine stays YAML-on-disk for authoring. It hands every file to the registry through a small interface defined in `internal/scenario`, which avoids an import cycle. All content dispatch goes through `Engine.ResolveExecutable`. Post-run interpretation reads the run's pinned version bytes through a run-scoped resolver. The intel generator becomes a DRAFT producer with provenance snapshots.

**Tech Stack:** Go 1.26, pgx v5, PostgreSQL 16 (testcontainers in tests), gopkg.in/yaml.v3, chi, vanilla JS dashboard (`wwwroot/index.html`).

**Spec:** `docs/superpowers/specs/2026-10-04-tcf-phase1-content-registry-design.md` (read it before starting; section numbers below refer to it).

## Global Constraints

- Allowed executable combinations, and only these: `VENDOR+VENDOR_SIGNED+PUBLISHED` and `LOCAL+LOCAL_TRUSTED+PUBLISHED_LOCAL`. In dev builds only (`!signingEnabled()`) also `VENDOR+UNTRUSTED+PUBLISHED`. Everything else is denied.
- `VENDOR_SIGNED` is assigned only on `verified == true` from an actual RSA verification, never because an error was absent.
- Version bytes are never updated. Changed bytes produce a new version. `bas_app` gets `UPDATE` only on `(lifecycle, trust_level, signature_bytes)` of `content_versions`, and `DELETE` on none of the registry tables.
- `scenario_runs.content_version_id` is written in the same `INSERT` that creates a content run, before dispatch.
- Historical reads never silently fall back to current YAML for versioned runs.
- `NO_DATA` / `NOT_APPLICABLE` are never in a denominator. An all-excluded aggregate reports `NO_DATA`.
- No triggers. Declarative constraints first. The only app-enforced invariant is "signature_bytes writable only while NULL" (`AttachVendorSignature`).
- Every tenant-owned table carries `tenant_id text NOT NULL DEFAULT 'default'`.
- DDL is idempotent (`IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`, `DO $$ … IF NOT EXISTS (pg_constraint) … $$` for constraints, following the `postgres.go:1223` precedent).
- Tests run against real Postgres: `cd orchestrator && go test ./internal/<pkg>/ -run <Name> -count=1 -p 1`. Docker Desktop must be running (start it manually). Full suite: `go test ./... -p 2` (fallback `-p 1`; the host has only about 7.8 GB RAM).
- Push after every commit: `git push` (branch `worktree-threatIntelligenceFactory` already tracks origin).
- Commit trailer on every commit: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- `TestRBACMatrix_NoDrift` already fails on main because of the `ca-root` route drift (a known, out-of-scope issue). New routes must add **no new** drift lines. Compare its output before and after Task 14.

## Plan amendments to the spec (found while mapping code; recorded in the spec by Task 1)

1. **`execution_kind` gains `adhoc_adversary`.** `handlers.go:4192`, `4215` and `4900` dispatch synthetic adversary scenarios (curated template ART lists, Caldera adversary IDs) through `dispatchRun`. These aren't registry content.
2. **New `content_registry_state` singleton table** (migration marker + stored inventory). Custom-file grandfathering applies **only before** the marker exists. Without this, a brand-new file dropped into `custom/` after migration would be grandfathered as `PUBLISHED_LOCAL`.
3. **New `content_versions.intake_source`** (`builtin|custom|intel`). It's needed to restore `Scenario.Source` when parsing stored bytes, and for the inventory.
4. **Deleting a custom scenario retires its executable versions.** `Engine.Delete` removes the file, but the registry would otherwise keep a runnable `PUBLISHED_LOCAL` version.
5. **`RETIRED → PUBLISHED_LOCAL` is allowed for LOCAL with a human actor** (re-approval). Re-creating a deleted custom scenario with identical bytes hits the existing version by hash, and without this transition it could never run again.
6. **Builtin-first intake order.** `WalkDir` is lexical: `custom/lolbin-…` sorts before the builtin `lolbin-…`, so on first registration a custom file could claim the identity and get the signed builtin refused.
7. **Two hashes per step:** `resolvedSha256` (right after `BuildSteps`, used for drift) and `commandSha256` (the exact bytes sent). `applyGeneratedArtifacts` and sink tokens inject per-run random values, so the sent-command hash can never match a rebuild.
8. **Signature verification is injectable** (`integrity.Verifier`). CI doesn't have the vendor private key (`scenario_authoring_test.go:151`), so VENDOR_SIGNED paths can only be tested with a test key.
9. **Known limitation:** historical detection-expectation resolution uses the step data from the pinned version, but detection *profiles* (`scenarios/detection-profiles/`) are still resolved from current files. Profiles aren't registry content in Phase 1.
10. **Minimal "Approve for local use" button** on intel/custom DRAFT cards (admin only). Without it, the only way to approve an intel DRAFT is curl, and schedules broken by migration would have no UI path to recovery.

## Review Focus

The input classes and failure modes most likely to bite users that the spec doesn't spell out. Each has a test in the owning task.

1. **Step subset chosen against the newest (disk) version while an older approved version executes.** The step indices must be validated against the *executed* version. Test: Task 9 `TestRunScenario_StepSubsetValidatedAgainstExecutedVersion`.
2. **Concurrent intake of the same content** (engine reload racing the connector reload): it must produce exactly one version. Test: Task 5 `TestIntake_ConcurrentSameBytesOneVersion`.
3. **Generator output must be byte-deterministic across syncs** with unchanged intel. Otherwise every 6-hour sync creates a new DRAFT. Test: Task 12 `TestGenerator_UnchangedInputsSameBytes`.
4. **Registry errors during engine load** (DB hiccup): the file must not become executable and the rest of the load must continue. Test: Task 7 `TestLoad_IntakeErrorKeepsLoadingAndDoesNotExecute`.
5. **Delete then re-create a custom scenario with identical bytes**: it must become executable again through re-approval, not get stuck in RETIRED. Test: Task 5 `TestRegisterLocalApproved_RecreateAfterRetire`.

---

## File Structure

| File | Status | Responsibility |
|---|---|---|
| `orchestrator/internal/db/content_registry_schema.go` | Create | All Phase 1 DDL (§4) |
| `orchestrator/internal/db/content_registry_schema_test.go` | Create | A3 (DB), A4, A8 (DB), A17 (DB), idempotency, empty-guard |
| `orchestrator/internal/db/app_role.go` | Modify | REVOKE/column-GRANT for registry tables |
| `orchestrator/internal/testutil/testdb.go` | Modify | Call `EnsureContentRegistrySchema` |
| `orchestrator/internal/testutil/signing.go` | Create | Test RSA key + signer + verifier |
| `orchestrator/internal/integrity/verifier.go` | Create | `Verifier`, `CompiledVerifier`, `VerifyScenarioBytes`, `ReadBuiltinSignature` |
| `orchestrator/internal/integrity/verifier_test.go` | Create | A15, A16 |
| `orchestrator/internal/contentregistry/types.go` | Create | Enums, kinds, errors |
| `orchestrator/internal/contentregistry/lifecycle.go` (+`_test`) | Create | State machine, `Executable`, `TrustAfter` |
| `orchestrator/internal/contentregistry/analyze.go` (+`_test`) | Create | Parse, technique IDs, structural check, safety verdict |
| `orchestrator/internal/contentregistry/registry.go` | Create | `Registry`, `New`, audit, refusals |
| `orchestrator/internal/contentregistry/store.go` (+`_test`) | Create | `createVersion`, `LoadVersion`, `ListVersions` |
| `orchestrator/internal/contentregistry/intake.go` (+`_test`) | Create | `Intake`, `RegisterLocalApproved`, `RetireExecutable` |
| `orchestrator/internal/contentregistry/gate.go` (+`_test`) | Create | `ResolveExecutable`, `Transition`, `AttachVendorSignature` |
| `orchestrator/internal/contentregistry/generated.go` (+`_test`) | Create | `RegisterGenerated`, source snapshots |
| `orchestrator/internal/contentregistry/runs.go` (+`_test`) | Create | `RunContent`, `RunResolver` |
| `orchestrator/internal/contentregistry/drift.go` (+`_test`) | Create | `CompareDrift` (pure) |
| `orchestrator/internal/contentregistry/migration.go` (+`_test`) | Create | `CompleteMigration`, `MigrationInventory` |
| `orchestrator/internal/contentregistry/validations.go` (+`_test`) | Create | `DetectionEffectiveness`, `ListValidations` |
| `orchestrator/internal/contentregistry/testmain_test.go` | Create | Shared testcontainers DB |
| `orchestrator/internal/scenario/registry.go` | Create | `ContentRegistry` interface + DTOs |
| `orchestrator/internal/scenario/engine.go` | Modify | Ordered intake, `AttachRegistry`, `SetVerifier`, `SaveAs`, `DeleteAs`, `ResolveExecutable` |
| `orchestrator/internal/scenario/builder.go` | Modify | `StepMeta` hashes, `BuildStepMeta` signature, `ResolvedHashes` |
| `orchestrator/internal/api/handlers.go` | Modify | Gate wiring, kinds, `persistStepMeta`, result interpretation, list enrichment |
| `orchestrator/internal/api/remediation_dispatch.go`, `variant_handlers.go` | Modify | Explicit `execution_kind` |
| `orchestrator/internal/api/content_registry_handlers.go` (+`_test`) | Create | §9 endpoints + drift |
| `orchestrator/internal/api/routes.go`, `rbac_matrix_test.go` | Modify | Routes + matrix |
| `orchestrator/internal/auth/permissions.go` | Modify | 3 new permissions |
| `orchestrator/internal/reporting/engine.go`, `detection_validation.go`, `html.go` | Modify | Run-scoped resolver, `contentProvenance` |
| `orchestrator/internal/verifysync/job.go` | Modify | Run-scoped resolver |
| `orchestrator/internal/api/verification_handlers.go`, `detectverify_handlers.go` | Modify | Run-scoped resolver |
| `orchestrator/internal/connector/generator.go`, `scheduler.go` | Modify | Deterministic YAML, actor-based ID, `Registrar` |
| `orchestrator/cmd/server/main.go` | Modify | Schema call, registry wiring, migration |
| `orchestrator/wwwroot/index.html` | Modify | Badges, approve button, run label, migration banner |

---

### Task 1: Registry schema, DB privileges, spec amendments

**Files:**
- Create: `orchestrator/internal/db/content_registry_schema.go`
- Create: `orchestrator/internal/db/content_registry_schema_test.go`
- Modify: `orchestrator/internal/db/app_role.go:63-85` (grants slice)
- Modify: `orchestrator/internal/testutil/testdb.go` (after the `EnsureAgentUninstallSchema` block)
- Modify: `orchestrator/cmd/server/main.go:269-272` (after `EnsureExerciseSchema`, before `EnsureAppRole`)
- Modify: `docs/superpowers/specs/2026-10-04-tcf-phase1-content-registry-design.md` (append §14)

**Interfaces:**
- Produces: `db.EnsureContentRegistrySchema(ctx context.Context, pool *pgxpool.Pool) error`; tables `content_versions`, `content_version_events`, `content_version_sources`, `content_safety_verdicts`, `content_validations`, `content_registry_state`; columns `scenarios.origin/created_at/generation_key`, `scenario_runs.content_version_id/execution_kind`.

- [ ] **Step 1: Append the plan amendments to the spec**

Append to the end of the spec file:

```markdown
## 14. Amendments made during implementation planning (2026-10-04)

1. `execution_kind` adds `adhoc_adversary` (synthetic adversary-template / Caldera-adversary runs via `dispatchRun`).
2. `content_registry_state` singleton (migration marker + stored inventory). Custom-file grandfathering applies only before the marker exists.
3. `content_versions.intake_source` (`builtin|custom|intel`).
4. Deleting a custom scenario retires its executable versions.
5. `RETIRED → PUBLISHED_LOCAL` allowed for LOCAL with a human actor (re-approval after delete/re-create with identical bytes).
6. Intake processes builtin files first, then custom, then intel, so first registration can never let a custom file claim a builtin's identity.
7. Two per-step hashes: `resolvedSha256` (post-`BuildSteps`, used for drift) and `commandSha256` (exact bytes sent; per-run artifact and sink-token substitution make it unreproducible by design).
8. Signature verification is injected via `integrity.Verifier` so VENDOR_SIGNED paths are testable without the vendor private key.
9. Limitation: detection profiles are still resolved from current files during historical reads; profiles are not registry content in Phase 1.
10. A minimal admin "Approve for local use" action on DRAFT cards.
```

- [ ] **Step 2: Write the failing schema tests**

Create `orchestrator/internal/db/content_registry_schema_test.go`:

```go
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
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/db/ -run 'ContentRegistry|ContentVersion|ScenarioRuns_Content' -count=1 -p 1`
Expected: FAIL, compile error `undefined: db.EnsureContentRegistrySchema`.

- [ ] **Step 4: Implement the schema**

Create `orchestrator/internal/db/content_registry_schema.go`:

```go
package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// addConstraint renders an idempotent ALTER TABLE ... ADD CONSTRAINT --
// PostgreSQL has no ADD CONSTRAINT IF NOT EXISTS, so this follows the DO $$
// precedent in postgres.go.
func addConstraint(table, name, def string) string {
	return fmt.Sprintf(`DO $$
BEGIN
	IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = '%s') THEN
		ALTER TABLE %s ADD CONSTRAINT %s %s;
	END IF;
END $$`, name, table, name, def)
}

// EnsureContentRegistrySchema creates the Threat Content Factory Phase 1
// Content Registry. See
// docs/superpowers/specs/2026-10-04-tcf-phase1-content-registry-design.md §4.
// Must run after EnsureSchema (scenario_runs) and EnsureContentSchema
// (scenarios), and before EnsureAppRole (whose REVOKEs target these tables).
func EnsureContentRegistrySchema(ctx context.Context, pool *pgxpool.Pool) error {
	// scenarios is repurposed as content identity. No code has ever written
	// it, so it should be empty; if it is not, refuse rather than guess an
	// origin for rows nobody can explain.
	var hasOrigin bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.columns
		  WHERE table_schema = current_schema() AND table_name = 'scenarios' AND column_name = 'origin')`,
	).Scan(&hasOrigin); err != nil {
		return fmt.Errorf("content registry: inspect scenarios: %w", err)
	}
	if !hasOrigin {
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM scenarios`).Scan(&n); err != nil {
			return fmt.Errorf("content registry: count scenarios: %w", err)
		}
		if n > 0 {
			return fmt.Errorf("content registry migration: table scenarios has %d unexpected row(s); refusing to assign an origin -- inspect and clear them manually", n)
		}
	}

	stmts := []string{
		`ALTER TABLE scenarios ADD COLUMN IF NOT EXISTS origin text`,
		`ALTER TABLE scenarios ALTER COLUMN origin SET NOT NULL`,
		`ALTER TABLE scenarios ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT NOW()`,
		`ALTER TABLE scenarios ADD COLUMN IF NOT EXISTS generation_key text`,
		addConstraint("scenarios", "scenarios_origin_check", `CHECK (origin IN ('VENDOR','LOCAL'))`),
		addConstraint("scenarios", "scenarios_id_origin_key", `UNIQUE (scenario_id, origin)`),

		`CREATE TABLE IF NOT EXISTS content_versions (
			id               text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			content_id       text        NOT NULL,
			origin           text        NOT NULL,
			version          int         NOT NULL CHECK (version >= 1),
			artifact_sha256  text        NOT NULL,
			artifact_size    int         NOT NULL,
			artifact_bytes   bytea       NOT NULL,
			signature_bytes  bytea,
			trust_level      text        NOT NULL CHECK (trust_level IN ('VENDOR_SIGNED','LOCAL_TRUSTED','UNTRUSTED')),
			lifecycle        text        NOT NULL CHECK (lifecycle IN ('DRAFT','VALIDATING','VALIDATED','APPROVED',
			                                                            'PUBLISHED','PUBLISHED_LOCAL','RETIRED','REJECTED')),
			intake_source    text        NOT NULL CHECK (intake_source IN ('builtin','custom','intel')),
			schema_version   int         NOT NULL,
			technique_ids    text[]      NOT NULL DEFAULT '{}',
			supported_os     text[]      NOT NULL DEFAULT '{}',
			generation       jsonb       NOT NULL DEFAULT '{}',
			created_by       text        NOT NULL,
			created_at       timestamptz NOT NULL DEFAULT NOW(),
			tenant_id        text        NOT NULL DEFAULT 'default',
			FOREIGN KEY (content_id, origin) REFERENCES scenarios (scenario_id, origin),
			UNIQUE (content_id, version),
			UNIQUE (content_id, artifact_sha256),
			CHECK (artifact_size = octet_length(artifact_bytes)),
			CHECK (trust_level <> 'VENDOR_SIGNED' OR (origin = 'VENDOR' AND signature_bytes IS NOT NULL)),
			CHECK (trust_level <> 'LOCAL_TRUSTED' OR origin = 'LOCAL'),
			CHECK (lifecycle <> 'PUBLISHED' OR origin = 'VENDOR'),
			CHECK (lifecycle <> 'PUBLISHED_LOCAL' OR origin = 'LOCAL')
		)`,
		`CREATE INDEX IF NOT EXISTS content_versions_techniques ON content_versions USING GIN (technique_ids)`,

		`CREATE TABLE IF NOT EXISTS content_version_events (
			id                  bigserial   PRIMARY KEY,
			content_version_id  text        NOT NULL REFERENCES content_versions(id),
			from_lifecycle      text,
			to_lifecycle        text        NOT NULL,
			from_trust          text,
			to_trust            text        NOT NULL,
			actor               text        NOT NULL,
			reason              text        NOT NULL DEFAULT '',
			at                  timestamptz NOT NULL DEFAULT NOW(),
			tenant_id           text        NOT NULL DEFAULT 'default',
			CHECK (to_lifecycle NOT IN ('APPROVED','PUBLISHED_LOCAL','REJECTED')
			       OR actor LIKE 'user:_%' OR actor = 'migration:pre-registry')
		)`,
		`CREATE INDEX IF NOT EXISTS content_version_events_vid ON content_version_events (content_version_id, at)`,

		`CREATE TABLE IF NOT EXISTS content_version_sources (
			content_version_id        text        NOT NULL REFERENCES content_versions(id),
			entity_type               text        NOT NULL CHECK (entity_type IN
			                              ('actor','campaign','malware','tool','technique_evidence')),
			entity_id                 text        NOT NULL,
			provider                  text        NOT NULL,
			external_id               text        NOT NULL DEFAULT '',
			confidence_at_generation  text        NOT NULL DEFAULT '',
			first_seen_at_generation  timestamptz,
			last_sync_at_generation   timestamptz,
			role                      text        NOT NULL CHECK (role IN ('primary','supporting')),
			tenant_id                 text        NOT NULL DEFAULT 'default',
			PRIMARY KEY (content_version_id, entity_type, entity_id, provider)
		)`,

		`CREATE TABLE IF NOT EXISTS content_safety_verdicts (
			id                  bigserial   PRIMARY KEY,
			content_version_id  text        NOT NULL REFERENCES content_versions(id),
			classifier          text        NOT NULL,
			classifier_version  text        NOT NULL,
			verdict             text        NOT NULL,
			detail              jsonb       NOT NULL DEFAULT '[]',
			evaluated_at        timestamptz NOT NULL DEFAULT NOW(),
			tenant_id           text        NOT NULL DEFAULT 'default',
			UNIQUE (content_version_id, classifier, classifier_version)
		)`,

		`CREATE TABLE IF NOT EXISTS content_validations (
			id                  text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			content_version_id  text        NOT NULL REFERENCES content_versions(id),
			level               text        NOT NULL CHECK (level IN
			                        ('STRUCTURAL','STATIC','EXECUTION','TELEMETRY','DETECTION')),
			outcome             text        NOT NULL CHECK (outcome IN
			                        ('PASS','FAIL','ERROR','DETECTED','PREVENTED','LOGGED','MISSED',
			                         'NO_DATA','NOT_APPLICABLE')),
			run_id              text        REFERENCES scenario_runs(id),
			validator           text        NOT NULL,
			validator_version   text        NOT NULL,
			environment         jsonb       NOT NULL DEFAULT '{}',
			detail              jsonb       NOT NULL DEFAULT '{}',
			created_at          timestamptz NOT NULL DEFAULT NOW(),
			tenant_id           text        NOT NULL DEFAULT 'default',
			CHECK (level IN ('STRUCTURAL','STATIC') OR outcome <> 'PASS' OR run_id IS NOT NULL),
			CHECK (level <> 'DETECTION' OR outcome NOT IN ('PASS','FAIL'))
		)`,
		`CREATE INDEX IF NOT EXISTS content_validations_vid ON content_validations (content_version_id, level)`,

		// Singleton migration marker (plan amendment 2). Custom files are
		// grandfathered only while this row does not exist.
		`CREATE TABLE IF NOT EXISTS content_registry_state (
			id           int         PRIMARY KEY DEFAULT 1 CHECK (id = 1),
			migrated_at  timestamptz NOT NULL DEFAULT NOW(),
			inventory    jsonb       NOT NULL DEFAULT '{}'
		)`,

		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS content_version_id text REFERENCES content_versions(id)`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS execution_kind text NOT NULL DEFAULT 'legacy'`,
		addConstraint("scenario_runs", "scenario_runs_execution_kind_check",
			`CHECK (execution_kind IN ('content','remediation','technique_verification','variant','adhoc_adversary','legacy'))`),
		addConstraint("scenario_runs", "scenario_runs_content_needs_version_check",
			`CHECK (execution_kind <> 'content' OR content_version_id IS NOT NULL)`),
		`CREATE INDEX IF NOT EXISTS idx_scenario_runs_content_version ON scenario_runs (content_version_id) WHERE content_version_id IS NOT NULL`,
	}
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			return fmt.Errorf("content registry schema exec failed:\n%s\nerror: %w", s, err)
		}
	}
	return nil
}
```

In `orchestrator/internal/db/app_role.go`, extend the `grants` slice after the `audit_logs` REVOKE line (`app_role.go:84`):

```go
		`REVOKE UPDATE, DELETE ON audit_logs FROM ` + appRole,

		// Content Registry immutability (TCF Phase 1 §4.2). A table-level
		// REVOKE also removes column privileges, so the column GRANT must
		// come after it -- otherwise the blanket grant above would keep
		// bas_app able to rewrite artifact bytes.
		`REVOKE UPDATE, DELETE ON content_versions FROM ` + appRole,
		`GRANT UPDATE (lifecycle, trust_level, signature_bytes) ON content_versions TO ` + appRole,
		`REVOKE UPDATE, DELETE ON content_version_events FROM ` + appRole,
		`REVOKE UPDATE, DELETE ON content_version_sources FROM ` + appRole,
		`REVOKE UPDATE, DELETE ON content_safety_verdicts FROM ` + appRole,
		`REVOKE DELETE ON scenarios FROM ` + appRole,
```

In `orchestrator/internal/testutil/testdb.go`, after the `EnsureAgentUninstallSchema` block inside `newTestDB`, add:

```go
	if err := db.EnsureContentRegistrySchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(context.Background())
		return nil, fmt.Errorf("testutil: EnsureContentRegistrySchema: %w", err)
	}
```

In `orchestrator/cmd/server/main.go`, right after the `EnsureExerciseSchema` block (`main.go:272-274`), add the same call in that file's error style (copy the surrounding `log.Fatalf` shape):

```go
	if err := db.EnsureContentRegistrySchema(context.Background(), adminPool); err != nil {
		log.Fatalf("content registry schema: %v", err)
	}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/db/ -run 'ContentRegistry|ContentVersion|ScenarioRuns_Content|EnsureAppRole' -count=1 -p 1`
Expected: PASS (all listed tests, including the existing `EnsureAppRole` tests).

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/db/content_registry_schema.go orchestrator/internal/db/content_registry_schema_test.go orchestrator/internal/db/app_role.go orchestrator/internal/testutil/testdb.go orchestrator/cmd/server/main.go docs/superpowers/specs/2026-10-04-tcf-phase1-content-registry-design.md
git commit -m "feat(tcf): content registry schema with DB-enforced invariants

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 2: Injectable signature verification

**Files:**
- Create: `orchestrator/internal/integrity/verifier.go`
- Create: `orchestrator/internal/integrity/verifier_test.go`
- Create: `orchestrator/internal/testutil/signing.go`

**Interfaces:**
- Produces:
  - `integrity.Verifier` interface: `Verify(content, sig []byte) (bool, error)`; `SigningEnabled() bool`
  - `integrity.CompiledVerifier{}` (production; uses `ScenarioPublicKeyPEM`)
  - `integrity.NewKeyVerifier(pub *rsa.PublicKey) Verifier`
  - `integrity.VerifyScenarioBytes(content, sig []byte) (bool, error)`: compiled key, `(false, nil)` in dev builds
  - `integrity.ReadBuiltinSignature(v Verifier, path string, content []byte) (sig []byte, verified bool, err error)`
  - `testutil.NewTestSigner(t) *TestSigner` with `.Sign(content []byte) []byte` and `.Verifier() integrity.Verifier`
  - `testutil.DevVerifier()`: an `integrity.Verifier` whose `SigningEnabled()` is false

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/integrity/verifier_test.go`:

```go
package integrity_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/integrity"
)

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sign(t *testing.T, k *rsa.PrivateKey, b []byte) []byte {
	t.Helper()
	h := sha256.Sum256(b)
	s, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestKeyVerifier_VerifiesOnlyMatchingSignature(t *testing.T) {
	k := testKey(t)
	v := integrity.NewKeyVerifier(&k.PublicKey)
	content := []byte("id: x\n")
	ok, err := v.Verify(content, sign(t, k, content))
	if !ok || err != nil {
		t.Fatalf("valid signature: ok=%v err=%v", ok, err)
	}
	ok, err = v.Verify([]byte("id: y\n"), sign(t, k, content))
	if ok || err == nil {
		t.Fatalf("tampered content must fail: ok=%v err=%v", ok, err)
	}
	if !v.SigningEnabled() {
		t.Fatal("key verifier must report signing enabled")
	}
}

// A15: a (false, nil) verification must never be mistaken for proof.
func TestReadBuiltinSignature_DevBuildIsNotVerified(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.yaml")
	content := []byte("id: a\n")
	_ = os.WriteFile(p, content, 0o644)
	sig, verified, err := integrity.ReadBuiltinSignature(devVerifier{}, p, content)
	if err != nil || verified || sig != nil {
		t.Fatalf("dev build without .sig: sig=%v verified=%v err=%v", sig, verified, err)
	}
}

func TestReadBuiltinSignature_MissingSigWhenEnabledIsErrUnsigned(t *testing.T) {
	k := testKey(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "a.yaml")
	content := []byte("id: a\n")
	_ = os.WriteFile(p, content, 0o644)
	if _, _, err := integrity.ReadBuiltinSignature(integrity.NewKeyVerifier(&k.PublicKey), p, content); err == nil {
		t.Fatal("missing .sig with signing enabled must error")
	}
	_ = os.WriteFile(p+".sig", []byte(base64.StdEncoding.EncodeToString(sign(t, k, content))), 0o644)
	sig, verified, err := integrity.ReadBuiltinSignature(integrity.NewKeyVerifier(&k.PublicKey), p, content)
	if err != nil || !verified || len(sig) == 0 {
		t.Fatalf("valid .sig: verified=%v err=%v", verified, err)
	}
}

type devVerifier struct{}

func (devVerifier) Verify([]byte, []byte) (bool, error) { return false, nil }
func (devVerifier) SigningEnabled() bool               { return false }

// A16: signingEnabled must depend only on the compiled-in constant. The
// variable is exported (signer.go rewrites it at keygen time), so the guard
// is a source scan: no non-test Go file outside integrity may assign it, and
// the integrity package must not read env/config.
func TestSigningEnabledNotRuntimeConfigurable(t *testing.T) {
	root := filepath.Join("..", "..")
	assign := regexp.MustCompile(`ScenarioPublicKeyPEM\s*=`)
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, _ := os.ReadFile(path)
		if !assign.Match(b) {
			return nil
		}
		slash := filepath.ToSlash(path)
		if strings.HasSuffix(slash, "internal/integrity/signing.go") || strings.HasSuffix(slash, "scripts/signer.go") {
			return nil // the declaration itself, and the offline keygen rewriter
		}
		t.Errorf("%s assigns ScenarioPublicKeyPEM at runtime", path)
		return nil
	})
	for _, f := range []string{"signing.go", "verifier.go"} {
		b, _ := os.ReadFile(f)
		if strings.Contains(string(b), "os.Getenv") || strings.Contains(string(b), "config.") {
			t.Errorf("%s must not consult env/config", f)
		}
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/integrity/ -count=1`
Expected: FAIL, `undefined: integrity.NewKeyVerifier`.

- [ ] **Step 3: Implement**

Create `orchestrator/internal/integrity/verifier.go`:

```go
package integrity

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Verifier checks a scenario artifact's RSA-SHA256 signature. verified is
// true ONLY when a real verification succeeded -- callers must never treat
// a nil error as proof (dev builds return (false, nil)). See TCF Phase 1
// spec §5.1.
type Verifier interface {
	Verify(content, sig []byte) (verified bool, err error)
	SigningEnabled() bool
}

// CompiledVerifier verifies with the compiled-in ScenarioPublicKeyPEM.
type CompiledVerifier struct{}

func (CompiledVerifier) SigningEnabled() bool { return signingEnabled() }

func (CompiledVerifier) Verify(content, sig []byte) (bool, error) {
	return VerifyScenarioBytes(content, sig)
}

// VerifyScenarioBytes verifies raw (already base64-decoded) signature bytes
// against content with the compiled-in key. Dev builds: (false, nil).
func VerifyScenarioBytes(content, sig []byte) (bool, error) {
	if !signingEnabled() {
		return false, nil
	}
	pub, err := parseContentPublicKey()
	if err != nil {
		return false, fmt.Errorf("content public key: %w", err)
	}
	return verifyWith(pub, content, sig)
}

func verifyWith(pub *rsa.PublicKey, content, sig []byte) (bool, error) {
	if len(sig) == 0 {
		return false, ErrUnsigned
	}
	h := sha256.Sum256(content)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig); err != nil {
		return false, fmt.Errorf("signature invalid: %w", err)
	}
	return true, nil
}

type keyVerifier struct{ pub *rsa.PublicKey }

// NewKeyVerifier verifies with an explicit public key (tests; future
// rotated keys). Always reports signing enabled.
func NewKeyVerifier(pub *rsa.PublicKey) Verifier { return keyVerifier{pub: pub} }

func (k keyVerifier) SigningEnabled() bool { return true }
func (k keyVerifier) Verify(content, sig []byte) (bool, error) {
	return verifyWith(k.pub, content, sig)
}

// ReadBuiltinSignature reads path+".sig" (base64, as written by
// scripts/signer.go) and verifies it with v.
//
//   - signing enabled, .sig missing  -> ErrUnsigned
//   - signing enabled, .sig invalid  -> (sig, false, err)
//   - signing disabled (dev build)   -> (sig-or-nil, false, nil)
func ReadBuiltinSignature(v Verifier, path string, content []byte) ([]byte, bool, error) {
	raw, err := os.ReadFile(path + ".sig")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if v.SigningEnabled() {
				return nil, false, fmt.Errorf("%w: %s", ErrUnsigned, path)
			}
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("read .sig: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, false, fmt.Errorf("decode signature: %w", err)
	}
	if !v.SigningEnabled() {
		return sig, false, nil
	}
	ok, err := v.Verify(content, sig)
	if err != nil {
		return sig, false, fmt.Errorf("scenario signature invalid for %s -- file may be tampered: %w", path, err)
	}
	return sig, ok, nil
}
```

Create `orchestrator/internal/testutil/signing.go`:

```go
package testutil

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"testing"

	"github.com/audspect/bas/internal/integrity"
)

// TestSigner stands in for the vendor key, whose private half is not
// available to tests or CI.
type TestSigner struct{ key *rsa.PrivateKey }

func NewTestSigner(t *testing.T) *TestSigner {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("testutil: rsa key: %v", err)
	}
	return &TestSigner{key: k}
}

func (s *TestSigner) Sign(content []byte) []byte {
	h := sha256.Sum256(content)
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, h[:])
	if err != nil {
		panic(err)
	}
	return sig
}

// WriteSigned writes content to path and its base64 signature to path+".sig".
func (s *TestSigner) WriteSigned(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".sig", []byte(base64.StdEncoding.EncodeToString(s.Sign(content))), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (s *TestSigner) Verifier() integrity.Verifier { return integrity.NewKeyVerifier(&s.key.PublicKey) }

type devVerifier struct{}

func (devVerifier) Verify([]byte, []byte) (bool, error) { return false, nil }
func (devVerifier) SigningEnabled() bool               { return false }

// DevVerifier simulates a dev build (placeholder key).
func DevVerifier() integrity.Verifier { return devVerifier{} }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/integrity/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/integrity/verifier.go orchestrator/internal/integrity/verifier_test.go orchestrator/internal/testutil/signing.go
git commit -m "feat(integrity): injectable verifier that reports explicit verification

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 3: Registry types and lifecycle state machine

**Files:**
- Create: `orchestrator/internal/contentregistry/types.go`
- Create: `orchestrator/internal/contentregistry/lifecycle.go`
- Create: `orchestrator/internal/contentregistry/lifecycle_test.go`

**Interfaces:**
- Produces: types `Origin`, `Trust`, `Lifecycle`, `IntakeSource` and their constants (below); kind constants `KindContent`, `KindRemediation`, `KindTechniqueVerification`, `KindVariant`, `KindAdhocAdversary`, `KindLegacy`; `ActorIntake`, `ActorGenerator`, `ActorMigration`, `MigrationReason`; errors `ErrOriginCollision`, `*ErrNotExecutable{ContentID, Reason}`, `*ErrIllegalTransition{From, To Lifecycle; Reason string}`, `ErrVersionNotFound`; funcs `IsHumanActor(string) bool`, `CheckTransition(Origin, Trust, Lifecycle, Lifecycle, string) error`, `TrustAfter(Origin, Trust, Lifecycle) Trust`, `Executable(Origin, Trust, Lifecycle, devBuild bool) bool`.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/contentregistry/lifecycle_test.go`:

```go
package contentregistry

import "testing"

var allOrigins = []Origin{OriginVendor, OriginLocal}
var allTrusts = []Trust{TrustVendorSigned, TrustLocalTrusted, TrustUntrusted}
var allLifecycles = []Lifecycle{LifecycleDraft, LifecycleValidating, LifecycleValidated, LifecycleApproved,
	LifecyclePublished, LifecyclePublishedLocal, LifecycleRetired, LifecycleRejected}

// A5 (pure half): exactly two combinations run in production; the dev
// exception adds exactly one.
func TestExecutableMatrix(t *testing.T) {
	for _, o := range allOrigins {
		for _, tr := range allTrusts {
			for _, lc := range allLifecycles {
				prod := (o == OriginVendor && tr == TrustVendorSigned && lc == LifecyclePublished) ||
					(o == OriginLocal && tr == TrustLocalTrusted && lc == LifecyclePublishedLocal)
				dev := prod || (o == OriginVendor && tr == TrustUntrusted && lc == LifecyclePublished)
				if got := Executable(o, tr, lc, false); got != prod {
					t.Errorf("prod %s/%s/%s = %v want %v", o, tr, lc, got, prod)
				}
				if got := Executable(o, tr, lc, true); got != dev {
					t.Errorf("dev %s/%s/%s = %v want %v", o, tr, lc, got, dev)
				}
			}
		}
	}
}

func TestCheckTransition_Rules(t *testing.T) {
	const user = "user:u1"
	cases := []struct {
		name     string
		o        Origin
		tr       Trust
		from, to Lifecycle
		actor    string
		ok       bool
	}{
		{"draft to validating by system", OriginVendor, TrustUntrusted, LifecycleDraft, LifecycleValidating, "system:validator", true},
		{"validated to approved vendor user", OriginVendor, TrustUntrusted, LifecycleValidated, LifecycleApproved, user, true},
		{"validated to approved needs human", OriginVendor, TrustUntrusted, LifecycleValidated, LifecycleApproved, "intake", false},
		{"approved local impossible", OriginLocal, TrustUntrusted, LifecycleValidated, LifecycleApproved, user, false},
		{"approved to published needs signature", OriginVendor, TrustUntrusted, LifecycleApproved, LifecyclePublished, user, false},
		{"approved to published signed", OriginVendor, TrustVendorSigned, LifecycleApproved, LifecyclePublished, user, true},
		{"draft to published_local local", OriginLocal, TrustUntrusted, LifecycleDraft, LifecyclePublishedLocal, user, true},
		{"draft to published_local vendor", OriginVendor, TrustUntrusted, LifecycleDraft, LifecyclePublishedLocal, user, false},
		{"draft straight to published", OriginVendor, TrustVendorSigned, LifecycleDraft, LifecyclePublished, user, false},
		{"retired to published_local re-approval", OriginLocal, TrustLocalTrusted, LifecycleRetired, LifecyclePublishedLocal, user, true},
		{"retired vendor is terminal", OriginVendor, TrustVendorSigned, LifecycleRetired, LifecyclePublished, user, false},
		{"rejected is terminal", OriginLocal, TrustUntrusted, LifecycleRejected, LifecycleDraft, user, false},
		{"published_local retire", OriginLocal, TrustLocalTrusted, LifecyclePublishedLocal, LifecycleRetired, user, true},
		{"retire needs human", OriginLocal, TrustLocalTrusted, LifecyclePublishedLocal, LifecycleRetired, "intake", false},
		{"validated is not executable shortcut", OriginLocal, TrustUntrusted, LifecycleValidated, LifecyclePublished, user, false},
		{"reject from approved", OriginVendor, TrustUntrusted, LifecycleApproved, LifecycleRejected, user, true},
	}
	for _, c := range cases {
		err := CheckTransition(c.o, c.tr, c.from, c.to, c.actor)
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v want ok=%v", c.name, err, c.ok)
		}
	}
}

func TestTrustAfter(t *testing.T) {
	if got := TrustAfter(OriginLocal, TrustUntrusted, LifecyclePublishedLocal); got != TrustLocalTrusted {
		t.Fatalf("local publish: %s", got)
	}
	if got := TrustAfter(OriginLocal, TrustLocalTrusted, LifecycleRetired); got != TrustLocalTrusted {
		t.Fatalf("retire keeps historical trust: %s", got)
	}
	if got := TrustAfter(OriginVendor, TrustUntrusted, LifecycleApproved); got != TrustUntrusted {
		t.Fatalf("approval never grants vendor trust: %s", got)
	}
}

func TestIsHumanActor(t *testing.T) {
	for in, want := range map[string]bool{"user:u1": true, "user:": false, "intake": false, "migration:pre-registry": false, "": false} {
		if IsHumanActor(in) != want {
			t.Errorf("IsHumanActor(%q) != %v", in, want)
		}
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/contentregistry/ -run 'Executable|CheckTransition|TrustAfter|IsHuman' -count=1`
Expected: FAIL, package has no non-test files / undefined identifiers.

- [ ] **Step 3: Implement**

Create `orchestrator/internal/contentregistry/types.go`:

```go
// Package contentregistry is the system of record for executable threat
// content and its lifecycle (TCF Phase 1). See
// docs/superpowers/specs/2026-10-04-tcf-phase1-content-registry-design.md.
package contentregistry

import (
	"errors"
	"fmt"
)

type Origin string

const (
	OriginVendor Origin = "VENDOR"
	OriginLocal  Origin = "LOCAL"
)

type Trust string

const (
	TrustVendorSigned Trust = "VENDOR_SIGNED"
	TrustLocalTrusted Trust = "LOCAL_TRUSTED"
	TrustUntrusted    Trust = "UNTRUSTED"
)

type Lifecycle string

const (
	LifecycleDraft          Lifecycle = "DRAFT"
	LifecycleValidating     Lifecycle = "VALIDATING"
	LifecycleValidated      Lifecycle = "VALIDATED"
	LifecycleApproved       Lifecycle = "APPROVED"
	LifecyclePublished      Lifecycle = "PUBLISHED"
	LifecyclePublishedLocal Lifecycle = "PUBLISHED_LOCAL"
	LifecycleRetired        Lifecycle = "RETIRED"
	LifecycleRejected       Lifecycle = "REJECTED"
)

type IntakeSource string

const (
	SourceBuiltin IntakeSource = "builtin"
	SourceCustom  IntakeSource = "custom"
	SourceIntel   IntakeSource = "intel"
)

// scenario_runs.execution_kind values (spec §4.8 + plan amendment 1).
const (
	KindContent               = "content"
	KindRemediation           = "remediation"
	KindTechniqueVerification = "technique_verification"
	KindVariant               = "variant"
	KindAdhocAdversary        = "adhoc_adversary"
	KindLegacy                = "legacy"
)

const (
	ActorIntake     = "intake"
	ActorGenerator  = "generator:connector"
	ActorMigration  = "migration:pre-registry"
	MigrationReason = "historical authorization: authored via operator UI before approval tracking existed; not reviewed during migration"
)

var (
	ErrOriginCollision = errors.New("content id already registered with a different origin")
	ErrVersionNotFound = errors.New("content version not found")
)

// ErrNotExecutable is the runtime gate's denial. Its Error() text is what
// operators see (409 body, scheduled-job failure, campaign skip reason).
type ErrNotExecutable struct {
	ContentID string
	Reason    string
}

func (e *ErrNotExecutable) Error() string {
	return fmt.Sprintf("content not executable: %s: %s", e.ContentID, e.Reason)
}

type ErrIllegalTransition struct {
	From, To Lifecycle
	Reason   string
}

func (e *ErrIllegalTransition) Error() string {
	return fmt.Sprintf("illegal lifecycle transition %s -> %s: %s", e.From, e.To, e.Reason)
}
```

Create `orchestrator/internal/contentregistry/lifecycle.go`:

```go
package contentregistry

import "strings"

// IsHumanActor reports whether actor names a real user ("user:<id>").
func IsHumanActor(actor string) bool {
	return strings.HasPrefix(actor, "user:") && len(actor) > len("user:")
}

type transitionRule struct {
	from, to Lifecycle
	origin   Origin // "" = any origin
	human    bool
}

// transitionRules is the complete allowed-transition table (spec §4.3 +
// plan amendment 5). Anything not listed is illegal; REJECTED is terminal,
// RETIRED is terminal except LOCAL re-approval.
var transitionRules = []transitionRule{
	{LifecycleDraft, LifecycleValidating, "", false},
	{LifecycleValidating, LifecycleValidated, "", false},
	{LifecycleValidating, LifecycleDraft, "", false},
	{LifecycleValidated, LifecycleApproved, OriginVendor, true},
	{LifecycleApproved, LifecyclePublished, OriginVendor, true},
	{LifecycleValidated, LifecyclePublishedLocal, OriginLocal, true},
	{LifecycleDraft, LifecyclePublishedLocal, OriginLocal, true},
	{LifecycleRetired, LifecyclePublishedLocal, OriginLocal, true},
	{LifecycleDraft, LifecycleRejected, "", true},
	{LifecycleValidating, LifecycleRejected, "", true},
	{LifecycleValidated, LifecycleRejected, "", true},
	{LifecycleApproved, LifecycleRejected, "", true},
	{LifecyclePublished, LifecycleRetired, OriginVendor, true},
	{LifecyclePublishedLocal, LifecycleRetired, OriginLocal, true},
}

// CheckTransition validates one lifecycle move. It is the single
// application-level authority; the DB CHECKs independently block illegal
// resulting states.
func CheckTransition(origin Origin, trust Trust, from, to Lifecycle, actor string) error {
	for _, r := range transitionRules {
		if r.from != from || r.to != to {
			continue
		}
		if r.origin != "" && r.origin != origin {
			return &ErrIllegalTransition{From: from, To: to, Reason: "not allowed for " + string(origin) + " content"}
		}
		if r.human && !IsHumanActor(actor) {
			return &ErrIllegalTransition{From: from, To: to, Reason: "requires a human actor"}
		}
		if to == LifecyclePublished && trust != TrustVendorSigned {
			return &ErrIllegalTransition{From: from, To: to, Reason: "vendor signature not attached"}
		}
		return nil
	}
	return &ErrIllegalTransition{From: from, To: to, Reason: "transition not allowed"}
}

// TrustAfter is the trust a version holds after entering `to`. Only LOCAL
// publication changes trust; VENDOR_SIGNED is granted solely by verified
// intake or AttachVendorSignature, never by a transition.
func TrustAfter(origin Origin, current Trust, to Lifecycle) Trust {
	if origin == OriginLocal && to == LifecyclePublishedLocal {
		return TrustLocalTrusted
	}
	return current
}

// Executable is the runtime gate's combination rule (spec §6.1). devBuild
// must come from a compile-time property (integrity.Verifier.SigningEnabled
// of the compiled verifier), never from config.
func Executable(origin Origin, trust Trust, lc Lifecycle, devBuild bool) bool {
	switch {
	case origin == OriginVendor && trust == TrustVendorSigned && lc == LifecyclePublished:
		return true
	case origin == OriginLocal && trust == TrustLocalTrusted && lc == LifecyclePublishedLocal:
		return true
	case devBuild && origin == OriginVendor && trust == TrustUntrusted && lc == LifecyclePublished:
		return true
	}
	return false
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/contentregistry/ -run 'Executable|CheckTransition|TrustAfter|IsHuman' -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/contentregistry/
git commit -m "feat(tcf): content registry types and lifecycle state machine

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 4: Artifact analysis and the version store

**Files:**
- Create: `orchestrator/internal/contentregistry/analyze.go`, `analyze_test.go`
- Create: `orchestrator/internal/contentregistry/registry.go`
- Create: `orchestrator/internal/contentregistry/store.go`, `store_test.go`
- Create: `orchestrator/internal/contentregistry/testmain_test.go`

**Interfaces:**
- Consumes: Task 1 tables; Task 2 `integrity.Verifier`; Task 3 types.
- Produces:
  - `contentregistry.New(pool *pgxpool.Pool, v integrity.Verifier) *Registry`
  - `type Version struct { ID, ContentID string; Origin Origin; Number int; SHA256 string; Artifact, Signature []byte; Trust Trust; Lifecycle Lifecycle; Source IntakeSource; CreatedBy string; CreatedAt time.Time }`
  - `(Version).Parse() (*scenario.Scenario, error)` (sets `Scenario.Source = string(v.Source)`)
  - `(*Registry).LoadVersion(ctx, id string) (Version, error)` (`ErrVersionNotFound` when absent)
  - `(*Registry).ListVersions(ctx, contentID string) ([]Version, error)`, newest first
  - internal: `createVersion(ctx, newVersion) (id string, created bool, err error)`, `analyzeArtifact([]byte) (*analysis, error)`, `sha256Hex([]byte) string`, `(*Registry).audit(...)`

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/contentregistry/testmain_test.go`:

```go
package contentregistry

import (
	"os"
	"testing"

	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}
```

Create `orchestrator/internal/contentregistry/analyze_test.go`:

```go
package contentregistry

import "testing"

func TestAnalyze_TechniquesSortedDedupedUpper(t *testing.T) {
	a, err := analyzeArtifact([]byte(`id: x
name: X
art_techniques: [t1082, T1059.001]
steps:
  - name: s
    technique_id: T1082
    framework: custom
    command: whoami
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := a.techniqueIDs; len(got) != 2 || got[0] != "T1059.001" || got[1] != "T1082" {
		t.Fatalf("technique ids = %v", got)
	}
	if a.structural.outcome != "PASS" {
		t.Fatalf("structural = %+v", a.structural)
	}
}

func TestAnalyze_DynamicScopeAndStructuralFailures(t *testing.T) {
	a, err := analyzeArtifact([]byte("id: sweep\nname: S\nart_all_platform: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if a.dynamicScope != "art_all_platform" || len(a.techniqueIDs) != 0 {
		t.Fatalf("scope=%q ids=%v", a.dynamicScope, a.techniqueIDs)
	}
	if a.structural.outcome != "PASS" {
		t.Fatalf("art_all_platform is a real execution mode: %+v", a.structural)
	}
	bad, err := analyzeArtifact([]byte("id: bad\nart_techniques: [T10]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if bad.structural.outcome != "FAIL" {
		t.Fatalf("missing name + malformed technique must FAIL: %+v", bad.structural)
	}
}

func TestAnalyze_RejectsUnparseableAndMissingID(t *testing.T) {
	if _, err := analyzeArtifact([]byte("id: [unclosed")); err == nil {
		t.Fatal("unparseable YAML must error")
	}
	if _, err := analyzeArtifact([]byte("name: no id\n")); err == nil {
		t.Fatal("missing id must error")
	}
}

func TestAnalyze_SafetyWorstStepWins(t *testing.T) {
	a, err := analyzeArtifact([]byte(`id: s
name: S
steps:
  - {name: a, technique_id: T1082, framework: custom, command: x}
  - {name: b, technique_id: T9999, framework: custom, command: y}
`))
	if err != nil {
		t.Fatal(err)
	}
	// T9999 has no execclass entry -> fails closed to destructive.
	if a.safety.verdict != "destructive" {
		t.Fatalf("verdict = %s", a.safety.verdict)
	}
}
```

Create `orchestrator/internal/contentregistry/store_test.go`:

```go
package contentregistry

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

const yamlV1 = "id: store-sc\nname: Store\nlocal_check: true\n"
const yamlV2 = "id: store-sc\nname: Store v2\nlocal_check: true\n"

func mustAnalyze(t *testing.T, b string) *analysis {
	t.Helper()
	a, err := analyzeArtifact([]byte(b))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func localDraft(t *testing.T, art string) newVersion {
	return newVersion{contentID: "store-sc", origin: OriginLocal, source: SourceCustom, artifact: []byte(art),
		trust: TrustUntrusted, lifecycle: LifecycleDraft, actor: ActorIntake, analysis: mustAnalyze(t, art)}
}

func TestCreateVersion_IdempotentByHashAndIncrementing(t *testing.T) { // A2/A3 store half
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		id1, created, err := r.createVersion(ctx, localDraft(t, yamlV1))
		if err != nil || !created {
			t.Fatalf("v1: created=%v err=%v", created, err)
		}
		again, created, err := r.createVersion(ctx, localDraft(t, yamlV1))
		if err != nil || created || again != id1 {
			t.Fatalf("same bytes must be a no-op: id=%s created=%v err=%v", again, created, err)
		}
		id2, created, err := r.createVersion(ctx, localDraft(t, yamlV2))
		if err != nil || !created || id2 == id1 {
			t.Fatalf("v2: %v %v", created, err)
		}
		vs, err := r.ListVersions(ctx, "store-sc")
		if err != nil || len(vs) != 2 || vs[0].Number != 2 || vs[1].Number != 1 {
			t.Fatalf("list: %+v err=%v", vs, err)
		}
		v1, err := r.LoadVersion(ctx, id1)
		if err != nil || string(v1.Artifact) != yamlV1 || v1.SHA256 != sha256Hex([]byte(yamlV1)) {
			t.Fatalf("v1 must stay byte-identical: %q err=%v", v1.Artifact, err)
		}
		var events, structural, safety int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM content_version_events WHERE content_version_id=$1`, id1).Scan(&events)
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM content_validations WHERE content_version_id=$1 AND level='STRUCTURAL'`, id1).Scan(&structural)
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM content_safety_verdicts WHERE content_version_id=$1`, id1).Scan(&safety)
		if events != 1 || structural != 1 || safety != 1 {
			t.Fatalf("creation side rows: events=%d structural=%d safety=%d", events, structural, safety)
		}
	})
}

func TestCreateVersion_OriginCollision(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		if _, _, err := r.createVersion(ctx, localDraft(t, yamlV1)); err != nil {
			t.Fatal(err)
		}
		nv := localDraft(t, yamlV2)
		nv.origin, nv.source, nv.lifecycle = OriginVendor, SourceBuiltin, LifecyclePublished
		if _, _, err := r.createVersion(ctx, nv); err != ErrOriginCollision {
			t.Fatalf("want ErrOriginCollision, got %v", err)
		}
	})
}

func TestVersionParse_RestoresSource(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		id, _, err := r.createVersion(ctx, localDraft(t, yamlV1))
		if err != nil {
			t.Fatal(err)
		}
		v, _ := r.LoadVersion(ctx, id)
		sc, err := v.Parse()
		if err != nil || sc.ID != "store-sc" || sc.Source != "custom" {
			t.Fatalf("parse: %+v err=%v", sc, err)
		}
		if _, err := r.LoadVersion(ctx, "00000000-0000-0000-0000-000000000000"); err != ErrVersionNotFound {
			t.Fatalf("missing version: %v", err)
		}
	})
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/contentregistry/ -count=1 -p 1`
Expected: FAIL, `undefined: analyzeArtifact`, `undefined: New`.

- [ ] **Step 3: Implement**

Create `orchestrator/internal/contentregistry/analyze.go`:

```go
package contentregistry

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/audspect/bas/internal/scenario"
)

const (
	schemaVersion             = 1
	structuralValidator       = "contentregistry.structural"
	structuralValidatorVersion = "1"
	safetyClassifier          = "execclass"
	// safetyClassifierVersion must be bumped whenever scenario/execclass.go's
	// catalog changes meaningfully, so old verdicts stay attributable.
	safetyClassifierVersion = "1"
)

var (
	techniquePattern = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
	contentIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

type checkResult struct {
	outcome string // PASS | FAIL
	detail  map[string]any
}

type safetyResult struct {
	verdict string
	detail  []map[string]any
}

type analysis struct {
	sc           *scenario.Scenario
	contentID    string
	techniqueIDs []string
	supportedOS  []string
	dynamicScope string
	structural   checkResult
	safety       safetyResult
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// analyzeArtifact parses stored/intake bytes and derives everything the
// version row records. It never fails on content *quality* -- that becomes a
// STRUCTURAL FAIL row -- only on bytes that cannot identify a scenario.
func analyzeArtifact(raw []byte) (*analysis, error) {
	var sc scenario.Scenario
	if err := yaml.Unmarshal(raw, &sc); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if strings.TrimSpace(sc.ID) == "" {
		return nil, errors.New("missing required field 'id'")
	}
	a := &analysis{sc: &sc, contentID: sc.ID, supportedOS: append([]string{}, sc.SupportedOS...)}
	seen := map[string]bool{}
	add := func(id string) {
		id = strings.ToUpper(strings.TrimSpace(id))
		if id != "" && !seen[id] {
			seen[id] = true
			a.techniqueIDs = append(a.techniqueIDs, id)
		}
	}
	for _, st := range sc.Steps {
		add(st.TechniqueID)
	}
	for _, t := range sc.ARTTechniques {
		add(t)
	}
	sort.Strings(a.techniqueIDs)
	if a.techniqueIDs == nil {
		a.techniqueIDs = []string{}
	}
	a.dynamicScope = dynamicScope(&sc)
	a.structural = structuralCheck(&sc, a.techniqueIDs)
	a.safety = safetyVerdict(&sc, a.dynamicScope)
	return a, nil
}

// dynamicScope names modes whose executed steps are only known at dispatch.
func dynamicScope(sc *scenario.Scenario) string {
	switch {
	case sc.LocalCheck:
		return "local_check"
	case sc.CalderaAllWindows:
		return "caldera_all_windows"
	case sc.CalderaAdversaryID != "":
		return "caldera_adversary"
	case len(sc.CalderaAbilities) > 0:
		return "caldera_abilities"
	case sc.ARTAllWindows:
		return "art_all_windows"
	case sc.ARTAllPlatform:
		return "art_all_platform"
	case sc.ARTSelectiveWindows:
		return "art_selective_windows"
	case sc.ARTSelectivePlatform:
		return "art_selective_platform"
	}
	return ""
}

func hasExecutionMode(sc *scenario.Scenario) bool {
	return dynamicScope(sc) != "" || len(sc.ARTTechniques) > 0 || len(sc.Steps) > 0
}

func structuralCheck(sc *scenario.Scenario, techniqueIDs []string) checkResult {
	problems := []string{}
	if !contentIDPattern.MatchString(sc.ID) {
		problems = append(problems, "id is not a valid content id")
	}
	if strings.TrimSpace(sc.Name) == "" {
		problems = append(problems, "name is required")
	}
	for _, id := range techniqueIDs {
		if !techniquePattern.MatchString(id) {
			problems = append(problems, "malformed technique id "+id)
		}
	}
	if !hasExecutionMode(sc) {
		problems = append(problems, "no execution mode")
	}
	out := "PASS"
	if len(problems) > 0 {
		out = "FAIL"
	}
	return checkResult{outcome: out, detail: map[string]any{
		"problems": problems, "technique_ids_checked_against_catalog": false,
	}}
}

var classRank = map[scenario.ExecutionClass]int{
	scenario.ClassNonDestructive:         0,
	scenario.ClassPotentiallyDestructive: 1,
	scenario.ClassDestructive:            2,
}

// safetyVerdict stores execclass's native verdict (spec §4.6): worst static
// step wins; dynamically resolved steps are marked, never assumed safe or
// unsafe.
func safetyVerdict(sc *scenario.Scenario, scope string) safetyResult {
	worst := scenario.ClassNonDestructive
	detail := []map[string]any{}
	for _, st := range sc.Steps {
		c := scenario.ResolveExecutionClass(st.TechniqueID, st.ActionKey)
		detail = append(detail, map[string]any{
			"technique_id": st.TechniqueID, "action_key": st.ActionKey, "class": string(c.Class),
			"destructive_action": c.DestructiveAction, "blast_radius": c.BlastRadius,
		})
		if classRank[c.Class] > classRank[worst] {
			worst = c.Class
		}
	}
	switch {
	case scope != "":
		detail = append(detail, map[string]any{"dynamic": true, "mode": scope})
	case len(sc.ARTTechniques) > 0:
		detail = append(detail, map[string]any{"dynamic": true, "mode": "art_techniques"})
	}
	return safetyResult{verdict: string(worst), detail: detail}
}
```

Create `orchestrator/internal/contentregistry/registry.go`:

```go
package contentregistry

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/integrity"
)

// Refusal is one file intake refused since process start (inventory input).
type Refusal struct {
	Path      string    `json:"path"`
	ContentID string    `json:"contentId"`
	Reason    string    `json:"reason"`
	At        time.Time `json:"at"`
}

// Registry implements scenario.ContentRegistry against Postgres.
type Registry struct {
	pool     *pgxpool.Pool
	verifier integrity.Verifier

	mu       sync.Mutex
	refusals []Refusal
}

func New(pool *pgxpool.Pool, v integrity.Verifier) *Registry {
	return &Registry{pool: pool, verifier: v}
}

func (r *Registry) devBuild() bool { return !r.verifier.SigningEnabled() }

// NoteRefusal records an intake refusal for the migration inventory. Keeps
// the most recent 500.
func (r *Registry) NoteRefusal(path, contentID, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refusals = append(r.refusals, Refusal{Path: path, ContentID: contentID, Reason: reason, At: time.Now().UTC()})
	if len(r.refusals) > 500 {
		r.refusals = r.refusals[len(r.refusals)-500:]
	}
}

func (r *Registry) Refusals() []Refusal {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Refusal(nil), r.refusals...)
}

// audit writes an audit_logs row synchronously (registry events are rare and
// security-relevant; losing one to a fire-and-forget goroutine is not OK).
func (r *Registry) audit(ctx context.Context, action, resource string, detail map[string]any, outcome string) {
	b, _ := json.Marshal(detail)
	if _, err := r.pool.Exec(ctx,
		`INSERT INTO audit_logs (actor_id, action, resource, detail, ip, outcome) VALUES ('', $1, $2, $3, '', $4)`,
		action, resource, b, outcome); err != nil {
		log.Printf("[contentregistry] audit %s %s: %v", action, resource, err)
	}
}
```

Create `orchestrator/internal/contentregistry/store.go`:

```go
package contentregistry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"gopkg.in/yaml.v3"

	"github.com/audspect/bas/internal/scenario"
)

// Version is one immutable content version.
type Version struct {
	ID        string
	ContentID string
	Origin    Origin
	Number    int
	SHA256    string
	Artifact  []byte
	Signature []byte
	Trust     Trust
	Lifecycle Lifecycle
	Source    IntakeSource
	CreatedBy string
	CreatedAt time.Time
}

// Parse decodes the stored bytes -- never the disk file.
func (v Version) Parse() (*scenario.Scenario, error) {
	var sc scenario.Scenario
	if err := yaml.Unmarshal(v.Artifact, &sc); err != nil {
		return nil, fmt.Errorf("parse stored v%d of %s: %w", v.Number, v.ContentID, err)
	}
	sc.Source = string(v.Source)
	return &sc, nil
}

const versionCols = `id, content_id, origin, version, artifact_sha256, artifact_bytes, signature_bytes,
	trust_level, lifecycle, intake_source, created_by, created_at`

func scanVersion(row pgx.Row) (Version, error) {
	var v Version
	var origin, trust, lc, src string
	err := row.Scan(&v.ID, &v.ContentID, &origin, &v.Number, &v.SHA256, &v.Artifact, &v.Signature,
		&trust, &lc, &src, &v.CreatedBy, &v.CreatedAt)
	v.Origin, v.Trust, v.Lifecycle, v.Source = Origin(origin), Trust(trust), Lifecycle(lc), IntakeSource(src)
	return v, err
}

func (r *Registry) LoadVersion(ctx context.Context, id string) (Version, error) {
	v, err := scanVersion(r.pool.QueryRow(ctx, `SELECT `+versionCols+` FROM content_versions WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Version{}, ErrVersionNotFound
	}
	return v, err
}

// ListVersions returns every version of contentID, newest first.
func (r *Registry) ListVersions(ctx context.Context, contentID string) ([]Version, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+versionCols+` FROM content_versions WHERE content_id = $1 ORDER BY version DESC`, contentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Version
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

type sourceSnapshot struct {
	ref        SourceRef
	confidence string
	firstSeen  *time.Time
	lastSync   *time.Time
}

type newVersion struct {
	contentID     string
	origin        Origin
	source        IntakeSource
	artifact      []byte
	signature     []byte
	trust         Trust
	lifecycle     Lifecycle
	actor         string
	reason        string
	analysis      *analysis
	generation    map[string]any
	generationKey string
	sources       []sourceSnapshot
}

// createVersion inserts identity (if new), version, creation event,
// STRUCTURAL validation, safety verdict and source snapshots in ONE
// transaction. Identical bytes for the same content id return the existing
// version with created=false. Per-content advisory lock serializes
// concurrent intakes (Review Focus 2).
func (r *Registry) createVersion(ctx context.Context, nv newVersion) (string, bool, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return "", false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, nv.contentID); err != nil {
		return "", false, err
	}
	sum := sha256Hex(nv.artifact)
	var existing string
	err = tx.QueryRow(ctx, `SELECT id FROM content_versions WHERE content_id = $1 AND artifact_sha256 = $2`,
		nv.contentID, sum).Scan(&existing)
	if err == nil {
		return existing, false, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", false, err
	}

	var origin string
	err = tx.QueryRow(ctx, `SELECT origin FROM scenarios WHERE scenario_id = $1`, nv.contentID).Scan(&origin)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		_, err = tx.Exec(ctx,
			`INSERT INTO scenarios (scenario_id, name, category, origin, generation_key) VALUES ($1, $2, '', $3, NULLIF($4, ''))`,
			nv.contentID, nv.analysis.sc.Name, string(nv.origin), nv.generationKey)
	case err != nil:
		return "", false, err
	case Origin(origin) != nv.origin:
		return "", false, ErrOriginCollision
	default:
		_, err = tx.Exec(ctx,
			`UPDATE scenarios SET name = $2, updated_at = NOW(), generation_key = COALESCE(NULLIF($3, ''), generation_key) WHERE scenario_id = $1`,
			nv.contentID, nv.analysis.sc.Name, nv.generationKey)
	}
	if err != nil {
		return "", false, err
	}

	var next int
	if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) + 1 FROM content_versions WHERE content_id = $1`,
		nv.contentID).Scan(&next); err != nil {
		return "", false, err
	}
	gen := map[string]any{}
	for k, v := range nv.generation {
		gen[k] = v
	}
	if nv.analysis.dynamicScope != "" {
		gen["dynamic_scope"] = nv.analysis.dynamicScope
	}
	genJSON, _ := json.Marshal(gen)

	var vid string
	if err := tx.QueryRow(ctx,
		`INSERT INTO content_versions (content_id, origin, version, artifact_sha256, artifact_size, artifact_bytes,
		   signature_bytes, trust_level, lifecycle, intake_source, schema_version, technique_ids, supported_os,
		   generation, created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING id`,
		nv.contentID, string(nv.origin), next, sum, len(nv.artifact), nv.artifact, nv.signature,
		string(nv.trust), string(nv.lifecycle), string(nv.source), schemaVersion, nv.analysis.techniqueIDs,
		nonNil(nv.analysis.supportedOS), genJSON, nv.actor).Scan(&vid); err != nil {
		return "", false, err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO content_version_events (content_version_id, from_lifecycle, to_lifecycle, from_trust, to_trust, actor, reason)
		 VALUES ($1, NULL, $2, NULL, $3, $4, $5)`,
		vid, string(nv.lifecycle), string(nv.trust), nv.actor, nv.reason); err != nil {
		return "", false, err
	}

	structural := nv.analysis.structural
	if err := checkTechniqueCatalog(ctx, tx, nv.analysis.techniqueIDs, &structural); err != nil {
		return "", false, err
	}
	sdetail, _ := json.Marshal(structural.detail)
	if _, err := tx.Exec(ctx,
		`INSERT INTO content_validations (content_version_id, level, outcome, validator, validator_version, detail)
		 VALUES ($1, 'STRUCTURAL', $2, $3, $4, $5)`,
		vid, structural.outcome, structuralValidator, structuralValidatorVersion, sdetail); err != nil {
		return "", false, err
	}
	safety, _ := json.Marshal(nv.analysis.safety.detail)
	if _, err := tx.Exec(ctx,
		`INSERT INTO content_safety_verdicts (content_version_id, classifier, classifier_version, verdict, detail)
		 VALUES ($1, $2, $3, $4, $5)`,
		vid, safetyClassifier, safetyClassifierVersion, nv.analysis.safety.verdict, safety); err != nil {
		return "", false, err
	}
	for _, s := range nv.sources {
		if _, err := tx.Exec(ctx,
			`INSERT INTO content_version_sources (content_version_id, entity_type, entity_id, provider, external_id,
			   confidence_at_generation, first_seen_at_generation, last_sync_at_generation, role)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING`,
			vid, s.ref.EntityType, s.ref.EntityID, s.ref.Provider, s.ref.ExternalID, s.confidence,
			s.firstSeen, s.lastSync, s.ref.Role); err != nil {
			return "", false, err
		}
	}
	return vid, true, tx.Commit(ctx)
}

// checkTechniqueCatalog upgrades the structural check with an existence
// lookup when the ATT&CK catalog is populated; an empty catalog is recorded
// as "not checked", never as a pass or fail of the lookup.
func checkTechniqueCatalog(ctx context.Context, tx pgx.Tx, ids []string, res *checkResult) error {
	if len(ids) == 0 {
		return nil
	}
	var catalog int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM techniques`).Scan(&catalog); err != nil {
		return err
	}
	if catalog == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT technique_id FROM techniques WHERE technique_id = ANY($1)`, ids)
	if err != nil {
		return err
	}
	known := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		known[id] = true
	}
	rows.Close()
	problems, _ := res.detail["problems"].([]string)
	for _, id := range ids {
		if !known[id] {
			problems = append(problems, "unknown technique id "+id)
		}
	}
	res.detail["problems"] = problems
	res.detail["technique_ids_checked_against_catalog"] = true
	if len(problems) > 0 {
		res.outcome = "FAIL"
	}
	return nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
```

`SourceRef` is declared in Task 12 (`generated.go`). To keep this task compiling, create `generated.go` now with only the type:

```go
package contentregistry

// SourceRef names one intelligence entity a generated version derives from.
// EntityType: actor|campaign|malware|tool|technique_evidence. Role: primary|supporting.
type SourceRef struct {
	EntityType string
	EntityID   string
	Provider   string
	ExternalID string
	Role       string
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/contentregistry/ -count=1 -p 1`
Expected: PASS (Task 3 tests plus the new analyze/store tests).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/contentregistry/
git commit -m "feat(tcf): registry version store with structural and safety records

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 5: Intake, local approval, retirement

**Files:**
- Create: `orchestrator/internal/scenario/registry.go`
- Create: `orchestrator/internal/contentregistry/intake.go`, `intake_test.go`

**Interfaces:**
- Consumes: Task 4 `createVersion`, `ListVersions`, `LoadVersion`.
- Produces (in `scenario`):
  ```go
  type IntakeFile struct { Path, Source string; Artifact, Signature []byte; SignatureVerified bool }
  type IntakeDecision struct { Accepted bool; Reason string }
  type ExecutableVersion struct { VersionID, ContentID string; Version int; Origin, Trust, Lifecycle string; Scenario *Scenario }
  type ContentRegistry interface {
      Intake(ctx context.Context, f IntakeFile) (IntakeDecision, error)
      NoteRefusal(path, contentID, reason string)
      RegisterLocalApproved(ctx context.Context, contentID string, artifact []byte, actor string) error
      RetireExecutable(ctx context.Context, contentID, actor, reason string) error
      ResolveExecutable(ctx context.Context, contentID string) (ExecutableVersion, error)
  }
  var ErrNoRegistry error
  ```
- Produces (in `contentregistry`): `(*Registry).Intake`, `RegisterLocalApproved`, `RetireExecutable`, `MigrationDone(ctx) (bool, error)`, `Transition` (implemented here; Task 6 adds the gate on top).

- [ ] **Step 1: Write the scenario-side interface (no behavior, no test needed on its own)**

Create `orchestrator/internal/scenario/registry.go`:

```go
package scenario

import (
	"context"
	"errors"
)

// IntakeFile is one scenario YAML found on disk, handed to the content
// registry (TCF Phase 1 spec §5.1). Signature is the raw decoded RSA
// signature; SignatureVerified is true only after a real verification.
type IntakeFile struct {
	Path              string
	Source            string // builtin | custom | intel
	Artifact          []byte
	Signature         []byte
	SignatureVerified bool
}

type IntakeDecision struct {
	Accepted bool
	Reason   string
}

// ExecutableVersion is the runtime gate's answer: an immutable version that
// passed origin/trust/lifecycle checks, parsed from stored bytes.
type ExecutableVersion struct {
	VersionID string
	ContentID string
	Version   int
	Origin    string
	Trust     string
	Lifecycle string
	Scenario  *Scenario
}

// ContentRegistry is implemented by internal/contentregistry. Declared here
// so the engine can call it without an import cycle.
type ContentRegistry interface {
	Intake(ctx context.Context, f IntakeFile) (IntakeDecision, error)
	NoteRefusal(path, contentID, reason string)
	RegisterLocalApproved(ctx context.Context, contentID string, artifact []byte, actor string) error
	RetireExecutable(ctx context.Context, contentID, actor, reason string) error
	ResolveExecutable(ctx context.Context, contentID string) (ExecutableVersion, error)
}

// ErrNoRegistry is returned by Engine.ResolveExecutable when no registry is
// attached: fail closed, never fall back to the disk map.
var ErrNoRegistry = errors.New("content registry not attached")
```

- [ ] **Step 2: Write the failing intake tests**

Create `orchestrator/internal/contentregistry/intake_test.go`:

```go
package contentregistry

import (
	"context"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/testutil"
)

func latest(t *testing.T, r *Registry, id string) Version {
	t.Helper()
	vs, err := r.ListVersions(context.Background(), id)
	if err != nil || len(vs) == 0 {
		t.Fatalf("no versions for %s: %v", id, err)
	}
	return vs[0]
}

func file(src, body string) scenario.IntakeFile {
	return scenario.IntakeFile{Path: src + "/" + "x.yaml", Source: src, Artifact: []byte(body)}
}

func TestIntake_Matrix(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		signer := testutil.NewTestSigner(t)
		r := New(pool, signer.Verifier())

		vb := "id: vb\nname: VB\nlocal_check: true\n"
		f := file("builtin", vb)
		f.Signature, f.SignatureVerified = signer.Sign([]byte(vb)), true
		if d, err := r.Intake(ctx, f); err != nil || !d.Accepted {
			t.Fatalf("verified builtin: %+v %v", d, err)
		}
		if v := latest(t, r, "vb"); v.Origin != OriginVendor || v.Trust != TrustVendorSigned || v.Lifecycle != LifecyclePublished {
			t.Fatalf("verified builtin row: %+v", v)
		}

		ub := file("builtin", "id: ub\nname: UB\nlocal_check: true\n") // signing enabled, not verified
		if d, _ := r.Intake(ctx, ub); d.Accepted {
			t.Fatal("unverified builtin must be refused when signing is enabled")
		}

		if d, _ := r.Intake(ctx, file("intel", "id: in1\nname: In\nart_techniques: [T1082]\n")); !d.Accepted {
			t.Fatal("intel intake")
		}
		if v := latest(t, r, "in1"); v.Origin != OriginLocal || v.Trust != TrustUntrusted || v.Lifecycle != LifecycleDraft {
			t.Fatalf("intel row: %+v", v)
		}

		// Pre-migration custom file: grandfathered.
		if d, _ := r.Intake(ctx, file("custom", "id: cu1\nname: Cu\nlocal_check: true\n")); !d.Accepted {
			t.Fatal("custom intake")
		}
		v := latest(t, r, "cu1")
		if v.Trust != TrustLocalTrusted || v.Lifecycle != LifecyclePublishedLocal || v.CreatedBy != ActorMigration {
			t.Fatalf("grandfathered custom row: %+v", v)
		}
	})
}

func TestIntake_DevBuildBuiltinStaysUntrusted(t *testing.T) { // A6 (intake half)
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		r := New(pool, testutil.DevVerifier())
		if d, _ := r.Intake(context.Background(), file("builtin", "id: dv\nname: D\nlocal_check: true\n")); !d.Accepted {
			t.Fatal("dev builtin intake")
		}
		if v := latest(t, r, "dv"); v.Trust != TrustUntrusted || v.Lifecycle != LifecyclePublished {
			t.Fatalf("dev builtin must be UNTRUSTED/PUBLISHED: %+v", v)
		}
	})
}

func TestIntake_CustomAfterMigrationIsDraft(t *testing.T) { // plan amendment 2
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		if _, err := pool.Exec(ctx, `INSERT INTO content_registry_state (id) VALUES (1)`); err != nil {
			t.Fatal(err)
		}
		_, _ = r.Intake(ctx, file("custom", "id: cu2\nname: Cu\nlocal_check: true\n"))
		if v := latest(t, r, "cu2"); v.Lifecycle != LifecycleDraft || v.Trust != TrustUntrusted {
			t.Fatalf("post-migration out-of-band custom file must be DRAFT: %+v", v)
		}
	})
}

func TestIntake_LocalOutOfBandEditBecomesDraft(t *testing.T) { // A11
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		_, _ = pool.Exec(ctx, `INSERT INTO content_registry_state (id) VALUES (1)`)
		v1 := []byte("id: ob\nname: OB\nlocal_check: true\n")
		if err := r.RegisterLocalApproved(ctx, "ob", v1, "user:op"); err != nil {
			t.Fatal(err)
		}
		if d, _ := r.Intake(ctx, file("custom", string(v1))); !d.Accepted {
			t.Fatal("same bytes on disk must be a no-op accept")
		}
		_, _ = r.Intake(ctx, file("custom", "id: ob\nname: OB edited\nlocal_check: true\n"))
		vs, _ := r.ListVersions(ctx, "ob")
		if len(vs) != 2 || vs[0].Lifecycle != LifecycleDraft || vs[0].Trust != TrustUntrusted ||
			vs[1].Lifecycle != LifecyclePublishedLocal {
			t.Fatalf("versions: %+v", vs)
		}
	})
}

func TestIntake_CrossOriginCollisionRefused(t *testing.T) { // A12 (registry half)
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		_, _ = r.Intake(ctx, file("builtin", "id: col\nname: B\nlocal_check: true\n"))
		d, err := r.Intake(ctx, file("custom", "id: col\nname: C\nlocal_check: true\n"))
		if err != nil || d.Accepted {
			t.Fatalf("collision must be refused, not errored: %+v %v", d, err)
		}
		if v := latest(t, r, "col"); v.Origin != OriginVendor {
			t.Fatalf("builtin identity must survive: %+v", v)
		}
		var n int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action='content_registry.collision'`).Scan(&n)
		if n != 1 || len(r.Refusals()) != 1 {
			t.Fatalf("collision audit=%d refusals=%d", n, len(r.Refusals()))
		}
	})
}

func TestIntake_ConcurrentSameBytesOneVersion(t *testing.T) { // Review Focus 2
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = r.Intake(ctx, file("intel", "id: race\nname: R\nart_techniques: [T1082]\n"))
			}()
		}
		wg.Wait()
		if vs, _ := r.ListVersions(ctx, "race"); len(vs) != 1 {
			t.Fatalf("want 1 version, got %d", len(vs))
		}
	})
}

func TestRegisterLocalApproved_RecreateAfterRetire(t *testing.T) { // Review Focus 5
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		b := []byte("id: rr\nname: RR\nlocal_check: true\n")
		if err := r.RegisterLocalApproved(ctx, "rr", b, "user:op"); err != nil {
			t.Fatal(err)
		}
		if err := r.RetireExecutable(ctx, "rr", "user:op", "deleted"); err != nil {
			t.Fatal(err)
		}
		if v := latest(t, r, "rr"); v.Lifecycle != LifecycleRetired {
			t.Fatalf("retire: %+v", v)
		}
		if err := r.RegisterLocalApproved(ctx, "rr", b, "user:op2"); err != nil {
			t.Fatal(err)
		}
		vs, _ := r.ListVersions(ctx, "rr")
		if len(vs) != 1 || vs[0].Lifecycle != LifecyclePublishedLocal || vs[0].Trust != TrustLocalTrusted {
			t.Fatalf("re-approval: %+v", vs)
		}
	})
}

func TestRegisterLocalApproved_RequiresHumanActor(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		r := New(pool, testutil.DevVerifier())
		if err := r.RegisterLocalApproved(context.Background(), "h", []byte("id: h\nname: H\nlocal_check: true\n"), "intake"); err == nil {
			t.Fatal("non-human save must be rejected")
		}
	})
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/contentregistry/ -run 'Intake|RegisterLocal' -count=1 -p 1`
Expected: FAIL, `r.Intake undefined`.

- [ ] **Step 4: Implement**

Create `orchestrator/internal/contentregistry/intake.go`:

```go
package contentregistry

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/scenario"
)

// MigrationDone reports whether the one-time migration marker exists.
func (r *Registry) MigrationDone(ctx context.Context) (bool, error) {
	var done bool
	err := r.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM content_registry_state)`).Scan(&done)
	return done, err
}

func (r *Registry) versionByHash(ctx context.Context, contentID, sum string) (Version, bool, error) {
	v, err := scanVersion(r.pool.QueryRow(ctx,
		`SELECT `+versionCols+` FROM content_versions WHERE content_id = $1 AND artifact_sha256 = $2`, contentID, sum))
	if errors.Is(err, pgx.ErrNoRows) {
		return Version{}, false, nil
	}
	return v, err == nil, err
}

func (r *Registry) hasVersions(ctx context.Context, contentID string) (bool, error) {
	var ok bool
	err := r.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM content_versions WHERE content_id = $1)`, contentID).Scan(&ok)
	return ok, err
}

func (r *Registry) refuse(ctx context.Context, f scenario.IntakeFile, contentID, reason string) scenario.IntakeDecision {
	r.NoteRefusal(f.Path, contentID, reason)
	return scenario.IntakeDecision{Accepted: false, Reason: reason}
}

// Intake applies spec §5.1: origin/trust/lifecycle come from location and
// proof only, never from YAML fields. A returned error means infrastructure
// failure (the caller must treat the file as not executable); a refused
// decision means policy.
func (r *Registry) Intake(ctx context.Context, f scenario.IntakeFile) (scenario.IntakeDecision, error) {
	a, err := analyzeArtifact(f.Artifact)
	if err != nil {
		return r.refuse(ctx, f, "", err.Error()), nil
	}
	if _, hit, err := r.versionByHash(ctx, a.contentID, sha256Hex(f.Artifact)); err != nil {
		return scenario.IntakeDecision{}, err
	} else if hit {
		return scenario.IntakeDecision{Accepted: true}, nil
	}

	nv := newVersion{contentID: a.contentID, artifact: f.Artifact, analysis: a, actor: ActorIntake, source: IntakeSource(f.Source)}
	switch IntakeSource(f.Source) {
	case SourceBuiltin:
		nv.origin, nv.lifecycle = OriginVendor, LifecyclePublished
		switch {
		case f.SignatureVerified:
			nv.trust, nv.signature = TrustVendorSigned, f.Signature
		case r.devBuild():
			nv.trust = TrustUntrusted
		default:
			return r.refuse(ctx, f, a.contentID, "builtin signature not verified"), nil
		}
	case SourceIntel:
		nv.origin, nv.trust, nv.lifecycle, nv.actor = OriginLocal, TrustUntrusted, LifecycleDraft, ActorGenerator
	case SourceCustom:
		nv.origin = OriginLocal
		done, err := r.MigrationDone(ctx)
		if err != nil {
			return scenario.IntakeDecision{}, err
		}
		has, err := r.hasVersions(ctx, a.contentID)
		if err != nil {
			return scenario.IntakeDecision{}, err
		}
		if !done && !has {
			nv.trust, nv.lifecycle, nv.actor, nv.reason = TrustLocalTrusted, LifecyclePublishedLocal, ActorMigration, MigrationReason
		} else {
			nv.trust, nv.lifecycle, nv.reason = TrustUntrusted, LifecycleDraft, "changed outside the operator UI"
		}
	default:
		return scenario.IntakeDecision{}, fmt.Errorf("unknown intake source %q", f.Source)
	}

	if _, _, err := r.createVersion(ctx, nv); err != nil {
		if errors.Is(err, ErrOriginCollision) {
			r.audit(ctx, "content_registry.collision", a.contentID,
				map[string]any{"path": f.Path, "attempted_origin": string(nv.origin)}, "denied")
			return r.refuse(ctx, f, a.contentID, "content id already registered with a different origin"), nil
		}
		return scenario.IntakeDecision{}, err
	}
	return scenario.IntakeDecision{Accepted: true}, nil
}

// RegisterLocalApproved is the UI save path: an explicit operator action
// that approves exactly these bytes for local execution.
func (r *Registry) RegisterLocalApproved(ctx context.Context, contentID string, artifact []byte, actor string) error {
	if !IsHumanActor(actor) {
		return fmt.Errorf("local approval requires a human actor, got %q", actor)
	}
	a, err := analyzeArtifact(artifact)
	if err != nil {
		return err
	}
	if a.contentID != contentID {
		return fmt.Errorf("artifact id %q does not match %q", a.contentID, contentID)
	}
	v, hit, err := r.versionByHash(ctx, contentID, sha256Hex(artifact))
	if err != nil {
		return err
	}
	if hit {
		if v.Lifecycle == LifecyclePublishedLocal {
			return nil
		}
		return r.Transition(ctx, v.ID, LifecyclePublishedLocal, actor, "operator save")
	}
	_, _, err = r.createVersion(ctx, newVersion{contentID: contentID, origin: OriginLocal, source: SourceCustom,
		artifact: artifact, trust: TrustLocalTrusted, lifecycle: LifecyclePublishedLocal, actor: actor,
		reason: "operator save", analysis: a})
	return err
}

// RetireExecutable retires every PUBLISHED / PUBLISHED_LOCAL version.
func (r *Registry) RetireExecutable(ctx context.Context, contentID, actor, reason string) error {
	vs, err := r.ListVersions(ctx, contentID)
	if err != nil {
		return err
	}
	for _, v := range vs {
		if v.Lifecycle == LifecyclePublished || v.Lifecycle == LifecyclePublishedLocal {
			if err := r.Transition(ctx, v.ID, LifecycleRetired, actor, reason); err != nil {
				return err
			}
		}
	}
	return nil
}

// Transition moves one version through the state machine, writing the
// update and its event in one transaction.
func (r *Registry) Transition(ctx context.Context, versionID string, to Lifecycle, actor, reason string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var origin, trust, lc string
	err = tx.QueryRow(ctx, `SELECT origin, trust_level, lifecycle FROM content_versions WHERE id = $1 FOR UPDATE`,
		versionID).Scan(&origin, &trust, &lc)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrVersionNotFound
	}
	if err != nil {
		return err
	}
	if err := CheckTransition(Origin(origin), Trust(trust), Lifecycle(lc), to, actor); err != nil {
		return err
	}
	newTrust := TrustAfter(Origin(origin), Trust(trust), to)
	if _, err := tx.Exec(ctx, `UPDATE content_versions SET lifecycle = $2, trust_level = $3 WHERE id = $1`,
		versionID, string(to), string(newTrust)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO content_version_events (content_version_id, from_lifecycle, to_lifecycle, from_trust, to_trust, actor, reason)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		versionID, lc, string(to), trust, string(newTrust), actor, reason); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
```

`*Registry` doesn't satisfy `scenario.ContentRegistry` until Task 6 adds `ResolveExecutable`. Don't add the compile-time assertion yet.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/contentregistry/ -count=1 -p 1`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/scenario/registry.go orchestrator/internal/contentregistry/
git commit -m "feat(tcf): registry intake, local approval, retirement

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 6: Runtime gate and vendor signature attachment

**Files:**
- Create: `orchestrator/internal/contentregistry/gate.go`, `gate_test.go`

**Interfaces:**
- Consumes: Tasks 3–5.
- Produces: `(*Registry).ResolveExecutable(ctx, contentID string) (scenario.ExecutableVersion, error)`; `(*Registry).AttachVendorSignature(ctx, versionID string, sig []byte, actor string) error`; compile-time assertion `var _ scenario.ContentRegistry = (*Registry)(nil)`.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/contentregistry/gate_test.go`:

```go
package contentregistry

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/testutil"
)

func TestResolveExecutable_GateMatrixAgainstDB(t *testing.T) { // A5
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		signer := testutil.NewTestSigner(t)
		for _, dev := range []bool{false, true} {
			r := New(pool, signer.Verifier())
			if dev {
				r = New(pool, testutil.DevVerifier())
			}
			n := 0
			for _, o := range allOrigins {
				for _, tr := range allTrusts {
					for _, lc := range allLifecycles {
						n++
						id := map[bool]string{false: "p", true: "d"}[dev] + "-" + string(rune('a'+n%26)) + itoa(n)
						art := []byte("id: " + id + "\nname: G\nlocal_check: true\n")
						var sig []byte
						if tr == TrustVendorSigned {
							sig = signer.Sign(art)
						}
						src := map[Origin]IntakeSource{OriginVendor: SourceBuiltin, OriginLocal: SourceCustom}[o]
						nv := newVersion{contentID: id, origin: o, source: src, artifact: art, signature: sig, trust: tr,
							lifecycle: lc, actor: ActorMigration, analysis: mustAnalyze(t, string(art))}
						if _, _, err := r.createVersion(ctx, nv); err != nil {
							continue // illegal combination rejected by DB (covered by A4)
						}
						_, err := r.ResolveExecutable(ctx, id)
						if got, want := err == nil, Executable(o, tr, lc, dev); got != want {
							t.Errorf("dev=%v %s/%s/%s: runnable=%v want %v (err=%v)", dev, o, tr, lc, got, want, err)
						}
					}
				}
			}
		}
	})
}

func itoa(i int) string { return string([]byte{byte('0' + i/100%10), byte('0' + i/10%10), byte('0' + i%10)}) }

func TestResolveExecutable_DraftDoesNotDisplacePublished(t *testing.T) { // A7
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		v1 := []byte("id: dd\nname: V1\nlocal_check: true\n")
		if err := r.RegisterLocalApproved(ctx, "dd", v1, "user:op"); err != nil {
			t.Fatal(err)
		}
		_, _ = pool.Exec(ctx, `INSERT INTO content_registry_state (id) VALUES (1)`)
		_, _ = r.Intake(ctx, scenario.IntakeFile{Path: "custom/dd.yaml", Source: "custom", Artifact: []byte("id: dd\nname: V2\nlocal_check: true\n")})
		ev, err := r.ResolveExecutable(ctx, "dd")
		if err != nil || ev.Version != 1 || ev.Scenario.Name != "V1" {
			t.Fatalf("want v1 from stored bytes, got %+v err=%v", ev, err)
		}
	})
}

func TestResolveExecutable_DenialReasons(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		_, err := r.ResolveExecutable(ctx, "nope")
		var ne *ErrNotExecutable
		if !errors.As(err, &ne) || ne.Reason != "not registered" {
			t.Fatalf("unregistered: %v", err)
		}
		_, _ = r.Intake(ctx, scenario.IntakeFile{Path: "intel/i.yaml", Source: "intel", Artifact: []byte("id: idr\nname: I\nart_techniques: [T1082]\n")})
		_, err = r.ResolveExecutable(ctx, "idr")
		if !errors.As(err, &ne) || ne.Reason != "no executable version; latest v1 is DRAFT/UNTRUSTED" {
			t.Fatalf("draft: %v", err)
		}
	})
}

func TestGateReverifiesVendorSignature(t *testing.T) { // A19
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		signer := testutil.NewTestSigner(t)
		r := New(pool, signer.Verifier())
		art := []byte("id: tv\nname: T\nlocal_check: true\n")
		if _, err := r.Intake(ctx, scenario.IntakeFile{Path: "tv.yaml", Source: "builtin", Artifact: art,
			Signature: signer.Sign(art), SignatureVerified: true}); err != nil {
			t.Fatal(err)
		}
		if _, err := r.ResolveExecutable(ctx, "tv"); err != nil {
			t.Fatalf("intact: %v", err)
		}
		// Superuser tamper of the stored bytes (keep size consistent with the CHECK).
		tampered := []byte("id: tv\nname: X\nlocal_check: true\n")
		if _, err := pool.Exec(ctx, `UPDATE content_versions SET artifact_bytes=$1, artifact_size=$2 WHERE content_id='tv'`,
			tampered, len(tampered)); err != nil {
			t.Fatal(err)
		}
		if _, err := r.ResolveExecutable(ctx, "tv"); err == nil {
			t.Fatal("tampered vendor content must be denied")
		}
		var n int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action='content_registry.tamper'`).Scan(&n)
		if n != 1 {
			t.Fatalf("tamper audit rows = %d", n)
		}
	})
}

func TestAttachVendorSignature(t *testing.T) { // A18
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		signer := testutil.NewTestSigner(t)
		r := New(pool, signer.Verifier())
		art := []byte("id: vf\nname: VF\nlocal_check: true\n")
		id, _, err := r.createVersion(ctx, newVersion{contentID: "vf", origin: OriginVendor, source: SourceBuiltin,
			artifact: art, trust: TrustUntrusted, lifecycle: LifecycleDraft, actor: "user:research", analysis: mustAnalyze(t, string(art))})
		if err != nil {
			t.Fatal(err)
		}
		for _, to := range []Lifecycle{LifecycleValidating, LifecycleValidated, LifecycleApproved} {
			if err := r.Transition(ctx, id, to, "user:research", ""); err != nil {
				t.Fatalf("-> %s: %v", to, err)
			}
		}
		if err := r.Transition(ctx, id, LifecyclePublished, "user:research", ""); err == nil {
			t.Fatal("publish before signature must fail")
		}
		if err := r.AttachVendorSignature(ctx, id, []byte("garbage"), "user:research"); err == nil {
			t.Fatal("invalid signature must fail")
		}
		if err := r.AttachVendorSignature(ctx, id, signer.Sign(art), "user:research"); err != nil {
			t.Fatalf("valid signature: %v", err)
		}
		if err := r.AttachVendorSignature(ctx, id, signer.Sign(art), "user:research"); err == nil {
			t.Fatal("second attach must fail (signature already set)")
		}
		if err := r.Transition(ctx, id, LifecyclePublished, "user:research", ""); err != nil {
			t.Fatalf("publish after signature: %v", err)
		}
		if _, err := r.ResolveExecutable(ctx, "vf"); err != nil {
			t.Fatalf("published vendor content must run: %v", err)
		}
		// LOCAL content can never receive a vendor signature.
		la := []byte("id: lf\nname: LF\nlocal_check: true\n")
		lid, _, _ := r.createVersion(ctx, newVersion{contentID: "lf", origin: OriginLocal, source: SourceCustom,
			artifact: la, trust: TrustUntrusted, lifecycle: LifecycleDraft, actor: ActorIntake, analysis: mustAnalyze(t, string(la))})
		if err := r.AttachVendorSignature(ctx, lid, signer.Sign(la), "user:research"); err == nil {
			t.Fatal("LOCAL content must be refused")
		}
	})
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/contentregistry/ -run 'ResolveExecutable|Reverifies|AttachVendor' -count=1 -p 1`
Expected: FAIL, `r.ResolveExecutable undefined`.

- [ ] **Step 3: Implement**

Create `orchestrator/internal/contentregistry/gate.go`:

```go
package contentregistry

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/scenario"
)

var _ scenario.ContentRegistry = (*Registry)(nil)

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// ResolveExecutable is the single authoritative execution boundary (spec
// §6.1): the highest version passing the gate, parsed from stored bytes.
// VENDOR_SIGNED versions are re-verified on every resolution; a failure
// denies (it never falls through to an older version) and audits a tamper.
func (r *Registry) ResolveExecutable(ctx context.Context, contentID string) (scenario.ExecutableVersion, error) {
	versions, err := r.ListVersions(ctx, contentID)
	if err != nil {
		return scenario.ExecutableVersion{}, fmt.Errorf("content registry unavailable: %w", err)
	}
	if len(versions) == 0 {
		return scenario.ExecutableVersion{}, &ErrNotExecutable{ContentID: contentID, Reason: "not registered"}
	}
	for _, v := range versions {
		if !Executable(v.Origin, v.Trust, v.Lifecycle, r.devBuild()) {
			continue
		}
		if v.Trust == TrustVendorSigned {
			ok, verr := r.verifier.Verify(v.Artifact, v.Signature)
			if !ok || verr != nil {
				r.audit(ctx, "content_registry.tamper", v.ID, map[string]any{
					"content_id": contentID, "version": v.Number, "error": errString(verr)}, "denied")
				return scenario.ExecutableVersion{}, &ErrNotExecutable{ContentID: contentID,
					Reason: fmt.Sprintf("signature re-verification failed for v%d", v.Number)}
			}
		}
		sc, perr := v.Parse()
		if perr != nil {
			return scenario.ExecutableVersion{}, &ErrNotExecutable{ContentID: contentID,
				Reason: fmt.Sprintf("v%d artifact unreadable: %v", v.Number, perr)}
		}
		return scenario.ExecutableVersion{VersionID: v.ID, ContentID: v.ContentID, Version: v.Number,
			Origin: string(v.Origin), Trust: string(v.Trust), Lifecycle: string(v.Lifecycle), Scenario: sc}, nil
	}
	l := versions[0]
	return scenario.ExecutableVersion{}, &ErrNotExecutable{ContentID: contentID,
		Reason: fmt.Sprintf("no executable version; latest v%d is %s/%s", l.Number, l.Lifecycle, l.Trust)}
}

// AttachVendorSignature is the ONLY writer of signature_bytes and the only
// non-declarative registry invariant (spec §4.2): NULL-only, VENDOR-only,
// verified against the immutable stored bytes, trust set atomically.
func (r *Registry) AttachVendorSignature(ctx context.Context, versionID string, sig []byte, actor string) error {
	if !IsHumanActor(actor) {
		return fmt.Errorf("signature attachment requires a human actor")
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var origin, trust, lc string
	var art, existing []byte
	err = tx.QueryRow(ctx,
		`SELECT origin, trust_level, lifecycle, artifact_bytes, signature_bytes FROM content_versions WHERE id = $1 FOR UPDATE`,
		versionID).Scan(&origin, &trust, &lc, &art, &existing)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrVersionNotFound
	}
	if err != nil {
		return err
	}
	if Origin(origin) != OriginVendor {
		return fmt.Errorf("only VENDOR content can carry a vendor signature")
	}
	if existing != nil {
		return fmt.Errorf("signature already attached")
	}
	ok, verr := r.verifier.Verify(art, sig)
	if !ok || verr != nil {
		return fmt.Errorf("signature does not verify against stored artifact: %v", verr)
	}
	if _, err := tx.Exec(ctx, `UPDATE content_versions SET signature_bytes = $2, trust_level = 'VENDOR_SIGNED' WHERE id = $1`,
		versionID, sig); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO content_version_events (content_version_id, from_lifecycle, to_lifecycle, from_trust, to_trust, actor, reason)
		 VALUES ($1, $2, $2, $3, 'VENDOR_SIGNED', $4, 'vendor signature attached')`,
		versionID, lc, trust, actor); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/contentregistry/ -count=1 -p 1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/contentregistry/
git commit -m "feat(tcf): fail-closed runtime gate with signature re-verification

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 7: Engine integration — ordered intake, gated resolution, approving save, retiring delete

**Files:**
- Modify: `orchestrator/internal/scenario/engine.go` (struct `:28-32`, `NewEngine :35`, `Load :46-95`, `Save :176-204`, `Delete :210+`)
- Create: `orchestrator/internal/scenario/engine_registry_test.go`
- Modify: every caller of `Engine.Save` / `Engine.Delete` (23 sites: `grep -rn "\.Save(" --include=*.go orchestrator/internal | grep -v "func (e"`)

**Interfaces:**
- Consumes: Task 2 `integrity.Verifier`, `integrity.ReadBuiltinSignature`; Task 5 `ContentRegistry`.
- Produces: `(*Engine).AttachRegistry(ContentRegistry)`, `(*Engine).Registry() ContentRegistry`, `(*Engine).SetVerifier(integrity.Verifier)`, `(*Engine).ResolveExecutable(ctx, id string) (ExecutableVersion, error)`, `(*Engine).SaveAs(ctx, s *Scenario, actor string) error` (**replaces `Save`**), `(*Engine).DeleteAs(ctx, id, actor string) error` (**replaces `Delete`**).

- [ ] **Step 1: Write the failing tests (fake registry, no DB)**

Create `orchestrator/internal/scenario/engine_registry_test.go`:

```go
package scenario

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type fakeRegistry struct {
	order       []string // "source:id" in intake order
	refuseIDs   map[string]bool
	errIDs      map[string]bool
	approved    map[string]string // id -> actor
	retired     map[string]string
	approveErr  error
}

func newFake() *fakeRegistry {
	return &fakeRegistry{refuseIDs: map[string]bool{}, errIDs: map[string]bool{}, approved: map[string]string{}, retired: map[string]string{}}
}

func idOf(b []byte) string {
	var s Scenario
	_ = yamlUnmarshal(b, &s)
	return s.ID
}

func (f *fakeRegistry) Intake(_ context.Context, in IntakeFile) (IntakeDecision, error) {
	id := idOf(in.Artifact)
	f.order = append(f.order, in.Source+":"+id)
	if f.errIDs[id] {
		return IntakeDecision{}, errors.New("db down")
	}
	if f.refuseIDs[id] {
		return IntakeDecision{Accepted: false, Reason: "refused"}, nil
	}
	return IntakeDecision{Accepted: true}, nil
}
func (f *fakeRegistry) NoteRefusal(string, string, string) {}
func (f *fakeRegistry) RegisterLocalApproved(_ context.Context, id string, _ []byte, actor string) error {
	if f.approveErr != nil {
		return f.approveErr
	}
	f.approved[id] = actor
	return nil
}
func (f *fakeRegistry) RetireExecutable(_ context.Context, id, actor, _ string) error {
	f.retired[id] = actor
	return nil
}
func (f *fakeRegistry) ResolveExecutable(_ context.Context, id string) (ExecutableVersion, error) {
	return ExecutableVersion{ContentID: id, VersionID: "v-" + id, Version: 1, Scenario: &Scenario{ID: id}}, nil
}

type devV struct{}

func (devV) Verify([]byte, []byte) (bool, error) { return false, nil }
func (devV) SigningEnabled() bool               { return false }

func write(t *testing.T, dir, rel, body string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoad_IntakesBuiltinBeforeCustomBeforeIntel(t *testing.T) { // plan amendment 6 / A12 ordering
	dir := t.TempDir()
	write(t, dir, "zzz-builtin.yaml", "id: lolbin\nname: B\nlocal_check: true\n")
	write(t, dir, "custom/lolbin.yaml", "id: lolbin-c\nname: C\nlocal_check: true\n")
	write(t, dir, "intel/intel-1.yaml", "id: intel-1\nname: I\nart_techniques: [T1082]\n")
	e := NewEngine(dir)
	e.SetVerifier(devV{})
	f := newFake()
	e.AttachRegistry(f)
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	want := []string{"builtin:lolbin", "custom:lolbin-c", "intel:intel-1"}
	if len(f.order) != 3 || f.order[0] != want[0] || f.order[1] != want[1] || f.order[2] != want[2] {
		t.Fatalf("intake order = %v, want %v", f.order, want)
	}
}

func TestLoad_RefusedFileNotInMap(t *testing.T) { // A12 engine half
	dir := t.TempDir()
	write(t, dir, "apt.yaml", "id: apt\nname: B\nlocal_check: true\n")
	write(t, dir, "custom/apt.yaml", "id: apt\nname: shadow\nlocal_check: true\n")
	e := NewEngine(dir)
	e.SetVerifier(devV{})
	f := newFake()
	e.AttachRegistry(f)
	// The second intake of "apt" (the custom one) is refused by the registry.
	calls := 0
	f2 := &countingRefuser{fakeRegistry: f, refuseAfter: 1, calls: &calls}
	e.AttachRegistry(f2)
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	sc, ok := e.Get("apt")
	if !ok || sc.Name != "B" || sc.Source != "builtin" {
		t.Fatalf("builtin must keep the map slot: %+v", sc)
	}
}

type countingRefuser struct {
	*fakeRegistry
	refuseAfter int
	calls       *int
}

func (c *countingRefuser) Intake(ctx context.Context, in IntakeFile) (IntakeDecision, error) {
	*c.calls++
	if *c.calls > c.refuseAfter {
		return IntakeDecision{Accepted: false, Reason: "collision"}, nil
	}
	return c.fakeRegistry.Intake(ctx, in)
}

func TestLoad_IntakeErrorKeepsLoadingAndDoesNotExecute(t *testing.T) { // Review Focus 4
	dir := t.TempDir()
	write(t, dir, "custom/a.yaml", "id: a\nname: A\nlocal_check: true\n")
	write(t, dir, "custom/b.yaml", "id: b\nname: B\nlocal_check: true\n")
	e := NewEngine(dir)
	e.SetVerifier(devV{})
	f := newFake()
	f.errIDs["a"] = true
	e.AttachRegistry(f)
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.Get("a"); ok {
		t.Fatal("a file whose intake errored must not be listed as loaded")
	}
	if _, ok := e.Get("b"); !ok {
		t.Fatal("load must continue past one intake error")
	}
}

func TestResolveExecutable_NoRegistryFailsClosed(t *testing.T) {
	e := NewEngine(t.TempDir())
	if _, err := e.ResolveExecutable(context.Background(), "x"); !errors.Is(err, ErrNoRegistry) {
		t.Fatalf("want ErrNoRegistry, got %v", err)
	}
}

func TestSaveAs_ApprovesAndRestoresOnFailure(t *testing.T) {
	dir := t.TempDir()
	e := NewEngine(dir)
	f := newFake()
	e.AttachRegistry(f)
	sc := &Scenario{ID: "sv", Name: "S", LocalCheck: true}
	if err := e.SaveAs(context.Background(), sc, "user:op"); err != nil {
		t.Fatal(err)
	}
	if f.approved["sv"] != "user:op" {
		t.Fatalf("approval actor = %q", f.approved["sv"])
	}
	before, _ := os.ReadFile(filepath.Join(dir, "custom", "sv.yaml"))
	f.approveErr = errors.New("db down")
	if err := e.SaveAs(context.Background(), &Scenario{ID: "sv", Name: "changed", LocalCheck: true}, "user:op"); err == nil {
		t.Fatal("registry failure must fail the save")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "custom", "sv.yaml"))
	if string(before) != string(after) {
		t.Fatal("failed save must restore the previous file")
	}
	if got, _ := e.Get("sv"); got.Name != "S" {
		t.Fatalf("map must keep the previous scenario, got %q", got.Name)
	}
}

func TestDeleteAs_RetiresBeforeRemovingFile(t *testing.T) {
	dir := t.TempDir()
	e := NewEngine(dir)
	f := newFake()
	e.AttachRegistry(f)
	_ = e.SaveAs(context.Background(), &Scenario{ID: "dl", Name: "D", LocalCheck: true}, "user:op")
	if err := e.DeleteAs(context.Background(), "dl", "user:op"); err != nil {
		t.Fatal(err)
	}
	if f.retired["dl"] != "user:op" {
		t.Fatal("delete must retire executable versions")
	}
	if _, err := os.Stat(filepath.Join(dir, "custom", "dl.yaml")); !os.IsNotExist(err) {
		t.Fatal("file must be removed")
	}
}
```

Add a one-line helper at the bottom of `engine.go` so tests can unmarshal without importing yaml themselves: `func yamlUnmarshal(b []byte, v any) error { return yaml.Unmarshal(b, v) }`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/scenario/ -run 'Load_|ResolveExecutable|SaveAs|DeleteAs' -count=1`
Expected: FAIL, `e.SetVerifier undefined`.

- [ ] **Step 3: Implement the engine changes**

In `engine.go`, replace the `Engine` struct and `NewEngine`:

```go
type Engine struct {
	dir       string
	scenarios map[string]*Scenario
	profiles  map[string]*DetectionProfile
	// registry is the TCF Content Registry. nil => nothing is executable
	// (ResolveExecutable fails closed); the disk map still serves authoring.
	registry ContentRegistry
	verifier integrity.Verifier
}

func NewEngine(dir string) *Engine {
	return &Engine{
		dir:       dir,
		scenarios: make(map[string]*Scenario),
		profiles:  make(map[string]*DetectionProfile),
		verifier:  integrity.CompiledVerifier{},
	}
}

func (e *Engine) AttachRegistry(r ContentRegistry) { e.registry = r }
func (e *Engine) Registry() ContentRegistry       { return e.registry }
func (e *Engine) SetVerifier(v integrity.Verifier) { e.verifier = v }

// ResolveExecutable is the only way callers may obtain a scenario to run.
func (e *Engine) ResolveExecutable(ctx context.Context, id string) (ExecutableVersion, error) {
	if e.registry == nil {
		return ExecutableVersion{}, ErrNoRegistry
	}
	return e.registry.ResolveExecutable(ctx, id)
}
```

Replace `Load` with a two-phase version: collect, sort by source rank, then intake.

```go
type loadedFile struct {
	path   string
	source string
	bytes  []byte
	sc     *Scenario
}

var sourceRank = map[string]int{"builtin": 0, "custom": 1, "intel": 2}

// Load reads all *.yaml files. With a registry attached, every file is
// handed to intake in builtin -> custom -> intel order (so first
// registration can never let a custom file claim a builtin identity); a
// refused or errored file is left out of the map. A bad file never blocks
// the rest.
func (e *Engine) Load() error {
	e.scenarios = make(map[string]*Scenario)
	e.loadProfiles()
	var files []loadedFile
	err := filepath.WalkDir(e.dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == profilesSubdir {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".yaml" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			log.Printf("[!] scenario: read %s: %v — skipping", path, err)
			return nil
		}
		var s Scenario
		if err := yaml.Unmarshal(b, &s); err != nil {
			log.Printf("[!] scenario: parse %s: %v — skipping", path, err)
			return nil
		}
		if s.ID == "" {
			log.Printf("[!] scenario: %s missing required field 'id' — skipping", path)
			return nil
		}
		s.Source = e.sourceForPath(path)
		files = append(files, loadedFile{path: path, source: s.Source, bytes: b, sc: &s})
		return nil
	})
	if err != nil {
		return err
	}
	sort.SliceStable(files, func(i, j int) bool { return sourceRank[files[i].source] < sourceRank[files[j].source] })

	ctx := context.Background()
	for _, f := range files {
		var sig []byte
		var verified bool
		if f.source == "builtin" {
			s, ok, verr := integrity.ReadBuiltinSignature(e.verifier, f.path, f.bytes)
			if verr != nil {
				log.Printf("[!] TAMPER ALERT: builtin scenario %s failed signature verification: %v — refusing to load", f.path, verr)
				if e.registry != nil {
					e.registry.NoteRefusal(f.path, f.sc.ID, verr.Error())
				}
				continue
			}
			sig, verified = s, ok
		}
		if e.registry != nil {
			d, ierr := e.registry.Intake(ctx, IntakeFile{Path: f.path, Source: f.source, Artifact: f.bytes,
				Signature: sig, SignatureVerified: verified})
			if ierr != nil {
				log.Printf("[!] content registry intake %s: %v — not loaded", f.path, ierr)
				continue
			}
			if !d.Accepted {
				log.Printf("[!] content registry refused %s: %s", f.path, d.Reason)
				continue
			}
		}
		if _, dup := e.scenarios[f.sc.ID]; dup && e.registry == nil {
			log.Printf("[!] scenario: duplicate id %s at %s — keeping the first (higher-precedence) file", f.sc.ID, f.path)
			continue
		}
		e.scenarios[f.sc.ID] = f.sc
	}
	return nil
}
```

Add `"context"` to the imports. Replace `Save` with `SaveAs`:

```go
// SaveAs validates a scenario, writes scenarios/custom/<id>.yaml and -- with
// a registry attached -- registers exactly those bytes as an operator-approved
// PUBLISHED_LOCAL version (spec §5.1 "UI save path"). If registration fails
// the previous file is restored and the map is unchanged.
func (e *Engine) SaveAs(ctx context.Context, s *Scenario, actor string) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if existing, ok := e.scenarios[s.ID]; ok && existing.Source != "custom" {
		return fmt.Errorf("scenario %q is %s and cannot be overwritten — clone it to a new ID instead", s.ID, existing.Source)
	}
	customDir := filepath.Join(e.dir, "custom")
	if err := os.MkdirAll(customDir, 0o755); err != nil {
		return fmt.Errorf("create custom dir: %w", err)
	}
	s.Source = ""
	b, err := yaml.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshal scenario: %w", err)
	}
	dest := filepath.Join(customDir, s.ID+".yaml")
	prev, prevErr := os.ReadFile(dest)
	if err := os.WriteFile(dest, b, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", dest, err)
	}
	if e.registry != nil {
		if err := e.registry.RegisterLocalApproved(ctx, s.ID, b, actor); err != nil {
			if prevErr == nil {
				_ = os.WriteFile(dest, prev, 0o644)
			} else {
				_ = os.Remove(dest)
			}
			return fmt.Errorf("content registry: %w", err)
		}
	}
	s.Source = "custom"
	e.scenarios[s.ID] = s
	return nil
}
```

Rename `Delete(id string) error` to `DeleteAs(ctx context.Context, id, actor string) error`. Insert this right after the builtin/intel guards and before the file search:

```go
	if e.registry != nil {
		if err := e.registry.RetireExecutable(ctx, id, actor, "scenario deleted by operator"); err != nil {
			return fmt.Errorf("content registry: retire %s: %w", id, err)
		}
	}
```

- [ ] **Step 4: Update every caller of `Save` / `Delete`**

The compiler lists them all: `cd orchestrator && go build ./... && go vet ./...`.

- Production handlers in `api/handlers.go` (`CreateScenario :2348`, `UpdateScenario :2376`, `CloneScenario :2438`, `UploadScenario :2463`, `DeleteScenario :2485`). Add this helper in `api/audit.go`:

  ```go
  // actorFor renders the registry actor for the authenticated caller.
  func actorFor(r *http.Request) string {
  	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil && c.UserID != "" {
  		return "user:" + c.UserID
  	}
  	return ""
  }
  ```

  and replace `h.engine.Save(&sc)` with `h.engine.SaveAs(r.Context(), &sc, actorFor(r))` (same pattern for `&clone`, `sc`). Replace `h.engine.Delete(id)` with `h.engine.DeleteAs(r.Context(), id, actorFor(r))`. An unauthenticated caller produces actor `""`, which the registry rejects. That's correct, because these routes are permission-gated anyway.
- Test call sites: replace `engine.Save(x)` / `e.Save(x)` with `engine.SaveAs(context.Background(), x, "user:test")`, and `Delete(id)` with `DeleteAs(context.Background(), id, "user:test")`. Add a `"context"` import where it's missing.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd orchestrator && go build ./... && go test ./internal/scenario/ -count=1`
Expected: PASS, including the pre-existing `TestLoad_UnsignedBuiltinRefused` (with no registry attached, an unsigned builtin is still refused by `ReadBuiltinSignature` under the compiled key).

- [ ] **Step 6: Commit**

```bash
git add -A orchestrator/internal
git commit -m "feat(tcf): engine hands files to the registry and gates execution

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 8: Step metadata hashes

**Files:**
- Modify: `orchestrator/internal/scenario/builder.go:62-90` (`StepMeta`, `BuildStepMeta`)
- Create: `orchestrator/internal/scenario/stepmeta_hash_test.go`

**Interfaces:**
- Produces: `StepMeta` fields `Component`, `ComponentVersion`, `Platform`, `ResolvedSHA256`, `CommandSHA256`; `type ComponentVersions struct { ART, Caldera string }`; `func StepCommandSHA256(st ScenarioStep) string`; `func ResolvedHashes(steps []ScenarioStep) map[string]string`; **new signature** `BuildStepMeta(steps []ScenarioStep, resolved map[string]string, cv ComponentVersions) map[string]StepMeta`.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/scenario/stepmeta_hash_test.go`:

```go
package scenario

import "testing"

func TestStepCommandSHA256_CoversExecutorCommandCleanupPayloads(t *testing.T) {
	base := ScenarioStep{TaskID: "t", Executor: "powershell", Command: "whoami", Cleanup: "x",
		Payloads: []Payload{{Name: "b.ps1", Content: "QQ=="}, {Name: "a.ps1", Content: "Qg=="}}}
	h := StepCommandSHA256(base)
	if len(h) != 64 {
		t.Fatalf("hash = %q", h)
	}
	reordered := base
	reordered.Payloads = []Payload{base.Payloads[1], base.Payloads[0]}
	if StepCommandSHA256(reordered) != h {
		t.Fatal("payload order must not change the hash")
	}
	for name, mut := range map[string]func(*ScenarioStep){
		"executor": func(s *ScenarioStep) { s.Executor = "cmd" },
		"command":  func(s *ScenarioStep) { s.Command = "hostname" },
		"cleanup":  func(s *ScenarioStep) { s.Cleanup = "" },
		"payload":  func(s *ScenarioStep) { s.Payloads = []Payload{{Name: "a.ps1", Content: "Zg=="}} },
	} {
		c := base
		mut(&c)
		if StepCommandSHA256(c) == h {
			t.Errorf("changing %s must change the hash", name)
		}
	}
}

func TestBuildStepMeta_RecordsComponentAndBothHashes(t *testing.T) {
	steps := []ScenarioStep{
		{TaskID: "a", TechniqueID: "T1082", Name: "n", Framework: "art", Platform: "windows", Executor: "powershell", Command: "systeminfo"},
		{TaskID: "c", TechniqueID: "T1059", Name: "c", Framework: "custom", Executor: "cmd", Command: "echo"},
	}
	resolved := ResolvedHashes(steps)
	steps[0].Command = "systeminfo #ARTIFACT-123" // per-run substitution after build
	meta := BuildStepMeta(steps, resolved, ComponentVersions{ART: "art-2026.09"})
	a := meta["a"]
	if a.Component != "art" || a.ComponentVersion != "art-2026.09" || a.Platform != "windows" {
		t.Fatalf("art meta: %+v", a)
	}
	if a.ResolvedSHA256 == "" || a.CommandSHA256 == "" || a.ResolvedSHA256 == a.CommandSHA256 {
		t.Fatalf("resolved and sent hashes must both exist and differ after substitution: %+v", a)
	}
	if c := meta["c"]; c.Component != "custom" || c.ComponentVersion != "" {
		t.Fatalf("custom meta: %+v", c)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/scenario/ -run 'StepCommandSHA256|BuildStepMeta_Records' -count=1`
Expected: FAIL, `undefined: StepCommandSHA256`.

- [ ] **Step 3: Implement**

In `builder.go`, add these fields to `StepMeta` (after `Framework`):

```go
	// TCF Phase 1 §4.9 / plan amendment 7. Component + version pin the
	// mutable catalog a step was resolved from; ResolvedSHA256 is taken right
	// after BuildSteps (comparable on rebuild -> drift), CommandSHA256 is what
	// was actually sent (includes per-run artifact/sink-token substitution).
	Component        string `json:"component,omitempty"`
	ComponentVersion string `json:"componentVersion,omitempty"`
	Platform         string `json:"platform,omitempty"`
	ResolvedSHA256   string `json:"resolvedSha256,omitempty"`
	CommandSHA256    string `json:"commandSha256,omitempty"`
```

Add this code and change `BuildStepMeta`. Keep its existing body, which fills `TechniqueID`, `Name`, `Framework` and the variant fields, and extend each entry as shown:

```go
type ComponentVersions struct {
	ART     string
	Caldera string
}

// StepCommandSHA256 hashes canonical JSON of exactly what an agent executes.
func StepCommandSHA256(st ScenarioStep) string {
	type p struct {
		Name   string `json:"name"`
		SHA256 string `json:"sha256"`
	}
	ps := make([]p, 0, len(st.Payloads))
	for _, pl := range st.Payloads {
		h := sha256.Sum256([]byte(pl.Content))
		ps = append(ps, p{Name: pl.Name, SHA256: hex.EncodeToString(h[:])})
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].Name < ps[j].Name })
	b, _ := json.Marshal(struct {
		Executor string `json:"executor"`
		Command  string `json:"command"`
		Cleanup  string `json:"cleanup"`
		Payloads []p    `json:"payloads"`
	}{st.Executor, st.Command, st.Cleanup, ps})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// ResolvedHashes snapshots per-step hashes right after BuildSteps, before
// any per-run substitution.
func ResolvedHashes(steps []ScenarioStep) map[string]string {
	out := make(map[string]string, len(steps))
	for _, st := range steps {
		out[st.TaskID] = StepCommandSHA256(st)
	}
	return out
}
```

Inside `BuildStepMeta(steps []ScenarioStep, resolved map[string]string, cv ComponentVersions)`, after the existing per-step assignment of `m` (the `StepMeta` value), add:

```go
		m.Component = st.Framework
		switch st.Framework {
		case "art":
			m.ComponentVersion = cv.ART
		case "caldera":
			m.ComponentVersion = cv.Caldera
		}
		m.Platform = st.Platform
		m.ResolvedSHA256 = resolved[st.TaskID]
		m.CommandSHA256 = StepCommandSHA256(st)
```

Add imports `crypto/sha256`, `encoding/hex`, `encoding/json`, `sort` if they're missing. The old `BuildStepMeta(steps)` callers break here on purpose. Task 9 fixes the one production caller (`persistStepMeta`). For any test callers, run `grep -rn "BuildStepMeta(" orchestrator/internal --include=*_test.go` and pass `nil, scenario.ComponentVersions{}`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/scenario/ -count=1`
Expected: PASS. (`go build ./...` will fail in `internal/api` until Task 9. That's expected.)

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/scenario/
git commit -m "feat(tcf): per-step component pin plus resolved and sent command hashes

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 9: Dispatch wiring — gate every content run, label every synthetic run

**Files:**
- Modify: `orchestrator/internal/api/handlers.go`: `dispatchOpts :1577`, `dispatchRun :1760`, `TriggerScan :1446`, `SafeScan :1510`, `RunScenario` (around `:2173`), `persistStepMeta :2593`, the skip switch `:2312`, adversary-template callers `:4192`/`:4215`, Caldera emu `:4900`
- Modify: `orchestrator/internal/api/remediation_dispatch.go:75,122`
- Modify: `orchestrator/internal/api/variant_handlers.go:717,757`
- Modify: `orchestrator/cmd/server/main.go:342-345` (attach registry before `engine.Load()`)
- Modify: `orchestrator/internal/api/run_dispatch_helpers_test.go:193-228` (helpers attach a registry)
- Create: `orchestrator/internal/api/content_gate_test.go`

**Interfaces:**
- Consumes: `Engine.ResolveExecutable`, `contentregistry.Kind*`, `scenario.BuildStepMeta(steps, resolved, cv)`, `scenario.ResolvedHashes`.
- Produces: `dispatchOpts.Kind string` (`""` means content); `(*Handler).persistStepMeta(ctx, runID string, steps []scenario.ScenarioStep, resolved map[string]string)`; `(*Handler).componentVersions(ctx) scenario.ComponentVersions`; the skip-reason prefix `"content not executable: "`.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/api/content_gate_test.go`:

```go
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/contentregistry"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/testutil"
	"github.com/audspect/bas/internal/ws"
)

func registryEngine(t *testing.T, pool *pgxpool.Pool) (*scenario.Engine, *contentregistry.Registry, string) {
	t.Helper()
	dir := t.TempDir()
	e := scenario.NewEngine(dir)
	e.SetVerifier(testutil.DevVerifier())
	reg := contentregistry.New(pool, testutil.DevVerifier())
	e.AttachRegistry(reg)
	return e, reg, dir
}

func seedAgent(t *testing.T, pool *pgxpool.Pool, id string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO agents (agent_id, hostname, os_version, state) VALUES ($1,'h','Windows 10','active') ON CONFLICT DO NOTHING`, id); err != nil {
		t.Fatal(err)
	}
}

func TestDispatchRun_DeniesDraftIntelAndRecordsNothing(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, _, dir := registryEngine(t, pool)
		_ = os.MkdirAll(filepath.Join(dir, "intel"), 0o755)
		_ = os.WriteFile(filepath.Join(dir, "intel", "i.yaml"), []byte("id: intel-x\nname: I\nlocal_check: true\n"), 0o644)
		if err := e.Load(); err != nil {
			t.Fatal(err)
		}
		seedAgent(t, pool, "ga")
		h := New(pool, ws.NewHub(), e, "")
		sc, _ := e.Get("intel-x")
		runID, skip, err := h.dispatchRun(context.Background(), sc, "ga", dispatchOpts{Mode: "posture"})
		if err != nil || runID != "" || !strings.HasPrefix(skip, "content not executable: ") {
			t.Fatalf("want gate denial, got run=%q skip=%q err=%v", runID, skip, err)
		}
		var n int
		_ = pool.QueryRow(context.Background(), `SELECT count(*) FROM scenario_runs`).Scan(&n)
		if n != 0 {
			t.Fatalf("a denied dispatch must not create a run row, got %d", n)
		}
	})
}

func TestDispatchRun_ContentRunPinnedBeforeDispatch(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, _, _ := registryEngine(t, pool)
		if err := e.SaveAs(context.Background(), &scenario.Scenario{ID: "pin", Name: "P", LocalCheck: true}, "user:op"); err != nil {
			t.Fatal(err)
		}
		seedAgent(t, pool, "pa")
		h := New(pool, ws.NewHub(), e, "")
		sc, _ := e.Get("pin")
		_, _, _ = h.dispatchRun(context.Background(), sc, "pa", dispatchOpts{Mode: "posture"}) // agent offline -> failed run, row still exists
		var kind string
		var vid *string
		if err := pool.QueryRow(context.Background(),
			`SELECT execution_kind, content_version_id FROM scenario_runs WHERE scenario_id='pin'`).Scan(&kind, &vid); err != nil {
			t.Fatal(err)
		}
		if kind != "content" || vid == nil || *vid == "" {
			t.Fatalf("kind=%s version=%v", kind, vid)
		}
	})
}

func TestRunScenario_GateDenialIs409(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, _, dir := registryEngine(t, pool)
		_ = os.MkdirAll(filepath.Join(dir, "intel"), 0o755)
		_ = os.WriteFile(filepath.Join(dir, "intel", "i.yaml"), []byte("id: intel-y\nname: I\nlocal_check: true\n"), 0o644)
		_ = e.Load()
		seedAgent(t, pool, "ra")
		h := New(pool, ws.NewHub(), e, "")
		body, _ := json.Marshal(map[string]any{"agentId": "ra"})
		req := httptest.NewRequest(http.MethodPost, "/api/scenarios/intel-y/run", bytes.NewReader(body))
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", "intel-y")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		rec := httptest.NewRecorder()
		h.RunScenario(rec, req)
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "DRAFT") {
			t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
		}
	})
}

// Review Focus 1: indices are validated against the executed version, not
// the newer disk file.
func TestRunScenario_StepSubsetValidatedAgainstExecutedVersion(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, _, dir := registryEngine(t, pool)
		one := &scenario.Scenario{ID: "sub", Name: "S", Executable: true,
			Steps: []scenario.Step{{Name: "a", TechniqueID: "T1082", Framework: "custom", Command: "a"}}}
		if err := e.SaveAs(context.Background(), one, "user:op"); err != nil {
			t.Fatal(err)
		}
		_, _ = pool.Exec(context.Background(), `INSERT INTO content_registry_state (id) VALUES (1)`)
		// Out-of-band edit adds a second step -> new DRAFT; v1 (one step) still executes.
		_ = os.WriteFile(filepath.Join(dir, "custom", "sub.yaml"), []byte(`id: sub
name: S
executable: true
steps:
  - {name: a, technique_id: T1082, framework: custom, command: a}
  - {name: b, technique_id: T1083, framework: custom, command: b}
`), 0o644)
		_ = e.Load()
		seedAgent(t, pool, "sa")
		h := New(pool, ws.NewHub(), e, "")
		body, _ := json.Marshal(map[string]any{"agentId": "sa", "steps": []int{1}})
		req := httptest.NewRequest(http.MethodPost, "/api/scenarios/sub/run", bytes.NewReader(body))
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", "sub")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		rec := httptest.NewRecorder()
		h.RunScenario(rec, req)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "out of range") {
			t.Fatalf("index 1 does not exist in executed v1: code=%d body=%s", rec.Code, rec.Body.String())
		}
	})
}

// A8 (source half): every INSERT INTO scenario_runs in internal/api sets
// execution_kind explicitly.
func TestEveryRunInsertSetsKind(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		src := string(b)
		for i := strings.Index(src, "INSERT INTO scenario_runs"); i >= 0; {
			end := strings.Index(src[i:], "VALUES")
			if end < 0 {
				end = len(src) - i
			}
			if !strings.Contains(src[i:i+end], "execution_kind") {
				t.Errorf("%s: INSERT INTO scenario_runs without execution_kind near offset %d", f, i)
			}
			next := strings.Index(src[i+1:], "INSERT INTO scenario_runs")
			if next < 0 {
				break
			}
			i = i + 1 + next
		}
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/ -run 'DispatchRun_Denies|ContentRunPinned|GateDenialIs409|StepSubsetValidated|EveryRunInsertSetsKind' -count=1 -p 1`
Expected: FAIL. `api` doesn't compile yet (`BuildStepMeta` signature from Task 8).

- [ ] **Step 3: Implement the dispatch wiring**

(a) `dispatchOpts` (`handlers.go:1577`): add a field.

```go
	// Kind is scenario_runs.execution_kind. "" means "content": the scenario
	// is resolved through the Content Registry gate and the run is pinned to
	// the resolved version. Synthetic callers MUST set their kind explicitly;
	// forgetting to do so fails closed (an unregistered synthetic id is denied).
	Kind string
```

(b) `dispatchRun`: right after the license check at the top, add:

```go
	kind := o.Kind
	if kind == "" {
		kind = contentregistry.KindContent
	}
	var contentVersionID *string
	if kind == contentregistry.KindContent {
		ev, gerr := h.engine.ResolveExecutable(ctx, sc.ID)
		if gerr != nil {
			return "", "content not executable: " + strings.TrimPrefix(gerr.Error(), "content not executable: "), nil
		}
		sc = ev.Scenario // execute the pinned version's stored bytes, never the disk file
		contentVersionID = &ev.VersionID
	}
```

Then change the run `INSERT` to:

```go
	_, err = h.db.Exec(ctx,
		`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, initiated_by, started_at, campaign_id, variant_depth, mode, max_privilege, dispatch_subset, execution_kind, content_version_id)
		 VALUES ($1, $2, $3, $4, 'running', $5, NOW(), $6, $7, $8, $9, $10, $11, $12)`,
		runID, sc.ID, agentID, runName, o.InitiatedBy, nullIfEmpty(o.CampaignID), vdepth, mode, o.MaxPrivilege, subsetJSON, kind, contentVersionID,
	)
```

After `steps, skippedContent, err := scenario.BuildSteps(...)` and its error check (`handlers.go:~1967`), and **before** `applyGeneratedArtifacts`, add `resolved := scenario.ResolvedHashes(steps)`. Change the later `h.persistStepMeta(ctx, runID, steps)` (`~:2117`) to `h.persistStepMeta(ctx, runID, steps, resolved)`.

(c) `persistStepMeta` (`handlers.go:2593`):

```go
func (h *Handler) persistStepMeta(ctx context.Context, runID string, steps []scenario.ScenarioStep, resolved map[string]string) {
	raw, err := json.Marshal(scenario.BuildStepMeta(steps, resolved, h.componentVersions(ctx)))
	if err != nil {
		return
	}
	if _, err := h.db.Exec(ctx, `UPDATE scenario_runs SET step_meta = $1 WHERE id = $2`, raw, runID); err != nil {
		log.Printf("[scenario] persist step_meta for run %s: %v", runID, err)
	}
}

// componentVersions reads the pinned catalog versions. There is no Caldera
// version source today (spec §4.9), so Caldera is always "".
func (h *Handler) componentVersions(ctx context.Context) scenario.ComponentVersions {
	var art string
	_ = h.db.QueryRow(ctx, `SELECT source_version FROM art_content_meta WHERE id = 1`).Scan(&art)
	return scenario.ComponentVersions{ART: art}
}
```

(d) `TriggerScan`: replace `sc, ok := h.engine.Get("full-scan")` and its 404 with:

```go
	ev, gerr := h.engine.ResolveExecutable(r.Context(), "full-scan")
	if gerr != nil {
		jsonError(w, gerr.Error(), http.StatusConflict)
		return
	}
	sc := ev.Scenario
```

After `BuildSteps`, add `resolved := scenario.ResolvedHashes(steps)`. Change the INSERT to add `execution_kind, content_version_id` with values `'content', $6` and argument `ev.VersionID`. Change `h.persistStepMeta(r.Context(), runID, steps)` to pass `resolved`. Do the same in `SafeScan` for `"safe-simulation"` (it doesn't build steps, so it doesn't call `persistStepMeta`).

(e) `RunScenario`: replace `sc, ok := h.engine.Get(scenarioID)` and its 404 with:

```go
	ev, gerr := h.engine.ResolveExecutable(r.Context(), scenarioID)
	if gerr != nil {
		var ne *contentregistry.ErrNotExecutable
		if errors.As(gerr, &ne) && ne.Reason == "not registered" {
			if _, onDisk := h.engine.Get(scenarioID); !onDisk {
				jsonError(w, "scenario not found", http.StatusNotFound)
				return
			}
		}
		jsonError(w, gerr.Error(), http.StatusConflict)
		return
	}
	sc := ev.Scenario // step-index validation below now checks the executed version (Review Focus 1)
```

In the skip `switch` (`handlers.go:~2312`), add as the first case:

```go
		case strings.HasPrefix(skip, "content not executable: "):
			jsonError(w, skip, http.StatusConflict)
```

(f) Synthetic `dispatchRun` callers: set `artOpts.Kind = contentregistry.KindAdhocAdversary` (`handlers.go:4190`). For the Caldera branch at `:4215`, build `calOpts := base; calOpts.Kind = contentregistry.KindAdhocAdversary` and pass `calOpts`. At `:4900`, add `Kind: contentregistry.KindAdhocAdversary` to the `dispatchOpts{…}` literal.

(g) `remediation_dispatch.go`: the first INSERT (`:75`, operator remediation command) becomes

```go
		`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at, execution_kind)
		 VALUES ($1, $2, $3, $4, 'running', NOW(), 'remediation')`,
```

and the second (`:122`, technique verification) uses `'technique_verification'`. Before each `h.persistStepMeta(ctx, runID, steps)` there, compute `resolved := scenario.ResolvedHashes(steps)` immediately after that function's `BuildSteps` call and pass it in.

(h) `variant_handlers.go:717`: add `execution_kind` to the column list, with literal value `'variant'` in VALUES. At `:757`, pass `scenario.ResolvedHashes(steps)` as the resolved map. The variant templates are themselves the resolved commands.

(i) `cmd/server/main.go` around `:342`, before `engine.Load()`:

```go
	contentRegistry := contentregistry.New(pool, integrity.CompiledVerifier{})
	engine.AttachRegistry(contentRegistry)
```

(`pool` is the `bas_app` runtime pool already used for `NewPayloadStoreFromDB` at `:352`. Use that same variable.)

(j) Test helpers in `run_dispatch_helpers_test.go:193-228`: attach a registry so the existing dispatch tests keep working. They call `engine.SaveAs` (Task 7), which approves:

```go
	engine := scenario.NewEngine(t.TempDir())
	engine.SetVerifier(testutil.DevVerifier())
	engine.AttachRegistry(contentregistry.New(sharedDB.Pool, testutil.DevVerifier()))
```

Apply the same three lines to every other test file that builds an engine and dispatches content runs. The failing tests from the next step identify them. Search with `grep -ln "scenario.NewEngine" orchestrator/internal/api/*_test.go`. Tests that create raw YAML in a temp dir and only list scenarios don't need a registry.

- [ ] **Step 4: Run the new tests, then the whole api package**

Run: `cd orchestrator && go test ./internal/api/ -run 'DispatchRun_Denies|ContentRunPinned|GateDenialIs409|StepSubsetValidated|EveryRunInsertSetsKind' -count=1 -p 1`
Expected: PASS.

Run: `cd orchestrator && go test ./internal/api/ -count=1 -p 1`
Expected: PASS, apart from the known pre-existing `TestRBACMatrix_NoDrift` ca-root drift. For any other failure: if the test dispatches a content run on an engine without a registry, apply the (j) helper lines. Any failure that isn't of that kind is a real regression; stop and debug it with superpowers:systematic-debugging.

- [ ] **Step 5: Commit**

```bash
git add -A orchestrator/internal/api orchestrator/cmd/server/main.go
git commit -m "feat(tcf): gate every content dispatch and pin runs to content versions

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 10: Historical interpretation through the pinned version

**Files:**
- Create: `orchestrator/internal/contentregistry/runs.go`, `runs_test.go`
- Modify: `orchestrator/internal/api/handlers.go:2645` (`SubmitScenarioResult` scenario lookup)
- Modify: `orchestrator/internal/api/verification_handlers.go:62-71` (`runScenario`)
- Modify: `orchestrator/internal/api/detectverify_handlers.go:313,342` (`Scenarios:` param)
- Modify: `orchestrator/internal/reporting/engine.go` (hook + `ContentProvenance` field), `detection_validation.go:389-393`, `html.go:1093-1096`
- Modify: `orchestrator/internal/verifysync/job.go:37,90`
- Modify: `orchestrator/cmd/server/main.go` (wire hooks after `reportingEngine` / `verifyJob` construction)

**Interfaces:**
- Consumes: `LoadVersion`, `scenario_runs.execution_kind/content_version_id`.
- Produces:
  - `contentregistry.RunContentStatus` constants: `RunVersioned "versioned"`, `RunUnversioned "unversioned"`, `RunUnreadable "unreadable"`, `RunSynthetic "synthetic"`
  - `type RunContent struct { Status RunContentStatus; Scenario *scenario.Scenario; VersionID, ContentID, Trust, Lifecycle string; Version int }` with `func (RunContent) Label() string`
  - `type CurrentLookup interface { Get(id string) (*scenario.Scenario, bool) }`
  - `(*Registry).RunContent(ctx, runID string, current CurrentLookup) RunContent`
  - `type RunResolver struct{...}` with `Get(id) (*scenario.Scenario, bool)` and `ResolveStepExpectations(scenario.Step) ([]scenario.ExpectedDetection, []scenario.ProfileRef)`
  - `(*Registry).ForRun(ctx, runID string, engine *scenario.Engine) RunResolver`
  - `reporting.RunContentInfo{Resolver ScenarioResolver; Status, Label string}`, `reporting.RunContentFunc func(ctx, runID string) RunContentInfo`, `(*reporting.Engine).WithRunContent(RunContentFunc) *Engine`, `FullReport.ContentProvenance *ContentProvenance` (`json:"contentProvenance,omitempty"`)
  - `(*verifysync.Job).WithRunContent(reporting.RunContentFunc) *Job`

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/contentregistry/runs_test.go`:

```go
package contentregistry

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/testutil"
)

type mapLookup map[string]*scenario.Scenario

func (m mapLookup) Get(id string) (*scenario.Scenario, bool) { s, ok := m[id]; return s, ok }

func TestRunContent_UsesStoredVersionNotCurrent(t *testing.T) { // A9
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		old := []byte("id: hist\nname: Old name\nsteps:\n  - {name: s1, technique_id: T1082, framework: custom, command: a}\n")
		if err := r.RegisterLocalApproved(ctx, "hist", old, "user:op"); err != nil {
			t.Fatal(err)
		}
		ev, _ := r.ResolveExecutable(ctx, "hist")
		_, _ = pool.Exec(ctx, `INSERT INTO agents (agent_id, hostname) VALUES ('ha','h')`)
		var runID string
		_ = pool.QueryRow(ctx, `INSERT INTO scenario_runs (scenario_id, agent_id, execution_kind, content_version_id)
			VALUES ('hist','ha','content',$1) RETURNING id`, ev.VersionID).Scan(&runID)
		current := mapLookup{"hist": {ID: "hist", Name: "New name"}}
		rc := r.RunContent(ctx, runID, current)
		if rc.Status != RunVersioned || rc.Scenario.Name != "Old name" || rc.Version != 1 {
			t.Fatalf("got %+v", rc)
		}
		res := r.ForRun(ctx, runID, nil)
		if sc, ok := res.Get("hist"); !ok || sc.Name != "Old name" {
			t.Fatalf("resolver must serve the pinned version: %+v", sc)
		}
	})
}

func TestRunContent_LegacyLabelledAndSyntheticEmpty(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		_, _ = pool.Exec(ctx, `INSERT INTO agents (agent_id, hostname) VALUES ('la','h')`)
		var legacyID, synthID string
		_ = pool.QueryRow(ctx, `INSERT INTO scenario_runs (scenario_id, agent_id) VALUES ('lg','la') RETURNING id`).Scan(&legacyID)
		_ = pool.QueryRow(ctx, `INSERT INTO scenario_runs (scenario_id, agent_id, execution_kind) VALUES ('__variant__t1082','la','variant') RETURNING id`).Scan(&synthID)
		rc := r.RunContent(ctx, legacyID, mapLookup{"lg": {ID: "lg", Name: "Current"}})
		if rc.Status != RunUnversioned || rc.Scenario.Name != "Current" ||
			rc.Label() != "Unversioned — interpreted against current content" {
			t.Fatalf("legacy: %+v label=%q", rc, rc.Label())
		}
		if s := r.RunContent(ctx, synthID, mapLookup{}); s.Status != RunSynthetic || s.Scenario != nil {
			t.Fatalf("synthetic: %+v", s)
		}
	})
}

func TestRunContent_UnreadableNeverFallsBack(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		_ = r.RegisterLocalApproved(ctx, "ur", []byte("id: ur\nname: U\nlocal_check: true\n"), "user:op")
		ev, _ := r.ResolveExecutable(ctx, "ur")
		bad := []byte("id: [broken")
		_, _ = pool.Exec(ctx, `UPDATE content_versions SET artifact_bytes=$1, artifact_size=$2 WHERE id=$3`, bad, len(bad), ev.VersionID)
		_, _ = pool.Exec(ctx, `INSERT INTO agents (agent_id, hostname) VALUES ('ua','h')`)
		var runID string
		_ = pool.QueryRow(ctx, `INSERT INTO scenario_runs (scenario_id, agent_id, execution_kind, content_version_id)
			VALUES ('ur','ua','content',$1) RETURNING id`, ev.VersionID).Scan(&runID)
		rc := r.RunContent(ctx, runID, mapLookup{"ur": {ID: "ur", Name: "Current"}})
		if rc.Status != RunUnreadable || rc.Scenario != nil || rc.Label() != "Content version unreadable" {
			t.Fatalf("got %+v", rc)
		}
	})
}
```

Add to `orchestrator/internal/api/content_gate_test.go`:

```go
// A9 end-to-end: result interpretation uses the pinned version's step names
// even after the disk YAML changed.
func TestSubmitResult_InterpretsAgainstPinnedVersion(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, reg, _ := registryEngine(t, pool)
		v1 := &scenario.Scenario{ID: "hp", Name: "HP", Executable: true,
			Steps: []scenario.Step{{Name: "Original step", TechniqueID: "T1082", Framework: "custom", Command: "a"}}}
		if err := e.SaveAs(context.Background(), v1, "user:op"); err != nil {
			t.Fatal(err)
		}
		ev, _ := reg.ResolveExecutable(context.Background(), "hp")
		seedAgent(t, pool, "hpa")
		var runID string
		_ = pool.QueryRow(context.Background(), `INSERT INTO scenario_runs (scenario_id, agent_id, execution_kind, content_version_id)
			VALUES ('hp','hpa','content',$1) RETURNING id`, ev.VersionID).Scan(&runID)
		v2 := *v1
		v2.Steps = []scenario.Step{{Name: "Renamed step", TechniqueID: "T1082", Framework: "custom", Command: "a"}}
		_ = e.SaveAs(context.Background(), &v2, "user:op")
		h := New(pool, ws.NewHub(), e, "")
		rc := h.runContent(context.Background(), runID)
		if rc.Scenario == nil || rc.Scenario.Steps[0].Name != "Original step" {
			t.Fatalf("pinned interpretation lost: %+v", rc.Scenario)
		}
	})
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/contentregistry/ -run RunContent -count=1 -p 1 && go test ./internal/api/ -run SubmitResult_Interprets -count=1 -p 1`
Expected: FAIL, `r.RunContent undefined`.

- [ ] **Step 3: Implement**

Create `orchestrator/internal/contentregistry/runs.go`:

```go
package contentregistry

import (
	"context"
	"fmt"

	"github.com/audspect/bas/internal/scenario"
)

type RunContentStatus string

const (
	RunVersioned   RunContentStatus = "versioned"
	RunUnversioned RunContentStatus = "unversioned"
	RunUnreadable  RunContentStatus = "unreadable"
	RunSynthetic   RunContentStatus = "synthetic"
)

type RunContent struct {
	Status    RunContentStatus
	Scenario  *scenario.Scenario
	VersionID string
	ContentID string
	Version   int
	Trust     string
	Lifecycle string
}

// Label is the operator/report-facing provenance line (spec §7).
func (rc RunContent) Label() string {
	switch rc.Status {
	case RunVersioned:
		return fmt.Sprintf("%s v%d (%s)", rc.ContentID, rc.Version, rc.Trust)
	case RunUnversioned:
		return "Unversioned — interpreted against current content"
	case RunUnreadable:
		return "Content version unreadable"
	}
	return ""
}

type CurrentLookup interface {
	Get(id string) (*scenario.Scenario, bool)
}

// RunContent resolves the scenario a run must be interpreted against. A
// versioned run NEVER falls back to current content; only pre-registry
// (legacy) runs do, and they are labelled.
func (r *Registry) RunContent(ctx context.Context, runID string, current CurrentLookup) RunContent {
	var kind, scenarioID string
	var vid *string
	if err := r.pool.QueryRow(ctx,
		`SELECT execution_kind, content_version_id, scenario_id FROM scenario_runs WHERE id = $1`, runID,
	).Scan(&kind, &vid, &scenarioID); err != nil {
		return RunContent{Status: RunUnreadable}
	}
	switch kind {
	case KindContent:
		if vid == nil {
			return RunContent{Status: RunUnreadable}
		}
		v, err := r.LoadVersion(ctx, *vid)
		if err != nil {
			return RunContent{Status: RunUnreadable, VersionID: *vid}
		}
		sc, err := v.Parse()
		if err != nil {
			return RunContent{Status: RunUnreadable, VersionID: v.ID, ContentID: v.ContentID, Version: v.Number}
		}
		return RunContent{Status: RunVersioned, Scenario: sc, VersionID: v.ID, ContentID: v.ContentID,
			Version: v.Number, Trust: string(v.Trust), Lifecycle: string(v.Lifecycle)}
	case KindLegacy:
		var sc *scenario.Scenario
		if current != nil {
			sc, _ = current.Get(scenarioID)
		}
		return RunContent{Status: RunUnversioned, Scenario: sc, ContentID: scenarioID}
	default:
		return RunContent{Status: RunSynthetic}
	}
}

// ExpectationResolver is the engine's detection-profile resolution (still
// current files -- plan amendment 9).
type ExpectationResolver interface {
	ResolveStepExpectations(step scenario.Step) ([]scenario.ExpectedDetection, []scenario.ProfileRef)
}

// RunResolver satisfies reporting.ScenarioResolver / detectverify.ScenarioResolver
// for exactly one run.
type RunResolver struct {
	Content RunContent
	exp     ExpectationResolver
}

func (rr RunResolver) Get(id string) (*scenario.Scenario, bool) {
	if rr.Content.Scenario == nil || rr.Content.Scenario.ID != id {
		return nil, false
	}
	return rr.Content.Scenario, true
}

func (rr RunResolver) ResolveStepExpectations(step scenario.Step) ([]scenario.ExpectedDetection, []scenario.ProfileRef) {
	if rr.exp == nil {
		return nil, nil
	}
	return rr.exp.ResolveStepExpectations(step)
}

// ForRun builds the run-scoped resolver. engine may be nil (no profile
// resolution, no legacy fallback).
func (r *Registry) ForRun(ctx context.Context, runID string, engine *scenario.Engine) RunResolver {
	var cur CurrentLookup
	var exp ExpectationResolver
	if engine != nil {
		cur, exp = engine, engine
	}
	return RunResolver{Content: r.RunContent(ctx, runID, cur), exp: exp}
}
```

In `api`, add a helper in `handlers.go` near `persistStepMeta`:

```go
// runContent is the ONLY way post-run code may obtain a run's scenario
// (spec §7). Without a registry (unit tests) it degrades to the legacy path.
func (h *Handler) runContent(ctx context.Context, runID string) contentregistry.RunContent {
	reg, ok := h.engine.Registry().(*contentregistry.Registry)
	if !ok || reg == nil {
		var sid string
		_ = h.db.QueryRow(ctx, `SELECT scenario_id FROM scenario_runs WHERE id = $1`, runID).Scan(&sid)
		sc, _ := h.engine.Get(sid)
		return contentregistry.RunContent{Status: contentregistry.RunUnversioned, Scenario: sc, ContentID: sid}
	}
	return reg.RunContent(ctx, runID, h.engine)
}

func (h *Handler) runResolver(ctx context.Context, runID string) contentregistry.RunResolver {
	if reg, ok := h.engine.Registry().(*contentregistry.Registry); ok && reg != nil {
		return reg.ForRun(ctx, runID, h.engine)
	}
	return contentregistry.RunResolver{Content: h.runContent(ctx, runID)}
}
```

- `SubmitScenarioResult` (`handlers.go:2645`): replace `sc, _ := h.engine.Get(raw.ScenarioID)` with `sc := h.runContent(r.Context(), raw.RunID).Scenario`. That also stops trusting the agent-supplied scenario ID.
- `verification_handlers.go` `runScenario`: replace the body after the nil-engine guard with:

  ```go
  	rc := h.runContent(ctx, runID)
  	return rc.Scenario, rc.Scenario != nil
  ```

- `detectverify_handlers.go:313` and `:342`: set `Scenarios: h.runResolver(ctx, runID)` (use the run ID variable already in scope at each site).
- `reporting/engine.go`: add

  ```go
  // RunContentInfo is the run-scoped content view (TCF Phase 1 §7).
  type RunContentInfo struct {
  	Resolver ScenarioResolver
  	Status   string
  	Label    string
  }
  type RunContentFunc func(ctx context.Context, runID string) RunContentInfo

  type ContentProvenance struct {
  	Status string `json:"status"`
  	Label  string `json:"label"`
  }

  func (e *Engine) WithRunContent(f RunContentFunc) *Engine { e.runContent = f; return e }
  ```

  Add the field `runContent RunContentFunc` to `Engine`, and add `ContentProvenance *ContentProvenance \`json:"contentProvenance,omitempty"\`` to `FullReport` next to `ScenarioName`. In `BuildFromRun`, after `report.ScenarioName` is set:

  ```go
  	if e.runContent != nil {
  		if info := e.runContent(ctx, runID); info.Label != "" {
  			report.ContentProvenance = &ContentProvenance{Status: info.Status, Label: info.Label}
  		}
  	}
  ```
- `reporting/detection_validation.go:389-393` `buildDetectionValidation`:

  ```go
  	resolver := e.scenarios
  	if e.runContent != nil {
  		if info := e.runContent(ctx, runID); info.Resolver != nil {
  			resolver = info.Resolver
  		}
  	}
  	if resolver == nil || scenarioID == "" {
  		return DetectionValidationSection{}
  	}
  	specs := ResolveStepDetectionSpecs(resolver, scenarioID)
  ```

  (Replace the existing `e.scenarios == nil` guard with the `resolver == nil` one.)
- `reporting/html.go` after the "Last Scenario" cell (`:1096`):

  ```html
      {{if .contentProvenance}}
      <div class="cg-cell">
        <div class="cg-label">Content Version</div>
        <div class="cg-value">{{.contentProvenance.label}}</div>
      </div>
      {{end}}
  ```
- `verifysync/job.go`: add field `runContent reporting.RunContentFunc` and `func (j *Job) WithRunContent(f reporting.RunContentFunc) *Job { j.runContent = f; return j }`. In `processRun` (`:90`):

  ```go
  	resolver := j.scenarios
  	if j.runContent != nil {
  		if info := j.runContent(ctx, runID); info.Resolver != nil {
  			resolver = info.Resolver
  		}
  	}
  	specs := reporting.ResolveStepDetectionSpecs(resolver, scenarioID)
  ```
- `cmd/server/main.go`: after `reportingEngine` and `verifyJob` are constructed:

  ```go
  	runContent := func(ctx context.Context, runID string) reporting.RunContentInfo {
  		rr := contentRegistry.ForRun(ctx, runID, engine)
  		return reporting.RunContentInfo{Resolver: rr, Status: string(rr.Content.Status), Label: rr.Content.Label()}
  	}
  	reportingEngine.WithRunContent(runContent)
  	verifyJob.WithRunContent(runContent)
  ```

  If `reportingEngine` is built as a single chained expression, append `.WithRunContent(runContent)` to the chain and declare `runContent` before it.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go build ./... && go test ./internal/contentregistry/ ./internal/reporting/ ./internal/verifysync/ -count=1 -p 1 && go test ./internal/api/ -run 'SubmitResult|Verification|DetectVerify|Report' -count=1 -p 1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A orchestrator/internal orchestrator/cmd/server/main.go
git commit -m "feat(tcf): interpret runs against their pinned content version

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 11: Component drift

**Files:**
- Create: `orchestrator/internal/contentregistry/drift.go`, `drift_test.go`
- Create: `orchestrator/internal/api/content_registry_handlers.go` (drift method only; Task 14 adds routes)

**Interfaces:**
- Produces: `type DriftItem struct { TaskID, Status, HistoricalVersion, CurrentVersion string }` with Status ∈ {`NO_DRIFT`, `COMPONENT_DRIFT`, `DRIFT_UNKNOWN`}; `CompareDrift(historical map[string]scenario.StepMeta, current map[string]string, currentComponent scenario.ComponentVersions) []DriftItem` (sorted by TaskID); `(*Handler).checkRunDrift(ctx, runID string) (DriftReport, error)` with `type DriftReport struct { RunID, Status string; Items []contentregistry.DriftItem }` (Status ∈ `checked|not_applicable|unversioned|unreadable`).

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/contentregistry/drift_test.go`:

```go
package contentregistry

import (
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func TestCompareDrift(t *testing.T) { // A10
	hist := map[string]scenario.StepMeta{
		"same":    {Component: "art", ComponentVersion: "v1", ResolvedSHA256: "aaa"},
		"changed": {Component: "art", ComponentVersion: "v1", ResolvedSHA256: "bbb"},
		"removed": {Component: "caldera", ResolvedSHA256: "ccc"},
		"legacy":  {Component: "art"},
		"variant": {Component: "custom", BaseTaskID: "same"},
	}
	cur := map[string]string{"same": "aaa", "changed": "zzz"}
	got := map[string]DriftItem{}
	for _, it := range CompareDrift(hist, cur, scenario.ComponentVersions{ART: "v2"}) {
		got[it.TaskID] = it
	}
	want := map[string]string{"same": "NO_DRIFT", "changed": "COMPONENT_DRIFT", "removed": "COMPONENT_DRIFT",
		"legacy": "DRIFT_UNKNOWN", "variant": "DRIFT_UNKNOWN"}
	for id, st := range want {
		if got[id].Status != st {
			t.Errorf("%s: %s want %s", id, got[id].Status, st)
		}
	}
	if c := got["changed"]; c.HistoricalVersion != "v1" || c.CurrentVersion != "v2" {
		t.Fatalf("versions: %+v", c)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/contentregistry/ -run CompareDrift -count=1 -p 1`
Expected: FAIL, `undefined: CompareDrift`.

- [ ] **Step 3: Implement**

Create `orchestrator/internal/contentregistry/drift.go`:

```go
package contentregistry

import (
	"sort"

	"github.com/audspect/bas/internal/scenario"
)

type DriftItem struct {
	TaskID            string `json:"taskId"`
	Status            string `json:"status"` // NO_DRIFT | COMPONENT_DRIFT | DRIFT_UNKNOWN
	HistoricalVersion string `json:"historicalComponentVersion,omitempty"`
	CurrentVersion    string `json:"currentComponentVersion,omitempty"`
}

// CompareDrift compares a run's recorded resolved hashes with a fresh
// rebuild of the same immutable version (spec §7). Steps without a recorded
// resolved hash (pre-registry runs, variant expansions) are DRIFT_UNKNOWN,
// never assumed unchanged.
func CompareDrift(historical map[string]scenario.StepMeta, current map[string]string, cv scenario.ComponentVersions) []DriftItem {
	out := make([]DriftItem, 0, len(historical))
	for taskID, m := range historical {
		it := DriftItem{TaskID: taskID, HistoricalVersion: m.ComponentVersion}
		switch m.Component {
		case "art":
			it.CurrentVersion = cv.ART
		case "caldera":
			it.CurrentVersion = cv.Caldera
		}
		cur, present := current[taskID]
		switch {
		case m.ResolvedSHA256 == "" || m.BaseTaskID != "":
			it.Status = "DRIFT_UNKNOWN"
		case !present || cur != m.ResolvedSHA256:
			it.Status = "COMPONENT_DRIFT"
		default:
			it.Status = "NO_DRIFT"
		}
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TaskID < out[j].TaskID })
	return out
}
```

Create `orchestrator/internal/api/content_registry_handlers.go`:

```go
package api

import (
	"context"
	"encoding/json"

	"github.com/audspect/bas/internal/contentregistry"
	"github.com/audspect/bas/internal/scenario"
)

type DriftReport struct {
	RunID  string                      `json:"runId"`
	Status string                      `json:"status"` // checked | not_applicable | unversioned | unreadable
	Items  []contentregistry.DriftItem `json:"items,omitempty"`
}

// checkRunDrift rebuilds the run's pinned version under the current
// ART/Caldera catalogs (full version, no subset: the rebuild is a superset
// of any subset run) and compares resolved hashes by TaskID.
func (h *Handler) checkRunDrift(ctx context.Context, runID string) (DriftReport, error) {
	rc := h.runContent(ctx, runID)
	rep := DriftReport{RunID: runID}
	switch rc.Status {
	case contentregistry.RunSynthetic:
		rep.Status = "not_applicable"
		return rep, nil
	case contentregistry.RunUnversioned:
		rep.Status = "unversioned"
		return rep, nil
	case contentregistry.RunUnreadable:
		rep.Status = "unreadable"
		return rep, nil
	}
	var metaRaw []byte
	if err := h.db.QueryRow(ctx, `SELECT step_meta FROM scenario_runs WHERE id = $1`, runID).Scan(&metaRaw); err != nil {
		return rep, err
	}
	hist := map[string]scenario.StepMeta{}
	_ = json.Unmarshal(metaRaw, &hist)
	platform := "windows"
	for _, m := range hist {
		if m.Platform != "" {
			platform = m.Platform
			break
		}
	}
	steps, _, err := scenario.BuildSteps(rc.Scenario, h.calderaURL, h.calderaKey, h.artStore, platform)
	if err != nil {
		return rep, err
	}
	rep.Status = "checked"
	rep.Items = contentregistry.CompareDrift(hist, scenario.ResolvedHashes(steps), h.componentVersions(ctx))
	return rep, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go build ./... && go test ./internal/contentregistry/ -run CompareDrift -count=1 -p 1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/contentregistry/drift.go orchestrator/internal/contentregistry/drift_test.go orchestrator/internal/api/content_registry_handlers.go
git commit -m "feat(tcf): on-demand component drift check per run

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 12: Generator rewire — deterministic DRAFTs with provenance snapshots

**Files:**
- Modify: `orchestrator/internal/contentregistry/generated.go` (extend the Task 4 stub)
- Create: `orchestrator/internal/contentregistry/generated_test.go`
- Modify: `orchestrator/internal/connector/generator.go` (`Write :61-91`, `buildYAML :95-177`, `NewGenerator :42`)
- Modify: `orchestrator/internal/connector/generator_test.go` (adapt `buildYAML` callers; add tests)
- Modify: `orchestrator/cmd/server/main.go:485` (pass the registry)

**Interfaces:**
- Produces: `type GeneratedCandidate struct { ContentID string; Artifact []byte; GenerationKey string; Generation map[string]any; Sources []SourceRef }`; `(*Registry).RegisterGenerated(ctx, GeneratedCandidate) (versionID string, created bool, err error)`; in `connector`: `type Registrar interface { RegisterGenerated(ctx context.Context, c contentregistry.GeneratedCandidate) (string, bool, error) }`, `(*Generator).WithRegistrar(Registrar) *Generator`, `intelContentID(actorName string) string`, `generationKey(actor ThreatActor) string`.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/contentregistry/generated_test.go`:

```go
package contentregistry

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

func TestRegisterGenerated_TraceableCandidate(t *testing.T) { // A1
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		seen := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
		if _, err := pool.Exec(ctx, `INSERT INTO threat_actor_profiles (name) VALUES ('RansomHub')`); err != nil {
			t.Fatal(err)
		}
		_, _ = pool.Exec(ctx, `INSERT INTO threat_actor_sources (actor_name, source, source_id, name, confidence, last_seen)
			VALUES ('RansomHub','misp','evt-1','RansomHub','high',$1), ('RansomHub','opencti','oc-9','RansomHub','medium',$1)`, seen)
		r := New(pool, testutil.DevVerifier())
		art := []byte("id: intel-abc\nname: RansomHub — Active Campaign (Intel)\nart_techniques: [T1059.001, T1082]\n")
		vid, created, err := r.RegisterGenerated(ctx, GeneratedCandidate{ContentID: "intel-abc", Artifact: art,
			GenerationKey: "k1", Generation: map[string]any{"generator": "connector/generator"},
			Sources: []SourceRef{{EntityType: "actor", EntityID: "RansomHub", Provider: "misp", ExternalID: "evt-1", Role: "primary"}}})
		if err != nil || !created {
			t.Fatalf("register: %v", err)
		}
		v, _ := r.LoadVersion(ctx, vid)
		if v.Lifecycle != LifecycleDraft || v.Trust != TrustUntrusted || v.Origin != OriginLocal {
			t.Fatalf("candidate state: %+v", v)
		}
		var techs []string
		var gk string
		_ = pool.QueryRow(ctx, `SELECT technique_ids FROM content_versions WHERE id=$1`, vid).Scan(&techs)
		_ = pool.QueryRow(ctx, `SELECT generation_key FROM scenarios WHERE scenario_id='intel-abc'`).Scan(&gk)
		if len(techs) != 2 || gk != "k1" {
			t.Fatalf("techniques=%v gk=%q", techs, gk)
		}
		rows, _ := pool.Query(ctx, `SELECT provider, external_id, confidence_at_generation, first_seen_at_generation, role
			FROM content_version_sources WHERE content_version_id=$1 ORDER BY provider`, vid)
		defer rows.Close()
		got := 0
		for rows.Next() {
			var prov, ext, conf, role string
			var fs *time.Time
			_ = rows.Scan(&prov, &ext, &conf, &fs, &role)
			got++
			if fs == nil || !fs.Equal(seen) {
				t.Errorf("%s first_seen snapshot = %v", prov, fs)
			}
			if prov == "misp" && (ext != "evt-1" || conf != "high" || role != "primary") {
				t.Errorf("misp row: %s %s %s", ext, conf, role)
			}
			if prov == "opencti" && role != "supporting" {
				t.Errorf("opencti must be supporting, got %s", role)
			}
		}
		if got != 2 {
			t.Fatalf("source rows = %d, want 2 (primary + supporting)", got)
		}
		// Snapshot is point-in-time: later source changes do not rewrite it.
		_, _ = pool.Exec(ctx, `UPDATE threat_actor_sources SET confidence='low' WHERE source='misp'`)
		var conf string
		_ = pool.QueryRow(ctx, `SELECT confidence_at_generation FROM content_version_sources WHERE content_version_id=$1 AND provider='misp'`, vid).Scan(&conf)
		if conf != "high" {
			t.Fatalf("snapshot must not follow live source rows, got %s", conf)
		}
	})
}
```

Add to `orchestrator/internal/connector/generator_test.go`:

```go
func TestGenerator_UnchangedInputsSameBytes(t *testing.T) { // Review Focus 3
	g := NewGenerator(t.TempDir(), nil, nil, nil)
	a := ThreatActor{Name: "RansomHub", Source: "misp", SourceID: "evt-1", Confidence: "high",
		LastSeen: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		Techniques: []TechniqueRef{{ID: "T1082"}, {ID: "T1059.001"}}}
	id := intelContentID(a.Name)
	first := g.buildYAML(a, id)
	time.Sleep(1100 * time.Millisecond) // a wall-clock timestamp in the YAML would now differ
	a.LastSeen = a.LastSeen.Add(24 * time.Hour) // last-seen churn alone must not change bytes
	if second := g.buildYAML(a, id); first != second {
		t.Fatalf("YAML must be deterministic for unchanged techniques/confidence:\n%s\n---\n%s", first, second)
	}
}

func TestIntelContentID_StablePerActor(t *testing.T) {
	if intelContentID("RansomHub") != intelContentID(" ransomhub ") {
		t.Fatal("content id must depend on the normalized actor name only")
	}
	if intelContentID("RansomHub") == intelContentID("Akira") {
		t.Fatal("different actors must not collide")
	}
}

type recRegistrar struct{ got []contentregistry.GeneratedCandidate }

func (r *recRegistrar) RegisterGenerated(_ context.Context, c contentregistry.GeneratedCandidate) (string, bool, error) {
	r.got = append(r.got, c)
	return "v", true, nil
}

func TestGenerator_WriteRegistersAndRewritesWorkingCopy(t *testing.T) { // A2 generator half
	dir := t.TempDir()
	rec := &recRegistrar{}
	g := NewGenerator(dir, nil, nil, nil).WithRegistrar(rec)
	a := ThreatActor{Name: "Akira", Source: "opencti", SourceID: "x", Confidence: "medium",
		Techniques: []TechniqueRef{{ID: "T1082"}, {ID: "T1083"}}}
	if _, err := g.Write([]ThreatActor{a}); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Write([]ThreatActor{a}); err != nil { // second sync: still registers; registry dedups
		t.Fatal(err)
	}
	if len(rec.got) != 2 || rec.got[0].GenerationKey != rec.got[1].GenerationKey ||
		string(rec.got[0].Artifact) != string(rec.got[1].Artifact) {
		t.Fatalf("same inputs must yield same key and bytes: %+v", rec.got)
	}
	if rec.got[0].ContentID != intelContentID("Akira") || rec.got[0].Sources[0].Role != "primary" {
		t.Fatalf("candidate: %+v", rec.got[0])
	}
	if _, err := os.Stat(filepath.Join(dir, "intel", intelContentID("Akira")+".yaml")); err != nil {
		t.Fatalf("working copy: %v", err)
	}
}
```

(Add the imports `context`, `os`, `path/filepath`, `time` and `github.com/audspect/bas/internal/contentregistry` to the test file.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/contentregistry/ -run RegisterGenerated -count=1 -p 1; go test ./internal/connector/ -run 'Generator_|IntelContentID' -count=1 -p 1`
Expected: FAIL, undefined `RegisterGenerated` / `intelContentID`.

- [ ] **Step 3: Implement**

Extend `orchestrator/internal/contentregistry/generated.go` (keep `SourceRef`):

```go
package contentregistry

import (
	"context"
	"fmt"
	"time"
)

// SourceRef names one intelligence entity a generated version derives from.
// EntityType: actor|campaign|malware|tool|technique_evidence. Role: primary|supporting.
type SourceRef struct {
	EntityType string
	EntityID   string
	Provider   string
	ExternalID string
	Role       string
}

type GeneratedCandidate struct {
	ContentID     string
	Artifact      []byte
	GenerationKey string
	Generation    map[string]any
	Sources       []SourceRef
}

// RegisterGenerated records a generator candidate as LOCAL/UNTRUSTED/DRAFT
// with point-in-time provenance snapshots (spec §4.5, §5.2). Identical bytes
// are a no-op (created=false).
func (r *Registry) RegisterGenerated(ctx context.Context, c GeneratedCandidate) (string, bool, error) {
	a, err := analyzeArtifact(c.Artifact)
	if err != nil {
		return "", false, err
	}
	if a.contentID != c.ContentID {
		return "", false, fmt.Errorf("artifact id %q does not match %q", a.contentID, c.ContentID)
	}
	snaps, err := r.snapshotSources(ctx, c.Sources)
	if err != nil {
		return "", false, err
	}
	return r.createVersion(ctx, newVersion{contentID: c.ContentID, origin: OriginLocal, source: SourceIntel,
		artifact: c.Artifact, trust: TrustUntrusted, lifecycle: LifecycleDraft, actor: ActorGenerator,
		analysis: a, generation: c.Generation, generationKey: c.GenerationKey, sources: snaps})
}

func earliest(ts ...*time.Time) *time.Time {
	var out *time.Time
	for _, t := range ts {
		if t != nil && (out == nil || t.Before(*out)) {
			out = t
		}
	}
	return out
}

// snapshotSources copies what the factory knew at generation time. Actor
// refs expand to every threat_actor_sources row for that actor (the primary
// provider keeps role=primary, the rest become supporting). Missing source
// rows yield empty/NULL snapshot fields -- never invented values.
func (r *Registry) snapshotSources(ctx context.Context, refs []SourceRef) ([]sourceSnapshot, error) {
	var out []sourceSnapshot
	for _, ref := range refs {
		switch ref.EntityType {
		case "actor":
			rows, err := r.pool.Query(ctx,
				`SELECT s.source, s.source_id, s.confidence, s.last_seen, s.updated_at, a.first_observed
				   FROM threat_actor_sources s
				   LEFT JOIN threat_actor_activity a ON a.actor_name = s.actor_name AND a.source = s.source
				  WHERE s.actor_name = $1 ORDER BY s.source`, ref.EntityID)
			if err != nil {
				return nil, err
			}
			found := false
			for rows.Next() {
				var prov, ext, conf string
				var lastSeen, firstObserved *time.Time
				var updated time.Time
				if err := rows.Scan(&prov, &ext, &conf, &lastSeen, &updated, &firstObserved); err != nil {
					rows.Close()
					return nil, err
				}
				found = true
				role := "supporting"
				if prov == ref.Provider {
					role = "primary"
				}
				u := updated
				out = append(out, sourceSnapshot{
					ref:        SourceRef{EntityType: "actor", EntityID: ref.EntityID, Provider: prov, ExternalID: ext, Role: role},
					confidence: conf, firstSeen: earliest(firstObserved, lastSeen), lastSync: &u})
			}
			rows.Close()
			if !found {
				out = append(out, sourceSnapshot{ref: ref})
			}
		case "campaign", "malware", "tool":
			var conf string
			var firstSeen, lastSync time.Time
			err := r.pool.QueryRow(ctx,
				`SELECT confidence, first_seen, last_sync FROM intelligence_entity_sources
				  WHERE entity_type = $1 AND entity_id = $2 AND provider = $3`,
				ref.EntityType, ref.EntityID, ref.Provider).Scan(&conf, &firstSeen, &lastSync)
			if err != nil {
				out = append(out, sourceSnapshot{ref: ref})
				continue
			}
			out = append(out, sourceSnapshot{ref: ref, confidence: conf, firstSeen: &firstSeen, lastSync: &lastSync})
		default:
			return nil, fmt.Errorf("provenance snapshot for entity type %q is not supported in Phase 1", ref.EntityType)
		}
	}
	return out, nil
}
```

In `connector/generator.go`:

```go
// Registrar is the slice of the Content Registry the generator writes to.
type Registrar interface {
	RegisterGenerated(ctx context.Context, c contentregistry.GeneratedCandidate) (string, bool, error)
}

const (
	generatorName    = "connector/generator"
	generatorVersion = "2" // 2 = registry-backed, deterministic YAML (TCF Phase 1)
	mappingVersion   = "1"
)
```

Add the field `registrar Registrar` to `Generator` and `func (g *Generator) WithRegistrar(r Registrar) *Generator { g.registrar = r; return g }`.

```go
// intelContentID is derived from the actor identity only, so technique-set
// changes become versions of one content id (spec §5.2).
func intelContentID(actorName string) string {
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(actorName))))
	return "intel-" + hex.EncodeToString(h[:])[:12]
}

func generationKey(a ThreatActor) string {
	b, _ := json.Marshal(map[string]any{
		"generator": generatorName, "generator_version": generatorVersion, "mapping_version": mappingVersion,
		"inputs":     []map[string]string{{"entity_type": "actor", "entity_id": a.Name, "provider": a.Source, "external_id": a.SourceID}},
		"techniques": dedupedTechniqueIDs(a.Techniques),
		"parameters": map[string]any{"min_techniques": minTechniques},
	})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
```

Replace `Write`'s loop body (from `fp := actorFingerprint(actor)` through `res.Created++`) with:

```go
		id := intelContentID(actor.Name)
		body := g.buildYAML(actor, id)
		fname := filepath.Join(g.intelDir, id+".yaml")
		if err := os.WriteFile(fname, []byte(body), 0644); err != nil {
			log.Printf("[connector/gen] write %s: %v", fname, err)
			continue
		}
		if g.registrar == nil {
			res.Updated++
			continue
		}
		_, created, err := g.registrar.RegisterGenerated(context.Background(), contentregistry.GeneratedCandidate{
			ContentID: id, Artifact: []byte(body), GenerationKey: generationKey(actor),
			Generation: map[string]any{"generator": generatorName, "generator_version": generatorVersion,
				"mapping_version": mappingVersion, "parameters": map[string]any{"min_techniques": minTechniques}},
			Sources: []contentregistry.SourceRef{{EntityType: "actor", EntityID: actor.Name, Provider: actor.Source,
				ExternalID: actor.SourceID, Role: "primary"}},
		})
		if err != nil {
			log.Printf("[connector/gen] register %s: %v", id, err)
			continue
		}
		if created {
			log.Printf("[connector/gen] new DRAFT %s (%s, %d techniques)", id, actor.Name, len(actor.Techniques))
			res.Created++
		} else {
			res.Skipped++
		}
```

In `buildYAML(actor ThreatActor, contentID string)`, remove every volatile field so the bytes are deterministic:
- `id := "intel-" + fingerprint` becomes `id := contentID`.
- Delete `date := ...`. The name line becomes `sb.WriteString(fmt.Sprintf("name: \"%s — Active Campaign (Intel)\"\n", actor.Name))`.
- In the description, drop the `Last seen: %s.` clause and its `lastSeen` variable: `"Auto-generated from %s. %s Confidence: %s."`.
- Delete the `intel_generated_at` line. Generation time now lives in `content_versions.created_at`.

Delete `actorFingerprint` if nothing references it any more (`grep -rn actorFingerprint orchestrator/internal`), and update any `generator_test.go` callers of `buildYAML(actor, "<fp>")`. The signature is unchanged; only its meaning is now the content ID.

In `cmd/server/main.go:485`: `gen := connector.NewGenerator(cfg.ScenariosDir, cfg.ThreatIntelSectors, cfg.ThreatIntelRegions, engine.Profiles()).WithRegistrar(contentRegistry)`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go build ./... && go test ./internal/contentregistry/ ./internal/connector/ -count=1 -p 1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A orchestrator/internal/contentregistry orchestrator/internal/connector orchestrator/cmd/server/main.go
git commit -m "feat(tcf): generator emits deterministic DRAFT candidates with provenance

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 13: Migration marker and inventory

**Files:**
- Create: `orchestrator/internal/contentregistry/migration.go`, `migration_test.go`
- Modify: `orchestrator/cmd/server/main.go` (after `engine.Load()` succeeds and `handler` exists)

**Interfaces:**
- Produces: `type Inventory struct { IntelDrafted []string; AffectedSchedules []AffectedRef; AffectedCampaigns []AffectedRef; CustomGrandfathered []string; BuiltinRefused []Refusal; MigratedAt time.Time }` (JSON camelCase), `type AffectedRef struct { ID, Name, ScenarioID string }`; `(*Registry).CompleteMigration(ctx) (inv Inventory, firstTime bool, err error)`; `(*Registry).MigrationInventory(ctx) (Inventory, bool, error)`; `(*Registry).BlockedSchedules(ctx) ([]AffectedRef, error)` (live).

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/contentregistry/migration_test.go`:

```go
package contentregistry

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/testutil"
)

func TestMigrationIdempotentWithInventory(t *testing.T) { // A14
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		r := New(pool, testutil.DevVerifier())
		in := func(src, body string) { _, _ = r.Intake(ctx, scenario.IntakeFile{Path: src + "/f.yaml", Source: src, Artifact: []byte(body)}) }
		in("builtin", "id: b1\nname: B\nlocal_check: true\n")
		in("custom", "id: c1\nname: C\nlocal_check: true\n")
		in("intel", "id: intel-1\nname: I\nart_techniques: [T1082]\n")
		r.NoteRefusal("tampered.yaml", "bad", "signature invalid")
		_, _ = pool.Exec(ctx, `INSERT INTO job_schedules (type, payload, agent_ids, day_of_week, time_of_day)
			VALUES ('scheduled_assessment', '{"scenarioId":"intel-1"}', '[]', 1, '09:00')`)

		inv, first, err := r.CompleteMigration(ctx)
		if err != nil || !first {
			t.Fatalf("first: %v %v", first, err)
		}
		if len(inv.IntelDrafted) != 1 || inv.IntelDrafted[0] != "intel-1" ||
			len(inv.CustomGrandfathered) != 1 || inv.CustomGrandfathered[0] != "c1" ||
			len(inv.AffectedSchedules) != 1 || len(inv.BuiltinRefused) != 1 {
			t.Fatalf("inventory: %+v", inv)
		}
		var events int
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM content_version_events WHERE actor = $1 AND reason = $2`, ActorMigration, MigrationReason).Scan(&events)
		if events != 1 {
			t.Fatalf("grandfather events = %d", events)
		}

		before, _ := r.ListVersions(ctx, "c1")
		in("custom", "id: c1\nname: C\nlocal_check: true\n") // re-run intake after migration: no-op
		inv2, first2, err := r.CompleteMigration(ctx)
		after, _ := r.ListVersions(ctx, "c1")
		if err != nil || first2 || len(after) != len(before) || inv2.MigratedAt != inv.MigratedAt {
			t.Fatalf("second run must be a no-op: first=%v err=%v versions %d->%d", first2, err, len(before), len(after))
		}
		blocked, _ := r.BlockedSchedules(ctx)
		if len(blocked) != 1 {
			t.Fatalf("blocked schedules = %d", len(blocked))
		}
	})
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/contentregistry/ -run Migration -count=1 -p 1`
Expected: FAIL, `r.CompleteMigration undefined`.

- [ ] **Step 3: Implement**

Create `orchestrator/internal/contentregistry/migration.go`:

```go
package contentregistry

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

type AffectedRef struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	ScenarioID string `json:"scenarioId"`
}

type Inventory struct {
	IntelDrafted        []string      `json:"intelDrafted"`
	AffectedSchedules   []AffectedRef `json:"affectedSchedules"`
	AffectedCampaigns   []AffectedRef `json:"affectedCampaigns"`
	CustomGrandfathered []string      `json:"customGrandfathered"`
	BuiltinRefused      []Refusal     `json:"builtinRefused"`
	MigratedAt          time.Time     `json:"migratedAt"`
}

// nonExecutableIntel lists intel content ids with no executable version.
func (r *Registry) nonExecutableIntel(ctx context.Context) ([]string, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT DISTINCT content_id FROM content_versions cv
		  WHERE intake_source = 'intel'
		    AND NOT EXISTS (SELECT 1 FROM content_versions x WHERE x.content_id = cv.content_id
		                     AND x.lifecycle = 'PUBLISHED_LOCAL' AND x.trust_level = 'LOCAL_TRUSTED')
		  ORDER BY content_id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

func (r *Registry) schedulesFor(ctx context.Context, ids []string) ([]AffectedRef, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, type, payload->>'scenarioId' FROM job_schedules
		  WHERE type = 'scheduled_assessment' AND enabled AND payload->>'scenarioId' = ANY($1) ORDER BY id`, ids)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (AffectedRef, error) {
		var a AffectedRef
		err := row.Scan(&a.ID, &a.Name, &a.ScenarioID)
		return a, err
	})
}

// BlockedSchedules is the live banner query: enabled scheduled assessments
// whose scenario currently has no executable version.
func (r *Registry) BlockedSchedules(ctx context.Context) ([]AffectedRef, error) {
	ids, err := r.nonExecutableIntel(ctx)
	if err != nil || len(ids) == 0 {
		return nil, err
	}
	return r.schedulesFor(ctx, ids)
}

// CompleteMigration computes and stores the inventory once, then sets the
// marker that ends custom-file grandfathering. Idempotent: later calls
// return the stored inventory with firstTime=false.
func (r *Registry) CompleteMigration(ctx context.Context) (Inventory, bool, error) {
	if inv, ok, err := r.MigrationInventory(ctx); err != nil || ok {
		return inv, false, err
	}
	var inv Inventory
	var err error
	if inv.IntelDrafted, err = r.nonExecutableIntel(ctx); err != nil {
		return inv, false, err
	}
	if inv.AffectedSchedules, err = r.schedulesFor(ctx, inv.IntelDrafted); err != nil {
		return inv, false, err
	}
	crow, err := r.pool.Query(ctx, `SELECT id, name, scenario_id FROM campaigns WHERE scenario_id = ANY($1) ORDER BY id`, inv.IntelDrafted)
	if err != nil {
		return inv, false, err
	}
	if inv.AffectedCampaigns, err = pgx.CollectRows(crow, func(row pgx.CollectableRow) (AffectedRef, error) {
		var a AffectedRef
		err := row.Scan(&a.ID, &a.Name, &a.ScenarioID)
		return a, err
	}); err != nil {
		return inv, false, err
	}
	grow, err := r.pool.Query(ctx,
		`SELECT DISTINCT cv.content_id FROM content_version_events e JOIN content_versions cv ON cv.id = e.content_version_id
		  WHERE e.actor = $1 ORDER BY cv.content_id`, ActorMigration)
	if err != nil {
		return inv, false, err
	}
	if inv.CustomGrandfathered, err = pgx.CollectRows(grow, pgx.RowTo[string]); err != nil {
		return inv, false, err
	}
	inv.BuiltinRefused = r.Refusals()
	inv.MigratedAt = time.Now().UTC().Truncate(time.Microsecond)
	b, _ := json.Marshal(inv)
	tag, err := r.pool.Exec(ctx,
		`INSERT INTO content_registry_state (id, migrated_at, inventory) VALUES (1, $1, $2) ON CONFLICT (id) DO NOTHING`,
		inv.MigratedAt, b)
	if err != nil {
		return inv, false, err
	}
	if tag.RowsAffected() == 0 { // lost a race with another instance: return what it stored
		stored, _, err := r.MigrationInventory(ctx)
		return stored, false, err
	}
	r.audit(ctx, "content_registry.migration_inventory", "content_registry", map[string]any{
		"intel_drafted": len(inv.IntelDrafted), "affected_schedules": len(inv.AffectedSchedules),
		"affected_campaigns": len(inv.AffectedCampaigns), "custom_grandfathered": len(inv.CustomGrandfathered),
		"builtin_refused": len(inv.BuiltinRefused)}, "ok")
	return inv, true, nil
}

func (r *Registry) MigrationInventory(ctx context.Context) (Inventory, bool, error) {
	var raw []byte
	var at time.Time
	err := r.pool.QueryRow(ctx, `SELECT migrated_at, inventory FROM content_registry_state WHERE id = 1`).Scan(&at, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return Inventory{}, false, nil
	}
	if err != nil {
		return Inventory{}, false, err
	}
	var inv Inventory
	_ = json.Unmarshal(raw, &inv)
	inv.MigratedAt = at.UTC()
	return inv, true, nil
}
```

The `AffectedRef.Name` for schedules is filled from `type` because `job_schedules` has no name column. The UI shows `ScenarioID` + `ID`.

In `cmd/server/main.go`, after `engine.Load()` succeeds and after `handler` is constructed (search for the existing `AuditLogSystem` usage to place it next to its precedent):

```go
	if inv, first, err := contentRegistry.CompleteMigration(context.Background()); err != nil {
		log.Printf("[contentregistry] migration inventory: %v", err)
	} else if first {
		log.Printf("[contentregistry] migration complete: %d intel scenario(s) now DRAFT, %d schedule(s) and %d campaign(s) affected, %d custom scenario(s) grandfathered, %d builtin file(s) refused",
			len(inv.IntelDrafted), len(inv.AffectedSchedules), len(inv.AffectedCampaigns), len(inv.CustomGrandfathered), len(inv.BuiltinRefused))
	}
```

(The audit row is written by the registry itself, so `AuditLogSystem` isn't needed here.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd orchestrator && go build ./... && go test ./internal/contentregistry/ -count=1 -p 1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/contentregistry/migration.go orchestrator/internal/contentregistry/migration_test.go orchestrator/cmd/server/main.go
git commit -m "feat(tcf): one-time migration marker with stored inventory

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 14: API endpoints, RBAC, validations aggregate, list enrichment

**Files:**
- Create: `orchestrator/internal/contentregistry/validations.go`, `validations_test.go`
- Modify: `orchestrator/internal/api/content_registry_handlers.go` (add handlers)
- Create: `orchestrator/internal/api/content_registry_handlers_test.go`
- Modify: `orchestrator/internal/auth/permissions.go` (3 constants; Admin/Analyst maps; `Permissions()` list)
- Modify: `orchestrator/internal/api/routes.go` (viewer group near `:212`, gated group near `:398`)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go:39+` (matrix rows)
- Modify: `orchestrator/internal/api/handlers.go:1554` (`ListScenarios` enrichment)

**Interfaces:**
- Produces: `contentregistry.DetectionEffectiveness(outcomes []string) (rate float64, status string)` (status `"OK"` or `"NO_DATA"`); `(*Registry).VersionDetail(ctx, vid string) (VersionDetail, error)`; `(*Registry).Summaries(ctx) (map[string]Summary, error)` with `type Summary struct { ExecutableVersion int; ExecutableLifecycle, ExecutableTrust string; LatestVersion int; LatestLifecycle, LatestTrust, LatestVersionID string }`; permissions `CanViewContentArtifact "content:artifact:view"`, `CanTransitionContent "content:transition"`, `CanViewContentMigrationReport "content:migration:view"`; routes:
  - `GET /api/content-registry/content/{id}/versions` (any role)
  - `GET /api/content-registry/versions/{vid}` (any role)
  - `GET /api/content-registry/versions/{vid}/artifact` (`CanViewContentArtifact`)
  - `POST /api/content-registry/versions/{vid}/transition` (`CanTransitionContent`)
  - `GET /api/content-registry/runs/{runId}/drift` (any role)
  - `GET /api/content-registry/runs/{runId}/content` (any role)
  - `GET /api/content-registry/migration-report` (`CanViewContentMigrationReport`)

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/contentregistry/validations_test.go`:

```go
package contentregistry

import "testing"

func TestNoDataExcludedFromDenominator(t *testing.T) { // A13
	rate, st := DetectionEffectiveness([]string{"DETECTED", "PREVENTED", "MISSED", "NO_DATA", "NOT_APPLICABLE", "NO_DATA"})
	if st != "OK" || rate < 0.666 || rate > 0.667 {
		t.Fatalf("rate=%v status=%s, want 2/3", rate, st)
	}
	if _, st := DetectionEffectiveness([]string{"NO_DATA", "NOT_APPLICABLE"}); st != "NO_DATA" {
		t.Fatalf("all-excluded must be NO_DATA, got %s", st)
	}
	if _, st := DetectionEffectiveness(nil); st != "NO_DATA" {
		t.Fatalf("empty must be NO_DATA, got %s", st)
	}
	// ERROR is a real outcome (counts in the denominator) but not a success.
	if rate, _ := DetectionEffectiveness([]string{"DETECTED", "ERROR"}); rate != 0.5 {
		t.Fatalf("ERROR counts against: %v", rate)
	}
}
```

Create `orchestrator/internal/api/content_registry_handlers_test.go`:

```go
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func withClaims(r *http.Request, userID string, role auth.Role) *http.Request {
	return r.WithContext(auth.WithClaims(r.Context(), &auth.Claims{UserID: userID, Role: role}))
}

func TestTransitionEndpoint_ApproveIntelDraftForLocalUse(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, reg, dir := registryEngine(t, pool)
		writeIntel(t, dir, "intel-ap", "id: intel-ap\nname: I\nlocal_check: true\n")
		_ = e.Load()
		h := New(pool, ws.NewHub(), e, "")
		vs, _ := reg.ListVersions(context.Background(), "intel-ap")
		body, _ := json.Marshal(map[string]string{"to": "PUBLISHED_LOCAL", "reason": "reviewed"})
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("vid", vs[0].ID)
		req = withClaims(req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx)), "admin1", auth.RoleAdmin)
		rec := httptest.NewRecorder()
		h.TransitionContentVersion(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
		}
		if _, err := e.ResolveExecutable(context.Background(), "intel-ap"); err != nil {
			t.Fatalf("approved draft must now execute: %v", err)
		}
		// Illegal transition -> 409.
		body, _ = json.Marshal(map[string]string{"to": "PUBLISHED"})
		req2 := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		req2 = withClaims(req2.WithContext(context.WithValue(req2.Context(), chi.RouteCtxKey, rctx)), "admin1", auth.RoleAdmin)
		rec2 := httptest.NewRecorder()
		h.TransitionContentVersion(rec2, req2)
		if rec2.Code != http.StatusConflict {
			t.Fatalf("illegal transition code=%d", rec2.Code)
		}
	})
}

func TestListScenarios_CarriesRegistrySummary(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, _, _ := registryEngine(t, pool)
		_ = e.SaveAs(context.Background(), &scenario.Scenario{ID: "ls", Name: "L", LocalCheck: true}, "user:op")
		h := New(pool, ws.NewHub(), e, "")
		rec := httptest.NewRecorder()
		h.ListScenarios(rec, httptest.NewRequest(http.MethodGet, "/api/scenarios", nil))
		var out []map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out) != 1 {
			t.Fatalf("list: %s", rec.Body.String())
		}
		reg, _ := out[0]["registry"].(map[string]any)
		if reg == nil || reg["executableLifecycle"] != "PUBLISHED_LOCAL" || reg["executableVersion"].(float64) != 1 {
			t.Fatalf("registry summary: %v", out[0]["registry"])
		}
	})
}
```

Add this helper to `content_gate_test.go`:

```go
func writeIntel(t *testing.T, dir, id, body string) {
	t.Helper()
	_ = os.MkdirAll(filepath.Join(dir, "intel"), 0o755)
	if err := os.WriteFile(filepath.Join(dir, "intel", id+".yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
```

`auth.WithClaims` may not exist. Check with `grep -n "func WithClaims\|func ContextWithClaims" orchestrator/internal/auth/*.go` and use whatever existing helper the other api tests use to inject claims (`grep -rn "ClaimsKey\|WithClaims" orchestrator/internal/api/*_test.go | head`).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/contentregistry/ -run NoData -count=1 -p 1; go test ./internal/api/ -run 'TransitionEndpoint|CarriesRegistrySummary' -count=1 -p 1`
Expected: FAIL, undefined `DetectionEffectiveness` / `TransitionContentVersion`.

- [ ] **Step 3: Implement**

Create `orchestrator/internal/contentregistry/validations.go`:

```go
package contentregistry

import (
	"context"
	"encoding/json"
	"time"
)

// DetectionEffectiveness = (DETECTED+PREVENTED+LOGGED) / (all outcomes except
// NO_DATA and NOT_APPLICABLE). A zero denominator is NO_DATA -- never 0%.
func DetectionEffectiveness(outcomes []string) (float64, string) {
	var num, den int
	for _, o := range outcomes {
		switch o {
		case "NO_DATA", "NOT_APPLICABLE":
			continue
		case "DETECTED", "PREVENTED", "LOGGED":
			num++
		}
		den++
	}
	if den == 0 {
		return 0, "NO_DATA"
	}
	return float64(num) / float64(den), "OK"
}

type ValidationRow struct {
	Level     string          `json:"level"`
	Outcome   string          `json:"outcome"`
	RunID     *string         `json:"runId,omitempty"`
	Validator string          `json:"validator"`
	Detail    json.RawMessage `json:"detail"`
	CreatedAt time.Time       `json:"createdAt"`
}

type EventRow struct {
	From   *string   `json:"fromLifecycle,omitempty"`
	To     string    `json:"toLifecycle"`
	Trust  string    `json:"toTrust"`
	Actor  string    `json:"actor"`
	Reason string    `json:"reason"`
	At     time.Time `json:"at"`
}

type SourceRow struct {
	EntityType string     `json:"entityType"`
	EntityID   string     `json:"entityId"`
	Provider   string     `json:"provider"`
	ExternalID string     `json:"externalId"`
	Confidence string     `json:"confidenceAtGeneration"`
	FirstSeen  *time.Time `json:"firstSeenAtGeneration,omitempty"`
	LastSync   *time.Time `json:"lastSyncAtGeneration,omitempty"`
	Role       string     `json:"role"`
}

type VersionDetail struct {
	ID            string          `json:"id"`
	ContentID     string          `json:"contentId"`
	Version       int             `json:"version"`
	Origin        string          `json:"origin"`
	Trust         string          `json:"trust"`
	Lifecycle     string          `json:"lifecycle"`
	SHA256        string          `json:"artifactSha256"`
	Source        string          `json:"intakeSource"`
	CreatedBy     string          `json:"createdBy"`
	CreatedAt     time.Time       `json:"createdAt"`
	Generation    json.RawMessage `json:"generation"`
	Sources       []SourceRow     `json:"sources"`
	Safety        json.RawMessage `json:"safetyVerdicts"`
	Validations   []ValidationRow `json:"validations"`
	Events        []EventRow      `json:"events"`
	DetectionRate *float64        `json:"detectionEffectiveness,omitempty"`
	DetectionStat string          `json:"detectionEffectivenessStatus"`
}

func (r *Registry) VersionDetail(ctx context.Context, vid string) (VersionDetail, error) {
	v, err := r.LoadVersion(ctx, vid)
	if err != nil {
		return VersionDetail{}, err
	}
	d := VersionDetail{ID: v.ID, ContentID: v.ContentID, Version: v.Number, Origin: string(v.Origin),
		Trust: string(v.Trust), Lifecycle: string(v.Lifecycle), SHA256: v.SHA256, Source: string(v.Source),
		CreatedBy: v.CreatedBy, CreatedAt: v.CreatedAt, Sources: []SourceRow{}, Validations: []ValidationRow{}, Events: []EventRow{}}
	_ = r.pool.QueryRow(ctx, `SELECT generation FROM content_versions WHERE id = $1`, vid).Scan(&d.Generation)
	_ = r.pool.QueryRow(ctx,
		`SELECT COALESCE(json_agg(json_build_object('classifier', classifier, 'classifierVersion', classifier_version,
		   'verdict', verdict, 'detail', detail, 'evaluatedAt', evaluated_at)), '[]') FROM content_safety_verdicts WHERE content_version_id = $1`,
		vid).Scan(&d.Safety)
	if rows, err := r.pool.Query(ctx, `SELECT entity_type, entity_id, provider, external_id, confidence_at_generation,
		first_seen_at_generation, last_sync_at_generation, role FROM content_version_sources WHERE content_version_id = $1
		ORDER BY role, provider`, vid); err == nil {
		for rows.Next() {
			var s SourceRow
			if rows.Scan(&s.EntityType, &s.EntityID, &s.Provider, &s.ExternalID, &s.Confidence, &s.FirstSeen, &s.LastSync, &s.Role) == nil {
				d.Sources = append(d.Sources, s)
			}
		}
		rows.Close()
	}
	var detection []string
	if rows, err := r.pool.Query(ctx, `SELECT level, outcome, run_id, validator, detail, created_at FROM content_validations
		WHERE content_version_id = $1 ORDER BY created_at`, vid); err == nil {
		for rows.Next() {
			var vr ValidationRow
			if rows.Scan(&vr.Level, &vr.Outcome, &vr.RunID, &vr.Validator, &vr.Detail, &vr.CreatedAt) == nil {
				d.Validations = append(d.Validations, vr)
				if vr.Level == "DETECTION" {
					detection = append(detection, vr.Outcome)
				}
			}
		}
		rows.Close()
	}
	if rate, st := DetectionEffectiveness(detection); st == "OK" {
		d.DetectionRate, d.DetectionStat = &rate, st
	} else {
		d.DetectionStat = st
	}
	if rows, err := r.pool.Query(ctx, `SELECT from_lifecycle, to_lifecycle, to_trust, actor, reason, at
		FROM content_version_events WHERE content_version_id = $1 ORDER BY at, id`, vid); err == nil {
		for rows.Next() {
			var e EventRow
			if rows.Scan(&e.From, &e.To, &e.Trust, &e.Actor, &e.Reason, &e.At) == nil {
				d.Events = append(d.Events, e)
			}
		}
		rows.Close()
	}
	return d, nil
}

type Summary struct {
	ExecutableVersion   int    `json:"executableVersion"`
	ExecutableLifecycle string `json:"executableLifecycle,omitempty"`
	ExecutableTrust     string `json:"executableTrust,omitempty"`
	LatestVersion       int    `json:"latestVersion"`
	LatestVersionID     string `json:"latestVersionId"`
	LatestLifecycle     string `json:"latestLifecycle"`
	LatestTrust         string `json:"latestTrust"`
}

// Summaries returns one badge summary per content id for list views. It
// mirrors the gate's combination rule (without signature re-verification,
// which only the dispatch path pays for).
func (r *Registry) Summaries(ctx context.Context) (map[string]Summary, error) {
	rows, err := r.pool.Query(ctx, `SELECT id, content_id, version, origin, trust_level, lifecycle FROM content_versions ORDER BY content_id, version DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Summary{}
	for rows.Next() {
		var id, cid, o, tr, lc string
		var n int
		if err := rows.Scan(&id, &cid, &n, &o, &tr, &lc); err != nil {
			return nil, err
		}
		s, seen := out[cid]
		if !seen {
			s = Summary{LatestVersion: n, LatestVersionID: id, LatestLifecycle: lc, LatestTrust: tr}
		}
		if s.ExecutableVersion == 0 && Executable(Origin(o), Trust(tr), Lifecycle(lc), r.devBuild()) {
			s.ExecutableVersion, s.ExecutableLifecycle, s.ExecutableTrust = n, lc, tr
		}
		out[cid] = s
	}
	return out, rows.Err()
}
```

Add the handlers to `orchestrator/internal/api/content_registry_handlers.go` (imports: `errors`, `net/http`, `github.com/go-chi/chi/v5`):

```go
func (h *Handler) registry(w http.ResponseWriter) (*contentregistry.Registry, bool) {
	reg, ok := h.engine.Registry().(*contentregistry.Registry)
	if !ok || reg == nil {
		jsonError(w, "content registry unavailable", http.StatusServiceUnavailable)
		return nil, false
	}
	return reg, true
}

// GET /api/content-registry/content/{id}/versions
func (h *Handler) ListContentVersions(w http.ResponseWriter, r *http.Request) {
	reg, ok := h.registry(w)
	if !ok {
		return
	}
	vs, err := reg.ListVersions(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	type row struct {
		ID        string `json:"id"`
		Version   int    `json:"version"`
		Origin    string `json:"origin"`
		Trust     string `json:"trust"`
		Lifecycle string `json:"lifecycle"`
		SHA256    string `json:"artifactSha256"`
		CreatedBy string `json:"createdBy"`
		CreatedAt string `json:"createdAt"`
	}
	out := make([]row, 0, len(vs))
	for _, v := range vs {
		out = append(out, row{v.ID, v.Number, string(v.Origin), string(v.Trust), string(v.Lifecycle), v.SHA256, v.CreatedBy, v.CreatedAt.UTC().Format(time.RFC3339)})
	}
	respond(w, out)
}

// GET /api/content-registry/versions/{vid}
func (h *Handler) GetContentVersion(w http.ResponseWriter, r *http.Request) {
	reg, ok := h.registry(w)
	if !ok {
		return
	}
	d, err := reg.VersionDetail(r.Context(), chi.URLParam(r, "vid"))
	if errors.Is(err, contentregistry.ErrVersionNotFound) {
		jsonError(w, "content version not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, d)
}

// GET /api/content-registry/versions/{vid}/artifact -- exact stored bytes.
func (h *Handler) GetContentArtifact(w http.ResponseWriter, r *http.Request) {
	reg, ok := h.registry(w)
	if !ok {
		return
	}
	v, err := reg.LoadVersion(r.Context(), chi.URLParam(r, "vid"))
	if errors.Is(err, contentregistry.ErrVersionNotFound) {
		jsonError(w, "content version not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-yaml; charset=utf-8")
	w.Header().Set("X-Artifact-SHA256", v.SHA256)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(v.Artifact)
}

// POST /api/content-registry/versions/{vid}/transition {to, reason}
func (h *Handler) TransitionContentVersion(w http.ResponseWriter, r *http.Request) {
	reg, ok := h.registry(w)
	if !ok {
		return
	}
	var req struct {
		To     string `json:"to"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.To == "" {
		jsonError(w, "body must be {to, reason}", http.StatusBadRequest)
		return
	}
	vid := chi.URLParam(r, "vid")
	err := reg.Transition(r.Context(), vid, contentregistry.Lifecycle(req.To), actorFor(r), req.Reason)
	var illegal *contentregistry.ErrIllegalTransition
	switch {
	case errors.Is(err, contentregistry.ErrVersionNotFound):
		jsonError(w, "content version not found", http.StatusNotFound)
		return
	case errors.As(err, &illegal):
		jsonError(w, err.Error(), http.StatusConflict)
		return
	case err != nil:
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "content_registry.transition", vid, map[string]any{"to": req.To, "reason": req.Reason}, "ok")
	d, _ := reg.VersionDetail(r.Context(), vid)
	respond(w, d)
}

// GET /api/content-registry/runs/{runId}/drift
func (h *Handler) GetRunDrift(w http.ResponseWriter, r *http.Request) {
	rep, err := h.checkRunDrift(r.Context(), chi.URLParam(r, "runId"))
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, rep)
}

// GET /api/content-registry/runs/{runId}/content -- provenance badge data.
func (h *Handler) GetRunContent(w http.ResponseWriter, r *http.Request) {
	rc := h.runContent(r.Context(), chi.URLParam(r, "runId"))
	respond(w, map[string]any{"status": rc.Status, "label": rc.Label(), "contentId": rc.ContentID,
		"version": rc.Version, "versionId": rc.VersionID, "trust": rc.Trust, "lifecycle": rc.Lifecycle})
}

// GET /api/content-registry/migration-report
func (h *Handler) GetContentMigrationReport(w http.ResponseWriter, r *http.Request) {
	reg, ok := h.registry(w)
	if !ok {
		return
	}
	inv, done, err := reg.MigrationInventory(r.Context())
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	blocked, err := reg.BlockedSchedules(r.Context())
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"migrated": done, "inventory": inv, "blockedSchedules": blocked})
}
```

(Add `encoding/json` and `time` to the imports; `context` and `scenario` are already imported from Task 11.)

`ListScenarios` (`handlers.go:1554`):

```go
// scenarioListItem embeds the scenario so the JSON shape stays a superset
// of what the dashboard already reads, plus the registry badge summary.
type scenarioListItem struct {
	*scenario.Scenario
	Registry *contentregistry.Summary `json:"registry,omitempty"`
}

func (h *Handler) ListScenarios(w http.ResponseWriter, r *http.Request) {
	list := h.engine.List()
	var sums map[string]contentregistry.Summary
	if reg, ok := h.engine.Registry().(*contentregistry.Registry); ok && reg != nil {
		sums, _ = reg.Summaries(r.Context())
	}
	out := make([]scenarioListItem, 0, len(list))
	for _, sc := range list {
		it := scenarioListItem{Scenario: sc}
		if s, ok := sums[sc.ID]; ok {
			s := s
			it.Registry = &s
		}
		out = append(out, it)
	}
	respond(w, out)
}
```

`auth/permissions.go`: add after `CanDeleteScenario` (`:61`):

```go
	CanViewContentArtifact        Permission = "content:artifact:view"
	CanTransitionContent          Permission = "content:transition"
	CanViewContentMigrationReport Permission = "content:migration:view"
```

Grant all three in `RoleAdmin`. Grant `CanViewContentArtifact: true` in `RoleAnalyst`. Append all three to the list in `Permissions()`.

`routes.go`: in the viewer block after `r.Get("/api/scenarios/{id}", h.GetScenario)`:

```go
		r.Get("/api/content-registry/content/{id}/versions", h.ListContentVersions)
		r.Get("/api/content-registry/versions/{vid}", h.GetContentVersion)
		r.Get("/api/content-registry/runs/{runId}/drift", h.GetRunDrift)
		r.Get("/api/content-registry/runs/{runId}/content", h.GetRunContent)
```

In the gated block after `DeleteScenario` (`:402`):

```go
		r.With(auth.RequirePermission(auth.CanViewContentArtifact)).Get("/api/content-registry/versions/{vid}/artifact", h.GetContentArtifact)
		r.With(auth.RequirePermission(auth.CanTransitionContent)).Post("/api/content-registry/versions/{vid}/transition", h.TransitionContentVersion)
		r.With(auth.RequirePermission(auth.CanViewContentMigrationReport)).Get("/api/content-registry/migration-report", h.GetContentMigrationReport)
```

`rbac_matrix_test.go`: add to `routeMatrix`:

```go
	{http.MethodGet, "/api/content-registry/content/{id}/versions", tierAny, ""},
	{http.MethodGet, "/api/content-registry/versions/{vid}", tierAny, ""},
	{http.MethodGet, "/api/content-registry/runs/{runId}/drift", tierAny, ""},
	{http.MethodGet, "/api/content-registry/runs/{runId}/content", tierAny, ""},
	{http.MethodGet, "/api/content-registry/versions/{vid}/artifact", tierPermission, auth.CanViewContentArtifact},
	{http.MethodPost, "/api/content-registry/versions/{vid}/transition", tierPermission, auth.CanTransitionContent},
	{http.MethodGet, "/api/content-registry/migration-report", tierPermission, auth.CanViewContentMigrationReport},
```

- [ ] **Step 4: Run the tests to verify they pass**

(Baseline: at the very start of this task, before Step 1, run `cd orchestrator && go test ./internal/api/ -run TestRBACMatrix_NoDrift -count=1 -p 1 > "$SCRATCH/rbac_before.txt" 2>&1`, where `$SCRATCH` is the session scratchpad directory. Never use `git stash` to get a baseline; the stash is shared across worktrees.)

Run: `cd orchestrator && go test ./internal/contentregistry/ -count=1 -p 1 && go test ./internal/api/ -run 'TransitionEndpoint|CarriesRegistrySummary|RBACMatrix' -count=1 -p 1 > "$SCRATCH/rbac_after.txt" 2>&1`
Expected: new tests PASS. `TestRBACMatrix_AuthorizationBoundary` PASS. `grep content-registry "$SCRATCH/rbac_after.txt"` prints nothing, and the `TestRBACMatrix_NoDrift` drift lines match `rbac_before.txt` (only the pre-existing ca-root drift).

- [ ] **Step 5: Commit**

```bash
git add -A orchestrator/internal
git commit -m "feat(tcf): content registry API, RBAC, list badges, NO_DATA-safe aggregate

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 15: Dashboard — badges, approve action, run label, migration banner

**Files:**
- Modify: `orchestrator/wwwroot/index.html`: intel card (`~:9005-9026`), custom card badges (`~:9028-9038`), run results drawer (find with `grep -n "function openRunDrawer\|function renderRunResults\|runDrawer" orchestrator/wwwroot/index.html | head`), scenarios landing header (`renderScenarioLanding :8664`)

**Interfaces:**
- Consumes: `GET /api/scenarios` (`.registry` summary), `POST /api/content-registry/versions/{vid}/transition`, `GET /api/content-registry/runs/{runId}/content`, `GET /api/content-registry/migration-report`.

- [ ] **Step 1: Add the badge helper and approve action**

Next to the other scenario helpers (just above `renderScenarioTileGroup`, `:8900`), add:

```js
// TCF Phase 1: registry lifecycle/trust badge. Uses only server-provided
// enum strings, still escaped via x() like everything else on this card.
function registryBadge(s) {
  var r = s.registry;
  if (!r) return '<span class="tag" title="Not registered — cannot run">unregistered</span> ';
  if (r.executableVersion) {
    var label = r.executableTrust === 'VENDOR_SIGNED' ? 'signed v' : (r.executableTrust === 'LOCAL_TRUSTED' ? 'approved v' : 'dev-unsigned v');
    var pending = r.latestVersion > r.executableVersion
      ? ' <span class="tag" title="Newer version awaiting approval">v' + x(String(r.latestVersion)) + ' ' + x(r.latestLifecycle) + '</span>'
      : '';
    return '<span class="tag" style="background:rgba(63,185,80,0.12);color:#3fb950">' + label + x(String(r.executableVersion)) + '</span>' + pending + ' ';
  }
  return '<span class="tag" style="background:rgba(210,153,34,0.15);color:#d29922" title="Not executable until approved">v' +
    x(String(r.latestVersion)) + ' ' + x(r.latestLifecycle) + '</span> ';
}

function canApproveForLocal(s) {
  var r = s.registry;
  return ROLE === 'admin' && r && !r.executableVersion && (s.source === 'intel' || s.source === 'custom') &&
    (r.latestLifecycle === 'DRAFT' || r.latestLifecycle === 'VALIDATED');
}

function approveForLocalUse(id, versionId) {
  var reason = window.prompt('Approve ' + id + ' for local execution. Reason (recorded in the audit trail):', 'reviewed');
  if (reason === null) return;
  apiFetch('/api/content-registry/versions/' + encodeURIComponent(versionId) + '/transition', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({to: 'PUBLISHED_LOCAL', reason: reason})
  }).then(function (res) {
    if (!res.ok) return res.json().then(function (e) { throw new Error(e.error || res.status); });
    showToast('Approved ' + id + ' for local use', 'success');
    loadScenarios();
  }).catch(function (e) { showToast('Approval failed: ' + e.message, 'error'); });
}
```

Before writing this, confirm the dashboard's existing helper names: `grep -n "function apiFetch\|function showToast\|function loadScenarios" orchestrator/wwwroot/index.html`. Use the names the file actually defines (for example, if fetching goes through `authFetch` or the toast function is `toast`, use those). `window.prompt` is acceptable here because it's an explicit operator action on an admin-only control.

- [ ] **Step 2: Render the badge and button on the cards**

In the intel card branch (`~:9018`), change `return '<div>' + intelBadge + '</div>' +` to `return '<div>' + registryBadge(s) + intelBadge + '</div>' +`. In its footer, before the Run button:

```js
            (canApproveForLocal(s) ? '<button class="btn btn-outline btn-sm" onclick="approveForLocalUse(\'' + x(s.id) + '\',\'' + x(s.registry.latestVersionId) + '\')">&#10003; Approve</button> ' : '') +
```

For the non-intel card, prefix `customBadge` with `registryBadge(s) +`, and add the same approve button to `editBtns` when `canApproveForLocal(s)`.

- [ ] **Step 3: Run-drawer provenance line**

Where the run results drawer header is rendered (from the grep in **Files**), after the run is loaded:

```js
apiFetch('/api/content-registry/runs/' + encodeURIComponent(runId) + '/content')
  .then(function (r) { return r.ok ? r.json() : null; })
  .then(function (c) {
    if (!c || !c.label) return;
    var el = document.getElementById('runContentProvenance');
    if (el) el.textContent = 'Content: ' + c.label;
  });
```

Add a `<div id="runContentProvenance" class="card-meta"></div>` element to the drawer header markup. It uses `textContent`, not `innerHTML`, because the label contains a content ID (this follows the Group G XSS guard; the G1 CI check must stay green).

- [ ] **Step 4: Migration banner**

In `renderScenarioLanding` (`:8664`), for admins only:

```js
if (ROLE === 'admin') {
  apiFetch('/api/content-registry/migration-report').then(function (r) { return r.ok ? r.json() : null; }).then(function (m) {
    if (!m || !m.blockedSchedules || !m.blockedSchedules.length) return;
    var host = document.getElementById('registryMigrationBanner');
    if (!host) return;
    host.style.display = '';
    host.textContent = m.blockedSchedules.length + ' scheduled assessment(s) reference threat-intel scenarios that now need approval before they can run (' +
      m.blockedSchedules.map(function (s) { return s.scenarioId; }).join(', ') + '). Approve them on their scenario cards.';
  });
}
```

Add `<div id="registryMigrationBanner" class="alert alert-warning" style="display:none"></div>` at the top of the scenarios landing markup.

- [ ] **Step 5: Verify in the browser and run the XSS guard**

Run: `cd orchestrator && go test ./internal/api/ -run 'G1|XSS|Sink' -count=1 -p 1` (the G1 regression guard from `285168ad`). Check its exact test name first with `grep -rln "G1" orchestrator/internal --include=*_test.go`.
Expected: PASS.

Then build and run the orchestrator locally (Docker Desktop + Postgres) and use the `run` skill to load the Scenarios page. Confirm the following:
- builtin cards show `signed vN`, or `dev-unsigned vN` on a dev build;
- intel cards show `vN DRAFT` plus an Approve button (as admin);
- clicking Approve flips the card to `approved vN`;
- a run started afterwards shows `Content: <id> vN (LOCAL_TRUSTED)` in the drawer.
Take a screenshot of each state for the PR.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(tcf): dashboard registry badges, local approval, run provenance, migration banner

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push
```

---

### Task 16: Whole-branch verification

**Files:** none new (fix whatever the checks surface, in the task that owns the code).

- [ ] **Step 1: Format, vet, build**

Run: `cd orchestrator && gofmt -l ./internal ./cmd && go vet ./... && go build ./...`
Expected: `gofmt -l` prints nothing for files this branch touched, and vet and build are clean. (The Test workflow's gofmt step is already red on main for pre-existing files. Only fix files changed on this branch: `git diff --name-only main... -- '*.go' | xargs gofmt -l`.)

- [ ] **Step 2: Full test suite**

Run: `cd orchestrator && go test ./... -p 2` (fall back to `-p 1` on memory pressure).
Expected: PASS, except the known pre-existing `TestRBACMatrix_NoDrift` ca-root drift, which must be the only failure. Copy the exact output into the PR description.

- [ ] **Step 3: Acceptance-test traceability check**

Run: `cd orchestrator && grep -rhoE "// A[0-9]+[^\n]*" internal --include=*_test.go | sort -u`
Expected: A1–A19 each appear at least once. Map: A1 Task 12, A2 Tasks 4/12, A3 Tasks 1/4, A4 Task 1, A5 Tasks 3/6, A6 Task 5, A7 Task 6, A8 Tasks 1/9, A9 Task 10, A10 Task 11, A11 Task 5, A12 Tasks 5/7, A13 Task 14, A14 Task 13, A15 Task 2, A16 Task 2, A17 Tasks 1/3, A18 Task 6, A19 Task 6. Add any missing marker to the test that actually covers it, or add the test.

- [ ] **Step 4: Live startup check against a real database**

Start the stack locally. Then:
1. Confirm the startup log contains `[contentregistry] migration complete: …` exactly once.
2. Restart, and confirm it does **not** appear again (idempotent).
3. Query `psql -c "SELECT intake_source, lifecycle, trust_level, count(*) FROM content_versions GROUP BY 1,2,3"` and confirm builtin rows are `PUBLISHED/VENDOR_SIGNED` on a production-key build (or `PUBLISHED/UNTRUSTED` on a dev build), and that there are no LOCAL rows with `VENDOR_SIGNED`.
4. Trigger a full-scan and confirm `scenario_runs` has `execution_kind='content'` and a non-null `content_version_id`.

- [ ] **Step 5: Request final review and update memory**

Use superpowers:requesting-code-review for a whole-branch review against the spec and this plan. Then update `project_threat_content_factory.md` in memory with the shipped commit range and any review findings left open.

---

## Self-review notes (done while writing)

- **Spec coverage.**
  - §4.1–4.8 → Task 1 (schema) + Tasks 4/5/6 (writers).
  - §4.9 → Task 8.
  - §5.1 → Tasks 5/7.
  - §5.2 → Task 12.
  - §6 → Tasks 3/6/7/9.
  - §7 → Tasks 10/11.
  - §8 → Tasks 5 (grandfather) and 13.
  - §9 → Tasks 14/15.
  - §10 failure table → denial paths in Task 9 (409, scheduled via skip→error→notify, already wired in `jobs/dispatch.go:131-137`), Task 6 (registry unavailable → `content registry unavailable` error → skip), Task 10 (unreadable), Task 5 (collision).
  - §12 A1–A19 → Task 16 Step 3 map.
- **Type consistency.**
  - `scenario.ExecutableVersion` is defined in Task 5 and used in Tasks 6/7/9.
  - `contentregistry.RunContent` / `RunResolver` / `ForRun` are defined in Task 10 and used in Tasks 11/14.
  - `BuildStepMeta(steps, resolved, cv)` is defined in Task 8 and used in Task 9.
  - `persistStepMeta(ctx, runID, steps, resolved)` is defined and used in Task 9.
  - `Summary` is defined in Task 14 and consumed in Task 15 as camelCase JSON (`executableVersion`, `latestVersionId`, …).
- **Known judgment calls the executor may hit.**
  - Exact dashboard helper names (`apiFetch`, `showToast`, `loadScenarios`): verify with grep (Task 15 Step 1).
  - The claims-injection helper for api tests (Task 14 Step 1): use the existing one.
  - `main.go` variable names for the runtime pool: use the one passed to `NewPayloadStoreFromDB`.
