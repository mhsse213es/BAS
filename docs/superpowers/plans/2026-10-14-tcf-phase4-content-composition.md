# TCF Phase 4 — Content Reuse and Composition Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an admin assemble a new content candidate from existing, proven pieces — ART/Caldera technique references and steps lifted from Audspect's own previously-published scenarios — with full provenance, a compatibility/safety refusal gate before anything is registered, and zero special-casing needed anywhere downstream.

**Architecture:** One new table pair (`content_components`, `content_version_components`) holds the component catalog and composition provenance. Promotion (turning a step of a published scenario into a reusable internal component, or registering an external ART/Caldera reference) and composition (assembling chosen components into a new `content_versions` row) are both new methods on the existing `contentregistry.Registry`, reusing its existing `createVersion`/`analyzeArtifact` pipeline unchanged. Two new admin-gated API endpoints expose promotion and composition; no new frontend (explicitly out of scope).

**Tech Stack:** Go, PostgreSQL (pgx/v5), `internal/contentregistry`, `internal/db`, `internal/auth`, `internal/api`, `gopkg.in/yaml.v3`.

**Spec:** `docs/superpowers/specs/2026-10-14-tcf-phase4-content-composition-design.md`

## Global Constraints

- A step can only be promoted to an internal component from a `content_version` that currently passes the existing `Executable()` gate (`contentregistry.Executable`, `lifecycle.go:75-85`) — not a new, stricter bar (spec §2.2).
- An internal component's `step_snapshot` is captured once, at promotion time, and never changes afterward (spec acceptance criterion 2).
- Composing with components whose `supported_os` sets share no common platform is refused **before** any `content_versions` row is created (spec acceptance criterion 3).
- Composing with an assembled `Steps` list that fails the existing `safetyVerdict` worst-step-wins check is refused the same way, reusing that function unmodified — no new safety-scoring logic (spec acceptance criterion 4).
- A successfully composed candidate is an ordinary `content_versions` row (`origin = 'LOCAL'`, created `DRAFT`) — no new lifecycle state, no special-casing in any existing consumer (spec acceptance criterion 5).
- `content_version_components` makes "which components built this candidate" a single-join query, never a multi-hop chain (spec acceptance criterion 6).
- A component can never be promoted from a composed candidate's own content_version — promotion is single-source-only (spec acceptance criterion 7, §2.5).
- External components pin their ART/Caldera reference into the composed candidate's `Steps` at composition time — never left dynamic (spec acceptance criterion 8).
- Both new endpoints are gated by a new `CanManageComponents` permission at the Admin tier.

## Review Focus

- Promoting a step from a non-executable (e.g. `DRAFT`) content_version — must be refused, not silently allowed through a looser check than the stated `Executable()` bar.
- Composing with zero `supported_os` overlap across chosen components — must refuse before any row is written, not after.
- Composing with a component whose step fails `safetyVerdict`'s worst-step-wins check — must refuse, reusing the existing function rather than inventing a parallel one.
- Attempting to promote a component from a composed candidate's own content_version — must be refused; this is what makes the one-level provenance guarantee actually hold, not just claim to.
- A composed candidate's downstream visibility — it must show up correctly in an existing read path (e.g. `Registry.Summaries`, which Phase 10's `/api/threats/exposure` depends on) with zero special-casing, proving the "ordinary content_versions row" design claim is true in practice.

---

### Task 1: Schema — component tables, RBAC permission, app-role grants

**Files:**
- Create: `orchestrator/internal/db/content_components_schema.go`
- Create: `orchestrator/internal/db/content_components_schema_test.go`
- Modify: `orchestrator/cmd/server/main.go:277-279` (wire the new schema call)
- Modify: `orchestrator/internal/db/app_role.go` (REVOKE UPDATE/DELETE on both new tables, matching the project's append-only-provenance pattern)
- Modify: `orchestrator/internal/auth/permissions.go` (new `CanManageComponents` permission)

**Interfaces:**
- Consumes: nothing from earlier tasks (first task).
- Produces: tables `content_components`, `content_version_components` (exact DDL below) and `auth.CanManageComponents` — Tasks 2-5 depend on both.

- [ ] **Step 1: Write the failing schema test**

```go
// orchestrator/internal/db/content_components_schema_test.go
package db_test

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/db"
)

func TestEnsureContentComponentsSchema_CreatesTables(t *testing.T) {
	pool := sharedDB.Pool
	if err := db.EnsureContentComponentsSchema(context.Background(), pool); err != nil {
		t.Fatalf("EnsureContentComponentsSchema: %v", err)
	}
	// Idempotent: running twice must not error.
	if err := db.EnsureContentComponentsSchema(context.Background(), pool); err != nil {
		t.Fatalf("second EnsureContentComponentsSchema: %v", err)
	}
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM information_schema.tables WHERE table_name IN ('content_components','content_version_components')`).
		Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("expected both tables to exist, found %d", n)
	}
}

func TestEnsureContentComponentsSchema_KindCheckConstraintEnforced(t *testing.T) {
	pool := sharedDB.Pool
	if err := db.EnsureContentComponentsSchema(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
	// A row claiming kind='internal' but missing origin_content_version_id/step_snapshot
	// must be rejected by the CHECK constraint, not silently accepted.
	_, err := pool.Exec(context.Background(), `INSERT INTO content_components
		(kind, technique_id, title, promoted_by) VALUES ('internal', 'T1059', 'bad row', 'test')`)
	if err == nil {
		t.Fatal("expected the CHECK constraint to reject an internal component with no origin/snapshot")
	}
}
```

This test file is `package db_test` (external), using `sharedDB.Pool` directly — matching `generation_attempts_schema_test.go`'s exact convention (confirmed in this session's Phase 9 work), not `testutil.NewTestDB(t)` per-test.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/db/... -run TestEnsureContentComponentsSchema -v -count=1`
Expected: FAIL — compile error, `db.EnsureContentComponentsSchema` undefined.

- [ ] **Step 3: Implement the schema**

```go
// orchestrator/internal/db/content_components_schema.go
package db

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EnsureContentComponentsSchema creates the component catalog and
// composition-provenance tables (TCF Phase 4, spec
// docs/superpowers/specs/2026-10-14-tcf-phase4-content-composition-design.md
// §2.1, §2.3). Must run after EnsureContentRegistrySchema (content_versions).
func EnsureContentComponentsSchema(ctx context.Context, pool *pgxpool.Pool) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS content_components (
			id                         text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			kind                       text        NOT NULL CHECK (kind IN ('internal','external')),
			technique_id               text        NOT NULL,
			title                      text        NOT NULL,
			supported_os               text[]      NOT NULL DEFAULT '{}',
			origin_content_version_id  text        REFERENCES content_versions(id),
			step_snapshot              jsonb,
			framework                  text,
			ability_id                 text,
			action_key                 text,
			test_index                 int,
			library_version            text,
			promoted_by                text        NOT NULL,
			promoted_at                timestamptz NOT NULL DEFAULT NOW(),
			CHECK (
				(kind = 'internal' AND origin_content_version_id IS NOT NULL AND step_snapshot IS NOT NULL
					AND framework IS NULL AND ability_id IS NULL AND library_version IS NULL AND action_key IS NULL)
				OR
				(kind = 'external' AND framework IS NOT NULL
					AND origin_content_version_id IS NULL AND step_snapshot IS NULL)
			)
		)`,
		`CREATE TABLE IF NOT EXISTS content_version_components (
			content_version_id text NOT NULL REFERENCES content_versions(id),
			component_id        text NOT NULL REFERENCES content_components(id),
			step_order           int NOT NULL,
			PRIMARY KEY (content_version_id, component_id)
		)`,
		`CREATE INDEX IF NOT EXISTS cvc_version ON content_version_components(content_version_id)`,
	}
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			return err
		}
	}
	return nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd orchestrator && go test ./internal/db/... -run TestEnsureContentComponentsSchema -v -count=1`
Expected: PASS, both tests.

- [ ] **Step 5: Wire the schema call into boot**

In `orchestrator/cmd/server/main.go`, immediately after line 279 (`EnsureContentRegistrySchema`'s closing brace):

```go
	if err := db.EnsureContentComponentsSchema(context.Background(), adminPool); err != nil {
		log.Fatalf("[FATAL] content components schema: %v", err)
	}
```

- [ ] **Step 6: Add app-role grants**

In `orchestrator/internal/db/app_role.go`, immediately after the `content_version_threats` line (the one reading `REVOKE UPDATE, DELETE ON content_version_threats FROM ` + appRole`):

```go
			`REVOKE UPDATE, DELETE ON content_components FROM ` + appRole,
			`REVOKE UPDATE, DELETE ON content_version_components FROM ` + appRole,
```

These follow the same append-only-provenance pattern already used for `content_version_threats`/`content_version_events` — once a component is promoted or a composition's provenance is recorded, the app layer cannot rewrite or delete it.

- [ ] **Step 7: Add the RBAC permission**

In `orchestrator/internal/auth/permissions.go`, add the constant next to `CanTransitionContent` (line 66):

```go
	CanManageComponents            Permission = "content:manage-components"
```

Add `CanManageComponents: true` to the Admin tier's membership map, in the same line as `CanTransitionContent` (around line 253):

```go
		CanViewContentArtifact: true, CanTransitionContent: true, CanViewContentMigrationReport: true, CanManageComponents: true,
```

Add `CanManageComponents` to the enumeration slice (around line 375), same line as `CanTransitionContent`:

```go
		CanViewContentArtifact, CanTransitionContent, CanViewContentMigrationReport, CanManageComponents,
```

- [ ] **Step 8: Run the full db package test suite and gofmt**

Run: `cd orchestrator && go test ./internal/db/... -count=1 && gofmt -l internal/db/content_components_schema.go internal/db/content_components_schema_test.go internal/db/app_role.go internal/auth/permissions.go cmd/server/main.go`
Expected: tests PASS, gofmt output empty.

- [ ] **Step 9: Commit**

```bash
git add orchestrator/internal/db/content_components_schema.go orchestrator/internal/db/content_components_schema_test.go orchestrator/internal/db/app_role.go orchestrator/internal/auth/permissions.go orchestrator/cmd/server/main.go
git commit -m "feat(tcf-phase4): content_components schema, CanManageComponents permission"
```

---

### Task 2: Internal component promotion

**Files:**
- Create: `orchestrator/internal/contentregistry/components_promote.go`
- Create: `orchestrator/internal/contentregistry/components_promote_test.go`
- Modify: `orchestrator/internal/api/handlers.go` (new handler)
- Modify: `orchestrator/internal/api/routes.go` (new route)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go` (new row)
- Test: `orchestrator/internal/api/component_promote_handler_test.go`

**Interfaces:**
- Consumes: Task 1's `content_components` table, `auth.CanManageComponents`.
- Produces: `Registry.PromoteInternalComponent(ctx, contentVersionID string, stepIndex int, actor string) (string, error)` (returns the new component id) — Task 4's composition logic looks up components by id via a plain `LoadComponent`-style query this task also adds (see Step 3); Task 5's handler calls `PromoteInternalComponent` directly.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/contentregistry/components_promote_test.go
package contentregistry

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/testutil"
)

func TestPromoteInternalComponent_RequiresExecutableVersion(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool interface {
		Exec(ctx context.Context, sql string, args ...any) (interface{ RowsAffected() int64 }, error)
	}) {
		// placeholder signature replaced below -- see note
	})
}
```

The sketch above is deliberately incomplete: before writing this task's real test file, grep `orchestrator/internal/contentregistry/*_test.go` for the exact `sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {...})` signature this package's own tests use (confirmed in this session's Phase 10 grounding work to be `func(pool *pgxpool.Pool)`, not the placeholder above) and use that real signature. Write two real tests with it:

```go
package contentregistry

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

// seedExecutableVersion creates a PUBLISHED_LOCAL/LOCAL_TRUSTED content_version
// with the given steps (as YAML `steps:` entries), ready to promote from.
func seedExecutableVersion(t *testing.T, pool *pgxpool.Pool, contentID string, stepsYAML string) string {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO scenarios (scenario_id, origin) VALUES ($1, 'LOCAL') ON CONFLICT DO NOTHING`, contentID); err != nil {
		t.Fatal(err)
	}
	artifact := []byte("id: " + contentID + "\nname: Test\nsupported_os: [windows]\nsteps:\n" + stepsYAML)
	var versionID string
	if err := pool.QueryRow(ctx, `INSERT INTO content_versions
		(content_id, origin, version, artifact_sha256, artifact_size, artifact_bytes,
		 trust_level, lifecycle, intake_source, schema_version, technique_ids, supported_os, created_by)
		VALUES ($1, 'LOCAL', 1, 'sha-'||gen_random_uuid()::text, 1, $2,
		 'LOCAL_TRUSTED', 'PUBLISHED_LOCAL', 'custom', 1, '{T1059}', '{windows}', 'test')
		RETURNING id`, contentID, artifact).Scan(&versionID); err != nil {
		t.Fatal(err)
	}
	return versionID
}

func TestPromoteInternalComponent_RequiresExecutableVersion(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `INSERT INTO scenarios (scenario_id, origin) VALUES ('intel-draft-promote', 'LOCAL') ON CONFLICT DO NOTHING`); err != nil {
			t.Fatal(err)
		}
		var draftID string
		if err := pool.QueryRow(ctx, `INSERT INTO content_versions
			(content_id, origin, version, artifact_sha256, artifact_size, artifact_bytes,
			 trust_level, lifecycle, intake_source, schema_version, technique_ids, created_by)
			VALUES ('intel-draft-promote', 'LOCAL', 1, 'sha-draft', 1,
			 'id: intel-draft-promote\nname: T\nsupported_os: [windows]\nsteps:\n- name: s\n  technique_id: T1059\n  framework: art\n  test_index: 0\n',
			 'UNTRUSTED', 'DRAFT', 'custom', 1, '{T1059}', 'test') RETURNING id`).Scan(&draftID); err != nil {
			t.Fatal(err)
		}
		reg := New(pool, testutil.DevVerifier())
		_, err := reg.PromoteInternalComponent(ctx, draftID, 0, "admin-test")
		if err == nil {
			t.Fatal("expected promotion from a DRAFT (non-executable) version to be refused")
		}
	})
}

func TestPromoteInternalComponent_SnapshotsStepAndIsImmutable(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		versionID := seedExecutableVersion(t, pool, "intel-promote-ok", "- name: s\n  technique_id: T1059\n  framework: art\n  test_index: 0\n")
		reg := New(pool, testutil.DevVerifier())

		componentID, err := reg.PromoteInternalComponent(ctx, versionID, 0, "admin-test")
		if err != nil {
			t.Fatalf("PromoteInternalComponent: %v", err)
		}

		var kind, techniqueID string
		var supportedOS []string
		if err := pool.QueryRow(ctx, `SELECT kind, technique_id, supported_os FROM content_components WHERE id = $1`,
			componentID).Scan(&kind, &techniqueID, &supportedOS); err != nil {
			t.Fatal(err)
		}
		if kind != "internal" {
			t.Fatalf("expected kind=internal, got %q", kind)
		}
		if techniqueID != "T1059" {
			t.Fatalf("expected technique_id=T1059, got %q", techniqueID)
		}
		if len(supportedOS) != 1 || supportedOS[0] != "windows" {
			t.Fatalf("expected supported_os carried forward from origin scenario ([windows]), got %v", supportedOS)
		}
	})
}

func TestPromoteInternalComponent_RefusesPromotingFromAComposedCandidate(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		composedID := seedExecutableVersion(t, pool, "intel-composed-source", "- name: s\n  technique_id: T1059\n  framework: art\n  test_index: 0\n")
		// Mark it as composed by inserting a content_version_components row --
		// this is what a real composition (Task 4) would have produced.
		if _, err := pool.Exec(ctx, `INSERT INTO content_components
			(kind, technique_id, title, origin_content_version_id, step_snapshot, promoted_by)
			VALUES ('internal', 'T1053', 'other component', $1, '{}', 'test')`, composedID); err != nil {
			t.Fatal(err)
		}
		var someOtherComponentID string
		if err := pool.QueryRow(ctx, `SELECT id FROM content_components WHERE origin_content_version_id = $1`, composedID).Scan(&someOtherComponentID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO content_version_components (content_version_id, component_id, step_order) VALUES ($1, $2, 0)`,
			composedID, someOtherComponentID); err != nil {
			t.Fatal(err)
		}

		reg := New(pool, testutil.DevVerifier())
		_, err := reg.PromoteInternalComponent(ctx, composedID, 0, "admin-test")
		if err == nil {
			t.Fatal("expected promotion from a composed candidate's own content_version to be refused")
		}
	})
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/contentregistry/... -run TestPromoteInternalComponent -v -count=1`
Expected: FAIL — compile error, `Registry.PromoteInternalComponent` undefined.

- [ ] **Step 3: Implement**

```go
// orchestrator/internal/contentregistry/components_promote.go
package contentregistry

import (
	"context"
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/audspect/bas/internal/scenario"
)

// PromoteInternalComponent turns one step of an already-executable
// content_version into a reusable, first-class component (spec §2.2). The
// origin version must currently pass the Executable() gate, and must not
// itself be a composed candidate (spec §2.5, acceptance criterion 7).
func (r *Registry) PromoteInternalComponent(ctx context.Context, contentVersionID string, stepIndex int, actor string) (string, error) {
	var contentID, origin, trust, lifecycle string
	var artifact []byte
	if err := r.pool.QueryRow(ctx,
		`SELECT content_id, origin, trust_level, lifecycle, artifact_bytes FROM content_versions WHERE id = $1`,
		contentVersionID).Scan(&contentID, &origin, &trust, &lifecycle, &artifact); err != nil {
		return "", fmt.Errorf("content_version %s: %w", contentVersionID, err)
	}
	if !Executable(Origin(origin), Trust(trust), Lifecycle(lifecycle), r.devBuild()) {
		return "", fmt.Errorf("content_version %s is not executable (origin=%s trust=%s lifecycle=%s)", contentVersionID, origin, trust, lifecycle)
	}
	var composedCount int
	if err := r.pool.QueryRow(ctx,
		`SELECT count(*) FROM content_version_components WHERE content_version_id = $1`,
		contentVersionID).Scan(&composedCount); err != nil {
		return "", err
	}
	if composedCount > 0 {
		return "", fmt.Errorf("content_version %s is itself a composed candidate -- components can only be promoted from a single-source scenario (spec §2.5)", contentVersionID)
	}

	var sc scenario.Scenario
	if err := yaml.Unmarshal(artifact, &sc); err != nil {
		return "", fmt.Errorf("parse artifact: %w", err)
	}
	if stepIndex < 0 || stepIndex >= len(sc.Steps) {
		return "", fmt.Errorf("step index %d out of range (scenario has %d steps)", stepIndex, len(sc.Steps))
	}
	step := sc.Steps[stepIndex]
	snapshot, err := json.Marshal(step)
	if err != nil {
		return "", err
	}

	var componentID string
	if err := r.pool.QueryRow(ctx, `INSERT INTO content_components
		(kind, technique_id, title, supported_os, origin_content_version_id, step_snapshot, promoted_by)
		VALUES ('internal', $1, $2, $3, $4, $5, $6) RETURNING id`,
		step.TechniqueID, step.Name, nonNil(sc.SupportedOS), contentVersionID, snapshot, actor,
	).Scan(&componentID); err != nil {
		return "", err
	}
	return componentID, nil
}
```

`nonNil` already exists in this package (used in `store.go`'s `createVersion` for `supportedOS`) — confirm it's accessible from this new file (same package, no import needed) before writing this step; if its signature doesn't match `[]string`, adapt the call rather than guessing.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/contentregistry/... -run TestPromoteInternalComponent -v -count=1`
Expected: PASS, all 3 tests.

- [ ] **Step 5: Write the failing handler test**

```go
// orchestrator/internal/api/component_promote_handler_test.go
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/contentregistry"
	"github.com/audspect/bas/internal/testutil"
)

func TestPromoteComponent_Returns200AndComponentID(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `INSERT INTO scenarios (scenario_id, origin) VALUES ('intel-handler-promote', 'LOCAL') ON CONFLICT DO NOTHING`); err != nil {
			t.Fatal(err)
		}
		var versionID string
		if err := pool.QueryRow(ctx, `INSERT INTO content_versions
			(content_id, origin, version, artifact_sha256, artifact_size, artifact_bytes,
			 trust_level, lifecycle, intake_source, schema_version, technique_ids, supported_os, created_by)
			VALUES ('intel-handler-promote', 'LOCAL', 1, 'sha-h', 1,
			 'id: intel-handler-promote\nname: T\nsupported_os: [windows]\nsteps:\n- name: s\n  technique_id: T1059\n  framework: art\n  test_index: 0\n',
			 'LOCAL_TRUSTED', 'PUBLISHED_LOCAL', 'custom', 1, '{T1059}', '{windows}', 'test') RETURNING id`).Scan(&versionID); err != nil {
			t.Fatal(err)
		}

		h := &Handler{db: pool}
		h.engine = testutil.RegistryOnlyEngine(pool, contentregistry.New(pool, testutil.DevVerifier()))
		body, _ := json.Marshal(map[string]any{"contentVersionId": versionID, "stepIndex": 0})
		req := httptest.NewRequest(http.MethodPost, "/api/content-registry/components/promote", bytes.NewReader(body))
		w := httptest.NewRecorder()
		h.PromoteComponent(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	})
}
```

`testutil.RegistryOnlyEngine` does not exist yet — before writing this step, use the SAME `registryEngine(t, pool)` package-level helper from `content_gate_test.go` that Phase 10's handler tests used (`e, _, _ := registryEngine(t, pool)`, then `h.engine = e`), not a new testutil function. The sketch names the shape; copy the real, already-existing helper call.

- [ ] **Step 6: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestPromoteComponent -v -count=1`
Expected: FAIL — compile error, `h.PromoteComponent` undefined.

- [ ] **Step 7: Implement the handler, route, and RBAC row**

In `orchestrator/internal/api/handlers.go`, add near `GetThreatExposure` (Phase 10's handler, same file):

```go
// PromoteComponent handles POST /api/content-registry/components/promote --
// turns one step of an executable content_version into a reusable internal
// component (TCF Phase 4, spec
// docs/superpowers/specs/2026-10-14-tcf-phase4-content-composition-design.md §2.2).
func (h *Handler) PromoteComponent(w http.ResponseWriter, r *http.Request) {
	reg, ok := h.engine.Registry().(*contentregistry.Registry)
	if !ok || reg == nil {
		jsonError(w, "content registry not available", http.StatusServiceUnavailable)
		return
	}
	var body struct {
		ContentVersionID string `json:"contentVersionId"`
		StepIndex        int    `json:"stepIndex"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	actor := actorFor(r)
	componentID, err := reg.PromoteInternalComponent(r.Context(), body.ContentVersionID, body.StepIndex, actor)
	if err != nil {
		jsonError(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	respond(w, map[string]string{"componentId": componentID})
}
```

Before writing this, grep `handlers.go` for `actorFor(r)` to confirm its exact signature (it's referenced in the Phase 7 gap-analysis findings earlier this session as the existing "derive actor from JWT claims, never request body" helper — confirm the call shape matches rather than guessing). `encoding/json` must already be imported in `handlers.go` (it's used pervasively); confirm with a grep rather than assuming.

In `orchestrator/internal/api/routes.go`, add next to `/api/threats/exposure`:

```go
		r.With(auth.RequirePermission(auth.CanManageComponents)).Post("/api/content-registry/components/promote", h.PromoteComponent)
```

In `orchestrator/internal/api/rbac_matrix_test.go`, add next to the `/api/intel/sources/{id}/trust` row added in this session's earlier pre-PR fix:

```go
	{http.MethodPost, "/api/content-registry/components/promote", tierPermission, auth.CanManageComponents},
```

- [ ] **Step 8: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run "TestPromoteComponent|TestRBACMatrix" -v -count=1`
Expected: PASS for `TestPromoteComponent_*` and all `TestRBACMatrix_*` subtests involving the new route; `TestRBACMatrix_NoDrift` passes overall (the pre-existing gap this session already fixed).

- [ ] **Step 9: gofmt and commit**

Run: `cd orchestrator && gofmt -l internal/contentregistry/components_promote.go internal/contentregistry/components_promote_test.go internal/api/handlers.go internal/api/routes.go internal/api/rbac_matrix_test.go internal/api/component_promote_handler_test.go`
Expected: empty output.

```bash
git add orchestrator/internal/contentregistry/components_promote.go orchestrator/internal/contentregistry/components_promote_test.go orchestrator/internal/api/handlers.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go orchestrator/internal/api/component_promote_handler_test.go
git commit -m "feat(tcf-phase4): internal component promotion"
```

---

### Task 3: External component reference registration

**Files:**
- Create: `orchestrator/internal/contentregistry/components_reference.go`
- Create: `orchestrator/internal/contentregistry/components_reference_test.go`
- Modify: `orchestrator/internal/api/handlers.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`
- Test: `orchestrator/internal/api/component_reference_handler_test.go`

**Interfaces:**
- Consumes: Task 1's `content_components` table, `auth.CanManageComponents`.
- Produces: `Registry.RegisterExternalComponent(ctx context.Context, framework, techniqueID, title, abilityID, actionKey string, testIndex int, libraryVersion string, supportedOS []string, actor string) (string, error)` — Task 4 consumes component rows this writes, by id, the same way it consumes internal ones. `actionKey` is the `scenario.ResolveExecutionClass` action key this reference should carry into a composed candidate's pinned `Step` (empty string resolves to the catalog's own "enumerate" default per `execclass.go:1088-1095` — confirmed in this plan's grounding, not a guess).

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/contentregistry/components_reference_test.go
package contentregistry

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/testutil"
)

func TestRegisterExternalComponent_CreatesExternalRow(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpoolPool) {
		// placeholder import note below
	})
}
```

As in Task 2 Step 1, confirm this package's real `sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {...})` signature from a sibling test file before writing the real version; the type name above is intentionally wrong as a reminder to verify, not to copy. The real test:

```go
package contentregistry

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRegisterExternalComponent_CreatesExternalRow(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reg := New(pool, nil)
		id, err := reg.RegisterExternalComponent(context.Background(), "art", "T1059", "ART T1059 test", "", "", 5, "v1.2.3", []string{"windows"}, "admin-test")
		if err != nil {
			t.Fatalf("RegisterExternalComponent: %v", err)
		}
		var kind, framework string
		var testIndex int
		if err := pool.QueryRow(context.Background(),
			`SELECT kind, framework, test_index FROM content_components WHERE id = $1`, id).Scan(&kind, &framework, &testIndex); err != nil {
			t.Fatal(err)
		}
		if kind != "external" || framework != "art" || testIndex != 5 {
			t.Fatalf("expected kind=external framework=art test_index=5, got kind=%s framework=%s test_index=%d", kind, framework, testIndex)
		}
	})
}

func TestRegisterExternalComponent_RequiresFramework(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reg := New(pool, nil)
		_, err := reg.RegisterExternalComponent(context.Background(), "", "T1059", "bad", "", "", 0, "v1", nil, "admin-test")
		if err == nil {
			t.Fatal("expected an empty framework to be refused")
		}
	})
}
```

`New(pool, nil)` for the verifier argument: confirm this is safe for a test that never calls anything verifier-dependent (`RegisterExternalComponent` doesn't touch `devBuild()`/signatures) by checking `contentregistry.New`'s body doesn't dereference `v` at construction time; if it does, use `testutil.DevVerifier()` instead, matching every other test in this package.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/contentregistry/... -run TestRegisterExternalComponent -v -count=1`
Expected: FAIL — compile error, `Registry.RegisterExternalComponent` undefined.

- [ ] **Step 3: Implement**

```go
// orchestrator/internal/contentregistry/components_reference.go
package contentregistry

import (
	"context"
	"errors"
)

// RegisterExternalComponent records a reference to an existing ART/Caldera
// library technique as a reusable external component (spec §2.1). Unlike an
// internal component, there is no origin content_version to validate against
// -- the framework's own catalog is the source of truth for whether the
// reference is real; this registry only records the pointer and the library
// version active at reference time.
func (r *Registry) RegisterExternalComponent(ctx context.Context, framework, techniqueID, title, abilityID, actionKey string, testIndex int, libraryVersion string, supportedOS []string, actor string) (string, error) {
	if framework == "" {
		return "", errors.New("framework is required for an external component")
	}
	if techniqueID == "" {
		return "", errors.New("technique_id is required")
	}
	var id string
	if err := r.pool.QueryRow(ctx, `INSERT INTO content_components
		(kind, technique_id, title, supported_os, framework, ability_id, action_key, test_index, library_version, promoted_by)
		VALUES ('external', $1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
		techniqueID, title, nonNil(supportedOS), framework, abilityID, actionKey, testIndex, libraryVersion, actor,
	).Scan(&id); err != nil {
		return "", err
	}
	return id, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/contentregistry/... -run TestRegisterExternalComponent -v -count=1`
Expected: PASS, both tests.

- [ ] **Step 5: Write the failing handler test**

```go
// orchestrator/internal/api/component_reference_handler_test.go
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestReferenceComponent_Returns200AndComponentID(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, _, _ := registryEngine(t, pool)
		h := &Handler{db: pool, engine: e}
		body, _ := json.Marshal(map[string]any{
			"framework": "art", "techniqueId": "T1059", "title": "ART T1059", "actionKey": "",
			"testIndex": 5, "libraryVersion": "v1.2.3", "supportedOS": []string{"windows"},
		})
		req := httptest.NewRequest(http.MethodPost, "/api/content-registry/components/reference", bytes.NewReader(body))
		w := httptest.NewRecorder()
		h.ReferenceComponent(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	})
}
```

- [ ] **Step 6: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestReferenceComponent -v -count=1`
Expected: FAIL — compile error, `h.ReferenceComponent` undefined.

- [ ] **Step 7: Implement the handler, route, and RBAC row**

In `orchestrator/internal/api/handlers.go`, next to `PromoteComponent`:

```go
// ReferenceComponent handles POST /api/content-registry/components/reference
// -- registers a reusable external (ART/Caldera) component reference
// (spec §2.1, §2.2).
func (h *Handler) ReferenceComponent(w http.ResponseWriter, r *http.Request) {
	reg, ok := h.engine.Registry().(*contentregistry.Registry)
	if !ok || reg == nil {
		jsonError(w, "content registry not available", http.StatusServiceUnavailable)
		return
	}
	var body struct {
		Framework      string   `json:"framework"`
		TechniqueID    string   `json:"techniqueId"`
		Title          string   `json:"title"`
		AbilityID      string   `json:"abilityId"`
		ActionKey      string   `json:"actionKey"`
		TestIndex      int      `json:"testIndex"`
		LibraryVersion string   `json:"libraryVersion"`
		SupportedOS    []string `json:"supportedOS"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	actor := actorFor(r)
	componentID, err := reg.RegisterExternalComponent(r.Context(), body.Framework, body.TechniqueID, body.Title,
		body.AbilityID, body.ActionKey, body.TestIndex, body.LibraryVersion, body.SupportedOS, actor)
	if err != nil {
		jsonError(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	respond(w, map[string]string{"componentId": componentID})
}
```

In `orchestrator/internal/api/routes.go`, next to the promote route:

```go
		r.With(auth.RequirePermission(auth.CanManageComponents)).Post("/api/content-registry/components/reference", h.ReferenceComponent)
```

In `orchestrator/internal/api/rbac_matrix_test.go`, next to the promote row:

```go
	{http.MethodPost, "/api/content-registry/components/reference", tierPermission, auth.CanManageComponents},
```

- [ ] **Step 8: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run "TestReferenceComponent|TestRBACMatrix" -v -count=1`
Expected: PASS.

- [ ] **Step 9: gofmt and commit**

Run: `cd orchestrator && gofmt -l internal/contentregistry/components_reference.go internal/contentregistry/components_reference_test.go internal/api/handlers.go internal/api/routes.go internal/api/rbac_matrix_test.go internal/api/component_reference_handler_test.go`
Expected: empty output.

```bash
git add orchestrator/internal/contentregistry/components_reference.go orchestrator/internal/contentregistry/components_reference_test.go orchestrator/internal/api/handlers.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go orchestrator/internal/api/component_reference_handler_test.go
git commit -m "feat(tcf-phase4): external component reference registration"
```

---

### Task 4: Composition core logic (resolve, refuse, create)

**Files:**
- Create: `orchestrator/internal/contentregistry/compose.go`
- Create: `orchestrator/internal/contentregistry/compose_test.go`
- Modify: `orchestrator/internal/contentregistry/types.go:57-62` (add `ActorComposer`)

**Interfaces:**
- Consumes: Task 2's/Task 3's `content_components` rows (by id), the package-private `createVersion`/`analyzeArtifact`/`safetyVerdict` (already exist in this package, confirmed at `store.go:142`, `analyze.go:61`, `analyze.go:182`).
- Produces: `Registry.Compose(ctx context.Context, componentIDs []string, threatID, actor string) (string, bool, error)` (versionID, created, error — same return shape as `RegisterGenerated`/`createVersion`) — Task 5's handler calls this directly.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/contentregistry/compose_test.go
package contentregistry

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/testutil"
)

func TestCompose_RefusesWhenNoCommonOS(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reg := New(pool, testutil.DevVerifier())
		ctx := context.Background()
		c1, err := reg.RegisterExternalComponent(ctx, "art", "T1059", "c1", "", "", 1, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		c2, err := reg.RegisterExternalComponent(ctx, "art", "T1053", "c2", "", "", 2, "v1", []string{"linux"}, "test")
		if err != nil {
			t.Fatal(err)
		}

		threatID := seedComposeThreat(t, pool, "APT-compose-noos")
		var countBefore int
		pool.QueryRow(ctx, `SELECT count(*) FROM content_versions`).Scan(&countBefore)

		_, _, err = reg.Compose(ctx, []string{c1, c2}, threatID, "admin-test")
		if err == nil {
			t.Fatal("expected refusal: components share no common supported_os")
		}
		var countAfter int
		pool.QueryRow(ctx, `SELECT count(*) FROM content_versions`).Scan(&countAfter)
		if countAfter != countBefore {
			t.Fatalf("expected zero new content_versions rows on refusal, got %d new", countAfter-countBefore)
		}
	})
}

func TestCompose_RefusesWhenAStepIsDestructive(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reg := New(pool, testutil.DevVerifier())
		ctx := context.Background()
		// T1003.002 action_key "hive_save" is confirmed ClassDestructive in
		// scenario/execclass.go:86-90 ("reg.exe save of SAM/SYSTEM hives...").
		// ResolveExecutionClass defaults an EMPTY action_key to "enumerate"
		// (execclass.go:1088-1095), which for most techniques including this
		// one resolves NonDestructive -- so this test must pass a real,
		// non-empty action_key to actually exercise the destructive branch,
		// not rely on the empty-string default.
		c1, err := reg.RegisterExternalComponent(ctx, "art", "T1003.002", "destructive", "", "hive_save", 1, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		// Needs >=2 components (Compose's own minimum, see implementation)
		// sharing a common OS, so the refusal under test is the safety
		// check, not the earlier OS-intersection check.
		c2, err := reg.RegisterExternalComponent(ctx, "art", "T1059", "benign", "", "", 2, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		threatID := seedComposeThreat(t, pool, "APT-compose-destructive")

		_, _, err = reg.Compose(ctx, []string{c1, c2}, threatID, "admin-test")
		if err == nil {
			t.Fatal("expected refusal: a destructive step should fail the safety check")
		}
	})
}

func TestCompose_SucceedsAndRecordsProvenance(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reg := New(pool, testutil.DevVerifier())
		ctx := context.Background()
		c1, err := reg.RegisterExternalComponent(ctx, "art", "T1059", "c1", "", "", 1, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		c2, err := reg.RegisterExternalComponent(ctx, "art", "T1053", "c2", "", "", 2, "v1", []string{"windows", "linux"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		threatID := seedComposeThreat(t, pool, "APT-compose-ok")

		versionID, created, err := reg.Compose(ctx, []string{c1, c2}, threatID, "admin-test")
		if err != nil {
			t.Fatalf("Compose: %v", err)
		}
		if !created {
			t.Fatal("expected created=true for a brand-new composition")
		}

		var origin, lifecycle string
		if err := pool.QueryRow(ctx, `SELECT origin, lifecycle FROM content_versions WHERE id = $1`, versionID).Scan(&origin, &lifecycle); err != nil {
			t.Fatal(err)
		}
		if origin != "LOCAL" || lifecycle != "DRAFT" {
			t.Fatalf("expected origin=LOCAL lifecycle=DRAFT, got origin=%s lifecycle=%s", origin, lifecycle)
		}

		var componentCount int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM content_version_components WHERE content_version_id = $1`, versionID).Scan(&componentCount); err != nil {
			t.Fatal(err)
		}
		if componentCount != 2 {
			t.Fatalf("expected provenance for both components, got %d rows", componentCount)
		}
	})
}

// TestCompose_VisibleViaExistingLoadVersion pins acceptance criterion 5 and
// Review Focus item 5: a composed candidate must be readable through the
// SAME existing registry read path every other content_version uses, with
// no special-casing. LoadVersion (store.go:54) is that existing path.
func TestCompose_VisibleViaExistingLoadVersion(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		reg := New(pool, testutil.DevVerifier())
		ctx := context.Background()
		c1, err := reg.RegisterExternalComponent(ctx, "art", "T1059", "c1", "", "", 1, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		c2, err := reg.RegisterExternalComponent(ctx, "art", "T1053", "c2", "", "", 2, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		threatID := seedComposeThreat(t, pool, "APT-compose-visibility")

		versionID, _, err := reg.Compose(ctx, []string{c1, c2}, threatID, "admin-test")
		if err != nil {
			t.Fatalf("Compose: %v", err)
		}
		if _, err := reg.LoadVersion(ctx, versionID); err != nil {
			t.Fatalf("expected composed candidate visible via the existing LoadVersion path, got: %v", err)
		}
	})
}

func seedComposeThreat(t *testing.T, pool *pgxpool.Pool, name string) string {
	t.Helper()
	idStore := threatidentity.NewStore(pool)
	resolved, err := idStore.ResolveAndPersist(context.Background(), threatidentity.Incoming{Name: name}, threatidentity.ProfileFields{})
	if err != nil {
		t.Fatal(err)
	}
	return resolved.ThreatID
}
```

This file needs `"github.com/jackc/pgx/v5/pgxpool"` and `"github.com/audspect/bas/internal/threatidentity"` imported alongside the two already shown. Before finalizing `TestCompose_RefusesWhenAStepIsDestructive`, open `orchestrator/internal/scenario/execclass.go` and confirm a real `(technique_id, action_key="")` pair that resolves to `ClassDestructive` — do not ship the test with an unverified guess; if `T1490` with an empty action key does not resolve to destructive on its own, find one that does (or construct the pair that does) and use that instead, updating the comment to say what you verified.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/contentregistry/... -run TestCompose -v -count=1`
Expected: FAIL — compile error, `Registry.Compose` undefined.

- [ ] **Step 3: Add the `ActorComposer` constant**

In `orchestrator/internal/contentregistry/types.go`, in the const block with `ActorGenerator` (lines 57-62):

```go
const (
	ActorIntake     = "intake"
	ActorGenerator  = "generator:connector"
	ActorComposer   = "composer:admin"
	ActorMigration  = "migration:pre-registry"
	MigrationReason = "historical authorization: authored via operator UI before approval tracking existed; not reviewed during migration"
)
```

- [ ] **Step 4: Implement**

```go
// orchestrator/internal/contentregistry/compose.go
package contentregistry

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/audspect/bas/internal/scenario"
)

type loadedComponent struct {
	id           string
	techniqueID  string
	supportedOS  []string
	kind         string
	stepSnapshot []byte // internal only
	framework    string // external only
	abilityID    string
	actionKey    string
	testIndex    int
}

// Compose assembles the given components into a new content_version,
// refusing before any row is created if the components share no common
// supported_os or if the assembled Steps list fails the existing
// safetyVerdict worst-step-wins check (spec §2.3-§2.4).
func (r *Registry) Compose(ctx context.Context, componentIDs []string, threatID, actor string) (string, bool, error) {
	if len(componentIDs) < 2 {
		return "", false, fmt.Errorf("composition requires at least 2 components, got %d", len(componentIDs))
	}
	components, err := r.loadComponents(ctx, componentIDs)
	if err != nil {
		return "", false, err
	}

	commonOS := components[0].supportedOS
	for _, c := range components[1:] {
		commonOS = intersect(commonOS, c.supportedOS)
	}
	if len(commonOS) == 0 {
		return "", false, fmt.Errorf("composition refused: components share no common supported_os")
	}

	sc := scenario.Scenario{
		ID:          "composed-" + uuid.New().String(),
		Name:        "Composed candidate",
		SupportedOS: commonOS,
	}
	for _, c := range components {
		step, err := c.toStep()
		if err != nil {
			return "", false, err
		}
		sc.Steps = append(sc.Steps, step)
	}
	artifact, err := yaml.Marshal(&sc)
	if err != nil {
		return "", false, err
	}

	a, err := analyzeArtifact(artifact)
	if err != nil {
		return "", false, err
	}
	if a.structural.outcome != "PASS" {
		return "", false, fmt.Errorf("composition refused: structural check failed: %v", a.structural.detail["problems"])
	}
	if a.safety.verdict == string(scenario.ClassDestructive) {
		return "", false, fmt.Errorf("composition refused: assembled steps classify as destructive")
	}

	versionID, created, err := r.createVersion(ctx, newVersion{
		contentID: sc.ID, origin: OriginLocal, source: SourceCustom,
		artifact: artifact, trust: TrustUntrusted, lifecycle: LifecycleDraft, actor: ActorComposer,
		analysis: a, threatID: threatID, generationRef: "composed",
	})
	if err != nil {
		return "", false, err
	}
	if created {
		for i, c := range components {
			if _, err := r.pool.Exec(ctx, `INSERT INTO content_version_components (content_version_id, component_id, step_order) VALUES ($1, $2, $3)`,
				versionID, c.id, i); err != nil {
				return "", false, err
			}
		}
	}
	return versionID, created, nil
}

func (r *Registry) loadComponents(ctx context.Context, ids []string) ([]loadedComponent, error) {
	out := make([]loadedComponent, 0, len(ids))
	for _, id := range ids {
		var c loadedComponent
		var snapshot []byte
		var framework, abilityID, actionKey *string
		var testIndex *int
		if err := r.pool.QueryRow(ctx, `SELECT id, technique_id, supported_os, kind, step_snapshot, framework, ability_id, action_key, test_index
			FROM content_components WHERE id = $1`, id).
			Scan(&c.id, &c.techniqueID, &c.supportedOS, &c.kind, &snapshot, &framework, &abilityID, &actionKey, &testIndex); err != nil {
			return nil, fmt.Errorf("component %s: %w", id, err)
		}
		c.stepSnapshot = snapshot
		if framework != nil {
			c.framework = *framework
		}
		if abilityID != nil {
			c.abilityID = *abilityID
		}
		if actionKey != nil {
			c.actionKey = *actionKey
		}
		if testIndex != nil {
			c.testIndex = *testIndex
		}
		out = append(out, c)
	}
	return out, nil
}

func (c loadedComponent) toStep() (scenario.Step, error) {
	if c.kind == "internal" {
		var step scenario.Step
		if err := json.Unmarshal(c.stepSnapshot, &step); err != nil {
			return scenario.Step{}, fmt.Errorf("unmarshal snapshot for component %s: %w", c.id, err)
		}
		return step, nil
	}
	return scenario.Step{
		Name:        c.techniqueID + " (external: " + c.framework + ")",
		TechniqueID: c.techniqueID,
		Framework:   c.framework,
		AbilityID:   c.abilityID,
		ActionKey:   c.actionKey,
		TestIndex:   c.testIndex,
	}, nil
}

func intersect(a, b []string) []string {
	set := map[string]bool{}
	for _, x := range a {
		set[x] = true
	}
	var out []string
	for _, x := range b {
		if set[x] {
			out = append(out, x)
		}
	}
	return out
}

```

`sc.ID` deliberately drops `threatID` from the generated content id (unlike the earlier sketch) -- `contentIDPattern` (`analyze.go:29`) only allows `[A-Za-z0-9._-]`, and a threat id's own format is not guaranteed to satisfy that charset, so concatenating it risked an avoidable STRUCTURAL FAIL. The threat relationship is already recorded correctly via `newVersion.threatID` in the `createVersion` call below (a `content_version_threats` row), independent of what the content id string itself contains.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/contentregistry/... -run TestCompose -v -count=1`
Expected: PASS, all 4 tests.

- [ ] **Step 6: Run the full contentregistry suite**

Run: `cd orchestrator && go test ./internal/contentregistry/... -count=1`
Expected: PASS (confirms Task 2's/Task 3's tests and everything pre-existing in this package still pass alongside Task 4's additions).

- [ ] **Step 7: gofmt and commit**

Run: `cd orchestrator && gofmt -l internal/contentregistry/compose.go internal/contentregistry/compose_test.go internal/contentregistry/types.go`
Expected: empty output.

```bash
git add orchestrator/internal/contentregistry/compose.go orchestrator/internal/contentregistry/compose_test.go orchestrator/internal/contentregistry/types.go
git commit -m "feat(tcf-phase4): composition core logic -- resolve, refuse, create"
```

---

### Task 5: Composition API endpoint

**Files:**
- Modify: `orchestrator/internal/api/handlers.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`
- Test: `orchestrator/internal/api/compose_handler_test.go`

**Interfaces:**
- Consumes: Task 4's `Registry.Compose(ctx, componentIDs []string, threatID, actor string) (string, bool, error)`.
- Produces: `POST /api/content-registry/compose` — last task, nothing downstream in this plan.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/api/compose_handler_test.go
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/contentregistry"
	"github.com/audspect/bas/internal/testutil"
	"github.com/audspect/bas/internal/threatidentity"
)

func TestComposeContent_Returns200AndVersionID(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		reg := contentregistry.New(pool, testutil.DevVerifier())
		c1, err := reg.RegisterExternalComponent(ctx, "art", "T1059", "c1", "", "", 1, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		c2, err := reg.RegisterExternalComponent(ctx, "art", "T1053", "c2", "", "", 2, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		idStore := threatidentity.NewStore(pool)
		resolved, err := idStore.ResolveAndPersist(ctx, threatidentity.Incoming{Name: "APT-compose-handler"}, threatidentity.ProfileFields{})
		if err != nil {
			t.Fatal(err)
		}

		e, _, _ := registryEngine(t, pool)
		h := &Handler{db: pool, engine: e}
		body, _ := json.Marshal(map[string]any{"componentIds": []string{c1, c2}, "threatId": resolved.ThreatID})
		req := httptest.NewRequest(http.MethodPost, "/api/content-registry/compose", bytes.NewReader(body))
		w := httptest.NewRecorder()
		h.ComposeContent(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	})
}

func TestComposeContent_RefusalReturns422(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		reg := contentregistry.New(pool, testutil.DevVerifier())
		c1, err := reg.RegisterExternalComponent(ctx, "art", "T1059", "c1", "", "", 1, "v1", []string{"windows"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		c2, err := reg.RegisterExternalComponent(ctx, "art", "T1053", "c2", "", "", 2, "v1", []string{"linux"}, "test")
		if err != nil {
			t.Fatal(err)
		}
		idStore := threatidentity.NewStore(pool)
		resolved, err := idStore.ResolveAndPersist(ctx, threatidentity.Incoming{Name: "APT-compose-handler-refuse"}, threatidentity.ProfileFields{})
		if err != nil {
			t.Fatal(err)
		}

		e, _, _ := registryEngine(t, pool)
		h := &Handler{db: pool, engine: e}
		body, _ := json.Marshal(map[string]any{"componentIds": []string{c1, c2}, "threatId": resolved.ThreatID})
		req := httptest.NewRequest(http.MethodPost, "/api/content-registry/compose", bytes.NewReader(body))
		w := httptest.NewRecorder()
		h.ComposeContent(w, req)

		if w.Code != http.StatusUnprocessableEntity {
			t.Fatalf("expected 422 on a no-common-OS refusal, got %d: %s", w.Code, w.Body.String())
		}
	})
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run TestComposeContent -v -count=1`
Expected: FAIL — compile error, `h.ComposeContent` undefined.

- [ ] **Step 3: Implement the handler, route, and RBAC row**

In `orchestrator/internal/api/handlers.go`, next to `ReferenceComponent`:

```go
// ComposeContent handles POST /api/content-registry/compose -- assembles
// the given components into a new content_version (TCF Phase 4, spec §2.3).
func (h *Handler) ComposeContent(w http.ResponseWriter, r *http.Request) {
	reg, ok := h.engine.Registry().(*contentregistry.Registry)
	if !ok || reg == nil {
		jsonError(w, "content registry not available", http.StatusServiceUnavailable)
		return
	}
	var body struct {
		ComponentIDs []string `json:"componentIds"`
		ThreatID     string   `json:"threatId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	actor := actorFor(r)
	versionID, created, err := reg.Compose(r.Context(), body.ComponentIDs, body.ThreatID, actor)
	if err != nil {
		jsonError(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	respond(w, map[string]any{"versionId": versionID, "created": created})
}
```

In `orchestrator/internal/api/routes.go`, next to the reference route:

```go
		r.With(auth.RequirePermission(auth.CanManageComponents)).Post("/api/content-registry/compose", h.ComposeContent)
```

In `orchestrator/internal/api/rbac_matrix_test.go`, next to the reference row:

```go
	{http.MethodPost, "/api/content-registry/compose", tierPermission, auth.CanManageComponents},
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run "TestComposeContent|TestRBACMatrix" -v -count=1`
Expected: PASS.

- [ ] **Step 5: Run the full api package test suite**

Run: `cd orchestrator && go test ./internal/api/... -count=1`
Expected: PASS (full package, confirming Tasks 2/3/4/5's additions plus everything pre-existing all pass together). `TestRBACMatrix_NoDrift` must pass (the pre-existing gap this session already fixed, re-confirmed here).

- [ ] **Step 6: gofmt and commit**

Run: `cd orchestrator && gofmt -l internal/api/handlers.go internal/api/routes.go internal/api/rbac_matrix_test.go internal/api/compose_handler_test.go`
Expected: empty output.

```bash
git add orchestrator/internal/api/handlers.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go orchestrator/internal/api/compose_handler_test.go
git commit -m "feat(tcf-phase4): POST /api/content-registry/compose"
```
