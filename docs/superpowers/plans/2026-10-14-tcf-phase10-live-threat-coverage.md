# TCF Phase 10 — Live Threat Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Answer "given the threats currently known to us, which ones can we meaningfully simulate with available content, and where are the gaps?" by assembling three already-existing, already-populated data relationships (`threats`, `content_version_threats`, `scenario_runs.content_version_id`) into one honest, customer-facing read endpoint and a new section on the existing Coverage page.

**Architecture:** One new package (`internal/exposure`) does the data assembly — no new schema, no new tables. It reads `threats`/`threat_techniques` (threat identity + evidence layer, built in earlier TCF phases), `content_version_threats`/`content_versions` (the Phase 2C threat↔content join, including the already-populated `technique_ids text[]` column), and `scenario_runs.content_version_id` (the already-populated run↔version FK), and reuses `contentregistry.Registry.Summaries`' existing gate logic for "is this executable" rather than re-deriving it. One new handler exposes it at `GET /api/threats/exposure`. One new frontend section on the Coverage page renders it, clearly separated from the existing static-ATT&CK technique drilldown.

**Tech Stack:** Go, PostgreSQL (pgx/v5), the existing `internal/threatidentity`, `internal/evidence`, `internal/contentregistry`, `internal/db`, `internal/api` packages, plain JS (no framework) in `orchestrator/web`.

**Spec:** `docs/superpowers/specs/2026-10-14-tcf-phase10-live-threat-coverage-design.md`

## Global Constraints

- The endpoint is `tierAny` (every authenticated user) — no new permission, matching every other Coverage-adjacent route (spec §2.1, confirmed via `rbac_matrix_test.go` rows for `/api/coverage/analytics`, `/api/techniques/unified`, `/api/attack/matrix`).
- `content[].isExecutable` must come from `contentregistry.Registry.Summaries(ctx)` (`validations.go:191-224`) — never a second, independently-derived definition of executable (spec acceptance criterion 3).
- `content[].validation` is always the literal string `"structural-only"` — never computed to imply dynamic validation happened (spec §1.6, acceptance criterion 4).
- `content[].lastRunAt`/`runCount` only ever count rows where `scenario_runs.content_version_id IS NOT NULL` — never a `scenario_id` string-match fallback (spec acceptance criterion 5).
- A threat with no matching rows in `content_version_threats` renders `content: []`, never omitted or defaulted to "covered" (spec acceptance criterion 2).
- `?limit=`/`?offset=` are bounded: default 20, max 100 (spec acceptance criterion 8, matching `GetCoverageAnalytics`'s own `?limit=` convention, `handlers.go:4531+`).
- The existing static-ATT&CK technique drilldown (`coverage.js`'s `openTechnique`, "Known actors" row) is relabeled only — its behavior and data source do not change (spec acceptance criterion 6).

## Review Focus

- A threat with active techniques but zero `content_version_threats` rows — the response must show an honest empty `content: []`, not an error, not an omitted threat, not a false "covered" inference.
- A content version whose `lifecycle` is `DRAFT` — must still appear in `content[]` with `isExecutable: false` (drafts are real, relevant information), not be filtered out.
- A technique in `threat_techniques` that no content version's `technique_ids` array contains — must show `hasExecutableContent: false`, not an incorrect `true`.
- A content version reachable only through a `remediation_dispatch.go`/`variant_handlers.go` run (no `content_version_id` set on that row) — `lastRunAt`/`runCount` must show no-run for it, not silently pick up an unrelated run via some fallback.
- `?limit=`/`?offset=` at the boundary: 0 active threats, exactly `limit` threats, more than `limit`, a garbage/negative `limit` or `offset` value — no off-by-one, no unbounded query, no panic on bad input.

---

### Task 1: `internal/exposure` package — data assembly

**Files:**
- Create: `orchestrator/internal/exposure/exposure.go`
- Create: `orchestrator/internal/exposure/exposure_test.go`
- Create: `orchestrator/internal/exposure/testmain_test.go`

**Interfaces:**
- Consumes: `threatidentity.NewStore`/`ResolveAndPersist` (test setup only, to seed real threats), `contentregistry.New`/`Registry.Summaries(ctx) (map[string]Summary, error)` (`validations.go:191`), `testutil.MustSharedTestDB()`, `testutil.DevVerifier()`.
- Produces: `exposure.ListActiveThreatExposure(ctx context.Context, pool *pgxpool.Pool, reg *contentregistry.Registry, limit, offset int) ([]ThreatExposure, error)` and the `ThreatExposure`/`TechniqueExposure`/`ContentExposure` types — Task 2's handler calls this directly.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/exposure/testmain_test.go
package exposure

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

```go
// orchestrator/internal/exposure/exposure_test.go
package exposure

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/contentregistry"
	"github.com/audspect/bas/internal/testutil"
	"github.com/audspect/bas/internal/threatidentity"
)

// seedThreatWithTechnique resolves a new canonical threat and attaches one
// active technique, returning the threat id. Mirrors the pattern already
// used by connector's generator_attempts_test.go (ResolveAndPersist +
// seedActiveTechnique), but exposure has no sibling test file to import
// that helper from, so it's redefined here, scoped to this package.
func seedThreatWithTechnique(t *testing.T, pool *pgxpool.Pool, name, techniqueID string) string {
	t.Helper()
	idStore := threatidentity.NewStore(pool)
	resolved, err := idStore.ResolveAndPersist(context.Background(), threatidentity.Incoming{Name: name}, threatidentity.ProfileFields{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO threat_techniques
		(threat_id, technique_id, last_seen_at, status, status_reason)
		VALUES ($1, $2, NOW(), 'active', 'supported')`, resolved.ThreatID, techniqueID); err != nil {
		t.Fatal(err)
	}
	return resolved.ThreatID
}

// seedContentVersion inserts one PUBLISHED_LOCAL, executable content_versions
// row with the given technique_ids, and links it to threatID via
// content_version_threats. Returns the new content_version id.
func seedContentVersion(t *testing.T, pool *pgxpool.Pool, threatID string, techniqueIDs []string) string {
	t.Helper()
	ctx := context.Background()
	var versionID string
	err := pool.QueryRow(ctx, `INSERT INTO content_versions
		(content_id, origin, version, artifact_sha256, artifact_size, artifact_bytes,
		 trust_level, lifecycle, intake_source, schema_version, technique_ids, created_by)
		VALUES ($1, 'LOCAL', 1, 'sha-'||gen_random_uuid()::text, 1, 'x',
		 'LOCAL_TRUSTED', 'PUBLISHED_LOCAL', 'intel', 1, $2, 'test')
		RETURNING id`, "intel-"+threadSuffix(t), techniqueIDs).Scan(&versionID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO content_version_threats
		(content_version_id, threat_id, relationship_kind, provenance_type, provenance_ref)
		VALUES ($1, $2, 'generated_for', 'generator', 'test')`, versionID, threatID); err != nil {
		t.Fatal(err)
	}
	return versionID
}

func threadSuffix(t *testing.T) string { return t.Name() }

func newTestRegistry(pool *pgxpool.Pool) *contentregistry.Registry {
	return contentregistry.New(pool, testutil.DevVerifier())
}

func TestListActiveThreatExposure_ThreatWithNoContentReturnsEmptyContentSlice(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedThreatWithTechnique(t, pool, "APT-exposure-nocontent", "T1059")

		got, err := ListActiveThreatExposure(context.Background(), pool, newTestRegistry(pool), 20, 0)
		if err != nil {
			t.Fatalf("ListActiveThreatExposure: %v", err)
		}
		var found *ThreatExposure
		for i := range got {
			if got[i].Title == "APT-exposure-nocontent" {
				found = &got[i]
			}
		}
		if found == nil {
			t.Fatalf("expected the seeded threat in the result, got %+v", got)
		}
		if found.Content == nil || len(found.Content) != 0 {
			t.Fatalf("expected an empty (not nil, not omitted) content slice, got %+v", found.Content)
		}
	})
}

func TestListActiveThreatExposure_DraftContentAppearsAsNotExecutable(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		threatID := seedThreatWithTechnique(t, pool, "APT-exposure-draft", "T1059")
		ctx := context.Background()
		var versionID string
		err := pool.QueryRow(ctx, `INSERT INTO content_versions
			(content_id, origin, version, artifact_sha256, artifact_size, artifact_bytes,
			 trust_level, lifecycle, intake_source, schema_version, technique_ids, created_by)
			VALUES ('intel-draft-test', 'LOCAL', 1, 'sha-draft', 1, 'x',
			 'UNTRUSTED', 'DRAFT', 'intel', 1, '{T1059}', 'test')
			RETURNING id`).Scan(&versionID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO content_version_threats
			(content_version_id, threat_id, relationship_kind, provenance_type, provenance_ref)
			VALUES ($1, $2, 'generated_for', 'generator', 'test')`, versionID, threatID); err != nil {
			t.Fatal(err)
		}

		got, err := ListActiveThreatExposure(ctx, pool, newTestRegistry(pool), 20, 0)
		if err != nil {
			t.Fatalf("ListActiveThreatExposure: %v", err)
		}
		var found *ContentExposure
		for _, te := range got {
			for i := range te.Content {
				if te.Content[i].ContentVersionID == versionID {
					found = &te.Content[i]
				}
			}
		}
		if found == nil {
			t.Fatal("expected the DRAFT content version to appear in the response")
		}
		if found.IsExecutable {
			t.Fatalf("expected DRAFT content to be isExecutable=false, got true: %+v", found)
		}
		if found.Validation != "structural-only" {
			t.Fatalf("expected validation=structural-only, got %q", found.Validation)
		}
	})
}

func TestListActiveThreatExposure_TechniqueWithNoMatchingContentIsNotExecutable(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		threatID := seedThreatWithTechnique(t, pool, "APT-exposure-notech", "T1059")
		// Content exists for this threat, but covers a different technique.
		seedContentVersion(t, pool, threatID, []string{"T1053"})

		got, err := ListActiveThreatExposure(context.Background(), pool, newTestRegistry(pool), 20, 0)
		if err != nil {
			t.Fatalf("ListActiveThreatExposure: %v", err)
		}
		var found *ThreatExposure
		for i := range got {
			if got[i].ThreatID == threatID {
				found = &got[i]
			}
		}
		if found == nil {
			t.Fatal("expected the seeded threat in the result")
		}
		var tech *TechniqueExposure
		for i := range found.Techniques {
			if found.Techniques[i].TechniqueID == "T1059" {
				tech = &found.Techniques[i]
			}
		}
		if tech == nil {
			t.Fatal("expected T1059 in the technique list")
		}
		if tech.HasExecutableContent {
			t.Fatalf("expected hasExecutableContent=false (content covers a different technique), got true: %+v", tech)
		}
	})
}

func TestListActiveThreatExposure_OnlyCountsRunsWithRealContentVersionID(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		threatID := seedThreatWithTechnique(t, pool, "APT-exposure-runs", "T1059")
		versionID := seedContentVersion(t, pool, threatID, []string{"T1059"})
		ctx := context.Background()

		// A real run against this version.
		if _, err := pool.Exec(ctx, `INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at, content_version_id)
			VALUES (gen_random_uuid()::text, 'intel-exposure-runs', gen_random_uuid()::text, 'r', 'completed', NOW(), $1)`,
			versionID); err != nil {
			t.Fatal(err)
		}
		// An unrelated run with the same scenario_id string but no content_version_id --
		// must NOT be counted, per the spec's "no string-match fallback" rule.
		if _, err := pool.Exec(ctx, `INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at, content_version_id)
			VALUES (gen_random_uuid()::text, 'intel-exposure-runs', gen_random_uuid()::text, 'r2', 'completed', NOW(), NULL)`); err != nil {
			t.Fatal(err)
		}

		got, err := ListActiveThreatExposure(ctx, pool, newTestRegistry(pool), 20, 0)
		if err != nil {
			t.Fatalf("ListActiveThreatExposure: %v", err)
		}
		var found *ContentExposure
		for _, te := range got {
			for i := range te.Content {
				if te.Content[i].ContentVersionID == versionID {
					found = &te.Content[i]
				}
			}
		}
		if found == nil {
			t.Fatal("expected the seeded content version in the response")
		}
		if found.RunCount != 1 {
			t.Fatalf("expected runCount=1 (only the row with a real content_version_id), got %d", found.RunCount)
		}
		if found.LastRunAt == nil {
			t.Fatal("expected lastRunAt to be set")
		}
	})
}

func TestListActiveThreatExposure_ExcludesInactiveThreats(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		threatID := seedThreatWithTechnique(t, pool, "APT-exposure-inactive", "T1059")
		if _, err := pool.Exec(context.Background(), `UPDATE threats SET status = 'inactive' WHERE id = $1`, threatID); err != nil {
			t.Fatal(err)
		}

		got, err := ListActiveThreatExposure(context.Background(), pool, newTestRegistry(pool), 20, 0)
		if err != nil {
			t.Fatalf("ListActiveThreatExposure: %v", err)
		}
		for _, te := range got {
			if te.ThreatID == threatID {
				t.Fatalf("expected the inactive threat to be excluded from the default (active) listing, got it in results: %+v", te)
			}
		}
	})
}

func TestListActiveThreatExposure_LimitAndOffsetBounded(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		for i := 0; i < 3; i++ {
			seedThreatWithTechnique(t, pool, "APT-exposure-page-"+time.Now().Format("150405.000000")+"-"+string(rune('a'+i)), "T1059")
		}
		got, err := ListActiveThreatExposure(context.Background(), pool, newTestRegistry(pool), 2, 0)
		if err != nil {
			t.Fatalf("ListActiveThreatExposure: %v", err)
		}
		if len(got) > 2 {
			t.Fatalf("expected limit=2 to cap results, got %d", len(got))
		}
		// Garbage limit must not panic or run unbounded.
		if _, err := ListActiveThreatExposure(context.Background(), pool, newTestRegistry(pool), -5, -5); err != nil {
			t.Fatalf("expected negative limit/offset to be defaulted, not error: %v", err)
		}
	})
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/exposure/... -v -count=1`
Expected: FAIL — compile error, `ListActiveThreatExposure`/`ThreatExposure`/`TechniqueExposure`/`ContentExposure` are undefined. (6 test functions total: the 5 above plus `TestListActiveThreatExposure_ExcludesInactiveThreats`.)

- [ ] **Step 3: Implement**

```go
// orchestrator/internal/exposure/exposure.go
package exposure

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/contentregistry"
)

// ThreatExposure is one currently-active threat, with its live techniques and
// the content the factory has produced for it (spec 2026-10-14 §2.1).
type ThreatExposure struct {
	ThreatID    string              `json:"threatId"`
	Title       string              `json:"title"`
	FirstSeenAt *time.Time          `json:"firstSeenAt,omitempty"`
	LastSeenAt  *time.Time          `json:"lastSeenAt,omitempty"`
	Techniques  []TechniqueExposure `json:"techniques"`
	Content     []ContentExposure   `json:"content"`
}

type TechniqueExposure struct {
	TechniqueID          string    `json:"techniqueId"`
	LastSeenAt           time.Time `json:"lastSeenAt"`
	HasExecutableContent bool      `json:"hasExecutableContent"`
}

type ContentExposure struct {
	ContentVersionID string     `json:"contentVersionId"`
	ContentID        string     `json:"contentId"`
	RelationshipKind string     `json:"relationshipKind"`
	Lifecycle        string     `json:"lifecycle"`
	Trust            string     `json:"trust"`
	IsExecutable     bool       `json:"isExecutable"`
	Validation       string     `json:"validation"`
	LastRunAt        *time.Time `json:"lastRunAt,omitempty"`
	RunCount         int        `json:"runCount"`
	techniqueIDs     []string   // not serialized; used to compute TechniqueExposure.HasExecutableContent
}

// ListActiveThreatExposure assembles the live threat-coverage view (spec
// §2.1-§2.2). limit<=0 defaults to 20, capped at 100; offset<0 defaults to 0.
func ListActiveThreatExposure(ctx context.Context, pool *pgxpool.Pool, reg *contentregistry.Registry, limit, offset int) ([]ThreatExposure, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	summaries, err := reg.Summaries(ctx)
	if err != nil {
		return nil, fmt.Errorf("exposure: registry summaries: %w", err)
	}

	rows, err := pool.Query(ctx, `SELECT id, title, first_seen_at, last_seen_at FROM threats
		WHERE status = 'active' ORDER BY last_seen_at DESC NULLS LAST LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("exposure: list threats: %w", err)
	}
	var out []ThreatExposure
	for rows.Next() {
		var te ThreatExposure
		if err := rows.Scan(&te.ThreatID, &te.Title, &te.FirstSeenAt, &te.LastSeenAt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("exposure: scan threat: %w", err)
		}
		out = append(out, te)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()

	for i := range out {
		if err := loadTechniques(ctx, pool, &out[i]); err != nil {
			return nil, err
		}
		if err := loadContent(ctx, pool, summaries, &out[i]); err != nil {
			return nil, err
		}
		computeHasExecutableContent(&out[i])
	}
	return out, nil
}

func loadTechniques(ctx context.Context, pool *pgxpool.Pool, te *ThreatExposure) error {
	rows, err := pool.Query(ctx, `SELECT technique_id, last_seen_at FROM threat_techniques
		WHERE threat_id = $1 AND status = 'active'`, te.ThreatID)
	if err != nil {
		return fmt.Errorf("exposure: list techniques for %s: %w", te.ThreatID, err)
	}
	defer rows.Close()
	te.Techniques = []TechniqueExposure{}
	for rows.Next() {
		var t TechniqueExposure
		if err := rows.Scan(&t.TechniqueID, &t.LastSeenAt); err != nil {
			return fmt.Errorf("exposure: scan technique: %w", err)
		}
		te.Techniques = append(te.Techniques, t)
	}
	return rows.Err()
}

func loadContent(ctx context.Context, pool *pgxpool.Pool, summaries map[string]contentregistry.Summary, te *ThreatExposure) error {
	rows, err := pool.Query(ctx, `SELECT cv.id, cv.content_id, cvt.relationship_kind, cv.lifecycle, cv.trust_level, cv.technique_ids
		FROM content_version_threats cvt JOIN content_versions cv ON cv.id = cvt.content_version_id
		WHERE cvt.threat_id = $1`, te.ThreatID)
	if err != nil {
		return fmt.Errorf("exposure: list content for %s: %w", te.ThreatID, err)
	}
	te.Content = []ContentExposure{}
	for rows.Next() {
		var ce ContentExposure
		if err := rows.Scan(&ce.ContentVersionID, &ce.ContentID, &ce.RelationshipKind, &ce.Lifecycle, &ce.Trust, &ce.techniqueIDs); err != nil {
			rows.Close()
			return fmt.Errorf("exposure: scan content: %w", err)
		}
		ce.Validation = "structural-only"
		if s, ok := summaries[ce.ContentID]; ok && s.ExecutableVersion > 0 {
			// Summaries keys by content_id and names the one version the gate
			// actually selected; this row is executable only if it IS that version.
			ce.IsExecutable = s.ExecutableLifecycle == ce.Lifecycle && s.ExecutableTrust == ce.Trust
		}
		te.Content = append(te.Content, ce)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	for i := range te.Content {
		var lastRunAt *time.Time
		var count int
		if err := pool.QueryRow(ctx, `SELECT MAX(started_at), COUNT(*) FROM scenario_runs WHERE content_version_id = $1`,
			te.Content[i].ContentVersionID).Scan(&lastRunAt, &count); err != nil {
			return fmt.Errorf("exposure: run aggregate for %s: %w", te.Content[i].ContentVersionID, err)
		}
		te.Content[i].LastRunAt = lastRunAt
		te.Content[i].RunCount = count
	}
	return nil
}

func computeHasExecutableContent(te *ThreatExposure) {
	for i := range te.Techniques {
		for _, c := range te.Content {
			if !c.IsExecutable {
				continue
			}
			for _, tid := range c.techniqueIDs {
				if tid == te.Techniques[i].TechniqueID {
					te.Techniques[i].HasExecutableContent = true
				}
			}
		}
	}
}
```

Note on `loadContent`'s `IsExecutable` check: `Registry.Summaries` (`validations.go:191-224`) keys its result by `content_id` and names only the single version the gate's "first version passing Executable, scanning newest-first" rule selected (`ExecutableVersion`/`ExecutableLifecycle`/`ExecutableTrust`) — it does not return a per-version boolean map. A `content_version_threats` row for an older, superseded version of the same `content_id` must not be marked executable just because *some* version of that content id is; comparing this row's own `lifecycle`/`trust` against the summary's `ExecutableLifecycle`/`ExecutableTrust` is how this plan distinguishes "this exact row is the one the gate selected" from "a different version of the same content happens to be executable." This is a deliberate, minimal reuse of `Summaries`' existing result shape rather than exposing a new per-version method on `Registry` — if a later task finds this ambiguous for content ids with many versions, that is a real finding to raise in review, not a plan defect.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/exposure/... -v -count=1`
Expected: PASS, all 6 tests.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/exposure/
git commit -m "feat(tcf-phase10): internal/exposure — live threat-coverage data assembly"
```

---

### Task 2: `GET /api/threats/exposure`

**Files:**
- Modify: `orchestrator/internal/api/handlers.go` (new handler)
- Modify: `orchestrator/internal/api/routes.go:264` (register next to `/api/techniques/unified`)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go:92` (add the new route's `tierAny` row)
- Test: `orchestrator/internal/api/threat_exposure_handler_test.go`

**Interfaces:**
- Consumes: Task 1's `exposure.ListActiveThreatExposure`.
- Produces: `GET /api/threats/exposure` — Task 3's frontend calls this.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/api/threat_exposure_handler_test.go
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/threatidentity"
)

// registryEngine is the existing package-level test helper from
// content_gate_test.go (same package: api) — it returns a *scenario.Engine
// with a *contentregistry.Registry already attached via e.AttachRegistry.
// No e.Load() call is needed here: GetThreatExposure only calls
// h.engine.Registry(), it never touches loaded scenario files.

func TestGetThreatExposure_ReturnsActiveThreats(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		idStore := threatidentity.NewStore(pool)
		if _, err := idStore.ResolveAndPersist(context.Background(), threatidentity.Incoming{Name: "APT-handler-exposure"}, threatidentity.ProfileFields{}); err != nil {
			t.Fatal(err)
		}

		e, _, _ := registryEngine(t, pool)
		h := &Handler{db: pool, engine: e}

		req := httptest.NewRequest(http.MethodGet, "/api/threats/exposure", nil)
		w := httptest.NewRecorder()
		h.GetThreatExposure(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "APT-handler-exposure") {
			t.Fatalf("expected the seeded threat's title in the response, got: %s", w.Body.String())
		}
	})
}

func TestGetThreatExposure_LimitQueryParamRespected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, _, _ := registryEngine(t, pool)
		h := &Handler{db: pool, engine: e}

		req := httptest.NewRequest(http.MethodGet, "/api/threats/exposure?limit=99999", nil)
		w := httptest.NewRecorder()
		h.GetThreatExposure(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		// As with GetCoverageAnalytics/GetGenerationAttempts's existing tests, the
		// real cap is exercised inside exposure.ListActiveThreatExposure itself
		// (Task 1); this just confirms the handler doesn't error on an absurd value.
	})
}

func TestGetThreatExposure_NoRegistryReturns503(t *testing.T) {
	h := &Handler{engine: &scenario.Engine{}}
	req := httptest.NewRequest(http.MethodGet, "/api/threats/exposure", nil)
	w := httptest.NewRecorder()
	h.GetThreatExposure(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when no registry is attached, got %d: %s", w.Code, w.Body.String())
	}
}
```

`TestGetThreatExposure_NoRegistryReturns503` needs `"github.com/audspect/bas/internal/scenario"` added to this file's imports. `scenario.Engine.Registry()` (`engine.go:73`) is a plain field getter (`return e.registry`) with no other dereferences, so a zero-value `&scenario.Engine{}` returns a nil `ContentRegistry` interface safely — the handler's `.(*contentregistry.Registry)` assertion on that nil interface returns `ok == false`, which is exactly the 503 path. No panic risk; verified against the real implementation, not assumed.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestGetThreatExposure -v`
Expected: FAIL — compile error, `h.GetThreatExposure` undefined (3 test functions: `TestGetThreatExposure_ReturnsActiveThreats`, `TestGetThreatExposure_LimitQueryParamRespected`, `TestGetThreatExposure_NoRegistryReturns503`).

- [ ] **Step 3: Implement the handler**

```go
// GET /api/threats/exposure — live threat coverage: which currently-active
// threats have validated/executable content, and which don't (TCF Phase 10,
// spec 2026-10-14 §2.1).
//
// Query params:
//
//	limit — max threats, default 20, max 100
//	offset — pagination offset, default 0
func (h *Handler) GetThreatExposure(w http.ResponseWriter, r *http.Request) {
	reg, ok := h.engine.Registry().(*contentregistry.Registry)
	if !ok || reg == nil {
		jsonError(w, "content registry not available", http.StatusServiceUnavailable)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	result, err := exposure.ListActiveThreatExposure(r.Context(), h.db, reg, limit, offset)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, result)
}
```

Add `"github.com/audspect/bas/internal/exposure"` to `handlers.go`'s import block in correct gofmt alphabetical position (after `endpointrisk`, before `evidence` — mind the exact ordering gofmt enforces; the Phase 9 final review caught a misordered import here once already, verify with `gofmt -l orchestrator/internal/api/handlers.go` after this edit, not just by eye).

- [ ] **Step 4: Register the route**

In `orchestrator/internal/api/routes.go`, immediately after line 264:

```go
		r.Get("/api/techniques/unified", h.GetUnifiedTechniques)
		r.Get("/api/threats/exposure", h.GetThreatExposure)
```

- [ ] **Step 5: Add the RBAC matrix row**

In `orchestrator/internal/api/rbac_matrix_test.go`, immediately after the `/api/techniques/unified` row (around line 92):

```go
	{http.MethodGet, "/api/techniques/unified", tierAny, ""},
	{http.MethodGet, "/api/threats/exposure", tierAny, ""},
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run "TestGetThreatExposure|TestRBACMatrix" -v`
Expected: PASS for both `TestGetThreatExposure*` tests and `TestRBACMatrix_AuthorizationBoundary`'s subtests for the new route. `TestRBACMatrix_NoDrift` fails on the pre-existing, unrelated `POST /api/intel/sources/{id}/trust` gap (confirmed in the Phase 9 ledger to predate this plan) — confirm the new route is not implicated, don't treat that one failure as this task's responsibility.

- [ ] **Step 7: Run gofmt**

Run: `gofmt -l orchestrator/internal/api/handlers.go`
Expected: no output (clean).

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/api/handlers.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go orchestrator/internal/api/threat_exposure_handler_test.go
git commit -m "feat(tcf-phase10): GET /api/threats/exposure"
```

---

### Task 3: Frontend — Live Threat Coverage section

**Files:**
- Modify: `orchestrator/web/index.html:1631-1633` (insert a new section between the ATT&CK matrix and the Unified Technique Library)
- Modify: `orchestrator/web/src/features/coverage.js` (new render function; relabel the existing "Known actors" row)

**Interfaces:**
- Consumes: Task 2's `GET /api/threats/exposure`.
- Produces: nothing further downstream — this is the last task.

This task has no automated test (this codebase has no JS unit-test convention for feature pages — confirmed via `find orchestrator/web -iname "*.test.js"` returning nothing for any existing feature, not just this one). Verify by starting the dev server and loading the Coverage page in a browser, per this project's standing frontend-verification practice.

- [ ] **Step 1: Add the new section's markup**

In `orchestrator/web/index.html`, immediately after line 1631 (`<div class="tiny muted" id="cov-foot" ...></div>`) and before the `<!-- Unified Technique Library -->` comment at line 1633:

```html
        <!-- Live Threat Coverage — assembled from the real threat-intel pipeline, not the static ATT&CK dataset above. -->
        <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;margin:1.75rem 0 1rem;flex-wrap:wrap">
          <div>
            <h1 style="font-family:var(--font-display);font-size:1.5rem;font-weight:700;letter-spacing:-0.02em;margin:0 0 0.3rem;color:var(--text)">Live Threat Coverage</h1>
            <div style="font-size:0.8rem;color:var(--muted)">Threats currently tracked by your intelligence sources, and whether validated, executable content exists for them.</div>
          </div>
        </div>
        <div class="dash-panel"><div class="dash-panel-body" id="lte-body" style="padding:0.75rem"><div class="empty" style="padding:2rem">Loading…</div></div></div>
        <div class="tiny muted" id="lte-foot" style="margin-top:0.75rem"></div>
```

- [ ] **Step 2: Add the render function**

In `orchestrator/web/src/features/coverage.js`, after `loadCoverage()` (the function ending around line 322, which is the last function before the `renderCovMatrix`/`renderCovToolbar` block):

```js
// ── Live Threat Coverage (TCF Phase 10) ──────────────────────────────────────
export function loadThreatExposure() {
  apicall('/api/threats/exposure?limit=50').catch(function() { return null; }).then(function(d) {
    renderThreatExposure(d || []);
  });
}

function renderThreatExposure(threats) {
  var body = document.getElementById('lte-body');
  var foot = document.getElementById('lte-foot');
  if (!threats.length) {
    body.innerHTML = '<div class="empty" style="padding:2rem">No active threats tracked yet.</div>';
    foot.textContent = '';
    return;
  }
  var row = function(label, v) {
    return '<div style="display:flex;gap:0.6rem;padding:0.3rem 0;border-bottom:1px solid var(--border);font-size:0.78rem">' +
      '<span style="color:var(--muted);min-width:110px">' + x(label) + '</span><span class="u-flex1">' + v + '</span></div>';
  };
  body.innerHTML = threats.map(function(t) {
    var techCount = (t.techniques || []).length;
    var withContent = (t.techniques || []).filter(function(tc) { return tc.hasExecutableContent; }).length;
    var contentRows = (t.content || []).map(function(c) {
      var badge = c.isExecutable
        ? '<span class="sbadge" style="background:transparent;border:1px solid var(--success);color:var(--success)">Executable</span>'
        : '<span class="sbadge" style="background:transparent;border:1px solid var(--muted);color:var(--muted)">' + x(c.lifecycle) + '</span>';
      var runInfo = c.runCount > 0 ? c.runCount + ' run(s), last ' + new Date(c.lastRunAt).toLocaleDateString() : 'never run';
      return '<div style="display:flex;justify-content:space-between;align-items:center;padding:0.3rem 0;font-size:0.76rem">' +
        '<span>' + x(c.contentId) + ' <span style="color:var(--muted)">(' + x(c.relationshipKind) + ', ' + x(c.validation) + ')</span></span>' +
        '<span style="display:flex;gap:0.5rem;align-items:center">' + badge + '<span style="color:var(--muted)">' + runInfo + '</span></span></div>';
    }).join('') || '<div class="empty" style="padding:0.5rem 0;font-size:0.76rem">No content available for this threat yet.</div>';
    return '<div class="dash-panel" style="margin-bottom:0.75rem;padding:0.75rem">' +
      '<div style="font-weight:600;margin-bottom:0.3rem">' + x(t.title) + '</div>' +
      row('Last seen', t.lastSeenAt ? new Date(t.lastSeenAt).toLocaleDateString() : 'unknown') +
      row('Techniques', techCount + ' tracked, ' + withContent + ' with executable content') +
      contentRows +
      '</div>';
  }).join('');
  foot.textContent = threats.length + ' active threat(s) shown.';
}
```

- [ ] **Step 3: Relabel the existing static-ATT&CK row**

In `orchestrator/web/src/features/coverage.js`, in `openTechnique`'s `row('Known actors', ...)` call (the exact line found at plan-writing time was `coverage.js:361`; confirm the current line number before editing, since Task 1/2 commits don't touch this file so it should be unchanged, but always verify rather than trusting a stale line number):

```js
      row('Known actors (ATT&CK reference)', list(e.groups)) + row('Data sources', list(e.dataSources)) +
```

This is the only change to this function — it still shows the same static `attackdata.Groups` data, only the label changes, so nobody mistakes this per-technique reference panel for the new live section above it.

- [ ] **Step 4: Wire `loadThreatExposure` into the Coverage page's load sequence**

Find where `loadCoverage()` is currently called when the Coverage page/tab is opened (grep `loadCoverage()` outside `coverage.js` itself — likely in a router/nav module that calls each feature's load function when its tab activates) and add a call to `loadThreatExposure()` alongside it, so the new section populates whenever the existing Coverage page does.

- [ ] **Step 5: Manual verification**

Start the dev server (this project's existing `visual.sh` or equivalent dev-server script — check `docs/` or `package.json` scripts if the exact command isn't already known from session context) and load the Coverage page in a browser. Confirm:
- The new "Live Threat Coverage" section appears between the ATT&CK matrix and the Unified Technique Library, visually distinct (its own `dash-panel`, its own heading).
- It shows real seeded/live threats if any exist in the dev database, or the "No active threats tracked yet" empty state otherwise.
- Clicking a technique cell in the ATT&CK matrix above still opens the existing detail overlay, now showing "Known actors (ATT&CK reference)" as the row label.
- No console errors on page load.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/web/index.html orchestrator/web/src/features/coverage.js
git commit -m "feat(tcf-phase10): Live Threat Coverage section on the Coverage page"
```
