# TCF Phase 2B — Evidence, Claims, Projection, Generation Reproducibility — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the factory an immutable evidence trail from raw source record to a materialized `threat_techniques` active set, so retraction, trust, and confidence are explicit and generation is reproducible — replacing "absence of a filter" with "absence is not retraction" as the governing rule.

**Architecture:** A new `internal/evidence` package owns source trust, sync completeness, append-only observations/claims, and the `threat_techniques` projection, mirroring how `internal/threatidentity` was split out in Phase 2A. `internal/connector`'s three live sources (MISP, OpenCTI, OTX) and the bundle source each report their own completeness and emit raw per-record claims through two new optional interfaces (`CompletenessSource`, `EvidenceSource`), read by `Scheduler.sync()` the same way `StatsSource`/`TechniqueEvidenceSource` are read today. The generator consumes the projection's active set instead of the raw merged actor list, and records a reproducibility snapshot per generation.

**Tech Stack:** Go, PostgreSQL via `jackc/pgx/v5`, the existing boot-time `Ensure*Schema` pattern (no versioned-migration framework exists on `main` yet), the repo's own `go test` + `testutil.MustSharedTestDB()` harness (testcontainers Postgres).

**Spec:** `docs/superpowers/specs/2026-10-06-tcf-phase2-canonical-threat-design.md` — milestone 2B (§5 Evidence model, §6 Claims and retractions, §7 Projection, §8 Generation reproducibility; acceptance tests 14–24).

## Global Constraints

- No versioned-migration framework exists on `main` (confirmed: no `internal/db/migrations` directory). Ship schema via a new `EnsureEvidenceSchema` boot-time function, same pattern as `EnsureThreatIdentitySchema`.
- `bas_app` grants are least-privilege and declarative (spec §12): append-only tables get `SELECT, INSERT` only; `threat_techniques` gets `SELECT, INSERT, UPDATE` (no `DELETE`); nothing else gets `UPDATE`.
- Absence is not retraction (spec §6.1): a retraction is written **only** when `completeness = 'complete' AND observation_mode = 'snapshot'` for that sync. The evidence layer enforces this itself — it never trusts an adapter's request to retract.
- Claims are append-only; a later observation never overwrites an earlier one (spec §6.3).
- The MISP/OpenCTI ≥2-technique minimum is a **generation policy**, not an evidence filter (spec §6.2): raw claims for every actor+technique the adapter sees, including actors below the threshold, must be captured before that filter is applied.
- Confidence is recorded but never used as an implicit threshold (spec §7.2); normalization is an explicit, versioned, closed per-source mapping (spec §7.3) and unrecognized values normalize to `NULL`, never an invented value.
- `first_seen_at` only counts claims observed under a trust version that was `trusted` at observation time; granting trust later never backdates it (spec §7.4).
- Every projection recompute runs immediately after the write that triggered it, for every threat that write touched (spec §7.4, closing sentence). **Task-ordering note:** `RecomputeThreatTechniques` (Task 7) is defined after `RecordClaims` (Task 6) and `SetTrust` (Task 3), so this plan calls it as the next statement after each triggering write rather than literally folding it into that write's own transaction (which would require Task 7 to exist before Tasks 3/6, breaking per-task incremental compilation). A crash between the two leaves the append-only evidence correct and just re-derives a stale projection on the next write to that threat — never a correctness violation of the append-only record itself.
- Package boundary: `internal/evidence` must not import `internal/connector` (connector depends on evidence, not the reverse — same direction as connector's existing dependency on `internal/threatidentity`).

## Review Focus

- **A sync that fails outright (network error, 5xx) must never be mistaken for a complete snapshot.** `status = 'failed'` always implies `completeness = 'failed'` and never produces a retraction — pinned in Task 4's tests.
- **Two sources claiming the exact same (actor, technique) must not collapse into one claim row.** Spec §5.3: "Identical text from two providers is not deduplicated away." Pinned in Task 6's tests (two `technique_claims` rows survive, not one).
- **A technique that drops out of the merged actor roster (filtered below 2) must still show up as an active claim in the evidence layer**, distinguishing "no content generated" from "no evidence exists." Pinned in Task 8/9's tests by asserting a `technique_claims` row exists for a 1-technique actor that the merged `ThreatActor.Techniques` list would have hidden.
- **Revoking trust on a source that is the sole supporting source for a technique must flip that technique to `retracted` with `status_reason = 'trust_revocation'`, not silently vanish or get confused with a real source retraction.** Pinned in Task 7's tests.
- **Re-running the exact same sync twice (idempotency) must not create duplicate `technique_claims` rows or double-count `supporting_source_count`.** The spec doesn't say this explicitly but a sync scheduler runs on a timer — a non-idempotent claim writer would corrupt `supporting_source_count` within days. Pinned in Task 6 via `record_hash`-based dedup within a single sync.

---

## File Structure

New:
- `internal/db/evidence_schema.go` — `EnsureEvidenceSchema`: `source_instances`, `source_trust_versions`, `source_syncs`, `source_observations`, `threat_sources`, `technique_claims`, `threat_techniques`, `content_generations`.
- `internal/evidence/types.go` — `TrustState`, `ObservationMode`, `Completeness`, `ClaimKind`, `RawClaim`, `SyncReport`.
- `internal/evidence/store.go` — `Store` struct + `NewStore`.
- `internal/evidence/confidence.go` — `NormalizeConfidence(source string, raw string) (raw *string, normalized *int, mappingVersion string)`.
- `internal/evidence/trust.go` — `EnsureSourceInstance`, `CurrentTrust`, `SetTrust`.
- `internal/evidence/sync.go` — `RecordSync`.
- `internal/evidence/observations.go` — `RecordObservation`, `LinkThreatSource`.
- `internal/evidence/claims.go` — `RecordClaims` (the §6.1 refusal rule lives here).
- `internal/evidence/projection.go` — `RecomputeThreatTechniques`.
- `internal/evidence/generation.go` — `ActiveTechniques`, `RecordGeneration`.
- `internal/evidence/testmain_test.go` — shared test DB, same pattern as `internal/threatidentity/testmain_test.go`.
- `internal/api/intel_sources_handlers.go` — `POST /api/intel/sources/{id}/trust`.

Modified:
- `internal/db/app_role.go` — grants for the new tables.
- `cmd/server/main.go:280-282` — boot `EnsureEvidenceSchema` after `EnsureThreatIdentitySchema`.
- `internal/testutil/testdb.go:116-120` — same, for the test harness.
- `internal/auth/permissions.go` — new `CanManageSourceTrust` permission, Admin-only.
- `internal/api/routes.go` — register the new route.
- `internal/connector/types.go` — `CompletenessSource`, `EvidenceSource` interfaces.
- `internal/connector/misp.go` — completeness tracking + raw-claim capture before the 2-technique filter.
- `internal/connector/opencti.go` — truncation detection (top-level + nested connections) + raw-claim capture.
- `internal/connector/otx.go` — completeness (`activity_window`, never authoritative).
- `internal/connector/bundle.go` — completeness (`complete` iff signature verified and fully parsed).
- `internal/connector/scheduler.go` — wire evidence recording into `sync()`.
- `internal/connector/generator.go` — consume the projection's active set; record `content_generations`.

---

### Task 1: Evidence schema and grants

**Files:**
- Create: `internal/db/evidence_schema.go`
- Modify: `internal/db/app_role.go`
- Modify: `cmd/server/main.go:280-282`
- Modify: `internal/testutil/testdb.go:116-120`
- Test: `internal/db/evidence_schema_test.go`

**Interfaces:**
- Consumes: `threats(id)`, `threat_actor_profiles(id)` (Phase 2A, already on `main`).
- Produces: tables `source_instances`, `source_trust_versions`, `source_syncs`, `source_observations`, `threat_sources`, `technique_claims`, `threat_techniques`, `content_generations` — exact columns below, consumed by every later task in this plan.

- [ ] **Step 1: Write the failing test**

```go
// internal/db/evidence_schema_test.go
package db

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/testutil"
)

func TestEnsureEvidenceSchema_CreatesTablesAndIsIdempotent(t *testing.T) {
	tdb := testutil.MustSharedTestDB()
	defer tdb.Cleanup()
	ctx := context.Background()

	for _, table := range []string{
		"source_instances", "source_trust_versions", "source_syncs",
		"source_observations", "threat_sources", "technique_claims",
		"threat_techniques", "content_generations",
	} {
		var exists bool
		if err := tdb.Pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)`,
			table).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Errorf("table %q was not created", table)
		}
	}

	// Idempotent: a second call must not error.
	if err := EnsureEvidenceSchema(ctx, tdb.Pool); err != nil {
		t.Fatalf("second EnsureEvidenceSchema call: %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/db/... -run TestEnsureEvidenceSchema_CreatesTablesAndIsIdempotent -v`
Expected: FAIL — `undefined: EnsureEvidenceSchema` (compile error), since the function does not exist yet. (This test will also fail to compile until Task 1's `internal/testutil/testdb.go` edit lands, because `testutil.MustSharedTestDB()` would not yet call `EnsureEvidenceSchema` — that's fine, this task writes both together.)

- [ ] **Step 3: Write minimal implementation**

```go
// internal/db/evidence_schema.go
package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EnsureEvidenceSchema creates the TCF Phase 2B evidence tables (spec
// 2026-10-06 §5-§8). Must run after EnsureThreatIdentitySchema (threats,
// threat_actor_profiles.id) and before EnsureAppRole. Idempotent.
func EnsureEvidenceSchema(ctx context.Context, pool *pgxpool.Pool) error {
	for _, s := range evidenceTables {
		if _, err := pool.Exec(ctx, s); err != nil {
			return fmt.Errorf("evidence schema: %w\n%s", err, s)
		}
	}
	return nil
}

var evidenceTables = []string{
	`CREATE TABLE IF NOT EXISTS source_instances (
		id               text        PRIMARY KEY,
		source_type      text        NOT NULL CHECK (source_type IN ('bundle','misp','opencti','otx')),
		display_name     text        NOT NULL,
		observation_mode text        NOT NULL CHECK (observation_mode IN ('snapshot','activity_window')),
		created_at       timestamptz NOT NULL DEFAULT NOW()
	)`,
	`CREATE TABLE IF NOT EXISTS source_trust_versions (
		id                 bigserial   PRIMARY KEY,
		source_instance_id text        NOT NULL REFERENCES source_instances(id),
		trust_state        text        NOT NULL CHECK (trust_state IN ('trusted','untrusted')),
		effective_at       timestamptz NOT NULL DEFAULT NOW(),
		changed_by         text        NOT NULL,
		reason             text        NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS idx_source_trust_versions_instance_effective
		ON source_trust_versions (source_instance_id, effective_at DESC)`,
	`CREATE TABLE IF NOT EXISTS source_syncs (
		id                 text        PRIMARY KEY DEFAULT ('sync-' || gen_random_uuid()::text),
		source_instance_id text        NOT NULL REFERENCES source_instances(id),
		started_at         timestamptz NOT NULL,
		completed_at       timestamptz,
		status             text        NOT NULL CHECK (status IN ('succeeded','failed')),
		completeness       text        NOT NULL CHECK (completeness IN ('complete','partial','truncated','failed')),
		authoritative      boolean     NOT NULL,
		diagnostic         text        NOT NULL DEFAULT '',
		CHECK (status = 'succeeded' OR completeness = 'failed'),
		CHECK (NOT authoritative OR completeness = 'complete')
	)`,
	`CREATE TABLE IF NOT EXISTS source_observations (
		id                  text        PRIMARY KEY DEFAULT ('obs-' || gen_random_uuid()::text),
		sync_id             text        NOT NULL REFERENCES source_syncs(id),
		source_instance_id  text        NOT NULL REFERENCES source_instances(id),
		external_id         text        NOT NULL DEFAULT '',
		raw_name            text        NOT NULL,
		record_hash         text        NOT NULL,
		observed_at         timestamptz NOT NULL,
		raw                 jsonb       NOT NULL,
		trust_version_id    bigint      NOT NULL REFERENCES source_trust_versions(id),
		candidate_id        text        REFERENCES actor_resolution_candidates(id)
	)`,
	`CREATE INDEX IF NOT EXISTS idx_source_observations_sync ON source_observations (sync_id)`,
	`CREATE TABLE IF NOT EXISTS threat_sources (
		id                     text        PRIMARY KEY DEFAULT ('tsrc-' || gen_random_uuid()::text),
		threat_id              text        NOT NULL REFERENCES threats(id),
		observation_id         text        NOT NULL REFERENCES source_observations(id),
		provider               text        NOT NULL,
		external_id            text        NOT NULL DEFAULT '',
		observed_at            timestamptz NOT NULL,
		source_confidence      smallint,
		record_hash            text        NOT NULL,
		first_seen_at_generation text      NOT NULL DEFAULT '',
		linked_by              text        NOT NULL CHECK (linked_by IN ('resolver','admin')),
		linked_ref             text        NOT NULL DEFAULT '',
		UNIQUE (observation_id)
	)`,
	`CREATE INDEX IF NOT EXISTS idx_threat_sources_threat ON threat_sources (threat_id)`,
	`CREATE TABLE IF NOT EXISTS technique_claims (
		id                          text        PRIMARY KEY DEFAULT ('claim-' || gen_random_uuid()::text),
		observation_id              text        NOT NULL REFERENCES source_observations(id),
		sync_id                     text        NOT NULL REFERENCES source_syncs(id),
		source_instance_id          text        NOT NULL REFERENCES source_instances(id),
		threat_id                   text        NOT NULL REFERENCES threats(id),
		technique_id                text        NOT NULL,
		kind                        text        NOT NULL CHECK (kind IN ('claim','retraction')),
		via                         text        NOT NULL DEFAULT '',
		via_name                    text        NOT NULL DEFAULT '',
		start_time                  timestamptz,
		stop_time                   timestamptz,
		raw_confidence              text,
		normalized_confidence       smallint,
		confidence_mapping_version  text,
		trust_version_id            bigint      NOT NULL REFERENCES source_trust_versions(id),
		observed_at                 timestamptz NOT NULL,
		record_hash                 text        NOT NULL,
		UNIQUE (source_instance_id, threat_id, technique_id, via, via_name, record_hash)
	)`,
	`CREATE INDEX IF NOT EXISTS idx_technique_claims_threat_technique
		ON technique_claims (threat_id, technique_id, source_instance_id, observed_at DESC)`,
	`CREATE TABLE IF NOT EXISTS threat_techniques (
		threat_id                text        NOT NULL REFERENCES threats(id),
		technique_id              text        NOT NULL,
		first_seen_at             timestamptz,
		last_seen_at              timestamptz NOT NULL,
		supporting_source_count   int         NOT NULL DEFAULT 0,
		best_confidence           smallint,
		status                    text        NOT NULL CHECK (status IN ('active','retracted')),
		status_reason             text        NOT NULL CHECK (status_reason IN ('supported','source_retraction','trust_revocation')),
		projected_at              timestamptz NOT NULL DEFAULT NOW(),
		PRIMARY KEY (threat_id, technique_id)
	)`,
	`CREATE TABLE IF NOT EXISTS content_generations (
		id                       text        PRIMARY KEY DEFAULT ('gen-' || gen_random_uuid()::text),
		threat_id                text        NOT NULL REFERENCES threats(id),
		content_id               text        NOT NULL,
		content_version_id       text,
		generation_number        int         NOT NULL,
		policy_version            text        NOT NULL,
		technique_set_hash        text        NOT NULL,
		evidence_snapshot_hash    text        NOT NULL,
		evidence_snapshot         jsonb       NOT NULL,
		generated_at              timestamptz NOT NULL DEFAULT NOW(),
		UNIQUE (threat_id, generation_number)
	)`,
}
```

```go
// internal/db/app_role.go — append to the `grants` slice literal, after the
// existing TCF Phase 2A block (after line 113's threat_actor_profiles grant)
`REVOKE UPDATE, DELETE ON source_trust_versions FROM ` + appRole,
`REVOKE UPDATE, DELETE ON source_syncs FROM ` + appRole,
`REVOKE UPDATE, DELETE ON source_observations FROM ` + appRole,
`REVOKE UPDATE, DELETE ON threat_sources FROM ` + appRole,
`REVOKE UPDATE, DELETE ON technique_claims FROM ` + appRole,
`REVOKE UPDATE, DELETE ON content_generations FROM ` + appRole,
`REVOKE DELETE ON threat_techniques FROM ` + appRole,
```

```go
// cmd/server/main.go — insert after line 282 (EnsureThreatIdentitySchema), before line 283's log line
	if err := db.EnsureEvidenceSchema(context.Background(), adminPool); err != nil {
		log.Fatalf("[FATAL] evidence schema: %v", err)
	}
```

```go
// internal/testutil/testdb.go — insert after line 120 (EnsureThreatIdentitySchema block), before line 121's blank line/return
	if err := db.EnsureEvidenceSchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(context.Background())
		return nil, fmt.Errorf("testutil: EnsureEvidenceSchema: %w", err)
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/db/... -run TestEnsureEvidenceSchema_CreatesTablesAndIsIdempotent -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/db/evidence_schema.go internal/db/evidence_schema_test.go internal/db/app_role.go cmd/server/main.go internal/testutil/testdb.go
git commit -m "feat(tcf2b): evidence schema — source instances, trust, syncs, observations, claims, projection, generation (spec §5-§8)"
```

---

### Task 2: Evidence types, Store scaffold, confidence normalization

**Files:**
- Create: `internal/evidence/types.go`
- Create: `internal/evidence/store.go`
- Create: `internal/evidence/confidence.go`
- Create: `internal/evidence/testmain_test.go`
- Test: `internal/evidence/confidence_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks (pure types + a DB-free function).
- Produces: `Store` struct + `NewStore(pool *pgxpool.Pool) *Store`, consumed by every later task. `NormalizeConfidence(source, raw string) (rawOut *string, normalized *int, mappingVersion string)`, consumed by Task 6.

- [ ] **Step 1: Write the failing test**

```go
// internal/evidence/confidence_test.go
package evidence

import "testing"

func TestNormalizeConfidence_OpenCTIIntegerPassesThrough(t *testing.T) {
	raw, norm, version := NormalizeConfidence("opencti", "72")
	if raw == nil || *raw != "72" {
		t.Fatalf("raw = %v, want \"72\"", raw)
	}
	if norm == nil || *norm != 72 {
		t.Fatalf("normalized = %v, want 72", norm)
	}
	if version == "" {
		t.Fatal("mapping version must not be empty")
	}
}

func TestNormalizeConfidence_MISPKnownLevelMaps(t *testing.T) {
	_, norm, _ := NormalizeConfidence("misp", "high")
	if norm == nil || *norm != 85 {
		t.Fatalf("normalized = %v, want 85 for MISP \"high\"", norm)
	}
}

func TestNormalizeConfidence_MISPUnrecognizedIsNil(t *testing.T) {
	_, norm, _ := NormalizeConfidence("misp", "extremely-confident")
	if norm != nil {
		t.Fatalf("normalized = %v, want nil for an unrecognized MISP level", norm)
	}
}

func TestNormalizeConfidence_BundleAndOTXAlwaysNil(t *testing.T) {
	for _, source := range []string{"bundle", "otx"} {
		raw, norm, _ := NormalizeConfidence(source, "90")
		if raw != nil {
			t.Errorf("%s: raw = %v, want nil (no invented value)", source, raw)
		}
		if norm != nil {
			t.Errorf("%s: normalized = %v, want nil", source, norm)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/evidence/... -run TestNormalizeConfidence -v`
Expected: FAIL — `undefined: NormalizeConfidence` (package `internal/evidence` does not exist yet).

- [ ] **Step 3: Write minimal implementation**

```go
// internal/evidence/types.go
package evidence

import "time"

type TrustState string

const (
	TrustTrusted   TrustState = "trusted"
	TrustUntrusted TrustState = "untrusted"
)

type ObservationMode string

const (
	ModeSnapshot       ObservationMode = "snapshot"
	ModeActivityWindow ObservationMode = "activity_window"
)

// Completeness is the source adapter's own assessment of how much of its
// data this sync actually captured (spec §5.2) — never inferred from HTTP
// success alone.
type Completeness string

const (
	Complete  Completeness = "complete"
	Partial   Completeness = "partial"
	Truncated Completeness = "truncated"
	Failed    Completeness = "failed"
)

type ClaimKind string

const (
	ClaimAsserted  ClaimKind = "claim"
	ClaimRetracted ClaimKind = "retraction"
)

// RawClaim is one (actor, technique) assertion exactly as a source adapter
// saw it, captured before any downstream actor-merge or technique-count
// filter (spec §6.2). ActorName is matched against the resolved threat
// roster by the scheduler, the same way upsertActorSources already does.
type RawClaim struct {
	ActorName     string
	TechniqueID   string
	Via           string
	ViaName       string
	ExternalID    string // the event/object id this claim came from
	ObservedAt    time.Time
	StartTime     time.Time
	StopTime      time.Time
	RawConfidence string
	Raw           map[string]any // the full raw record, stored as source_observations.raw
}

// SyncReport is what a source adapter computed about its own most recent
// Fetch() call — read by Scheduler.sync() via the CompletenessSource
// interface (internal/connector/types.go), the same pattern as StatsSource.
type SyncReport struct {
	Completeness Completeness
	Diagnostic   string
}
```

```go
// internal/evidence/store.go
package evidence

import "github.com/jackc/pgx/v5/pgxpool"

type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }
```

```go
// internal/evidence/confidence.go
package evidence

// confidenceMappingVersion versions the per-source normalization table
// (spec §7.3). Bump it, and add a new table/branch, rather than mutating
// values an already-generated content_generations.evidence_snapshot_hash
// depends on.
const confidenceMappingVersion = "tcf2b-confidence-v1"

// mispConfidenceLevels is MISP's confidence-level taxonomy, closed and
// documented (spec §7.3) — an unrecognized raw string normalizes to nil,
// never an invented value.
var mispConfidenceLevels = map[string]int{
	"low":      25,
	"medium":   55,
	"high":     85,
	"complete": 100,
}

func ptrStr(s string) *string { return &s }
func ptrInt(i int) *int       { return &i }

// NormalizeConfidence maps one source's raw confidence string to a 0-100
// normalized value, per the closed, versioned, per-source table in spec
// §7.3. raw is preserved verbatim when non-empty and the source structurally
// carries confidence at all; bundle and OTX never do, so both return (nil,
// nil, version) regardless of input — no invented 100, ever.
func NormalizeConfidence(source, raw string) (rawOut *string, normalized *int, mappingVersion string) {
	mappingVersion = confidenceMappingVersion
	switch source {
	case "opencti":
		if raw == "" {
			return nil, nil, mappingVersion
		}
		var n int
		for _, c := range raw {
			if c < '0' || c > '9' {
				return ptrStr(raw), nil, mappingVersion
			}
			n = n*10 + int(c-'0')
		}
		return ptrStr(raw), ptrInt(n), mappingVersion
	case "misp":
		if raw == "" {
			return nil, nil, mappingVersion
		}
		if n, ok := mispConfidenceLevels[raw]; ok {
			return ptrStr(raw), ptrInt(n), mappingVersion
		}
		return ptrStr(raw), nil, mappingVersion
	default: // "bundle", "otx": no structural confidence (spec §7.3)
		return nil, nil, mappingVersion
	}
}
```

```go
// internal/evidence/testmain_test.go
package evidence

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

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/evidence/... -run TestNormalizeConfidence -v`
Expected: PASS (all 4 subtests)

- [ ] **Step 5: Commit**

```bash
git add internal/evidence/types.go internal/evidence/store.go internal/evidence/confidence.go internal/evidence/testmain_test.go internal/evidence/confidence_test.go
git commit -m "feat(tcf2b): evidence package scaffold, types, confidence normalization (spec §7.3)"
```

---

### Task 3: Source trust + admin API

**Files:**
- Create: `internal/evidence/trust.go`
- Create: `internal/api/intel_sources_handlers.go`
- Modify: `internal/auth/permissions.go` (add `CanManageSourceTrust`, near `CanResolveActorIdentity` at line 220; add to `RoleAdmin` map near line 278; add to the completeness list near line 363)
- Modify: `internal/api/routes.go` (register the route, near line 411)
- Test: `internal/evidence/trust_test.go`
- Test: `internal/auth/permissions_source_trust_test.go`

**Interfaces:**
- Consumes: `Store` (Task 2).
- Produces: `(s *Store) EnsureSourceInstance(ctx, id, sourceType, displayName string, mode ObservationMode, defaultTrust TrustState) error`, `(s *Store) CurrentTrust(ctx, instanceID string) (TrustState, int64, error)`, `(s *Store) SetTrust(ctx, instanceID string, state TrustState, changedBy, reason string) error` — all consumed by Task 4 (sync recording needs the current trust version id) and every later evidence-writing task.

- [ ] **Step 1: Write the failing test**

```go
// internal/evidence/trust_test.go
package evidence

import (
	"context"
	"testing"
)

func TestSourceTrust_DefaultOnCreateThenAdminOverride(t *testing.T) {
	ctx := context.Background()
	store := NewStore(sharedDB.Pool)
	id := "misp-test-1"

	if err := store.EnsureSourceInstance(ctx, id, "misp", "Test MISP", ModeSnapshot, TrustTrusted); err != nil {
		t.Fatal(err)
	}
	state, _, err := store.CurrentTrust(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if state != TrustTrusted {
		t.Fatalf("state = %q, want trusted (MISP default)", state)
	}

	// Re-ensuring an existing instance never resets trust (spec §5.1: trust
	// changes only through SetTrust).
	if err := store.EnsureSourceInstance(ctx, id, "misp", "Test MISP", ModeSnapshot, TrustUntrusted); err != nil {
		t.Fatal(err)
	}
	state, _, err = store.CurrentTrust(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if state != TrustTrusted {
		t.Fatalf("state = %q after re-ensure, want unchanged trusted", state)
	}

	if err := store.SetTrust(ctx, id, TrustUntrusted, "admin-1", "demoted for review"); err != nil {
		t.Fatal(err)
	}
	state, versionID, err := store.CurrentTrust(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if state != TrustUntrusted {
		t.Fatalf("state after SetTrust = %q, want untrusted", state)
	}
	if versionID == 0 {
		t.Fatal("trust version id must be set")
	}
}

func TestSourceTrust_SetTrustRequiresReason(t *testing.T) {
	ctx := context.Background()
	store := NewStore(sharedDB.Pool)
	id := "otx-test-1"
	if err := store.EnsureSourceInstance(ctx, id, "otx", "Test OTX", ModeActivityWindow, TrustUntrusted); err != nil {
		t.Fatal(err)
	}
	if err := store.SetTrust(ctx, id, TrustTrusted, "admin-1", ""); err == nil {
		t.Fatal("expected an error for an empty reason")
	}
}
```

```go
// internal/auth/permissions_source_trust_test.go
package auth

import "testing"

func TestCanManageSourceTrust_AdminOnly(t *testing.T) {
	if !HasPermission(RoleAdmin, CanManageSourceTrust) {
		t.Error("expected RoleAdmin to hold CanManageSourceTrust")
	}
	if HasPermission(RoleAnalyst, CanManageSourceTrust) {
		t.Error("expected RoleAnalyst NOT to hold CanManageSourceTrust")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/evidence/... -run TestSourceTrust -v && go test ./internal/auth/... -run TestCanManageSourceTrust -v`
Expected: FAIL — `undefined: EnsureSourceInstance` / `undefined: CanManageSourceTrust` (neither exists yet).

- [ ] **Step 3: Write minimal implementation**

```go
// internal/evidence/trust.go
package evidence

import (
	"context"
	"fmt"
)

// EnsureSourceInstance creates a source instance if absent, writing the
// source's default trust version as its first trust_versions row (spec
// §5.1's default-trust table). Idempotent: an existing instance's trust is
// left untouched, even if defaultTrust differs from what's stored -- trust
// changes only through SetTrust, an audited admin action.
func (s *Store) EnsureSourceInstance(ctx context.Context, id, sourceType, displayName string, mode ObservationMode, defaultTrust TrustState) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx, `INSERT INTO source_instances (id, source_type, display_name, observation_mode)
		VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO NOTHING`, id, sourceType, displayName, mode)
	if err != nil {
		return fmt.Errorf("evidence: ensure source instance: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, `INSERT INTO source_trust_versions (source_instance_id, trust_state, changed_by, reason)
		VALUES ($1, $2, 'system', 'default trust on instance creation')`, id, defaultTrust); err != nil {
		return fmt.Errorf("evidence: default trust version: %w", err)
	}
	return tx.Commit(ctx)
}

// CurrentTrust returns the source instance's trust state in force right
// now (the latest trust_versions row by effective_at), and that row's id --
// every claim/observation written under it must carry this trust_version_id
// (spec §7.4: history answers "was this source trusted when observed",
// never current configuration).
func (s *Store) CurrentTrust(ctx context.Context, instanceID string) (TrustState, int64, error) {
	var state string
	var id int64
	err := s.pool.QueryRow(ctx, `SELECT trust_state, id FROM source_trust_versions
		WHERE source_instance_id = $1 ORDER BY effective_at DESC, id DESC LIMIT 1`, instanceID).Scan(&state, &id)
	if err != nil {
		return "", 0, fmt.Errorf("evidence: current trust for %q: %w", instanceID, err)
	}
	return TrustState(state), id, nil
}

// SetTrust records a new trust version -- an admin-only, audited action
// (spec §5.1). Append-only: never updates or deletes an earlier version.
func (s *Store) SetTrust(ctx context.Context, instanceID string, state TrustState, changedBy, reason string) error {
	if reason == "" {
		return fmt.Errorf("evidence: SetTrust requires a reason")
	}
	if _, err := s.pool.Exec(ctx, `INSERT INTO source_trust_versions (source_instance_id, trust_state, changed_by, reason)
		VALUES ($1, $2, $3, $4)`, instanceID, state, changedBy, reason); err != nil {
		return fmt.Errorf("evidence: set trust: %w", err)
	}
	return nil
}
```

```go
// internal/api/intel_sources_handlers.go
package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/evidence"
)

// SetSourceTrust -- POST /api/intel/sources/{id}/trust
// {trustState: trusted|untrusted, reason}. Admin-only, audited (spec §5.1).
func (h *Handler) SetSourceTrust(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		jsonError(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		TrustState string `json:"trustState"`
		Reason     string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		jsonError(w, "body must be {trustState, reason}", http.StatusBadRequest)
		return
	}
	if req.TrustState != "trusted" && req.TrustState != "untrusted" {
		jsonError(w, `trustState must be "trusted" or "untrusted"`, http.StatusBadRequest)
		return
	}
	if req.Reason == "" {
		jsonError(w, "reason is required", http.StatusBadRequest)
		return
	}
	id := chi.URLParam(r, "id")
	store := evidence.NewStore(h.db)
	if err := store.SetTrust(r.Context(), id, evidence.TrustState(req.TrustState), actorFor(r), req.Reason); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "intel.source.set_trust", id, map[string]any{
		"trustState": req.TrustState, "reason": req.Reason}, "ok")
	respond(w, map[string]any{"sourceId": id, "trustState": req.TrustState})
}
```

```go
// internal/auth/permissions.go -- insert after line 220's CanResolveActorIdentity
	// TCF Phase 2B: change a source instance's trust state (Admin only).
	CanManageSourceTrust Permission = "intel:manage-source-trust"
```

```go
// internal/auth/permissions.go -- insert into the RoleAdmin map literal, after line 278's CanResolveActorIdentity: true,
		CanManageSourceTrust:    true,
```

```go
// internal/auth/permissions.go -- insert into the completeness list, after line 363's CanResolveActorIdentity,
		CanManageSourceTrust,
```

```go
// internal/api/routes.go -- insert after line 411 (DecideActorResolution route)
		r.With(auth.RequirePermission(auth.CanManageSourceTrust)).Post("/api/intel/sources/{id}/trust", h.SetSourceTrust)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/evidence/... -run TestSourceTrust -v && go test ./internal/auth/... -run TestCanManageSourceTrust -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/evidence/trust.go internal/evidence/trust_test.go internal/api/intel_sources_handlers.go internal/auth/permissions.go internal/auth/permissions_source_trust_test.go internal/api/routes.go
git commit -m "feat(tcf2b): source trust store + admin trust-change API (spec §5.1)"
```

---

### Task 4: Sync recording

**Files:**
- Create: `internal/evidence/sync.go`
- Test: `internal/evidence/sync_test.go`

**Interfaces:**
- Consumes: `Store.EnsureSourceInstance` (Task 3).
- Produces: `(s *Store) RecordSync(ctx, instanceID string, mode ObservationMode, started time.Time, status string, completeness Completeness, diagnostic string) (syncID string, authoritative bool, err error)` — consumed by Task 5 (observations), Task 6 (claims), and Task 11 (scheduler wiring).

- [ ] **Step 1: Write the failing test**

```go
// internal/evidence/sync_test.go
package evidence

import (
	"context"
	"testing"
	"time"
)

func TestRecordSync_CompleteSnapshotIsAuthoritative(t *testing.T) {
	ctx := context.Background()
	store := NewStore(sharedDB.Pool)
	id := "misp-sync-test-1"
	if err := store.EnsureSourceInstance(ctx, id, "misp", "Test", ModeSnapshot, TrustTrusted); err != nil {
		t.Fatal(err)
	}
	_, authoritative, err := store.RecordSync(ctx, id, ModeSnapshot, time.Now(), "succeeded", Complete, "")
	if err != nil {
		t.Fatal(err)
	}
	if !authoritative {
		t.Fatal("complete snapshot sync must be authoritative")
	}
}

func TestRecordSync_PartialSnapshotIsNotAuthoritative(t *testing.T) {
	ctx := context.Background()
	store := NewStore(sharedDB.Pool)
	id := "misp-sync-test-2"
	if err := store.EnsureSourceInstance(ctx, id, "misp", "Test", ModeSnapshot, TrustTrusted); err != nil {
		t.Fatal(err)
	}
	_, authoritative, err := store.RecordSync(ctx, id, ModeSnapshot, time.Now(), "succeeded", Partial, "one event detail fetch failed")
	if err != nil {
		t.Fatal(err)
	}
	if authoritative {
		t.Fatal("partial snapshot sync must not be authoritative")
	}
}

func TestRecordSync_ActivityWindowNeverAuthoritative(t *testing.T) {
	ctx := context.Background()
	store := NewStore(sharedDB.Pool)
	id := "otx-sync-test-1"
	if err := store.EnsureSourceInstance(ctx, id, "otx", "Test", ModeActivityWindow, TrustUntrusted); err != nil {
		t.Fatal(err)
	}
	_, authoritative, err := store.RecordSync(ctx, id, ModeActivityWindow, time.Now(), "succeeded", Complete, "")
	if err != nil {
		t.Fatal(err)
	}
	if authoritative {
		t.Fatal("activity_window source must never be authoritative, even if it reports complete")
	}
}

func TestRecordSync_FailedSyncForcesFailedCompleteness(t *testing.T) {
	ctx := context.Background()
	store := NewStore(sharedDB.Pool)
	id := "misp-sync-test-3"
	if err := store.EnsureSourceInstance(ctx, id, "misp", "Test", ModeSnapshot, TrustTrusted); err != nil {
		t.Fatal(err)
	}
	syncID, authoritative, err := store.RecordSync(ctx, id, ModeSnapshot, time.Now(), "failed", Complete, "network error")
	if err != nil {
		t.Fatal(err)
	}
	if authoritative {
		t.Fatal("a failed sync must never be authoritative, regardless of the completeness argument passed")
	}
	var storedCompleteness string
	if err := sharedDB.Pool.QueryRow(ctx, `SELECT completeness FROM source_syncs WHERE id = $1`, syncID).Scan(&storedCompleteness); err != nil {
		t.Fatal(err)
	}
	if storedCompleteness != "failed" {
		t.Fatalf("stored completeness = %q, want failed", storedCompleteness)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/evidence/... -run TestRecordSync -v`
Expected: FAIL — `undefined: RecordSync`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/evidence/sync.go
package evidence

import (
	"context"
	"fmt"
	"time"
)

// RecordSync writes one source_syncs row and computes authoritative per the
// evidence layer's own rule (spec §6.1): authoritative = (completeness ==
// complete AND mode == snapshot), regardless of what the caller passes --
// the evidence layer decides this itself, never trusting an adapter's own
// say-so. A failed sync is always forced to completeness = failed.
func (s *Store) RecordSync(ctx context.Context, instanceID string, mode ObservationMode, started time.Time, status string, completeness Completeness, diagnostic string) (syncID string, authoritative bool, err error) {
	if status != "succeeded" && status != "failed" {
		return "", false, fmt.Errorf("evidence: RecordSync status must be succeeded or failed, got %q", status)
	}
	if status == "failed" {
		completeness = Failed
	}
	authoritative = completeness == Complete && mode == ModeSnapshot
	err = s.pool.QueryRow(ctx, `INSERT INTO source_syncs
		(source_instance_id, started_at, completed_at, status, completeness, authoritative, diagnostic)
		VALUES ($1, $2, NOW(), $3, $4, $5, $6) RETURNING id`,
		instanceID, started, status, completeness, authoritative, diagnostic).Scan(&syncID)
	if err != nil {
		return "", false, fmt.Errorf("evidence: record sync: %w", err)
	}
	return syncID, authoritative, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/evidence/... -run TestRecordSync -v`
Expected: PASS (all 4 subtests)

- [ ] **Step 5: Commit**

```bash
git add internal/evidence/sync.go internal/evidence/sync_test.go
git commit -m "feat(tcf2b): sync recording with evidence-layer-computed authoritative flag (spec §5.2, §6.1)"
```

---

### Task 5: Observations and threat-source linking

**Files:**
- Create: `internal/evidence/observations.go`
- Test: `internal/evidence/observations_test.go` (also defines the `seedThreat` helper, reused by Tasks 6-7)

**Interfaces:**
- Consumes: `Store.RecordSync`, `Store.CurrentTrust` (Tasks 3-4).
- Produces: `(s *Store) RecordObservation(ctx, syncID, instanceID, externalID, rawName, recordHash string, observedAt time.Time, raw map[string]any, trustVersionID int64) (observationID string, err error)`, `(s *Store) LinkThreatSource(ctx, threatID, observationID, provider, externalID string, observedAt time.Time, sourceConfidence *int, recordHash, linkedBy, linkedRef string) error` — consumed by Task 6 (claims reference the same observation) and Task 11 (scheduler wiring).
- `seedThreat(t, pool, name string) string` test helper — consumed by Tasks 6 and 7's tests.

- [ ] **Step 1: Write the failing test**

```go
// internal/evidence/observations_test.go
package evidence

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// seedThreat creates a resolved actor + its Threat directly, bypassing the
// resolver (this package tests evidence recording, not identity
// resolution, which internal/threatidentity already covers).
func seedThreat(t *testing.T, pool *pgxpool.Pool, name string) string {
	t.Helper()
	ctx := context.Background()
	var actorID string
	if err := pool.QueryRow(ctx, `INSERT INTO threat_actor_profiles (name, aliases) VALUES ($1, '{}') RETURNING id`,
		name).Scan(&actorID); err != nil {
		t.Fatal(err)
	}
	var threatID string
	if err := pool.QueryRow(ctx, `INSERT INTO threats (id, subject_type, subject_id, actor_id, title)
		VALUES ('thr-' || gen_random_uuid()::text, 'actor', $1, $1, $2) RETURNING id`,
		actorID, name).Scan(&threatID); err != nil {
		t.Fatal(err)
	}
	return threatID
}

func TestRecordObservationAndLinkThreatSource(t *testing.T) {
	ctx := context.Background()
	store := NewStore(sharedDB.Pool)
	instanceID := "misp-obs-test-1"
	if err := store.EnsureSourceInstance(ctx, instanceID, "misp", "Test", ModeSnapshot, TrustTrusted); err != nil {
		t.Fatal(err)
	}
	syncID, _, err := store.RecordSync(ctx, instanceID, ModeSnapshot, time.Now(), "succeeded", Complete, "")
	if err != nil {
		t.Fatal(err)
	}
	_, trustVersionID, err := store.CurrentTrust(ctx, instanceID)
	if err != nil {
		t.Fatal(err)
	}

	obsID, err := store.RecordObservation(ctx, syncID, instanceID, "evt-1", "APT29", "hash-abc",
		time.Now(), map[string]any{"name": "APT29"}, trustVersionID)
	if err != nil {
		t.Fatal(err)
	}
	if obsID == "" {
		t.Fatal("observation id must be set")
	}

	threatID := seedThreat(t, sharedDB.Pool, "APT29-obs-test")
	conf := 85
	if err := store.LinkThreatSource(ctx, threatID, obsID, "misp", "evt-1", time.Now(), &conf, "hash-abc", "resolver", ""); err != nil {
		t.Fatal(err)
	}

	var count int
	if err := sharedDB.Pool.QueryRow(ctx, `SELECT count(*) FROM threat_sources WHERE threat_id = $1`, threatID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("threat_sources rows = %d, want 1", count)
	}

	// A second link attempt for the SAME observation is refused -- an
	// observation is evidence for exactly one threat (UNIQUE(observation_id)).
	if err := store.LinkThreatSource(ctx, threatID, obsID, "misp", "evt-1", time.Now(), &conf, "hash-abc", "resolver", ""); err == nil {
		t.Fatal("expected an error linking the same observation twice")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/evidence/... -run TestRecordObservationAndLinkThreatSource -v`
Expected: FAIL — `undefined: RecordObservation`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/evidence/observations.go
package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// RecordObservation writes one append-only source_observations row (spec
// §5.3). recordHash identifies this exact raw record so a later identical
// re-fetch can be recognized without re-deriving meaning from raw.
func (s *Store) RecordObservation(ctx context.Context, syncID, instanceID, externalID, rawName, recordHash string, observedAt time.Time, raw map[string]any, trustVersionID int64) (observationID string, err error) {
	rawJSON, err := json.Marshal(raw)
	if err != nil {
		return "", fmt.Errorf("evidence: marshal raw observation: %w", err)
	}
	err = s.pool.QueryRow(ctx, `INSERT INTO source_observations
		(sync_id, source_instance_id, external_id, raw_name, record_hash, observed_at, raw, trust_version_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
		syncID, instanceID, externalID, rawName, recordHash, observedAt, rawJSON, trustVersionID).Scan(&observationID)
	if err != nil {
		return "", fmt.Errorf("evidence: record observation: %w", err)
	}
	return observationID, nil
}

// LinkThreatSource links one observation's evidence to a resolved threat
// (spec §5.3). An observation is linked at most once -- schema's
// UNIQUE(observation_id) turns a second attempt into an error rather than
// a silently accepted duplicate link.
func (s *Store) LinkThreatSource(ctx context.Context, threatID, observationID, provider, externalID string, observedAt time.Time, sourceConfidence *int, recordHash, linkedBy, linkedRef string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO threat_sources
		(threat_id, observation_id, provider, external_id, observed_at, source_confidence, record_hash, linked_by, linked_ref)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		threatID, observationID, provider, externalID, observedAt, sourceConfidence, recordHash, linkedBy, linkedRef)
	if err != nil {
		return fmt.Errorf("evidence: link threat source: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/evidence/... -run TestRecordObservationAndLinkThreatSource -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/evidence/observations.go internal/evidence/observations_test.go
git commit -m "feat(tcf2b): source observations and threat-source linking (spec §5.3)"
```

---

### Task 6: Claims and the retraction-refusal rule

**Files:**
- Create: `internal/evidence/claims.go`
- Test: `internal/evidence/claims_test.go`

**Interfaces:**
- Consumes: `Store.RecordSync`, `Store.RecordObservation`, `Store.CurrentTrust`, `NormalizeConfidence`, `seedThreat` (Tasks 2-5).
- Produces: `Claim` struct, `ErrRetractionRefused`, `(s *Store) RecordClaims(ctx context.Context, claims []Claim) error` — consumed by Task 7 (projection reads `technique_claims`) and Task 11 (scheduler wiring).

- [ ] **Step 1: Write the failing test**

```go
// internal/evidence/claims_test.go
package evidence

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRecordClaims_RetractionRefusedOnNonAuthoritativeSync(t *testing.T) {
	ctx := context.Background()
	store := NewStore(sharedDB.Pool)
	instanceID := "misp-claims-test-1"
	if err := store.EnsureSourceInstance(ctx, instanceID, "misp", "Test", ModeSnapshot, TrustTrusted); err != nil {
		t.Fatal(err)
	}
	syncID, authoritative, err := store.RecordSync(ctx, instanceID, ModeSnapshot, time.Now(), "succeeded", Partial, "one event detail fetch failed")
	if err != nil {
		t.Fatal(err)
	}
	if authoritative {
		t.Fatal("test setup: this sync must not be authoritative")
	}
	_, trustVersionID, err := store.CurrentTrust(ctx, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	threatID := seedThreat(t, sharedDB.Pool, "APT-claims-retraction-refused")
	obsID, err := store.RecordObservation(ctx, syncID, instanceID, "evt-1", "APT", "hash-1", time.Now(), map[string]any{}, trustVersionID)
	if err != nil {
		t.Fatal(err)
	}

	err = store.RecordClaims(ctx, []Claim{{
		ObservationID: obsID, SyncID: syncID, InstanceID: instanceID, ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimRetracted, Source: "misp",
		TrustVersionID: trustVersionID, ObservedAt: time.Now(), RecordHash: "hash-1",
	}})
	if !errors.Is(err, ErrRetractionRefused) {
		t.Fatalf("err = %v, want ErrRetractionRefused", err)
	}

	var count int
	if err := sharedDB.Pool.QueryRow(ctx, `SELECT count(*) FROM technique_claims WHERE threat_id = $1`, threatID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("technique_claims rows = %d, want 0 (refused call must write nothing)", count)
	}
}

func TestRecordClaims_RetractionAcceptedOnAuthoritativeSync(t *testing.T) {
	ctx := context.Background()
	store := NewStore(sharedDB.Pool)
	instanceID := "misp-claims-test-2"
	if err := store.EnsureSourceInstance(ctx, instanceID, "misp", "Test", ModeSnapshot, TrustTrusted); err != nil {
		t.Fatal(err)
	}
	syncID, authoritative, err := store.RecordSync(ctx, instanceID, ModeSnapshot, time.Now(), "succeeded", Complete, "")
	if err != nil {
		t.Fatal(err)
	}
	if !authoritative {
		t.Fatal("test setup: this sync must be authoritative")
	}
	_, trustVersionID, err := store.CurrentTrust(ctx, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	threatID := seedThreat(t, sharedDB.Pool, "APT-claims-retraction-accepted")
	obsID, err := store.RecordObservation(ctx, syncID, instanceID, "evt-1", "APT", "hash-2", time.Now(), map[string]any{}, trustVersionID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordClaims(ctx, []Claim{{
		ObservationID: obsID, SyncID: syncID, InstanceID: instanceID, ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimRetracted, Source: "misp",
		TrustVersionID: trustVersionID, ObservedAt: time.Now(), RecordHash: "hash-2",
	}}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := sharedDB.Pool.QueryRow(ctx,
		`SELECT count(*) FROM technique_claims WHERE threat_id = $1 AND kind = 'retraction'`, threatID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("retraction rows = %d, want 1", count)
	}
}

func TestRecordClaims_TwoSourcesSameClaimBothSurvive(t *testing.T) {
	ctx := context.Background()
	store := NewStore(sharedDB.Pool)
	threatID := seedThreat(t, sharedDB.Pool, "APT-claims-two-sources")

	mispID, otherID := "misp-claims-test-3a", "misp-claims-test-3b"
	for _, id := range []string{mispID, otherID} {
		if err := store.EnsureSourceInstance(ctx, id, "misp", "Test", ModeSnapshot, TrustTrusted); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{mispID, otherID} {
		syncID, _, err := store.RecordSync(ctx, id, ModeSnapshot, time.Now(), "succeeded", Complete, "")
		if err != nil {
			t.Fatal(err)
		}
		_, trustVersionID, err := store.CurrentTrust(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		obsID, err := store.RecordObservation(ctx, syncID, id, "evt-x", "APT", "hash-"+id, time.Now(), map[string]any{}, trustVersionID)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.RecordClaims(ctx, []Claim{{
			ObservationID: obsID, SyncID: syncID, InstanceID: id, ThreatID: threatID,
			TechniqueID: "T1059", Kind: ClaimAsserted, Source: "misp",
			TrustVersionID: trustVersionID, ObservedAt: time.Now(), RecordHash: "hash-" + id,
		}}); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := sharedDB.Pool.QueryRow(ctx,
		`SELECT count(*) FROM technique_claims WHERE threat_id = $1 AND technique_id = 'T1059'`, threatID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("claim rows = %d, want 2 -- identical text from two providers must not be deduplicated away", count)
	}
}

func TestRecordClaims_IdempotentOnRecordHash(t *testing.T) {
	ctx := context.Background()
	store := NewStore(sharedDB.Pool)
	instanceID := "misp-claims-test-4"
	if err := store.EnsureSourceInstance(ctx, instanceID, "misp", "Test", ModeSnapshot, TrustTrusted); err != nil {
		t.Fatal(err)
	}
	syncID, _, err := store.RecordSync(ctx, instanceID, ModeSnapshot, time.Now(), "succeeded", Complete, "")
	if err != nil {
		t.Fatal(err)
	}
	_, trustVersionID, err := store.CurrentTrust(ctx, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	threatID := seedThreat(t, sharedDB.Pool, "APT-claims-idempotent")
	obsID, err := store.RecordObservation(ctx, syncID, instanceID, "evt-1", "APT", "hash-rerun", time.Now(), map[string]any{}, trustVersionID)
	if err != nil {
		t.Fatal(err)
	}
	claim := Claim{
		ObservationID: obsID, SyncID: syncID, InstanceID: instanceID, ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimAsserted, Source: "misp",
		TrustVersionID: trustVersionID, ObservedAt: time.Now(), RecordHash: "hash-rerun",
	}
	if err := store.RecordClaims(ctx, []Claim{claim}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordClaims(ctx, []Claim{claim}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := sharedDB.Pool.QueryRow(ctx,
		`SELECT count(*) FROM technique_claims WHERE threat_id = $1 AND technique_id = 'T1059'`, threatID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("claim rows after re-recording identical claim = %d, want 1", count)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/evidence/... -run TestRecordClaims -v`
Expected: FAIL — `undefined: RecordClaims`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/evidence/claims.go
package evidence

import (
	"context"
	"fmt"
	"time"
)

// Claim is one (threat, technique) assertion from a single observation.
type Claim struct {
	ObservationID       string
	SyncID              string
	InstanceID          string
	ThreatID            string
	TechniqueID         string
	Kind                ClaimKind
	Via, ViaName        string
	StartTime, StopTime time.Time
	RawConfidence       string
	Source              string // "misp" | "opencti" | "bundle" | "otx" -- selects the confidence mapping
	TrustVersionID      int64
	ObservedAt          time.Time
	RecordHash          string
}

// ErrRetractionRefused is returned by RecordClaims when a retraction is
// requested on a sync that is not authoritative (spec §6.1: absence is not
// retraction, except from a sync that is complete AND a snapshot source).
var ErrRetractionRefused = fmt.Errorf("evidence: retraction refused: sync is not authoritative")

// RecordClaims writes append-only technique_claims rows. A claim is always
// accepted. A retraction is accepted only when its owning sync is
// authoritative -- checked here from source_syncs, never trusting the
// caller's Kind. Any retraction in the batch that fails this check refuses
// the WHOLE call (fail closed, not a partial write).
func (s *Store) RecordClaims(ctx context.Context, claims []Claim) error {
	if len(claims) == 0 {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	authoritativeBySync := map[string]bool{}
	for _, c := range claims {
		if c.Kind != ClaimRetracted {
			continue
		}
		if _, checked := authoritativeBySync[c.SyncID]; checked {
			continue
		}
		var authoritative bool
		if err := tx.QueryRow(ctx, `SELECT authoritative FROM source_syncs WHERE id = $1`, c.SyncID).Scan(&authoritative); err != nil {
			return fmt.Errorf("evidence: check sync authoritative: %w", err)
		}
		authoritativeBySync[c.SyncID] = authoritative
		if !authoritative {
			return ErrRetractionRefused
		}
	}

	for _, c := range claims {
		rawConf, normConf, mappingVersion := NormalizeConfidence(c.Source, c.RawConfidence)
		var startTime, stopTime *time.Time
		if !c.StartTime.IsZero() {
			startTime = &c.StartTime
		}
		if !c.StopTime.IsZero() {
			stopTime = &c.StopTime
		}
		if _, err := tx.Exec(ctx, `INSERT INTO technique_claims
			(observation_id, sync_id, source_instance_id, threat_id, technique_id, kind, via, via_name,
			 start_time, stop_time, raw_confidence, normalized_confidence, confidence_mapping_version,
			 trust_version_id, observed_at, record_hash)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
			ON CONFLICT (source_instance_id, threat_id, technique_id, via, via_name, record_hash) DO NOTHING`,
			c.ObservationID, c.SyncID, c.InstanceID, c.ThreatID, c.TechniqueID, c.Kind, c.Via, c.ViaName,
			startTime, stopTime, rawConf, normConf, mappingVersion,
			c.TrustVersionID, c.ObservedAt, c.RecordHash); err != nil {
			return fmt.Errorf("evidence: record claim (%s, %s): %w", c.ThreatID, c.TechniqueID, err)
		}
	}
	return tx.Commit(ctx)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/evidence/... -run TestRecordClaims -v`
Expected: PASS (all 4 subtests)

- [ ] **Step 5: Commit**

```bash
git add internal/evidence/claims.go internal/evidence/claims_test.go
git commit -m "feat(tcf2b): append-only technique claims with retraction-refusal rule (spec §6.1, §6.3)"
```

---

### Task 7: Projection — `threat_techniques`

**Files:**
- Create: `internal/evidence/projection.go`
- Modify: `internal/evidence/store.go` (add the `Querier` interface and the `pgx`/`pgconn` imports it needs)
- Test: `internal/evidence/projection_test.go`

**Interfaces:**
- Consumes: `Store.RecordClaims`, `Store.SetTrust`, `ClaimAsserted`/`ClaimRetracted`, `TrustTrusted`/`TrustUntrusted`, `seedThreat` (Tasks 2-6).
- Produces: `Querier` interface (the subset of pgx shared by `*pgxpool.Pool` and `pgx.Tx`), `(s *Store) RecomputeThreatTechniques(ctx context.Context, threatID string) error` — called explicitly after `RecordClaims` and after `SetTrust` by Task 11 (scheduler wiring) and Task 3's admin handler; consumed by Task 12 (generation reads the resulting active set).

- [ ] **Step 1: Write the failing test**

```go
// internal/evidence/projection_test.go
package evidence

import (
	"context"
	"testing"
	"time"
)

// claimsFixture sets up one source instance + sync + observation, ready to
// record claims against. Returns the store and everything a claim needs.
func claimsFixture(t *testing.T, instanceID string, trust TrustState, completeness Completeness) (store *Store, syncID, trustVersionIDSource string, trustVersionID int64, obsID func(threatID, hash string) string) {
	t.Helper()
	ctx := context.Background()
	store = NewStore(sharedDB.Pool)
	if err := store.EnsureSourceInstance(ctx, instanceID, "misp", "Test", ModeSnapshot, trust); err != nil {
		t.Fatal(err)
	}
	sID, _, err := store.RecordSync(ctx, instanceID, ModeSnapshot, time.Now(), "succeeded", completeness, "")
	if err != nil {
		t.Fatal(err)
	}
	_, tvID, err := store.CurrentTrust(ctx, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	return store, sID, instanceID, tvID, func(threatID, hash string) string {
		id, err := store.RecordObservation(ctx, sID, instanceID, "evt-"+hash, "APT", hash, time.Now(), map[string]any{}, tvID)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
}

func TestRecomputeThreatTechniques_ActiveFromTrustedClaim(t *testing.T) {
	ctx := context.Background()
	store, syncID, instanceID, tvID, mkObs := claimsFixture(t, "misp-proj-test-1", TrustTrusted, Complete)
	threatID := seedThreat(t, sharedDB.Pool, "APT-proj-active")
	obsID := mkObs(threatID, "hash-active")
	if err := store.RecordClaims(ctx, []Claim{{
		ObservationID: obsID, SyncID: syncID, InstanceID: instanceID, ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimAsserted, Source: "misp", RawConfidence: "high",
		TrustVersionID: tvID, ObservedAt: time.Now(), RecordHash: "hash-active",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecomputeThreatTechniques(ctx, threatID); err != nil {
		t.Fatal(err)
	}

	var status string
	var confidence *int
	if err := sharedDB.Pool.QueryRow(ctx,
		`SELECT status, best_confidence FROM threat_techniques WHERE threat_id = $1 AND technique_id = 'T1059'`,
		threatID).Scan(&status, &confidence); err != nil {
		t.Fatal(err)
	}
	if status != "active" {
		t.Fatalf("status = %q, want active", status)
	}
	if confidence == nil || *confidence != 85 {
		t.Fatalf("best_confidence = %v, want 85 (MISP \"high\")", confidence)
	}
}

func TestRecomputeThreatTechniques_SourceRetractionMarksRetracted(t *testing.T) {
	ctx := context.Background()
	store, syncID, instanceID, tvID, mkObs := claimsFixture(t, "misp-proj-test-2", TrustTrusted, Complete)
	threatID := seedThreat(t, sharedDB.Pool, "APT-proj-retracted")
	claimObs := mkObs(threatID, "hash-r-claim")
	if err := store.RecordClaims(ctx, []Claim{{
		ObservationID: claimObs, SyncID: syncID, InstanceID: instanceID, ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimAsserted, Source: "misp",
		TrustVersionID: tvID, ObservedAt: time.Now().Add(-time.Hour), RecordHash: "hash-r-claim",
	}}); err != nil {
		t.Fatal(err)
	}
	// A later, complete snapshot sync no longer contains this technique --
	// an explicit retraction observation (spec §6.1).
	retractObs := mkObs(threatID, "hash-r-retract")
	if err := store.RecordClaims(ctx, []Claim{{
		ObservationID: retractObs, SyncID: syncID, InstanceID: instanceID, ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimRetracted, Source: "misp",
		TrustVersionID: tvID, ObservedAt: time.Now(), RecordHash: "hash-r-retract",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecomputeThreatTechniques(ctx, threatID); err != nil {
		t.Fatal(err)
	}

	var status, reason string
	if err := sharedDB.Pool.QueryRow(ctx,
		`SELECT status, status_reason FROM threat_techniques WHERE threat_id = $1 AND technique_id = 'T1059'`,
		threatID).Scan(&status, &reason); err != nil {
		t.Fatal(err)
	}
	if status != "retracted" || reason != "source_retraction" {
		t.Fatalf("status/reason = %q/%q, want retracted/source_retraction", status, reason)
	}
}

func TestRecomputeThreatTechniques_TrustRevocationDistinctFromSourceRetraction(t *testing.T) {
	ctx := context.Background()
	store, syncID, instanceID, tvID, mkObs := claimsFixture(t, "misp-proj-test-3", TrustTrusted, Complete)
	threatID := seedThreat(t, sharedDB.Pool, "APT-proj-trust-revoked")
	obsID := mkObs(threatID, "hash-tr-claim")
	if err := store.RecordClaims(ctx, []Claim{{
		ObservationID: obsID, SyncID: syncID, InstanceID: instanceID, ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimAsserted, Source: "misp",
		TrustVersionID: tvID, ObservedAt: time.Now(), RecordHash: "hash-tr-claim",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecomputeThreatTechniques(ctx, threatID); err != nil {
		t.Fatal(err)
	}
	// Revoking trust removes this source's claims from current support
	// (spec §7.4) -- distinguishable from a source retraction.
	if err := store.SetTrust(ctx, instanceID, TrustUntrusted, "admin-1", "source compromised"); err != nil {
		t.Fatal(err)
	}
	if err := store.RecomputeThreatTechniques(ctx, threatID); err != nil {
		t.Fatal(err)
	}

	var status, reason string
	if err := sharedDB.Pool.QueryRow(ctx,
		`SELECT status, status_reason FROM threat_techniques WHERE threat_id = $1 AND technique_id = 'T1059'`,
		threatID).Scan(&status, &reason); err != nil {
		t.Fatal(err)
	}
	if status != "retracted" || reason != "trust_revocation" {
		t.Fatalf("status/reason = %q/%q, want retracted/trust_revocation", status, reason)
	}
}

func TestRecomputeThreatTechniques_FirstSeenNeverBackdatedByLaterTrust(t *testing.T) {
	ctx := context.Background()
	store, syncID, instanceID, tvID, mkObs := claimsFixture(t, "otx-proj-test-1", TrustUntrusted, Complete)
	threatID := seedThreat(t, sharedDB.Pool, "APT-proj-untrusted-then-trusted")
	untrustedObs := mkObs(threatID, "hash-ut-claim")
	untrustedTime := time.Now().Add(-48 * time.Hour)
	if err := store.RecordClaims(ctx, []Claim{{
		ObservationID: untrustedObs, SyncID: syncID, InstanceID: instanceID, ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimAsserted, Source: "otx",
		TrustVersionID: tvID, ObservedAt: untrustedTime, RecordHash: "hash-ut-claim",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetTrust(ctx, instanceID, TrustTrusted, "admin-1", "elevated after review"); err != nil {
		t.Fatal(err)
	}
	_, trustedTvID, err := store.CurrentTrust(ctx, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	trustedTime := time.Now()
	trustedSyncID, _, err := store.RecordSync(ctx, instanceID, ModeActivityWindow, trustedTime, "succeeded", Complete, "")
	if err != nil {
		t.Fatal(err)
	}
	trustedObsID, err := store.RecordObservation(ctx, trustedSyncID, instanceID, "evt-trusted", "APT", "hash-t-claim", trustedTime, map[string]any{}, trustedTvID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordClaims(ctx, []Claim{{
		ObservationID: trustedObsID, SyncID: trustedSyncID, InstanceID: instanceID, ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimAsserted, Source: "otx",
		TrustVersionID: trustedTvID, ObservedAt: trustedTime, RecordHash: "hash-t-claim",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecomputeThreatTechniques(ctx, threatID); err != nil {
		t.Fatal(err)
	}

	var firstSeenAt time.Time
	if err := sharedDB.Pool.QueryRow(ctx,
		`SELECT first_seen_at FROM threat_techniques WHERE threat_id = $1 AND technique_id = 'T1059'`,
		threatID).Scan(&firstSeenAt); err != nil {
		t.Fatal(err)
	}
	if firstSeenAt.Before(trustedTime.Add(-time.Minute)) {
		t.Fatalf("first_seen_at = %v, must not be backdated to the untrusted claim at %v", firstSeenAt, untrustedTime)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/evidence/... -run TestRecomputeThreatTechniques -v`
Expected: FAIL — `undefined: RecomputeThreatTechniques`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/evidence/projection.go
package evidence

import (
	"context"
	"fmt"
	"time"
)

// recomputeThreatTechniques rebuilds every threat_techniques row for one
// threat from current technique_claims (spec §7). "Current" for a (source
// instance, technique) pair is its latest claim/retraction row by
// observed_at (§7.2). first_seen_at only advances from claims observed
// under a trust version that was trusted AT THAT TIME (§7.4) -- trust
// granted later never backdates it.
func recomputeThreatTechniques(ctx context.Context, q Querier, threatID string) error {
	rows, err := q.Query(ctx, `
		SELECT technique_id, source_instance_id, kind, observed_at, normalized_confidence,
		       (SELECT trust_state FROM source_trust_versions WHERE id = technique_claims.trust_version_id) AS trust_state_then,
		       (SELECT trust_state FROM source_trust_versions tv2
		          WHERE tv2.source_instance_id = technique_claims.source_instance_id
		          ORDER BY tv2.effective_at DESC, tv2.id DESC LIMIT 1) AS trust_state_now
		  FROM technique_claims
		 WHERE threat_id = $1
		 ORDER BY technique_id, source_instance_id, observed_at`, threatID)
	if err != nil {
		return fmt.Errorf("evidence: load claims for projection: %w", err)
	}
	type claimRow struct {
		techniqueID, instanceID, kind, trustStateThen, trustStateNow string
		observedAt                                                   time.Time
		normalizedConfidence                                         *int
	}
	var all []claimRow
	for rows.Next() {
		var r claimRow
		if err := rows.Scan(&r.techniqueID, &r.instanceID, &r.kind, &r.observedAt, &r.normalizedConfidence,
			&r.trustStateThen, &r.trustStateNow); err != nil {
			rows.Close()
			return err
		}
		all = append(all, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	// Latest row per (technique, source instance) is "current" (spec §7.2).
	type key struct{ technique, instance string }
	latest := map[key]claimRow{}
	for _, r := range all {
		k := key{r.techniqueID, r.instanceID}
		if existing, ok := latest[k]; !ok || r.observedAt.After(existing.observedAt) {
			latest[k] = r
		}
	}

	type techState struct {
		active            bool
		supportingSources int
		bestConfidence    *int
		firstSeenAt       *time.Time
		lastSeenAt        time.Time
		sourceRetracted   bool
		trustRevoked      bool
	}
	states := map[string]*techState{}
	for k, r := range latest {
		st, ok := states[k.technique]
		if !ok {
			st = &techState{}
			states[k.technique] = st
		}
		if r.observedAt.After(st.lastSeenAt) {
			st.lastSeenAt = r.observedAt
		}
		isClaim := r.kind == string(ClaimAsserted)
		trustedNow := r.trustStateNow == string(TrustTrusted)
		if isClaim && trustedNow {
			st.active = true
			st.supportingSources++
			if r.normalizedConfidence != nil && (st.bestConfidence == nil || *r.normalizedConfidence > *st.bestConfidence) {
				st.bestConfidence = r.normalizedConfidence
			}
		}
		if !isClaim {
			st.sourceRetracted = true
		}
		if isClaim && !trustedNow {
			st.trustRevoked = true
		}
		if isClaim && r.trustStateThen == string(TrustTrusted) {
			if st.firstSeenAt == nil || r.observedAt.Before(*st.firstSeenAt) {
				st.firstSeenAt = &r.observedAt
			}
		}
	}

	for techniqueID, st := range states {
		status, reason := "retracted", "source_retraction"
		switch {
		case st.active:
			status, reason = "active", "supported"
		case st.trustRevoked && !st.sourceRetracted:
			reason = "trust_revocation"
		}
		if _, err := q.Exec(ctx, `INSERT INTO threat_techniques
			(threat_id, technique_id, first_seen_at, last_seen_at, supporting_source_count, best_confidence, status, status_reason, projected_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
			ON CONFLICT (threat_id, technique_id) DO UPDATE SET
				first_seen_at = CASE
					WHEN threat_techniques.first_seen_at IS NULL THEN EXCLUDED.first_seen_at
					WHEN EXCLUDED.first_seen_at IS NULL THEN threat_techniques.first_seen_at
					ELSE LEAST(threat_techniques.first_seen_at, EXCLUDED.first_seen_at) END,
				last_seen_at = GREATEST(threat_techniques.last_seen_at, EXCLUDED.last_seen_at),
				supporting_source_count = EXCLUDED.supporting_source_count,
				best_confidence = EXCLUDED.best_confidence,
				status = EXCLUDED.status,
				status_reason = EXCLUDED.status_reason,
				projected_at = NOW()`,
			threatID, techniqueID, st.firstSeenAt, st.lastSeenAt, st.supportingSources, st.bestConfidence, status, reason); err != nil {
			return fmt.Errorf("evidence: upsert threat_techniques (%s, %s): %w", threatID, techniqueID, err)
		}
	}
	return nil
}

// RecomputeThreatTechniques is the Store's entry point, called immediately
// after RecordClaims and after SetTrust for every threat the triggering
// write touched (see this plan's Global Constraints note on why this is a
// separate transaction from the write itself).
func (s *Store) RecomputeThreatTechniques(ctx context.Context, threatID string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := recomputeThreatTechniques(ctx, tx, threatID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
```

```go
// internal/evidence/store.go -- add the Querier interface (used by projection.go's
// internal recomputeThreatTechniques, shared shape between *pgxpool.Pool and pgx.Tx)
// insert after the existing `type Store struct{ pool *pgxpool.Pool }` line
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}
```

(This also requires adding `"github.com/jackc/pgx/v5"` and `"github.com/jackc/pgx/v5/pgconn"` to `internal/evidence/store.go`'s imports.)

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/evidence/... -run TestRecomputeThreatTechniques -v`
Expected: PASS (all 4 subtests)

- [ ] **Step 5: Commit**

```bash
git add internal/evidence/projection.go internal/evidence/projection_test.go internal/evidence/store.go
git commit -m "feat(tcf2b): threat_techniques projection — active rule, trust/retraction history, first_seen_at (spec §7)"
```

---

### Task 8: Connector interfaces + MISP completeness and raw claims

**Files:**
- Modify: `internal/connector/types.go` (add two interfaces)
- Modify: `internal/connector/misp.go:16-26` (struct fields), `:55-121` (`Fetch`), after `:124` (`Stats`, add two methods)
- Test: `internal/connector/misp_evidence_test.go`

**Interfaces:**
- Consumes: `evidence.SyncReport`, `evidence.RawClaim`, `evidence.Complete`/`evidence.Partial` (Task 2).
- Produces: `connector.CompletenessSource` interface (`Completeness() evidence.SyncReport`), `connector.EvidenceSource` interface (`RawClaims() []evidence.RawClaim`) — consumed by every other source task (9, 10) and Task 11 (scheduler wiring, via type assertion, same pattern as the existing `StatsSource`/`TechniqueEvidenceSource`).

- [ ] **Step 1: Write the failing test**

```go
// internal/connector/misp_evidence_test.go
package connector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/evidence"
)

func TestMISPClient_Fetch_CapturesRawClaimsBeforeFilterAndReportsPartial(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/events/index":
			events := []mispEventIndex{
				{ID: "1", Info: "event one", Tag: []mispTag{{Name: "mitre-attack-pattern"}}},
				{ID: "2", Info: "event two", Tag: []mispTag{{Name: "mitre-attack-pattern"}}},
			}
			json.NewEncoder(w).Encode(events)
		case "/events/1":
			// One technique only -- below the 2-technique generation
			// threshold, but a raw claim must still be captured (spec §6.2).
			var detail mispEventDetail
			detail.Event.Tag = []mispTag{{Name: `misp-galaxy:threat-actor="Solo Actor"`}}
			detail.Event.GalaxyCluster = []mispGalaxy{{
				Type: "mitre-attack-pattern",
				Meta: struct {
					ExternalID []string `json:"external_id"`
					KillChain  []string `json:"kill_chain"`
				}{ExternalID: []string{"T1059"}},
			}}
			json.NewEncoder(w).Encode(detail)
		case "/events/2":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	c := NewMISPClient(server.URL, "test-key", nil, nil, false)
	actors, err := c.Fetch()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(actors) != 0 {
		t.Fatalf("actors = %+v, want none (Solo Actor has only 1 technique, below the generation minimum)", actors)
	}

	claims := c.RawClaims()
	found := false
	for _, cl := range claims {
		if cl.ActorName == "Solo Actor" && cl.TechniqueID == "T1059" {
			found = true
		}
	}
	if !found {
		t.Fatalf("RawClaims() = %+v, want a claim for Solo Actor/T1059 even though it was filtered from Fetch()'s return value", claims)
	}

	report := c.Completeness()
	if report.Completeness != evidence.Partial {
		t.Fatalf("Completeness() = %+v, want Partial (event 2's detail fetch failed)", report)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/connector/... -run TestMISPClient_Fetch_CapturesRawClaimsBeforeFilterAndReportsPartial -v`
Expected: FAIL — `c.RawClaims undefined` (compile error; the method doesn't exist yet).

- [ ] **Step 3: Write minimal implementation**

```go
// internal/connector/types.go -- add to the import block
import "github.com/audspect/bas/internal/evidence"

// CompletenessSource is implemented by sources that can report their most
// recent Fetch() call's completeness per the source's own semantics (spec
// §5.2), read by Scheduler.sync() the same way StatsSource.Stats() is.
type CompletenessSource interface {
	Completeness() evidence.SyncReport
}

// EvidenceSource is implemented by sources that capture raw per-record
// claims as a side effect of Fetch(), before any actor-merge or
// technique-count filter (spec §6.2) -- every (actor, technique) assertion
// the source saw, even one Fetch()'s own filtered return value drops.
type EvidenceSource interface {
	RawClaims() []evidence.RawClaim
}
```

```go
// internal/connector/misp.go:16-26 -- two new fields on MISPClient
	lastCompleteness evidence.SyncReport
	lastRawClaims    []evidence.RawClaim
```

```go
// internal/connector/misp.go -- inside Fetch(), reset the claims slice and
// add a failure counter right after "actorMap := make(...)" (line 63)
	c.lastRawClaims = nil
	detailFetchFailures := 0
```

```go
// internal/connector/misp.go:80-84 -- count the detail-fetch failure
		detail, err := c.getEvent(ev.ID)
		if err != nil {
			log.Printf("[connector/misp] fetch event %s: %v", ev.ID, err)
			detailFetchFailures++
			continue
		}
```

```go
// internal/connector/misp.go:86-89 -- capture raw claims BEFORE the
// 2-technique filter (spec §6.2: filter is generation policy, not evidence)
		actor := c.extractActor(ev, detail)
		if actor != nil {
			observedAt, _ := parseTimestamp(ev.Timestamp)
			for _, tech := range actor.Techniques {
				c.lastRawClaims = append(c.lastRawClaims, evidence.RawClaim{
					ActorName: actor.Name, TechniqueID: tech.ID, ExternalID: ev.ID,
					ObservedAt: observedAt, RawConfidence: actor.Confidence,
					Raw: map[string]any{"event_id": ev.ID, "actor_name": actor.Name, "technique_id": tech.ID},
				})
			}
		}
		if actor == nil || len(actor.Techniques) < 2 {
			continue
		}
```

```go
// internal/connector/misp.go:116 -- right after the existing c.lastStat assignment
	completeness := evidence.Complete
	diagnostic := ""
	if detailFetchFailures > 0 {
		completeness = evidence.Partial
		diagnostic = fmt.Sprintf("%d event detail fetch(es) failed", detailFetchFailures)
	}
	c.lastCompleteness = evidence.SyncReport{Completeness: completeness, Diagnostic: diagnostic}
```

```go
// internal/connector/misp.go -- two new methods, after the existing Stats() (line 124)
// Completeness implements CompletenessSource.
func (c *MISPClient) Completeness() evidence.SyncReport { return c.lastCompleteness }

// RawClaims implements EvidenceSource.
func (c *MISPClient) RawClaims() []evidence.RawClaim { return c.lastRawClaims }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/connector/... -run TestMISPClient_Fetch_CapturesRawClaimsBeforeFilterAndReportsPartial -v`
Expected: PASS. Then run `go test ./internal/connector/... -run TestMISPClient -v` to confirm the existing MISP test suite (stats, filter, intelligence) is still green.

- [ ] **Step 5: Commit**

```bash
git add internal/connector/types.go internal/connector/misp.go internal/connector/misp_evidence_test.go
git commit -m "feat(tcf2b): MISP completeness tracking and pre-filter raw-claim capture (spec §5.2, §6.2)"
```

---

### Task 9: OpenCTI completeness (truncation) and raw claims

**Files:**
- Modify: `internal/connector/opencti.go:14-37` (struct fields, exact line depends on existing field block — insert alongside `lastStat`), `:54-94` (`Fetch`), `:428-485` (`queryThreatActorsWithRetry`/`queryThreatActors`), after `:97` (`Stats`, add two methods)
- Test: `internal/connector/opencti_evidence_test.go`

**Interfaces:**
- Consumes: `connector.CompletenessSource`, `connector.EvidenceSource`, `evidence.RawClaim`, `evidence.Truncated`/`evidence.Complete` (Tasks 2, 8).
- Produces: `*OpenCTIClient` implementing both interfaces, same as Task 8's MISP client — consumed by Task 11 (scheduler wiring).

- [ ] **Step 1: Write the failing test**

```go
// internal/connector/opencti_evidence_test.go
package connector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/evidence"
)

func TestOpenCTIClient_Fetch_TruncatedAtPageLimitAndCapturesRawClaims(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/graphql" {
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}
		resp := octiThreatActorsResp{}
		// Exactly openCTIPageLimit (100) top-level edges -- until cursor
		// pagination exists, this can never be distinguished from "there
		// were exactly 100 real results" (spec §5.2's OpenCTI row).
		resp.Data.ThreatActors.Edges = make([]octiActorEdge, openCTIPageLimit)
		for i := range resp.Data.ThreatActors.Edges {
			resp.Data.ThreatActors.Edges[i].Node = octiThreatActorNode{ID: "bulk", Name: "Bulk Actor"}
		}
		// One real actor with a single technique -- below the 2-technique
		// generation threshold, but a raw claim must still be captured
		// (spec §6.2).
		solo := octiThreatActorNode{ID: "solo-1", Name: "Solo Actor", Confidence: 70}
		solo.AttackPatterns.Edges = []octiRelationshipEdge{{Node: octiRelationshipNode{
			To: octiRelatedEntity{XMitreID: "T1059", Name: "Command Line"},
		}}}
		resp.Data.IntrusionSets.Edges = []octiActorEdge{{Node: solo}}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	c := NewOpenCTIClient(server.URL, "test-key", nil)
	actors, err := c.Fetch()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(actors) != 0 {
		t.Fatalf("actors = %+v, want none (Solo Actor has only 1 technique)", actors)
	}

	claims := c.RawClaims()
	found := false
	for _, cl := range claims {
		if cl.ActorName == "Solo Actor" && cl.TechniqueID == "T1059" {
			found = true
		}
	}
	if !found {
		t.Fatalf("RawClaims() = %+v, want a claim for Solo Actor/T1059", claims)
	}

	report := c.Completeness()
	if report.Completeness != evidence.Truncated {
		t.Fatalf("Completeness() = %+v, want Truncated (ThreatActors hit the %d-edge page limit)", report, openCTIPageLimit)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/connector/... -run TestOpenCTIClient_Fetch_TruncatedAtPageLimitAndCapturesRawClaims -v`
Expected: FAIL — `c.RawClaims undefined` / `undefined: openCTIPageLimit`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/connector/opencti.go -- new fields on OpenCTIClient, alongside the
// existing lastStat/lastCampaigns/lastMalware/lastTools/lastTechniqueEvidence block
	lastCompleteness evidence.SyncReport
	lastRawClaims    []evidence.RawClaim
```

```go
// internal/connector/opencti.go -- new const, near the top of the file
// openCTIPageLimit is the GraphQL "first:" value used on every connection
// in threatActorsQuery. Until cursor pagination is implemented, hitting it
// exactly is indistinguishable from truncation (spec §5.2).
const openCTIPageLimit = 100

func connectionTruncated(conn octiRelationshipConnection) bool {
	return len(conn.Edges) == openCTIPageLimit
}
```

```go
// internal/connector/opencti.go:54-94 -- Fetch(), rewritten to capture raw
// claims and truncation BEFORE convertActor's filter
func (c *OpenCTIClient) Fetch() ([]ThreatActor, error) {
	actorsRaw, err := c.queryThreatActorsWithRetry()
	if err != nil {
		c.lastStat = SourceStat{Name: "opencti", Error: err.Error(), FetchedAt: time.Now()}
		return nil, fmt.Errorf("opencti query actors: %w", err)
	}
	log.Printf("[connector/opencti] fetched %d threat actors", len(actorsRaw))

	var actors []ThreatActor
	var campaigns []intelligence.Campaign
	var malware []intelligence.Malware
	var tools []intelligence.Tool
	var evidenceList []TechniqueEvidence
	c.lastRawClaims = nil
	truncated := len(actorsRaw) == openCTIPageLimit
	for _, raw := range actorsRaw {
		if connectionTruncated(raw.AttackPatterns) || connectionTruncated(raw.Campaigns) ||
			connectionTruncated(raw.Malwares) || connectionTruncated(raw.Tools) {
			truncated = true
		}
		observedAt, parseErr := time.Parse(time.RFC3339, raw.Modified)
		if parseErr != nil {
			observedAt = time.Now()
		}
		for _, tech := range techniqueRefsFrom(raw.AttackPatterns) {
			c.lastRawClaims = append(c.lastRawClaims, evidence.RawClaim{
				ActorName: raw.Name, TechniqueID: tech.ID, ExternalID: raw.ID,
				ObservedAt: observedAt, RawConfidence: fmt.Sprintf("%d", raw.Confidence),
				Raw: map[string]any{"actor_id": raw.ID, "actor_name": raw.Name, "technique_id": tech.ID},
			})
		}

		actor := c.convertActor(raw)
		if actor == nil || len(actor.Techniques) < 2 {
			continue
		}
		actors = append(actors, *actor)
		evidenceList = append(evidenceList, techniqueEvidenceFrom(raw.AttackPatterns, actor.Name, "", "")...)

		for _, entity := range campaignEntitiesFrom(raw.Campaigns) {
			campaigns = append(campaigns, c.convertCampaign(entity, actor))
			evidenceList = append(evidenceList, techniqueEvidenceFrom(entity.AttackPatterns, actor.Name, "campaign", entity.Name)...)
		}
		for _, entity := range malwareEntitiesFrom(raw.Malwares) {
			malware = append(malware, c.convertMalware(entity, actor))
			evidenceList = append(evidenceList, techniqueEvidenceFrom(entity.AttackPatterns, actor.Name, "malware", entity.Name)...)
		}
		for _, entity := range toolEntitiesFrom(raw.Tools) {
			tools = append(tools, c.convertTool(entity, actor))
			evidenceList = append(evidenceList, techniqueEvidenceFrom(entity.AttackPatterns, actor.Name, "tool", entity.Name)...)
		}
	}
	c.lastStat = SourceStat{Name: "opencti", RawCount: len(actorsRaw), ActorCount: len(actors), FetchedAt: time.Now()}
	c.lastCampaigns = campaigns
	c.lastMalware = malware
	c.lastTools = tools
	c.lastTechniqueEvidence = evidenceList

	completeness := evidence.Complete
	diagnostic := ""
	if truncated {
		completeness = evidence.Truncated
		diagnostic = "a connection returned exactly the first:100 page limit; cursor pagination not yet implemented"
	}
	c.lastCompleteness = evidence.SyncReport{Completeness: completeness, Diagnostic: diagnostic}
	return actors, nil
}
```

```go
// internal/connector/opencti.go -- two new methods, after the existing Stats() (line 97)
// Completeness implements CompletenessSource.
func (c *OpenCTIClient) Completeness() evidence.SyncReport { return c.lastCompleteness }

// RawClaims implements EvidenceSource.
func (c *OpenCTIClient) RawClaims() []evidence.RawClaim { return c.lastRawClaims }
```

Add `"github.com/audspect/bas/internal/evidence"` to `internal/connector/opencti.go`'s import block.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/connector/... -run TestOpenCTIClient_Fetch_TruncatedAtPageLimitAndCapturesRawClaims -v`
Expected: PASS. Then run `go test ./internal/connector/... -run TestOpenCTIClient -v` to confirm the existing OpenCTI suite is still green.

- [ ] **Step 5: Commit**

```bash
git add internal/connector/opencti.go internal/connector/opencti_evidence_test.go
git commit -m "feat(tcf2b): OpenCTI truncation detection (top-level + nested) and pre-filter raw-claim capture (spec §5.2, §6.2)"
```

---

### Task 10: OTX and bundle completeness

**Files:**
- Modify: `internal/connector/otx.go:16-43` (struct field), `:81-139` (`FetchActivity`), after `Stats()` (add `Completeness`)
- Modify: `internal/connector/bundle.go:25-30` (struct field), `:49-75` (`Fetch`), after `:78` (add `Completeness`)
- Test: `internal/connector/otx_evidence_test.go`, `internal/connector/bundle_evidence_test.go`

**Interfaces:**
- Consumes: `connector.CompletenessSource`, `evidence.Complete`/`Partial`/`Truncated` (Tasks 2, 8).
- Produces: `*OTXSource` and `*BundleSource` implementing `CompletenessSource`. **Design note:** OTX produces only activity signals, never technique claims (spec's fact table), so it does **not** implement `EvidenceSource` — `Completeness` alone is enough for `RecordSync`'s `authoritative` computation to correctly always come out `false` for it (its `ObservationMode` is `ModeActivityWindow`). Bundle also skips `EvidenceSource`: its `Fetch()` already applies no 2-technique filter (confirmed in `types.go`'s own `SourceStat` doc comment), so nothing is hidden from its returned `[]ThreatActor` — Task 11's scheduler wiring derives bundle's claims directly from that return value instead of a second parallel method.

- [ ] **Step 1: Write the failing test**

```go
// internal/connector/otx_evidence_test.go
package connector

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/evidence"
)

func TestOTXSource_FetchActivity_TruncatedAtPageCap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every page returns a full otxPageLimit-sized page, so the loop
		// never sees a short page and must report truncated (spec §5.2).
		pulses := make([]otxPulse, otxPageLimit)
		for i := range pulses {
			pulses[i] = otxPulse{Name: fmt.Sprintf("pulse-%d", i), Modified: "2026-01-15T00:00:00Z"}
		}
		json.NewEncoder(w).Encode(otxPulsesResponse{Count: otxPageLimit * otxMaxPages, Results: pulses})
	}))
	defer server.Close()

	c := NewOTXSource("test-key")
	c.baseURL = server.URL
	if _, err := c.FetchActivity(); err != nil {
		t.Fatalf("FetchActivity: %v", err)
	}
	report := c.Completeness()
	if report.Completeness != evidence.Truncated {
		t.Fatalf("Completeness() = %+v, want Truncated", report)
	}
}

func TestOTXSource_FetchActivity_PartialOnLaterPageFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "1" {
			pulses := make([]otxPulse, otxPageLimit)
			for i := range pulses {
				pulses[i] = otxPulse{Name: fmt.Sprintf("pulse-%d", i), Modified: "2026-01-15T00:00:00Z"}
			}
			json.NewEncoder(w).Encode(otxPulsesResponse{Count: otxPageLimit * 2, Results: pulses})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c := NewOTXSource("test-key")
	c.baseURL = server.URL
	if _, err := c.FetchActivity(); err == nil {
		t.Fatal("expected an error from the page-2 failure")
	}
	report := c.Completeness()
	if report.Completeness != evidence.Partial {
		t.Fatalf("Completeness() = %+v, want Partial", report)
	}
}

func TestOTXSource_FetchActivity_CompleteOnShortFinalPage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(otxPulsesResponse{Count: 1, Results: []otxPulse{{Name: "p", Modified: "2026-01-15T00:00:00Z"}}})
	}))
	defer server.Close()

	c := NewOTXSource("test-key")
	c.baseURL = server.URL
	if _, err := c.FetchActivity(); err != nil {
		t.Fatalf("FetchActivity: %v", err)
	}
	report := c.Completeness()
	if report.Completeness != evidence.Complete {
		t.Fatalf("Completeness() = %+v, want Complete", report)
	}
}
```

```go
// internal/connector/bundle_evidence_test.go
package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/audspect/bas/internal/evidence"
)

func TestBundleSource_Fetch_CompletenessCompleteOnSuccess(t *testing.T) {
	dir := t.TempDir()
	bundle := Bundle{Version: "v1", GeneratedAt: time.Now(), Actors: []ThreatActor{
		{Name: "APT-bundle", Techniques: []TechniqueRef{{ID: "T1059"}, {ID: "T1055"}}},
	}}
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, BundleFileName), data, 0644); err != nil {
		t.Fatal(err)
	}

	b := NewBundleSource(dir, nil)
	if _, err := b.Fetch(); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	report := b.Completeness()
	if report.Completeness != evidence.Complete {
		t.Fatalf("Completeness() = %+v, want Complete", report)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/connector/... -run "TestOTXSource_FetchActivity_TruncatedAtPageCap|TestOTXSource_FetchActivity_PartialOnLaterPageFailure|TestOTXSource_FetchActivity_CompleteOnShortFinalPage|TestBundleSource_Fetch_CompletenessCompleteOnSuccess" -v`
Expected: FAIL — `c.Completeness undefined` / `b.Completeness undefined`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/connector/otx.go -- new field on OTXSource, alongside lastStat
	lastCompleteness evidence.SyncReport
```

```go
// internal/connector/otx.go:81-139 -- FetchActivity, tracking the last page's
// size to detect the cap-without-a-short-page case
func (c *OTXSource) FetchActivity() ([]ActivitySignal, error) {
	groupTechs := attackdata.GroupTechniqueIndex()
	normalizedGroups := make(map[string]string, len(groupTechs))
	for name := range groupTechs {
		normalizedGroups[normalizeAdversary(name)] = name
	}

	accByActor := make(map[string]*otxActivityAccumulator)
	var totalFetched int
	var lastPageSize int

	for page := 1; page <= otxMaxPages; page++ {
		pulses, err := c.fetchPulsesPage(page)
		if err != nil {
			if page == 1 {
				c.lastStat = SourceStat{Name: "otx", Error: err.Error(), FetchedAt: time.Now()}
				return nil, fmt.Errorf("otx fetch page 1: %w", err)
			}
			out := otxSignalsFromMap(accByActor)
			c.lastStat = SourceStat{Name: "otx", RawCount: totalFetched, ActorCount: len(out), Error: err.Error(), FetchedAt: time.Now()}
			c.lastCompleteness = evidence.SyncReport{Completeness: evidence.Partial,
				Diagnostic: fmt.Sprintf("page %d fetch failed after %d page(s) succeeded", page, page-1)}
			return out, fmt.Errorf("otx fetch page %d: %w", page, err)
		}

		lastPageSize = len(pulses)
		totalFetched += len(pulses)
		for _, p := range pulses {
			if strings.TrimSpace(p.Adversary) == "" {
				continue
			}
			groupName, ok := normalizedGroups[normalizeAdversary(p.Adversary)]
			if !ok {
				continue
			}
			modified, parseErr := time.Parse(time.RFC3339, p.Modified)
			if parseErr != nil {
				continue
			}

			acc, ok := accByActor[groupName]
			if !ok {
				acc = &otxActivityAccumulator{first: modified, last: modified}
				accByActor[groupName] = acc
			}
			acc.count++
			if modified.Before(acc.first) {
				acc.first = modified
			}
			if modified.After(acc.last) {
				acc.last = modified
			}
		}

		if len(pulses) < otxPageLimit {
			break
		}
	}

	out := otxSignalsFromMap(accByActor)
	c.lastStat = SourceStat{Name: "otx", RawCount: totalFetched, ActorCount: len(out), FetchedAt: time.Now()}
	if lastPageSize == otxPageLimit {
		c.lastCompleteness = evidence.SyncReport{Completeness: evidence.Truncated,
			Diagnostic: fmt.Sprintf("hit the %d-page cap", otxMaxPages)}
	} else {
		c.lastCompleteness = evidence.SyncReport{Completeness: evidence.Complete}
	}
	return out, nil
}

// Completeness implements CompletenessSource.
func (c *OTXSource) Completeness() evidence.SyncReport { return c.lastCompleteness }
```

```go
// internal/connector/bundle.go -- new field on BundleSource
	lastCompleteness evidence.SyncReport
```

```go
// internal/connector/bundle.go:73 -- right before "return bundle.Actors, nil"
	b.lastCompleteness = evidence.SyncReport{Completeness: evidence.Complete}
```

```go
// internal/connector/bundle.go -- new method, after Stats() (line 78)
// Completeness implements CompletenessSource.
func (b *BundleSource) Completeness() evidence.SyncReport { return b.lastCompleteness }
```

Add `"github.com/audspect/bas/internal/evidence"` to both files' import blocks.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/connector/... -run "TestOTXSource_FetchActivity_TruncatedAtPageCap|TestOTXSource_FetchActivity_PartialOnLaterPageFailure|TestOTXSource_FetchActivity_CompleteOnShortFinalPage|TestBundleSource_Fetch_CompletenessCompleteOnSuccess" -v`
Expected: PASS. Then run `go test ./internal/connector/... -run "TestOTXSource|TestBundleSource" -v` to confirm the existing suites are still green.

- [ ] **Step 5: Commit**

```bash
git add internal/connector/otx.go internal/connector/bundle.go internal/connector/otx_evidence_test.go internal/connector/bundle_evidence_test.go
git commit -m "feat(tcf2b): OTX and bundle completeness reporting (spec §5.2)"
```

---

### Task 11: Scheduler wiring

**Files:**
- Modify: `internal/connector/scheduler.go:23-68` (struct field + `WithEvidenceStore`), `:295-477` (`sync`)
- Test: `internal/connector/scheduler_evidence_test.go`

**Interfaces:**
- Consumes: everything from Tasks 2-10 (`evidence.Store` and all its methods, `CompletenessSource`, `EvidenceSource`).
- Produces: `(s *Scheduler) WithEvidenceStore(st *evidence.Store) *Scheduler` — the production wiring call site is wherever `WithIdentityStore` is already called (outside this plan's scope; `cmd/server/main.go`'s scheduler construction — note for a future task, not acted on here since it's outside milestone 2B's acceptance tests).

- [ ] **Step 1: Write the failing test**

```go
// internal/connector/scheduler_evidence_test.go
package connector

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/evidence"
	"github.com/audspect/bas/internal/threatidentity"
)

// stubEvidenceSource is a minimal Source + CompletenessSource + EvidenceSource
// test double standing in for MISP/OpenCTI without a network call.
type stubEvidenceSource struct {
	name   string
	actors []ThreatActor
	claims []evidence.RawClaim
}

func (s *stubEvidenceSource) Name() string                         { return s.name }
func (s *stubEvidenceSource) Fetch() ([]ThreatActor, error)        { return s.actors, nil }
func (s *stubEvidenceSource) Completeness() evidence.SyncReport    { return evidence.SyncReport{Completeness: evidence.Complete} }
func (s *stubEvidenceSource) RawClaims() []evidence.RawClaim       { return s.claims }

func TestScheduler_Sync_RecordsEvidenceAndProjectsActiveTechniques(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		src := &stubEvidenceSource{
			name: "misp",
			actors: []ThreatActor{
				{Name: "APT-sched-evidence", Source: "misp", SourceID: "evt-1",
					Techniques: []TechniqueRef{{ID: "T1059"}, {ID: "T1055"}}},
			},
			claims: []evidence.RawClaim{
				{ActorName: "APT-sched-evidence", TechniqueID: "T1059", ExternalID: "evt-1", ObservedAt: time.Now(), RawConfidence: "high"},
				{ActorName: "APT-sched-evidence", TechniqueID: "T1055", ExternalID: "evt-1", ObservedAt: time.Now(), RawConfidence: "high"},
			},
		}
		s := &Scheduler{pool: pool, sources: []Source{src}, generator: NewGenerator(t.TempDir(), nil, nil, nil), engine: scenarioEngineForTest(t)}
		s.WithIdentityStore(threatidentity.NewStore(pool))
		s.WithEvidenceStore(evidence.NewStore(pool))

		s.sync()

		var threatID string
		if err := pool.QueryRow(ctx, `SELECT t.id FROM threats t JOIN threat_actor_profiles p ON p.id = t.actor_id
			WHERE p.name = 'APT-sched-evidence'`).Scan(&threatID); err != nil {
			t.Fatalf("resolved threat not found: %v", err)
		}

		var activeCount int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM threat_techniques WHERE threat_id = $1 AND status = 'active'`, threatID).Scan(&activeCount); err != nil {
			t.Fatal(err)
		}
		if activeCount != 2 {
			t.Fatalf("active threat_techniques rows = %d, want 2 (T1059, T1055)", activeCount)
		}

		var claimCount int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM technique_claims WHERE threat_id = $1`, threatID).Scan(&claimCount); err != nil {
			t.Fatal(err)
		}
		if claimCount != 2 {
			t.Fatalf("technique_claims rows = %d, want 2", claimCount)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/connector/... -run TestScheduler_Sync_RecordsEvidenceAndProjectsActiveTechniques -v`
Expected: FAIL — `s.WithEvidenceStore undefined` / `scenarioEngineForTest undefined` (check `internal/connector/scheduler_test.go` for an existing engine-construction test helper with this or an equivalent name before assuming one must be added; if none exists, add a minimal one in this test file: a `*scenario.Engine` constructed the same way `NewScheduler`'s other tests already do, reusing that pattern instead of inventing a new one).

- [ ] **Step 3: Write minimal implementation**

```go
// internal/connector/scheduler.go -- add a field to the Scheduler struct
// (alongside the existing `identity *threatidentity.Store` field)
	evidence *evidence.Store
```

```go
// internal/connector/scheduler.go -- new setter, alongside WithIdentityStore (line 762)
// WithEvidenceStore wires the evidence layer (TCF Phase 2 spec §5-§8). A nil
// evidence store (the default) means sync() skips all evidence recording --
// the same opt-in pattern WithIdentityStore already uses for identity.
func (s *Scheduler) WithEvidenceStore(st *evidence.Store) *Scheduler {
	s.evidence = st
	return s
}
```

```go
// internal/connector/scheduler.go -- new types and helpers, same file
// sourceEvidenceDefaults is the spec §5.1 default-trust table, keyed by
// Source.Name()/ActivitySource.Name().
var sourceEvidenceDefaults = map[string]struct {
	sourceType string
	mode       evidence.ObservationMode
	trust      evidence.TrustState
}{
	"bundle":  {"bundle", evidence.ModeSnapshot, evidence.TrustTrusted},
	"misp":    {"misp", evidence.ModeSnapshot, evidence.TrustTrusted},
	"opencti": {"opencti", evidence.ModeSnapshot, evidence.TrustTrusted},
	"otx":     {"otx", evidence.ModeActivityWindow, evidence.TrustUntrusted},
}

type pendingClaim struct {
	actorName, techniqueID, externalID, rawConfidence, sourceType string
	observedAt                                                     time.Time
	syncID, instanceID                                             string
	trustVersionID                                                 int64
}

func claimRecordHash(instanceID, actorName, techniqueID, externalID string) string {
	sum := sha256.Sum256([]byte(instanceID + "|" + actorName + "|" + techniqueID + "|" + externalID))
	return hex.EncodeToString(sum[:])
}

// recordSourceSync writes the source_instances/source_syncs evidence for one
// source's Fetch() outcome and returns any raw claims it captured, ready to
// be resolved against the threat roster once identity resolution has run.
// completeness/diagnostic come from the source's own CompletenessSource
// report when it implements one (every call site below computes this before
// calling in); a fetchErr always forces status=failed, completeness=Failed,
// regardless of what the caller passed. A no-op (returns nil) when the
// evidence store isn't wired, or the source name has no entry in
// sourceEvidenceDefaults.
func (s *Scheduler) recordSourceSync(ctx context.Context, name string, rawClaims []evidence.RawClaim, fetchErr error, completeness evidence.Completeness, diagnostic string) []pendingClaim {
	if s.evidence == nil {
		return nil
	}
	def, ok := sourceEvidenceDefaults[name]
	if !ok {
		return nil
	}
	if err := s.evidence.EnsureSourceInstance(ctx, name, def.sourceType, name, def.mode, def.trust); err != nil {
		log.Printf("[connector/evidence] ensure source instance %s: %v", name, err)
		return nil
	}
	status := "succeeded"
	if fetchErr != nil {
		status = "failed"
		completeness = evidence.Failed
		diagnostic = fetchErr.Error()
	}
	syncID, _, err := s.evidence.RecordSync(ctx, name, def.mode, time.Now(), status, completeness, diagnostic)
	if err != nil {
		log.Printf("[connector/evidence] record sync %s: %v", name, err)
		return nil
	}
	if fetchErr != nil {
		return nil
	}
	_, trustVersionID, err := s.evidence.CurrentTrust(ctx, name)
	if err != nil {
		log.Printf("[connector/evidence] current trust %s: %v", name, err)
		return nil
	}
	pending := make([]pendingClaim, 0, len(rawClaims))
	for _, rc := range rawClaims {
		pending = append(pending, pendingClaim{
			actorName: rc.ActorName, techniqueID: rc.TechniqueID, externalID: rc.ExternalID,
			rawConfidence: rc.RawConfidence, sourceType: def.sourceType, observedAt: rc.ObservedAt,
			syncID: syncID, instanceID: name, trustVersionID: trustVersionID,
		})
	}
	return pending
}

// sourceCompleteness reads a source's own CompletenessSource report when it
// implements one, defaulting to Complete for a source that doesn't (bundle,
// misp, opencti and otx all implement it as of Tasks 8-10, so this default
// only matters for a future source type or a test double that doesn't).
func sourceCompleteness(src any) (evidence.Completeness, string) {
	if cs, ok := src.(CompletenessSource); ok {
		r := cs.Completeness()
		return r.Completeness, r.Diagnostic
	}
	return evidence.Complete, ""
}

// bundleClaimsFrom builds pendingClaim-shaped raw claims directly from the
// bundle source's own return value -- it applies no 2-technique filter
// (types.go's SourceStat doc comment), so nothing needs recovering the way
// MISP/OpenCTI's EvidenceSource does.
func bundleClaimsFrom(actors []ThreatActor) []evidence.RawClaim {
	var out []evidence.RawClaim
	for _, a := range actors {
		for _, tech := range a.Techniques {
			out = append(out, evidence.RawClaim{
				ActorName: a.Name, TechniqueID: tech.ID, ExternalID: a.SourceID,
				ObservedAt: a.LastSeen, RawConfidence: a.Confidence,
			})
		}
	}
	return out
}
```

```go
// internal/connector/scheduler.go:321-349 -- inside the existing per-source
// loop, capture completeness/raw claims right where Fetch() is already
// called, instead of letting them fall away once got is merged into actors
	var allPending []pendingClaim
	for _, src := range sources {
		got, err := src.Fetch()
		if ss, ok := src.(StatsSource); ok {
			bySource[src.Name()] = ss.Stats()
		}
		var rawClaims []evidence.RawClaim
		if es, ok := src.(EvidenceSource); ok {
			rawClaims = es.RawClaims()
		} else if _, ok := src.(*BundleSource); ok && err == nil {
			rawClaims = bundleClaimsFrom(got)
		}
		completeness, diagnostic := sourceCompleteness(src)
		allPending = append(allPending, s.recordSourceSync(context.Background(), src.Name(), rawClaims, err, completeness, diagnostic)...)
		if err != nil {
			log.Printf("[connector/%s] fetch error: %v", src.Name(), err)
			s.setError(src.Name()+": "+err.Error(), bySource)
			continue
		}
		log.Printf("[connector/%s] %d actors fetched", src.Name(), len(got))
		actors = append(actors, got...)
		if bs, ok := src.(*BundleSource); ok {
			bundleVersion = bs.Version()
		}
		if is, ok := src.(IntelligenceSource); ok {
			campaigns, malware, tools, ierr := is.FetchIntelligence()
			if ierr != nil {
				log.Printf("[connector/%s] intelligence fetch error: %v", src.Name(), ierr)
			} else {
				allCampaigns = append(allCampaigns, campaigns...)
				allMalware = append(allMalware, malware...)
				allTools = append(allTools, tools...)
			}
		}
		if tes, ok := src.(TechniqueEvidenceSource); ok {
			techEvidence = append(techEvidence, tes.FetchTechniqueEvidence()...)
		}
	}
```

```go
// internal/connector/scheduler.go -- for the activity-source loop (lines
// 361-372), record sync evidence too (no claims -- OTX never produces them)
	for _, asrc := range activitySources {
		signals, err := asrc.FetchActivity()
		if ss, ok := asrc.(StatsSource); ok {
			bySource[asrc.Name()] = ss.Stats()
		}
		completeness, diagnostic := sourceCompleteness(asrc)
		s.recordSourceSync(context.Background(), asrc.Name(), nil, err, completeness, diagnostic)
		if err != nil {
			log.Printf("[connector/%s] fetch error: %v", asrc.Name(), err)
			continue
		}
		log.Printf("[connector/%s] %d activity signals fetched", asrc.Name(), len(signals))
		activityResults = append(activityResults, activityFetch{source: asrc.Name(), signals: signals})
	}
```

```go
// internal/connector/scheduler.go -- right after "s.upsertTechniqueEvidence(techEvidence, actors)"
// (line 417), resolve pending claims against the now-identity-resolved
// roster and project the active set for every threat touched this sync.
	if s.evidence != nil && len(allPending) > 0 {
		s.resolvePendingClaims(context.Background(), allPending, actors)
	}
```

```go
// internal/connector/scheduler.go -- new method, near recordSourceSync
// resolvePendingClaims maps each pending raw claim's actor name to its
// resolved ThreatID (from the merged, identity-resolved roster) and writes
// the observation/threat-source link/claim for every one that resolved,
// then recomputes the projection for every threat touched (spec §7.4's
// "after every sync" rule). An actor that never resolved gets no claim --
// unresolved identities get no evidence tied to a Threat (spec §3.2).
func (s *Scheduler) resolvePendingClaims(ctx context.Context, pending []pendingClaim, resolved []ThreatActor) {
	threatByName := make(map[string]string, len(resolved))
	for _, a := range resolved {
		if a.ThreatID != "" {
			threatByName[a.Name] = a.ThreatID
		}
	}
	var claims []evidence.Claim
	touched := map[string]bool{}
	for _, pc := range pending {
		threatID, ok := threatByName[pc.actorName]
		if !ok {
			continue
		}
		hash := claimRecordHash(pc.instanceID, pc.actorName, pc.techniqueID, pc.externalID)
		obsID, err := s.evidence.RecordObservation(ctx, pc.syncID, pc.instanceID, pc.externalID, pc.actorName, hash,
			pc.observedAt, map[string]any{"actor_name": pc.actorName, "technique_id": pc.techniqueID}, pc.trustVersionID)
		if err != nil {
			log.Printf("[connector/evidence] record observation: %v", err)
			continue
		}
		_, normConf, _ := evidence.NormalizeConfidence(pc.sourceType, pc.rawConfidence)
		if err := s.evidence.LinkThreatSource(ctx, threatID, obsID, pc.sourceType, pc.externalID, pc.observedAt, normConf, hash, "resolver", ""); err != nil {
			log.Printf("[connector/evidence] link threat source: %v", err)
			continue
		}
		claims = append(claims, evidence.Claim{
			ObservationID: obsID, SyncID: pc.syncID, InstanceID: pc.instanceID, ThreatID: threatID,
			TechniqueID: pc.techniqueID, Kind: evidence.ClaimAsserted, RawConfidence: pc.rawConfidence,
			Source: pc.sourceType, TrustVersionID: pc.trustVersionID, ObservedAt: pc.observedAt, RecordHash: hash,
		})
		touched[threatID] = true
	}
	if len(claims) > 0 {
		if err := s.evidence.RecordClaims(ctx, claims); err != nil {
			log.Printf("[connector/evidence] record claims: %v", err)
		}
	}
	for threatID := range touched {
		if err := s.evidence.RecomputeThreatTechniques(ctx, threatID); err != nil {
			log.Printf("[connector/evidence] recompute %s: %v", threatID, err)
		}
	}
}
```

Add `"crypto/sha256"`, `"encoding/hex"`, and `"github.com/audspect/bas/internal/evidence"` to `internal/connector/scheduler.go`'s import block.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/connector/... -run TestScheduler_Sync_RecordsEvidenceAndProjectsActiveTechniques -v`
Expected: PASS. Then run `go test ./internal/connector/... -v` to confirm the entire existing scheduler/connector suite (identity resolution, activity signals, technique evidence, reconfigure) is still green — this task touches `sync()`'s shared control flow, the highest-risk point in this plan for a silent regression.

- [ ] **Step 5: Commit**

```bash
git add internal/connector/scheduler.go internal/connector/scheduler_evidence_test.go
git commit -m "feat(tcf2b): wire evidence recording and active-set projection into the sync cycle (spec §5-§7)"
```

---

### Task 12: Generation reproducibility

**Files:**
- Create: `internal/evidence/generation.go`
- Test: `internal/evidence/generation_test.go`
- Modify: `internal/connector/generator.go:46-69` (`Generator` struct + a `WithEvidenceStore` setter), `:131-207` (`Write`)
- Test: `internal/connector/generator_evidence_test.go`

**Interfaces:**
- Consumes: `Store` (Task 2), `threat_techniques` (Task 7).
- Produces: `(s *Store) ActiveTechniques(ctx, threatID string) ([]string, error)`, `(s *Store) NextGenerationNumber(ctx, threatID string) (int, error)`, `(s *Store) RecordGeneration(ctx, threatID, contentID, contentVersionID string, generationNumber int, policyVersion string) error` — consumed by `generator.go`'s `Write`.

- [ ] **Step 1: Write the failing test**

```go
// internal/evidence/generation_test.go
package evidence

import (
	"context"
	"testing"
)

func TestActiveTechniquesAndRecordGeneration(t *testing.T) {
	ctx := context.Background()
	store := NewStore(sharedDB.Pool)
	threatID := seedThreat(t, sharedDB.Pool, "APT-generation-test")

	for _, tc := range []struct{ id, status string }{
		{"T1059", "active"}, {"T1055", "active"}, {"T1021", "retracted"},
	} {
		if _, err := sharedDB.Pool.Exec(ctx, `INSERT INTO threat_techniques
			(threat_id, technique_id, last_seen_at, status, status_reason)
			VALUES ($1, $2, NOW(), $3, 'supported')`, threatID, tc.id, tc.status); err != nil {
			t.Fatal(err)
		}
	}

	active, err := store.ActiveTechniques(ctx, threatID)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 2 || active[0] != "T1055" || active[1] != "T1059" {
		t.Fatalf("ActiveTechniques = %v, want [T1055 T1059] (sorted, retracted excluded)", active)
	}

	genNum, err := store.NextGenerationNumber(ctx, threatID)
	if err != nil {
		t.Fatal(err)
	}
	if genNum != 1 {
		t.Fatalf("NextGenerationNumber = %d, want 1 (first generation)", genNum)
	}

	if err := store.RecordGeneration(ctx, threatID, "intel-abc123", "cv-1", genNum, "tcf2b-generation-v1"); err != nil {
		t.Fatal(err)
	}

	var hash1 string
	if err := sharedDB.Pool.QueryRow(ctx, `SELECT technique_set_hash FROM content_generations WHERE threat_id = $1 AND generation_number = 1`,
		threatID).Scan(&hash1); err != nil {
		t.Fatal(err)
	}
	if hash1 == "" {
		t.Fatal("technique_set_hash must be set")
	}

	genNum2, err := store.NextGenerationNumber(ctx, threatID)
	if err != nil {
		t.Fatal(err)
	}
	if genNum2 != 2 {
		t.Fatalf("NextGenerationNumber after one generation = %d, want 2", genNum2)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/evidence/... -run TestActiveTechniquesAndRecordGeneration -v`
Expected: FAIL — `undefined: ActiveTechniques`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/evidence/generation.go
package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// ActiveTechniques returns a threat's currently-active technique ids (spec
// §7.2's active set), sorted for a stable hash.
func (s *Store) ActiveTechniques(ctx context.Context, threatID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT technique_id FROM threat_techniques
		WHERE threat_id = $1 AND status = 'active' ORDER BY technique_id`, threatID)
	if err != nil {
		return nil, fmt.Errorf("evidence: active techniques for %q: %w", threatID, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// NextGenerationNumber returns the next sequential generation_number for a
// threat (spec §8). The caller must use it promptly -- the UNIQUE
// (threat_id, generation_number) constraint on content_generations catches
// a concurrent double-use rather than silently overwriting one.
func (s *Store) NextGenerationNumber(ctx context.Context, threatID string) (int, error) {
	var n int
	if err := s.pool.QueryRow(ctx,
		`SELECT coalesce(max(generation_number), 0) + 1 FROM content_generations WHERE threat_id = $1`,
		threatID).Scan(&n); err != nil {
		return 0, fmt.Errorf("evidence: next generation number: %w", err)
	}
	return n, nil
}

type evidenceSnapshot struct {
	ThreatID   string                      `json:"threatId"`
	Techniques []evidenceSnapshotTechnique `json:"techniques"`
}

type evidenceSnapshotTechnique struct {
	TechniqueID           string   `json:"techniqueId"`
	ClaimIDs              []string `json:"claimIds"`
	TrustVersionIDs       []int64  `json:"trustVersionIds"`
	NormalizedConfidence  *int     `json:"normalizedConfidence,omitempty"`
}

// RecordGeneration writes one content_generations row, computing
// technique_set_hash and evidence_snapshot_hash from the threat's current
// active claims (spec §8) -- "why did generation N include T1059 when
// generation N-1 did not" is answerable from the two rows' snapshots alone.
func (s *Store) RecordGeneration(ctx context.Context, threatID, contentID, contentVersionID string, generationNumber int, policyVersion string) error {
	rows, err := s.pool.Query(ctx, `
		SELECT c.technique_id, c.id, c.trust_version_id, c.normalized_confidence
		  FROM technique_claims c
		 WHERE c.threat_id = $1 AND c.kind = 'claim'
		   AND c.technique_id IN (SELECT technique_id FROM threat_techniques WHERE threat_id = $1 AND status = 'active')
		 ORDER BY c.technique_id, c.id`, threatID)
	if err != nil {
		return fmt.Errorf("evidence: load active claims for generation: %w", err)
	}
	byTechnique := map[string]*evidenceSnapshotTechnique{}
	var order []string
	for rows.Next() {
		var techniqueID, claimID string
		var trustVersionID int64
		var normConf *int
		if err := rows.Scan(&techniqueID, &claimID, &trustVersionID, &normConf); err != nil {
			rows.Close()
			return err
		}
		t, ok := byTechnique[techniqueID]
		if !ok {
			t = &evidenceSnapshotTechnique{TechniqueID: techniqueID}
			byTechnique[techniqueID] = t
			order = append(order, techniqueID)
		}
		t.ClaimIDs = append(t.ClaimIDs, claimID)
		t.TrustVersionIDs = append(t.TrustVersionIDs, trustVersionID)
		if normConf != nil && (t.NormalizedConfidence == nil || *normConf > *t.NormalizedConfidence) {
			t.NormalizedConfidence = normConf
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	sort.Strings(order)
	snap := evidenceSnapshot{ThreatID: threatID}
	techniqueIDs := make([]string, 0, len(order))
	for _, id := range order {
		snap.Techniques = append(snap.Techniques, *byTechnique[id])
		techniqueIDs = append(techniqueIDs, id)
	}

	techniqueSetHash := sha256.Sum256([]byte(fmt.Sprintf("%v", techniqueIDs)))
	snapJSON, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("evidence: marshal evidence snapshot: %w", err)
	}
	evidenceHash := sha256.Sum256(snapJSON)

	if _, err := s.pool.Exec(ctx, `INSERT INTO content_generations
		(threat_id, content_id, content_version_id, generation_number, policy_version, technique_set_hash, evidence_snapshot_hash, evidence_snapshot)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		threatID, contentID, contentVersionID, generationNumber, policyVersion,
		hex.EncodeToString(techniqueSetHash[:]), hex.EncodeToString(evidenceHash[:]), snapJSON); err != nil {
		return fmt.Errorf("evidence: record generation: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/evidence/... -run TestActiveTechniquesAndRecordGeneration -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/evidence/generation.go internal/evidence/generation_test.go
git commit -m "feat(tcf2b): active-set lookup and generation-reproducibility snapshot (spec §8)"
```

---

### Task 13: Generator consumes the active set

**Files:**
- Modify: `internal/connector/generator.go:46-69` (`Generator` struct, `WithEvidenceStore`), `:131-207` (`Write`)
- Test: `internal/connector/generator_evidence_test.go`

**Interfaces:**
- Consumes: `Store.ActiveTechniques`, `Store.NextGenerationNumber`, `Store.RecordGeneration` (Task 12).
- Produces: `(g *Generator) WithEvidenceStore(st *evidence.Store) *Generator` — the production wiring call site is wherever `NewGenerator`'s result is configured in `cmd/server/main.go` (outside this plan's scope, same note as Task 11).

- [ ] **Step 1: Write the failing test**

```go
// internal/connector/generator_evidence_test.go
package connector

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/evidence"
	"github.com/audspect/bas/internal/threatidentity"
)

func seedActiveTechnique(t *testing.T, pool *pgxpool.Pool, threatID, techniqueID string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `INSERT INTO threat_techniques
		(threat_id, technique_id, last_seen_at, status, status_reason)
		VALUES ($1, $2, NOW(), 'active', 'supported')`, threatID, techniqueID); err != nil {
		t.Fatal(err)
	}
}

func TestGenerator_Write_UsesActiveTechniqueSetNotMergedActorList(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		idStore := threatidentity.NewStore(pool)
		resolved, err := idStore.ResolveAndPersist(ctx, threatidentity.Incoming{Name: "APT-gen-active-set"}, threatidentity.ProfileFields{})
		if err != nil {
			t.Fatal(err)
		}
		// Two active techniques recorded by the evidence layer, even though
		// this actor's OWN merged Techniques list below is empty -- Write
		// must consult the active set, not actor.Techniques, for the
		// generation-policy threshold (spec §6.2, §8).
		seedActiveTechnique(t, pool, resolved.ThreatID, "T1059")
		seedActiveTechnique(t, pool, resolved.ThreatID, "T1055")

		g := NewGenerator(t.TempDir(), nil, nil, nil).WithEvidenceStore(evidence.NewStore(pool))
		res, err := g.Write([]ThreatActor{{Name: "APT-gen-active-set", ThreatID: resolved.ThreatID, Source: "misp"}})
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		if res.Created != 1 {
			t.Fatalf("GenerateResult = %+v, want Created=1", res)
		}

		var genCount int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM content_generations WHERE threat_id = $1`,
			resolved.ThreatID).Scan(&genCount); err != nil {
			t.Fatal(err)
		}
		if genCount != 1 {
			t.Fatalf("content_generations rows = %d, want 1", genCount)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/connector/... -run TestGenerator_Write_UsesActiveTechniqueSetNotMergedActorList -v`
Expected: FAIL — `g.WithEvidenceStore undefined`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/connector/generator.go -- new field on Generator, alongside
// the existing registrar/componentVersions fields (around line 46-69)
	evidence *evidence.Store
```

```go
// internal/connector/generator.go -- new setter, alongside WithRegistrar (line 91)
// WithEvidenceStore wires the evidence layer's active technique set into
// generation policy (TCF Phase 2 spec §6.2, §8). A nil evidence store (the
// default) falls back to the pre-2B behavior: policy reads actor.Techniques
// directly.
func (g *Generator) WithEvidenceStore(st *evidence.Store) *Generator {
	g.evidence = st
	return g
}
```

```go
// internal/connector/generator.go:146-207 -- Write, policy check now reads
// the active set, and a successful NEW registration records a generation
func (g *Generator) Write(actors []ThreatActor) (GenerateResult, error) {
	if err := os.MkdirAll(g.intelDir, 0755); err != nil {
		return GenerateResult{}, fmt.Errorf("mkdir %s: %w", g.intelDir, err)
	}

	var cv scenario.ComponentVersions
	var cvErr error
	if g.componentVersions != nil {
		cv, cvErr = g.componentVersions(context.Background())
		if cvErr != nil {
			log.Printf("[connector/gen] component versions unavailable: %v", cvErr)
		}
	}

	var res GenerateResult
	for _, actor := range actors {
		if actor.ThreatID == "" {
			res.Skipped++
			continue
		}

		activeTechniques := dedupedTechniqueIDs(actor.Techniques)
		if g.evidence != nil {
			at, err := g.evidence.ActiveTechniques(context.Background(), actor.ThreatID)
			if err != nil {
				log.Printf("[connector/gen] active techniques for %s: %v", actor.ThreatID, err)
				res.Failed++
				continue
			}
			activeTechniques = at
		}
		if len(activeTechniques) < minTechniques {
			res.Skipped++
			continue
		}

		id := threatidentity.ContentID(actor.ThreatID)
		body := g.buildYAML(actor, id)
		fname := filepath.Join(g.intelDir, id+".yaml")

		created := false
		if g.registrar != nil {
			var err error
			key := generationKey(actor)
			_, created, err = g.registrar.RegisterGenerated(context.Background(), contentregistry.GeneratedCandidate{
				ContentID: id, Artifact: []byte(body), GenerationKey: key, GenerationRef: key, ThreatID: actor.ThreatID,
				Generation: g.generationMeta(actor, cv, cvErr),
				Sources: []contentregistry.SourceRef{{EntityType: "actor", EntityID: actor.Name, Provider: actor.Source,
					ExternalID: actor.SourceID, Role: "primary"}},
			})
			if err != nil {
				switch {
				case errors.Is(err, contentregistry.ErrSourceCollision):
					log.Printf("[connector/gen] %s (%s) collides with a custom scenario of the same id; not written: %v", id, actor.Name, err)
				case errors.Is(err, contentregistry.ErrOriginCollision):
					log.Printf("[connector/gen] %s (%s) collides with content of a different origin; not written: %v", id, actor.Name, err)
				case errors.Is(err, contentregistry.ErrThreatCollision):
					log.Printf("[connector/gen] %s (%s) content id owned by a different threat; not written: %v", id, actor.Name, err)
				default:
					log.Printf("[connector/gen] register %s: %v", id, err)
				}
				res.Failed++
				continue
			}
		}
		if old, err := os.ReadFile(fname); err != nil || !bytes.Equal(old, []byte(body)) {
			if err := os.WriteFile(fname, []byte(body), 0644); err != nil {
				log.Printf("[connector/gen] write %s: %v", fname, err)
				res.Failed++
				continue
			}
			res.Changed++
		}
		if created {
			log.Printf("[connector/gen] new DRAFT %s (%s, %d active techniques)", id, actor.Name, len(activeTechniques))
			res.Created++
			if g.evidence != nil {
				genNum, err := g.evidence.NextGenerationNumber(context.Background(), actor.ThreatID)
				if err != nil {
					log.Printf("[connector/gen] next generation number for %s: %v", actor.ThreatID, err)
				} else if err := g.evidence.RecordGeneration(context.Background(), actor.ThreatID, id, "", genNum, generationPolicyVersion); err != nil {
					log.Printf("[connector/gen] record generation for %s: %v", actor.ThreatID, err)
				}
			}
		} else {
			res.Skipped++
		}
	}
	return res, nil
}
```

```go
// internal/connector/generator.go -- new const, alongside minTechniques (line 28)
const generationPolicyVersion = "tcf2b-generation-v1"
```

Add `"github.com/audspect/bas/internal/evidence"` to `internal/connector/generator.go`'s import block.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/connector/... -run TestGenerator_Write_UsesActiveTechniqueSetNotMergedActorList -v`
Expected: PASS. Then run `go test ./internal/connector/... -run TestGenerator -v` to confirm the existing generator suite (YAML building, registration, collisions) is still green — `g.evidence == nil` must preserve the exact pre-2B behavior for every existing test that doesn't call `WithEvidenceStore`.

- [ ] **Step 5: Commit**

```bash
git add internal/connector/generator.go internal/connector/generator_evidence_test.go
git commit -m "feat(tcf2b): generator consumes the evidence layer's active technique set, records generation snapshots (spec §6.2, §8)"
```

---

### Task 14: Integration tests closing the remaining acceptance-test gaps

**Acceptance-test coverage map** (spec §13, items 14-24): 14 (Task 8), 15 (Task 9), 16/23 (Tasks 4, 10), 17/20/21/22 (Task 7), 19 (Task 13) are each already pinned by an earlier task's test. **18** (two independent sources, one drops while the other still supports the technique, then the second also drops) and **24** (two generations' snapshots explain a technique-set difference) are cross-cutting sequences that need their own end-to-end tests, written here against the full `evidence.Store` API from Tasks 2-12.

**Files:**
- Test: `internal/evidence/integration_test.go`

**Interfaces:**
- Consumes: `Store` (all methods from Tasks 2-12), `seedThreat`, `claimsFixture` (Tasks 5, 7).

- [ ] **Step 1: Write the failing test**

```go
// internal/evidence/integration_test.go
package evidence

import (
	"context"
	"testing"
	"time"
)

// TestIntegration_TwoSourceDropSequence pins spec §13 acceptance test 18:
// source A claims T1059, then drops it (A alone retracted); source B also
// claims T1059 and keeps claiming it -- the technique must stay active on
// B's support alone, with first_seen_at anchored to A's original claim.
// Once B also drops it, the technique goes retracted.
func TestIntegration_TwoSourceDropSequence(t *testing.T) {
	ctx := context.Background()
	store := NewStore(sharedDB.Pool)
	threatID := seedThreat(t, sharedDB.Pool, "APT-two-source-drop")
	jan1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	setup := func(instanceID string) (syncID string, trustVersionID int64, obs func(hash string) string) {
		if err := store.EnsureSourceInstance(ctx, instanceID, "misp", "Test", ModeSnapshot, TrustTrusted); err != nil {
			t.Fatal(err)
		}
		sID, _, err := store.RecordSync(ctx, instanceID, ModeSnapshot, time.Now(), "succeeded", Complete, "")
		if err != nil {
			t.Fatal(err)
		}
		_, tvID, err := store.CurrentTrust(ctx, instanceID)
		if err != nil {
			t.Fatal(err)
		}
		return sID, tvID, func(hash string) string {
			id, err := store.RecordObservation(ctx, sID, instanceID, "evt-"+hash, "APT", hash, time.Now(), map[string]any{}, tvID)
			if err != nil {
				t.Fatal(err)
			}
			return id
		}
	}

	// A claims T1059 on Jan 1.
	syncA1, tvA, obsA1 := setup("misp-two-source-A")
	if err := store.RecordClaims(ctx, []Claim{{
		ObservationID: obsA1("a-claim"), SyncID: syncA1, InstanceID: "misp-two-source-A", ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimAsserted, Source: "misp", TrustVersionID: tvA, ObservedAt: jan1, RecordHash: "a-claim",
	}}); err != nil {
		t.Fatal(err)
	}
	// B also claims T1059, independently.
	syncB1, tvB, obsB1 := setup("misp-two-source-B")
	if err := store.RecordClaims(ctx, []Claim{{
		ObservationID: obsB1("b-claim"), SyncID: syncB1, InstanceID: "misp-two-source-B", ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimAsserted, Source: "misp", TrustVersionID: tvB, ObservedAt: jan1.Add(time.Hour), RecordHash: "b-claim",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecomputeThreatTechniques(ctx, threatID); err != nil {
		t.Fatal(err)
	}

	// A drops T1059 (a later complete snapshot sync no longer sees it).
	syncA2, _, obsA2 := setup("misp-two-source-A")
	if err := store.RecordClaims(ctx, []Claim{{
		ObservationID: obsA2("a-retract"), SyncID: syncA2, InstanceID: "misp-two-source-A", ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimRetracted, Source: "misp", TrustVersionID: tvA, ObservedAt: jan1.AddDate(0, 0, 10), RecordHash: "a-retract",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecomputeThreatTechniques(ctx, threatID); err != nil {
		t.Fatal(err)
	}

	var status string
	var firstSeenAt time.Time
	if err := sharedDB.Pool.QueryRow(ctx, `SELECT status, first_seen_at FROM threat_techniques WHERE threat_id = $1 AND technique_id = 'T1059'`,
		threatID).Scan(&status, &firstSeenAt); err != nil {
		t.Fatal(err)
	}
	if status != "active" {
		t.Fatalf("status after A alone drops = %q, want active (B still supports it)", status)
	}
	if !firstSeenAt.Equal(jan1) {
		t.Fatalf("first_seen_at = %v, want unchanged at %v (A's original claim; a later retraction never moves it)", firstSeenAt, jan1)
	}

	// B also drops it.
	syncB2, _, obsB2 := setup("misp-two-source-B")
	if err := store.RecordClaims(ctx, []Claim{{
		ObservationID: obsB2("b-retract"), SyncID: syncB2, InstanceID: "misp-two-source-B", ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimRetracted, Source: "misp", TrustVersionID: tvB, ObservedAt: jan1.AddDate(0, 0, 11), RecordHash: "b-retract",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecomputeThreatTechniques(ctx, threatID); err != nil {
		t.Fatal(err)
	}
	if err := sharedDB.Pool.QueryRow(ctx, `SELECT status FROM threat_techniques WHERE threat_id = $1 AND technique_id = 'T1059'`,
		threatID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "retracted" {
		t.Fatalf("status after both sources drop = %q, want retracted", status)
	}
}

// TestIntegration_GenerationSnapshotsExplainTechniqueSetDifference pins spec
// §13 acceptance test 24: two generations' evidence_snapshot_hash values
// differ exactly when their active technique sets differ, and the earlier
// snapshot's own content explains which technique was missing.
func TestIntegration_GenerationSnapshotsExplainTechniqueSetDifference(t *testing.T) {
	ctx := context.Background()
	store, syncID, instanceID, tvID, mkObs := claimsFixture(t, "misp-gen-diff-test", TrustTrusted, Complete)
	threatID := seedThreat(t, sharedDB.Pool, "APT-generation-diff")

	if err := store.RecordClaims(ctx, []Claim{{
		ObservationID: mkObs(threatID, "gen-diff-1"), SyncID: syncID, InstanceID: instanceID, ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimAsserted, Source: "misp", TrustVersionID: tvID, ObservedAt: time.Now(), RecordHash: "gen-diff-1",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecomputeThreatTechniques(ctx, threatID); err != nil {
		t.Fatal(err)
	}
	gen1, err := store.NextGenerationNumber(ctx, threatID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordGeneration(ctx, threatID, "intel-gen-diff", "cv-1", gen1, "tcf2b-generation-v1"); err != nil {
		t.Fatal(err)
	}

	// A second technique arrives before generation 2.
	if err := store.RecordClaims(ctx, []Claim{{
		ObservationID: mkObs(threatID, "gen-diff-2"), SyncID: syncID, InstanceID: instanceID, ThreatID: threatID,
		TechniqueID: "T1055", Kind: ClaimAsserted, Source: "misp", TrustVersionID: tvID, ObservedAt: time.Now(), RecordHash: "gen-diff-2",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecomputeThreatTechniques(ctx, threatID); err != nil {
		t.Fatal(err)
	}
	gen2, err := store.NextGenerationNumber(ctx, threatID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordGeneration(ctx, threatID, "intel-gen-diff", "cv-2", gen2, "tcf2b-generation-v1"); err != nil {
		t.Fatal(err)
	}

	var hash1, hash2, snapshot1, snapshot2 string
	if err := sharedDB.Pool.QueryRow(ctx, `SELECT evidence_snapshot_hash, evidence_snapshot::text FROM content_generations
		WHERE threat_id = $1 AND generation_number = $2`, threatID, gen1).Scan(&hash1, &snapshot1); err != nil {
		t.Fatal(err)
	}
	if err := sharedDB.Pool.QueryRow(ctx, `SELECT evidence_snapshot_hash, evidence_snapshot::text FROM content_generations
		WHERE threat_id = $1 AND generation_number = $2`, threatID, gen2).Scan(&hash2, &snapshot2); err != nil {
		t.Fatal(err)
	}
	if hash1 == hash2 {
		t.Fatal("generation 1 and 2 have different active sets but the same evidence_snapshot_hash")
	}
	if containsSubstring(snapshot1, "T1055") {
		t.Fatalf("generation 1's snapshot = %s, must not mention T1055 (claimed after generation 1)", snapshot1)
	}
	if !containsSubstring(snapshot2, "T1055") || !containsSubstring(snapshot2, "T1059") {
		t.Fatalf("generation 2's snapshot = %s, must mention both T1059 and T1055", snapshot2)
	}
}

func containsSubstring(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/evidence/... -run TestIntegration -v`
Expected: at this point every function these tests call already exists (Tasks 1-12 are all committed), so this step's "fail" is a genuine behavioral check, not a compile error — run it once before trusting it, per this plan's TDD discipline, even though a clean pass on the first try here would mean the two scenarios already worked from the pieces built earlier. If it fails, it is pointing at a real integration bug between tasks (e.g. a projection edge case Task 7's narrower tests didn't exercise) -- use superpowers:systematic-debugging, not a weakened assertion.

- [ ] **Step 3: Write minimal implementation**

No new implementation code is expected for this task — if Step 2 passes immediately, skip to Step 4. If it fails, the fix belongs in whichever of Tasks 1-12's files the failure actually points to (most likely `internal/evidence/projection.go` for test 18, or `internal/evidence/generation.go` for test 24); amend that file directly and note the fix here as a ruling.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/evidence/... -v` (the package's full suite, not just the two new tests — this is the last task in the plan, so this is the module-end full gate)
Expected: PASS, all tests in the package.

- [ ] **Step 5: Commit**

```bash
git add internal/evidence/integration_test.go
git commit -m "test(tcf2b): integration tests for two-source claim/retraction sequencing and generation-snapshot reproducibility (spec §13 acceptance tests 18, 24)"
```
