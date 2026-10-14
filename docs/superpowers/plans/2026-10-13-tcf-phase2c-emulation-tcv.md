# TCF Phase 2C — Emulation + TCV — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the content↔threat relationship model with the `emulates` link (vendor-signed builtin metadata and an admin API for custom content) and add Threat-to-Content-Velocity (TCV) measurement — the two immutable clocks and their write-once stops — so the factory can finally answer "how long from first intelligence to validated, executable coverage."

**Architecture:** A new `internal/tcv` package owns the two new append-only tables (`threat_clock_starts`, `threat_coverage_firsts`) as a set of `Querier`-based package functions (so callers can fold a write into their own transaction, exactly like `internal/evidence`'s `recomputeThreatTechniques`) plus a small `Store` for the read side (`Metrics`). `internal/contentregistry` gains the "is this version now executable coverage" decision (`qualifiesForTCVStop`, a strict subset of the existing `Executable()` gate that excludes the dev-only combination) and calls the new package's write functions from every place a version's origin/trust/lifecycle can change: `Transition`, `AttachVendorSignature`, and `createVersion` itself. Builtin scenarios gain a signature-covered `emulates` metadata block, resolved at intake against the canonical actor registry (`internal/threatidentity`) the same way MISP/OpenCTI resolve actor names today. Custom content gets the same `emulates` link through a new admin-only API. `internal/connector/scheduler.go`'s existing claim-resolution path (built in 2B) gains the two clock-start writes.

**Tech Stack:** Go, PostgreSQL via `jackc/pgx/v5`, the existing boot-time `Ensure*Schema` pattern, the repo's own `go test` + `testutil.MustSharedTestDB()` harness (testcontainers Postgres).

**Spec:** `docs/superpowers/specs/2026-10-06-tcf-phase2-canonical-threat-design.md` — milestone 2C (§9.2–§9.3 content↔threat relationships, §10 TCV; acceptance tests 25–33).

## Global Constraints

- No versioned-migration framework exists on `main`. Ship schema via a new `EnsureTCVSchema` boot-time function, same pattern as `EnsureEvidenceSchema` (2B).
- `bas_app` grants (spec §12): `threat_clock_starts` and `threat_coverage_firsts` are append-only — `SELECT, INSERT` only, no `UPDATE`, no `DELETE`.
- Both clocks and both coverage-firsts are **write-once**: every write uses `ON CONFLICT DO NOTHING` on their primary key. A later retraction, trust revocation, or re-link never moves an already-written row (spec §10.2, §10.3; acceptance tests 28, 31, 32).
- The dev-only executable combination (`devBuild && OriginVendor && TrustUntrusted && LifecyclePublished`, from `contentregistry.Executable`) **never** qualifies as a TCV stop (spec §10.4 via acceptance test 32) even though the runtime gate treats it as executable for local dev convenience. This is `qualifiesForTCVStop`'s entire reason to exist as a function distinct from `Executable`.
- `emulates` resolution never uses free-text or fuzzy name matching (spec §9.2, §9.3; acceptance tests 25, 27). Builtin metadata resolves only through `attackdata.GroupByID` + `threatidentity.Store.ResolveAndPersist`'s `CanonicalGroupID` field (the same mechanism MISP/OpenCTI already use for attack-group identity); the admin API takes an explicit, already-existing `threatId` and nothing else.
- A new version created without `emulates` metadata never inherits a link from an earlier version of the same content (spec §9.1's PK is per-version; acceptance test 27). No task in this plan copies a link forward.
- Package boundary: `internal/tcv` must not import `internal/contentregistry`, `internal/connector`, or `internal/evidence` (same "owns its own small thing" shape as `internal/evidence`). `internal/contentregistry` imports `internal/tcv` and `internal/threatidentity` (already does, via `legacy_intel.go`) and `internal/reporting/attackdata` (verified: `attackdata.go` has no internal-package imports of its own, so no cycle).

## Review Focus

- **A version that becomes executable through `AttachVendorSignature` alone (lifecycle unchanged, only trust flips VENDOR → VENDOR_SIGNED) must still record its coverage-first stop.** `Transition` is the obvious chokepoint; a plan that only wires `Transition` misses this one. Pinned in Task 7's test.
- **The dev-only executable combination must never write a coverage-first stop, even though `contentregistry.Executable` reports it as executable for the runtime gate.** Pinned in Task 6's test for `qualifiesForTCVStop` directly, and in Task 13's end-to-end test (acceptance 32).
- **An admin linking `emulates` on a version that is** ***already*** **executable must record the stop immediately, at link time — not wait for some future transition that may never come.** Pinned in Task 10's test (acceptance 33).
- **Retracting a technique or revoking a source's trust must never move an already-recorded clock start or coverage-first stop.** Both are write-once by construction (`ON CONFLICT DO NOTHING`), but a test must prove a retraction/revocation sequence doesn't somehow reach the write path with a different timestamp and overwrite nothing only by luck. Pinned in Task 13 (acceptance 31).
- **A builtin scenario's `emulates` entry naming a syntactically plausible but unknown MITRE group id (not a free-text guess, a real-shaped id that simply isn't in the catalog) must produce no link and a queued resolution candidate, not an error that fails the whole intake.** Pinned in Task 9's test (acceptance 26).

---

## File Structure

New:
- `internal/db/tcv_schema.go` — `EnsureTCVSchema`: `threat_clock_starts`, `threat_coverage_firsts`, plus the idempotent widening of `actor_resolution_candidates`'s `kind` CHECK constraint to add `'content_emulates_ref'`.
- `internal/tcv/types.go` — `ClockKind`, `RelationshipKind`, `MetricState`, `Metric`, `ThreatTCV`.
- `internal/tcv/store.go` — `Querier` interface, `Store` struct + `NewStore`.
- `internal/tcv/clocks.go` — `RecordThreatClockStart`, `RecordIntelligenceClockStart` (package-level, `Querier`-based).
- `internal/tcv/coverage.go` — `RecordCoverageFirst` (package-level, `Querier`-based).
- `internal/tcv/metrics.go` — `(*Store).Metrics`.
- `internal/tcv/testmain_test.go` — shared test DB.
- `internal/contentregistry/tcv.go` — `qualifiesForTCVStop`, `(*Registry).recordCoverageIfExecutable`.
- `internal/api/content_threats_handlers.go` — `POST /api/content/{contentId}/versions/{n}/threats`, `GET /api/intel/threats/{id}/tcv`.

Modified:
- `internal/db/app_role.go` — grants for the two new tables.
- `cmd/server/main.go` — boot `EnsureTCVSchema` after `EnsureEvidenceSchema`.
- `internal/testutil/testdb.go` — same, for the test harness.
- `internal/contentregistry/types.go` — `ErrThreatNotFound`.
- `internal/contentregistry/registry.go` — none (no new field needed; `recordCoverageIfExecutable` uses `r.pool`/the caller's `tx` directly).
- `internal/contentregistry/intake.go` — `newVersion.emulatesLinks`, `resolveEmulatesMetadata`, call site in `Intake`.
- `internal/contentregistry/store.go` — write `emulatesLinks` rows and call `recordCoverageIfExecutable` inside `createVersion`.
- `internal/contentregistry/gate.go` — call `recordCoverageIfExecutable` inside `AttachVendorSignature`.
- `internal/contentregistry/content_threats.go` (new) — `(*Registry).LinkThreat`.
- `internal/scenario/types.go` — `Scenario.Emulates []EmulatesRef`, `EmulatesRef` type.
- `internal/threatidentity/decide.go` — `(*Store).QueueEmulatesCandidate`.
- `internal/auth/permissions.go` — new `CanLinkContentThreat` permission, Admin-only.
- `internal/auth/permissions_test.go` — matrix/ordering rows for the new permission.
- `internal/api/routes.go` — register the two new routes.
- `internal/connector/scheduler.go` — `pendingClaim.trustState` field, populated in `recordSourceSync`; clock-start calls added to `resolvePendingClaims`.

---

### Task 1: TCV schema, candidate-kind widening, and grants

**Files:**
- Create: `internal/db/tcv_schema.go`
- Modify: `internal/db/app_role.go`
- Modify: `cmd/server/main.go`
- Modify: `internal/testutil/testdb.go`
- Test: `internal/db/tcv_schema_test.go`

**Interfaces:**
- Consumes: `threats(id)` (2A), `content_versions(id)` (Phase 1), `actor_resolution_candidates` (2A).
- Produces: tables `threat_clock_starts`, `threat_coverage_firsts`; widened `actor_resolution_candidates.kind` CHECK (now also accepts `'content_emulates_ref'`) — consumed by every later task in this plan.

- [ ] **Step 1: Write the failing test**

```go
// internal/db/tcv_schema_test.go
package db_test

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/db"
)

func TestEnsureTCVSchema_CreatesTablesAndWidensCandidateKind(t *testing.T) {
	ctx := context.Background()
	pool := sharedDB.Pool

	if err := db.EnsureTCVSchema(ctx, pool); err != nil {
		t.Fatalf("EnsureTCVSchema: %v", err)
	}
	// Idempotent -- running it twice must not error.
	if err := db.EnsureTCVSchema(ctx, pool); err != nil {
		t.Fatalf("EnsureTCVSchema (second run): %v", err)
	}

	for _, table := range []string{"threat_clock_starts", "threat_coverage_firsts"} {
		var exists bool
		if err := pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = $1)`,
			table).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Fatalf("table %q was not created", table)
		}
	}

	// The widened CHECK must now accept 'content_emulates_ref'.
	var threatID string
	if err := pool.QueryRow(ctx, `INSERT INTO threat_actor_profiles (name, aliases) VALUES ('APT-tcv-schema-test', '{}') RETURNING id`).
		Scan(&threatID); err != nil {
		t.Fatal(err)
	}
	_, err := pool.Exec(ctx, `INSERT INTO actor_resolution_candidates
		(kind, source, external_id, raw_name, ref_entity_id, reason, resolver_context, resolver_context_hash)
		VALUES ('content_emulates_ref', 'attackdata', 'G9999', 'G9999', 'cv-schema-test', 'test', '{}'::jsonb, '')`)
	if err != nil {
		t.Fatalf("widened CHECK should accept 'content_emulates_ref': %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/db/... -run TestEnsureTCVSchema_CreatesTablesAndWidensCandidateKind -v`
Expected: FAIL — `undefined: db.EnsureTCVSchema`.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/db/tcv_schema.go
package db

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EnsureTCVSchema creates the TCV (Threat-to-Content-Velocity) tables and
// widens actor_resolution_candidates.kind to accept a builtin scenario's
// unresolvable `emulates` reference (spec §9.2, §10.2-§10.3). Must run
// after EnsureThreatIdentitySchema (actor_resolution_candidates, threats)
// and EnsureContentRegistrySchema (content_versions), and before
// EnsureAppRole (whose REVOKEs target these tables).
func EnsureTCVSchema(ctx context.Context, pool *pgxpool.Pool) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS threat_clock_starts (
			threat_id   text        NOT NULL REFERENCES threats(id),
			clock       text        NOT NULL CHECK (clock IN ('threat','intelligence')),
			started_at  timestamptz NOT NULL,
			source_ref  text        NOT NULL DEFAULT '',
			PRIMARY KEY (threat_id, clock)
		)`,
		`CREATE TABLE IF NOT EXISTS threat_coverage_firsts (
			threat_id          text        NOT NULL REFERENCES threats(id),
			relationship_kind  text        NOT NULL CHECK (relationship_kind IN ('emulates','generated_for')),
			content_version_id text       NOT NULL REFERENCES content_versions(id),
			first_executable_at timestamptz NOT NULL,
			PRIMARY KEY (threat_id, relationship_kind)
		)`,
		// Postgres auto-names the CREATE TABLE's inline CHECK
		// actor_resolution_candidates_kind_check; widen it idempotently by
		// dropping (if present) and re-adding with the new value included.
		// Cheap metadata-only operation, safe to run every boot.
		`DO $$
		BEGIN
			IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'actor_resolution_candidates_kind_check') THEN
				ALTER TABLE actor_resolution_candidates DROP CONSTRAINT actor_resolution_candidates_kind_check;
			END IF;
			ALTER TABLE actor_resolution_candidates ADD CONSTRAINT actor_resolution_candidates_kind_check
				CHECK (kind IN ('source_record','campaign_ref','malware_ref','tool_ref','content_emulates_ref'));
		END $$`,
	}
	for _, stmt := range stmts {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}
```

Modify `internal/db/app_role.go` — add to the append-only-grants list (find the existing `source_trust_versions`/`technique_claims` grant block from 2B and extend it):

```go
// in the append-only SELECT,INSERT grants list, add:
"threat_clock_starts", "threat_coverage_firsts",
```

Modify `cmd/server/main.go` — immediately after the `EnsureEvidenceSchema` call:

```go
if err := db.EnsureTCVSchema(ctx, pool); err != nil {
    log.Fatalf("ensure TCV schema: %v", err)
}
```

Modify `internal/testutil/testdb.go` — same call, same position, in the test harness's schema bootstrap.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/db/... -run TestEnsureTCVSchema_CreatesTablesAndWidensCandidateKind -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/db/tcv_schema.go internal/db/tcv_schema_test.go internal/db/app_role.go cmd/server/main.go internal/testutil/testdb.go
git commit -m "feat(tcf2c): TCV schema + candidate-kind widening + grants (spec §10.2-§10.3, §9.2)"
```

---

### Task 2: `internal/tcv` package scaffold

**Files:**
- Create: `internal/tcv/types.go`
- Create: `internal/tcv/store.go`
- Create: `internal/tcv/testmain_test.go`
- Test: `internal/tcv/store_test.go`

**Interfaces:**
- Consumes: `internal/testutil.MustSharedTestDB()`.
- Produces: `ClockKind` (`ClockThreat`, `ClockIntelligence`), `RelationshipKind` (`RelationshipEmulates`, `RelationshipGeneratedFor`), `MetricState`, `Metric`, `ThreatTCV`, `Querier`, `Store`, `NewStore` — consumed by every later task.

- [ ] **Step 1: Write the failing test**

```go
// internal/tcv/store_test.go
package tcv

import "testing"

func TestNewStore_ReturnsNonNil(t *testing.T) {
	s := NewStore(sharedDB.Pool)
	if s == nil {
		t.Fatal("NewStore returned nil")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/tcv/... -v`
Expected: FAIL — package `internal/tcv` does not exist yet (no buildable Go files).

- [ ] **Step 3: Write minimal implementation**

```go
// internal/tcv/types.go
package tcv

import "time"

// ClockKind is one of TCV's two immutable start clocks (spec §10.2).
type ClockKind string

const (
	ClockThreat       ClockKind = "threat"
	ClockIntelligence ClockKind = "intelligence"
)

// RelationshipKind mirrors content_version_threats.relationship_kind --
// the two ways a content version can cover a threat (spec §9.1, §10.3).
type RelationshipKind string

const (
	RelationshipEmulates     RelationshipKind = "emulates"
	RelationshipGeneratedFor RelationshipKind = "generated_for"
)

// MetricState classifies one TCV metric's current shape (spec §10.4).
type MetricState string

const (
	// StateNoClock: the relevant clock (threat or intelligence) has never
	// started for this threat -- there is no evidence to measure from yet.
	StateNoClock MetricState = "no_clock"
	// StateOpen: the clock started but no qualifying content has yet
	// become executable coverage. Only ElapsedSeconds moves over time.
	StateOpen MetricState = "open"
	// StatePreExisting: content became executable coverage BEFORE the
	// clock started (e.g. a generic technique-overlap scenario already
	// existed). TCVSeconds is always 0, never negative.
	StatePreExisting MetricState = "pre_existing"
	// StateMeasured: the normal case -- coverage became executable at or
	// after the clock started. TCVSeconds is the real elapsed duration.
	StateMeasured MetricState = "measured"
)

// Metric is one of TCV's four measurements for a single threat (spec
// §10.4): Threat→Emulation, Threat→Generation, Intelligence→Emulation,
// Intelligence→Generation. Exactly one of (TCVSeconds, ElapsedSeconds) is
// set, and only when State is StateMeasured/StatePreExisting or StateOpen
// respectively; both are nil for StateNoClock.
type Metric struct {
	ClockStartedAt *time.Time  `json:"clockStartedAt,omitempty"`
	CoveredAt      *time.Time  `json:"coveredAt,omitempty"`
	State          MetricState `json:"state"`
	TCVSeconds     *int64      `json:"tcvSeconds,omitempty"`
	ElapsedSeconds *int64      `json:"elapsedSeconds,omitempty"`
}

// ThreatTCV is the full read-model for GET /api/intel/threats/{id}/tcv.
type ThreatTCV struct {
	ThreatID                 string `json:"threatId"`
	ThreatToEmulation        Metric `json:"threatToEmulation"`
	ThreatToGeneration       Metric `json:"threatToGeneration"`
	IntelligenceToEmulation  Metric `json:"intelligenceToEmulation"`
	IntelligenceToGeneration Metric `json:"intelligenceToGeneration"`
}
```

```go
// internal/tcv/store.go
package tcv

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Querier is the subset of pgx shared by *pgxpool.Pool and pgx.Tx, letting
// clocks.go/coverage.go's write functions run inside a caller's own
// transaction (contentregistry folds these into Transition/
// AttachVendorSignature/createVersion/LinkThreat) or standalone (the
// connector scheduler has no surrounding transaction for a clock start).
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Store is the read side: Metrics (metrics.go). Writes go through the
// package-level functions in clocks.go/coverage.go instead, so a caller
// that already has a transaction open never needs a second connection.
type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }
```

```go
// internal/tcv/testmain_test.go
package tcv

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

Run: `go test ./internal/tcv/... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/tcv/types.go internal/tcv/store.go internal/tcv/testmain_test.go internal/tcv/store_test.go
git commit -m "feat(tcf2c): internal/tcv package scaffold (spec §10.2-§10.4)"
```

---

### Task 3: Clock-start recording

**Files:**
- Create: `internal/tcv/clocks.go`
- Test: `internal/tcv/clocks_test.go`

**Interfaces:**
- Consumes: `Querier`, `ClockKind` (Task 2).
- Produces: `RecordThreatClockStart(ctx, q, threatID string, startedAt time.Time, sourceRef string) error`, `RecordIntelligenceClockStart(ctx, q, threatID string, startedAt time.Time, sourceRef string) error` — consumed by Task 11 (scheduler wiring) and Task 13 (integration tests).

- [ ] **Step 1: Write the failing test**

```go
// internal/tcv/clocks_test.go
package tcv

import (
	"context"
	"testing"
	"time"
)

func seedThreat(t *testing.T, name string) string {
	t.Helper()
	ctx := context.Background()
	var actorID string
	if err := sharedDB.Pool.QueryRow(ctx, `INSERT INTO threat_actor_profiles (name, aliases) VALUES ($1, '{}') RETURNING id`,
		name).Scan(&actorID); err != nil {
		t.Fatal(err)
	}
	var threatID string
	if err := sharedDB.Pool.QueryRow(ctx, `INSERT INTO threats (id, subject_type, subject_id, actor_id, title)
		VALUES ('thr-' || gen_random_uuid()::text, 'actor', $1, $1, $2) RETURNING id`,
		actorID, name).Scan(&threatID); err != nil {
		t.Fatal(err)
	}
	return threatID
}

func TestRecordThreatClockStart_WriteOnceNeverMoved(t *testing.T) {
	ctx := context.Background()
	threatID := seedThreat(t, "APT-clock-threat")
	first := time.Now().Add(-48 * time.Hour)
	later := time.Now()

	if err := RecordThreatClockStart(ctx, sharedDB.Pool, threatID, first, "sync-1"); err != nil {
		t.Fatal(err)
	}
	// A second, later call must not move the already-written start.
	if err := RecordThreatClockStart(ctx, sharedDB.Pool, threatID, later, "sync-2"); err != nil {
		t.Fatal(err)
	}

	var startedAt time.Time
	var sourceRef string
	if err := sharedDB.Pool.QueryRow(ctx, `SELECT started_at, source_ref FROM threat_clock_starts WHERE threat_id = $1 AND clock = 'threat'`,
		threatID).Scan(&startedAt, &sourceRef); err != nil {
		t.Fatal(err)
	}
	if diff := startedAt.Sub(first); diff < -time.Second || diff > time.Second {
		t.Fatalf("started_at = %v, want the first call's time %v (write-once)", startedAt, first)
	}
	if sourceRef != "sync-1" {
		t.Fatalf("source_ref = %q, want %q (first call wins)", sourceRef, "sync-1")
	}
}

func TestRecordIntelligenceClockStart_SeparateFromThreatClock(t *testing.T) {
	ctx := context.Background()
	threatID := seedThreat(t, "APT-clock-intel")
	threatStart := time.Now().Add(-24 * time.Hour)
	intelStart := time.Now()

	if err := RecordThreatClockStart(ctx, sharedDB.Pool, threatID, threatStart, "sync-t"); err != nil {
		t.Fatal(err)
	}
	if err := RecordIntelligenceClockStart(ctx, sharedDB.Pool, threatID, intelStart, "sync-i"); err != nil {
		t.Fatal(err)
	}

	var count int
	if err := sharedDB.Pool.QueryRow(ctx, `SELECT count(*) FROM threat_clock_starts WHERE threat_id = $1`, threatID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("threat_clock_starts rows = %d, want 2 (threat and intelligence are independent clocks)", count)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/tcv/... -run 'TestRecordThreatClockStart|TestRecordIntelligenceClockStart' -v`
Expected: FAIL — `undefined: RecordThreatClockStart`.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/tcv/clocks.go
package tcv

import (
	"context"
	"fmt"
	"time"
)

// RecordThreatClockStart writes the threat clock's start (spec §10.2):
// the earliest observed_at of a claim/observation made under a trust
// version that was trusted at observation time. Write-once -- a later
// call never moves an already-recorded start (acceptance test 28).
func RecordThreatClockStart(ctx context.Context, q Querier, threatID string, startedAt time.Time, sourceRef string) error {
	return recordClockStart(ctx, q, threatID, ClockThreat, startedAt, sourceRef)
}

// RecordIntelligenceClockStart writes the intelligence clock's start (spec
// §10.2): the first source_syncs.completed_at of a sync that produced a
// trusted claim/observation for the threat. Write-once, independent of
// the threat clock.
func RecordIntelligenceClockStart(ctx context.Context, q Querier, threatID string, startedAt time.Time, sourceRef string) error {
	return recordClockStart(ctx, q, threatID, ClockIntelligence, startedAt, sourceRef)
}

func recordClockStart(ctx context.Context, q Querier, threatID string, clock ClockKind, startedAt time.Time, sourceRef string) error {
	if _, err := q.Exec(ctx, `INSERT INTO threat_clock_starts (threat_id, clock, started_at, source_ref)
		VALUES ($1, $2, $3, $4) ON CONFLICT (threat_id, clock) DO NOTHING`,
		threatID, clock, startedAt, sourceRef); err != nil {
		return fmt.Errorf("tcv: record %s clock start for %s: %w", clock, threatID, err)
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/tcv/... -v`
Expected: PASS, all tests in the package.

- [ ] **Step 5: Commit**

```bash
git add internal/tcv/clocks.go internal/tcv/clocks_test.go
git commit -m "feat(tcf2c): threat and intelligence clock-start recording, write-once (spec §10.2)"
```

---

### Task 4: Coverage-first recording

**Files:**
- Create: `internal/tcv/coverage.go`
- Test: `internal/tcv/coverage_test.go`

**Interfaces:**
- Consumes: `Querier`, `RelationshipKind` (Task 2).
- Produces: `RecordCoverageFirst(ctx, q, threatID string, kind RelationshipKind, contentVersionID string, firstExecutableAt time.Time) error` — consumed by Task 6-10 (contentregistry wiring) and Task 13.

- [ ] **Step 1: Write the failing test**

```go
// internal/tcv/coverage_test.go
package tcv

import (
	"context"
	"testing"
	"time"
)

// seedContentVersion inserts a minimal content_versions row this package's
// FK can reference -- internal/tcv must not import internal/contentregistry
// (Global Constraints), so it builds its own minimal fixture row directly.
func seedContentVersion(t *testing.T, contentID string) string {
	t.Helper()
	ctx := context.Background()
	if _, err := sharedDB.Pool.Exec(ctx,
		`INSERT INTO scenarios (scenario_id, name, category, origin) VALUES ($1, $1, '', 'VENDOR')
		 ON CONFLICT (scenario_id) DO NOTHING`, contentID); err != nil {
		t.Fatal(err)
	}
	var vid string
	if err := sharedDB.Pool.QueryRow(ctx, `INSERT INTO content_versions
		(content_id, origin, version, artifact_sha256, artifact_size, artifact_bytes, trust_level, lifecycle,
		 intake_source, schema_version, technique_ids, supported_os, generation, created_by)
		VALUES ($1, 'VENDOR', 1, 'deadbeef', 0, '\x', 'VENDOR_SIGNED', 'PUBLISHED', 'builtin', 1, '{}', '{}', '{}'::jsonb, 'test')
		RETURNING id`, contentID).Scan(&vid); err != nil {
		t.Fatal(err)
	}
	return vid
}

func TestRecordCoverageFirst_WriteOncePerRelationshipKind(t *testing.T) {
	ctx := context.Background()
	threatID := seedThreat(t, "APT-coverage-test")
	vid1 := seedContentVersion(t, "cv-coverage-test-1")
	vid2 := seedContentVersion(t, "cv-coverage-test-2")
	first := time.Now().Add(-1 * time.Hour)
	later := time.Now()

	if err := RecordCoverageFirst(ctx, sharedDB.Pool, threatID, RelationshipEmulates, vid1, first); err != nil {
		t.Fatal(err)
	}
	// A later call for a DIFFERENT version, same (threat, kind), must not
	// move the already-written stop.
	if err := RecordCoverageFirst(ctx, sharedDB.Pool, threatID, RelationshipEmulates, vid2, later); err != nil {
		t.Fatal(err)
	}

	var gotVID string
	var firstExecutableAt time.Time
	if err := sharedDB.Pool.QueryRow(ctx,
		`SELECT content_version_id, first_executable_at FROM threat_coverage_firsts WHERE threat_id = $1 AND relationship_kind = 'emulates'`,
		threatID).Scan(&gotVID, &firstExecutableAt); err != nil {
		t.Fatal(err)
	}
	if gotVID != vid1 {
		t.Fatalf("content_version_id = %q, want the first call's version %q (write-once)", gotVID, vid1)
	}
	if diff := firstExecutableAt.Sub(first); diff < -time.Second || diff > time.Second {
		t.Fatalf("first_executable_at = %v, want %v", firstExecutableAt, first)
	}
}

func TestRecordCoverageFirst_EmulatesAndGeneratedForAreIndependent(t *testing.T) {
	ctx := context.Background()
	threatID := seedThreat(t, "APT-coverage-independent")
	vid := seedContentVersion(t, "cv-coverage-independent")
	now := time.Now()

	if err := RecordCoverageFirst(ctx, sharedDB.Pool, threatID, RelationshipEmulates, vid, now); err != nil {
		t.Fatal(err)
	}
	if err := RecordCoverageFirst(ctx, sharedDB.Pool, threatID, RelationshipGeneratedFor, vid, now); err != nil {
		t.Fatal(err)
	}

	var count int
	if err := sharedDB.Pool.QueryRow(ctx, `SELECT count(*) FROM threat_coverage_firsts WHERE threat_id = $1`, threatID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("threat_coverage_firsts rows = %d, want 2 (emulates and generated_for never collapse)", count)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/tcv/... -run TestRecordCoverageFirst -v`
Expected: FAIL — `undefined: RecordCoverageFirst`.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/tcv/coverage.go
package tcv

import (
	"context"
	"fmt"
	"time"
)

// RecordCoverageFirst writes the write-once moment a content version
// linked to threatID by kind first satisfies the execution gate (spec
// §10.3). ON CONFLICT DO NOTHING means a later call -- from a different
// version, or from the same version transitioning again -- never moves
// an already-recorded stop (acceptance tests 28, 31, 32).
func RecordCoverageFirst(ctx context.Context, q Querier, threatID string, kind RelationshipKind, contentVersionID string, firstExecutableAt time.Time) error {
	if _, err := q.Exec(ctx, `INSERT INTO threat_coverage_firsts (threat_id, relationship_kind, content_version_id, first_executable_at)
		VALUES ($1, $2, $3, $4) ON CONFLICT (threat_id, relationship_kind) DO NOTHING`,
		threatID, kind, contentVersionID, firstExecutableAt); err != nil {
		return fmt.Errorf("tcv: record coverage first for %s/%s: %w", threatID, kind, err)
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/tcv/... -v`
Expected: PASS, all tests in the package.

- [ ] **Step 5: Commit**

```bash
git add internal/tcv/coverage.go internal/tcv/coverage_test.go
git commit -m "feat(tcf2c): coverage-first recording, write-once per relationship kind (spec §10.3)"
```

---

### Task 5: TCV metrics

**Files:**
- Create: `internal/tcv/metrics.go`
- Test: `internal/tcv/metrics_test.go`

**Interfaces:**
- Consumes: `Store`, `ThreatTCV`, `Metric`, `MetricState`, `RecordThreatClockStart`/`RecordIntelligenceClockStart`/`RecordCoverageFirst` (Tasks 2-4).
- Produces: `(*Store).Metrics(ctx, threatID string) (ThreatTCV, error)` — consumed by Task 12 (read API) and Task 13.

- [ ] **Step 1: Write the failing test**

```go
// internal/tcv/metrics_test.go
package tcv

import (
	"context"
	"testing"
	"time"
)

func TestMetrics_NoClockStartedIsNoClock(t *testing.T) {
	ctx := context.Background()
	threatID := seedThreat(t, "APT-metrics-no-clock")
	store := NewStore(sharedDB.Pool)

	m, err := store.Metrics(ctx, threatID)
	if err != nil {
		t.Fatal(err)
	}
	if m.ThreatToEmulation.State != StateNoClock || m.ThreatToGeneration.State != StateNoClock {
		t.Fatalf("metrics = %+v, want StateNoClock for both threat-clock metrics", m)
	}
}

func TestMetrics_ClockStartedNoCoverageIsOpen(t *testing.T) {
	ctx := context.Background()
	threatID := seedThreat(t, "APT-metrics-open")
	start := time.Now().Add(-2 * time.Hour)
	if err := RecordThreatClockStart(ctx, sharedDB.Pool, threatID, start, "sync-1"); err != nil {
		t.Fatal(err)
	}
	store := NewStore(sharedDB.Pool)

	m, err := store.Metrics(ctx, threatID)
	if err != nil {
		t.Fatal(err)
	}
	if m.ThreatToEmulation.State != StateOpen {
		t.Fatalf("ThreatToEmulation.State = %q, want open", m.ThreatToEmulation.State)
	}
	if m.ThreatToEmulation.ElapsedSeconds == nil || *m.ThreatToEmulation.ElapsedSeconds < 3600 {
		t.Fatalf("ThreatToEmulation.ElapsedSeconds = %v, want >= ~7200 (elapsed since start, moves over time)", m.ThreatToEmulation.ElapsedSeconds)
	}
	if m.ThreatToEmulation.TCVSeconds != nil {
		t.Fatalf("ThreatToEmulation.TCVSeconds = %v, want nil while open", m.ThreatToEmulation.TCVSeconds)
	}
}

func TestMetrics_CoverageBeforeClockStartIsPreExistingZero(t *testing.T) {
	ctx := context.Background()
	threatID := seedThreat(t, "APT-metrics-preexisting")
	vid := seedContentVersion(t, "cv-metrics-preexisting")
	covered := time.Now().Add(-48 * time.Hour)
	start := time.Now()

	if err := RecordCoverageFirst(ctx, sharedDB.Pool, threatID, RelationshipEmulates, vid, covered); err != nil {
		t.Fatal(err)
	}
	if err := RecordThreatClockStart(ctx, sharedDB.Pool, threatID, start, "sync-1"); err != nil {
		t.Fatal(err)
	}
	store := NewStore(sharedDB.Pool)

	m, err := store.Metrics(ctx, threatID)
	if err != nil {
		t.Fatal(err)
	}
	if m.ThreatToEmulation.State != StatePreExisting {
		t.Fatalf("State = %q, want pre_existing (coverage predates the clock start)", m.ThreatToEmulation.State)
	}
	if m.ThreatToEmulation.TCVSeconds == nil || *m.ThreatToEmulation.TCVSeconds != 0 {
		t.Fatalf("TCVSeconds = %v, want exactly 0 (never negative)", m.ThreatToEmulation.TCVSeconds)
	}
}

func TestMetrics_CoverageAfterClockStartIsMeasured(t *testing.T) {
	ctx := context.Background()
	threatID := seedThreat(t, "APT-metrics-measured")
	vid := seedContentVersion(t, "cv-metrics-measured")
	start := time.Now().Add(-3 * time.Hour)
	covered := time.Now()

	if err := RecordThreatClockStart(ctx, sharedDB.Pool, threatID, start, "sync-1"); err != nil {
		t.Fatal(err)
	}
	if err := RecordCoverageFirst(ctx, sharedDB.Pool, threatID, RelationshipGeneratedFor, vid, covered); err != nil {
		t.Fatal(err)
	}
	store := NewStore(sharedDB.Pool)

	m, err := store.Metrics(ctx, threatID)
	if err != nil {
		t.Fatal(err)
	}
	if m.ThreatToGeneration.State != StateMeasured {
		t.Fatalf("State = %q, want measured", m.ThreatToGeneration.State)
	}
	if m.ThreatToGeneration.TCVSeconds == nil || *m.ThreatToGeneration.TCVSeconds < 10000 {
		t.Fatalf("TCVSeconds = %v, want roughly 10800 (3 hours)", m.ThreatToGeneration.TCVSeconds)
	}
	// The other three metrics are unaffected -- never collapsed together.
	if m.ThreatToEmulation.State != StateOpen {
		t.Fatalf("ThreatToEmulation.State = %q, want open (no emulates coverage recorded)", m.ThreatToEmulation.State)
	}
	if m.IntelligenceToGeneration.State != StateNoClock {
		t.Fatalf("IntelligenceToGeneration.State = %q, want no_clock (intelligence clock never started)", m.IntelligenceToGeneration.State)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/tcv/... -run TestMetrics -v`
Expected: FAIL — `(*Store).Metrics` undefined.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/tcv/metrics.go
package tcv

import (
	"context"
	"fmt"
	"time"
)

// Metrics computes all four TCV measurements for one threat (spec §10.4).
// No qualifying content and no clock started are both represented
// explicitly (StateNoClock, StateOpen) rather than as a zero-valued
// Metric that would be indistinguishable from a real zero-duration
// measurement.
func (s *Store) Metrics(ctx context.Context, threatID string) (ThreatTCV, error) {
	starts := map[ClockKind]time.Time{}
	rows, err := s.pool.Query(ctx, `SELECT clock, started_at FROM threat_clock_starts WHERE threat_id = $1`, threatID)
	if err != nil {
		return ThreatTCV{}, fmt.Errorf("tcv: load clock starts for %s: %w", threatID, err)
	}
	for rows.Next() {
		var clock ClockKind
		var startedAt time.Time
		if err := rows.Scan(&clock, &startedAt); err != nil {
			rows.Close()
			return ThreatTCV{}, err
		}
		starts[clock] = startedAt
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return ThreatTCV{}, err
	}

	firsts := map[RelationshipKind]time.Time{}
	rows2, err := s.pool.Query(ctx, `SELECT relationship_kind, first_executable_at FROM threat_coverage_firsts WHERE threat_id = $1`, threatID)
	if err != nil {
		return ThreatTCV{}, fmt.Errorf("tcv: load coverage firsts for %s: %w", threatID, err)
	}
	for rows2.Next() {
		var kind RelationshipKind
		var firstExecutableAt time.Time
		if err := rows2.Scan(&kind, &firstExecutableAt); err != nil {
			rows2.Close()
			return ThreatTCV{}, err
		}
		firsts[kind] = firstExecutableAt
	}
	rows2.Close()
	if err := rows2.Err(); err != nil {
		return ThreatTCV{}, err
	}

	build := func(clock ClockKind, kind RelationshipKind) Metric {
		start, hasStart := starts[clock]
		if !hasStart {
			return Metric{State: StateNoClock}
		}
		covered, hasCovered := firsts[kind]
		if !hasCovered {
			elapsed := int64(time.Since(start).Seconds())
			return Metric{ClockStartedAt: &start, State: StateOpen, ElapsedSeconds: &elapsed}
		}
		if covered.Before(start) {
			var zero int64
			return Metric{ClockStartedAt: &start, CoveredAt: &covered, State: StatePreExisting, TCVSeconds: &zero}
		}
		secs := int64(covered.Sub(start).Seconds())
		return Metric{ClockStartedAt: &start, CoveredAt: &covered, State: StateMeasured, TCVSeconds: &secs}
	}

	return ThreatTCV{
		ThreatID:                 threatID,
		ThreatToEmulation:        build(ClockThreat, RelationshipEmulates),
		ThreatToGeneration:       build(ClockThreat, RelationshipGeneratedFor),
		IntelligenceToEmulation:  build(ClockIntelligence, RelationshipEmulates),
		IntelligenceToGeneration: build(ClockIntelligence, RelationshipGeneratedFor),
	}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/tcv/... -v`
Expected: PASS, all tests in the package (module-end full gate for this package).

- [ ] **Step 5: Commit**

```bash
git add internal/tcv/metrics.go internal/tcv/metrics_test.go
git commit -m "feat(tcf2c): TCV metrics — four measurements, pre_existing/open/no_clock states (spec §10.4)"
```

---

### Task 6: `qualifiesForTCVStop` and `recordCoverageIfExecutable`, wired into `Transition`

**Files:**
- Create: `internal/contentregistry/tcv.go`
- Modify: `internal/contentregistry/intake.go:258-267` (`Transition`)
- Test: `internal/contentregistry/tcv_test.go`

**Interfaces:**
- Consumes: `Origin`, `Trust`, `Lifecycle`, `Executable` (existing, `lifecycle.go`), `tcv.Querier`, `tcv.RecordCoverageFirst`, `tcv.RelationshipKind` (Task 4).
- Produces: `qualifiesForTCVStop(origin Origin, trust Trust, lc Lifecycle) bool`, `(*Registry).recordCoverageIfExecutable(ctx, q tcv.Querier, versionID string, origin Origin, trust Trust, lc Lifecycle) error` — consumed by Tasks 7, 8, 10.

- [ ] **Step 1: Write the failing test**

This task's tests reuse the existing test suite's own helpers rather than inventing new ones: `mustAnalyze(t, string(artifact))` (`store_test.go`), `testutil.NewTestSigner(t)` / `signer.Verifier()` / `signer.Sign(art)` for a verifier with signing enabled, `testutil.DevVerifier()` for a dev-build verifier, and the `[]byte("id: "+id+"\nname: G\nlocal_check: true\n")` minimal-artifact shape used throughout `gate_test.go`/`lifecycle_test.go`. `seedThreatForTCVTest` is new (below) since no existing `contentregistry` test seeds a `threats` row.

```go
// internal/contentregistry/tcv_test.go
package contentregistry

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

// seedThreatForTCVTest mirrors internal/evidence's seedThreat -- this
// package has no existing helper that inserts a threats row.
func seedThreatForTCVTest(t *testing.T, pool *pgxpool.Pool, name string) string {
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

func TestQualifiesForTCVStop_ExcludesDevOnlyCombination(t *testing.T) {
	cases := []struct {
		name   string
		origin Origin
		trust  Trust
		lc     Lifecycle
		want   bool
	}{
		{"vendor signed published", OriginVendor, TrustVendorSigned, LifecyclePublished, true},
		{"local trusted published-local", OriginLocal, TrustLocalTrusted, LifecyclePublishedLocal, true},
		{"vendor untrusted published (dev-only combo)", OriginVendor, TrustUntrusted, LifecyclePublished, false},
		{"draft never qualifies", OriginVendor, TrustVendorSigned, LifecycleDraft, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := qualifiesForTCVStop(tc.origin, tc.trust, tc.lc); got != tc.want {
				t.Errorf("qualifiesForTCVStop(%s,%s,%s) = %v, want %v", tc.origin, tc.trust, tc.lc, got, tc.want)
			}
		})
	}
}

func TestTransition_RecordsCoverageFirstWhenLinkedVersionBecomesExecutable(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		reg := New(pool, testutil.DevVerifier())
		threatID := seedThreatForTCVTest(t, pool, "APT-transition-coverage")

		art := []byte("id: cv-transition-coverage\nname: G\nlocal_check: true\n")
		vid, _, err := reg.createVersion(ctx, newVersion{
			contentID: "cv-transition-coverage", artifact: art,
			analysis: mustAnalyze(t, string(art)),
			actor: ActorMigration, source: SourceCustom, origin: OriginLocal,
			trust: TrustUntrusted, lifecycle: LifecycleDraft, exclusiveLocalSource: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO content_version_threats
			(content_version_id, threat_id, relationship_kind, provenance_type, provenance_ref)
			VALUES ($1, $2, 'emulates', 'admin', 'test-setup')`, vid, threatID); err != nil {
			t.Fatal(err)
		}

		if err := reg.Transition(ctx, vid, LifecyclePublishedLocal, "admin", "approved"); err != nil {
			t.Fatal(err)
		}

		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM threat_coverage_firsts WHERE threat_id = $1 AND relationship_kind = 'emulates'`,
			threatID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("threat_coverage_firsts rows = %d, want 1 (version became executable via Transition)", count)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/contentregistry/... -run 'TestQualifiesForTCVStop|TestTransition_RecordsCoverageFirst' -v`
Expected: FAIL — `undefined: qualifiesForTCVStop`.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/contentregistry/tcv.go
package contentregistry

import (
	"context"
	"time"

	"github.com/audspect/bas/internal/tcv"
)

// qualifiesForTCVStop reports whether this origin/trust/lifecycle
// combination should stop a TCV clock (spec §10.3-§10.4). This is a
// strict SUBSET of Executable(): passing devBuild=false always excludes
// the dev-only combination (an unsigned VENDOR scenario accepted only
// because signing is disabled locally), which lets a scenario run in dev
// but must never count toward a customer-facing coverage metric
// (acceptance test 32). The two real executable combinations do not
// depend on devBuild, so this cannot exclude them.
func qualifiesForTCVStop(origin Origin, trust Trust, lc Lifecycle) bool {
	return Executable(origin, trust, lc, false)
}

// recordCoverageIfExecutable checks whether versionID, in its CURRENT
// origin/trust/lifecycle state, qualifies as executable coverage and, for
// every threat this version is linked to via content_version_threats,
// records a write-once coverage-first stop (spec §10.3). Idempotent
// (threat_coverage_firsts is write-once) -- safe to call after every state
// change a version goes through, not only the one that actually flips it
// to executable. q is the caller's own transaction when one is open, so
// the coverage write is atomic with the state change that caused it.
func (r *Registry) recordCoverageIfExecutable(ctx context.Context, q tcv.Querier, versionID string, origin Origin, trust Trust, lc Lifecycle) error {
	if !qualifiesForTCVStop(origin, trust, lc) {
		return nil
	}
	rows, err := q.Query(ctx, `SELECT threat_id, relationship_kind FROM content_version_threats WHERE content_version_id = $1`, versionID)
	if err != nil {
		return err
	}
	type link struct{ threatID, kind string }
	var links []link
	for rows.Next() {
		var l link
		if err := rows.Scan(&l.threatID, &l.kind); err != nil {
			rows.Close()
			return err
		}
		links = append(links, l)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	now := time.Now()
	for _, l := range links {
		if err := tcv.RecordCoverageFirst(ctx, q, l.threatID, tcv.RelationshipKind(l.kind), versionID, now); err != nil {
			return err
		}
	}
	return nil
}
```

Modify `internal/contentregistry/intake.go`'s `Transition` — insert the call right before the commit:

```go
	if _, err := tx.Exec(ctx,
		`INSERT INTO content_version_events (content_version_id, from_lifecycle, to_lifecycle, from_trust, to_trust, actor, reason)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		versionID, lc, string(to), trust, string(newTrust), actor, reason); err != nil {
		return err
	}
	if err := r.recordCoverageIfExecutable(ctx, tx, versionID, Origin(origin), newTrust, to); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/contentregistry/... -run 'TestQualifiesForTCVStop|TestTransition_RecordsCoverageFirst' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/contentregistry/tcv.go internal/contentregistry/tcv_test.go internal/contentregistry/intake.go
git commit -m "feat(tcf2c): qualifiesForTCVStop + recordCoverageIfExecutable, wired into Transition (spec §10.3-§10.4)"
```

---

### Task 7: Wire `recordCoverageIfExecutable` into `AttachVendorSignature`

**Files:**
- Modify: `internal/contentregistry/gate.go:119-129`
- Test: `internal/contentregistry/tcv_test.go` (add to the file from Task 6)

**Interfaces:**
- Consumes: `(*Registry).recordCoverageIfExecutable` (Task 6).

- [ ] **Step 1: Write the failing test**

```go
// append to internal/contentregistry/tcv_test.go
func TestAttachVendorSignature_RecordsCoverageFirstOnTrustFlipAlone(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		signer := testutil.NewTestSigner(t)
		reg := New(pool, signer.Verifier())
		threatID := seedThreatForTCVTest(t, pool, "APT-signature-coverage")

		// VENDOR + PUBLISHED but NOT yet signed -- not executable yet (the
		// runtime gate requires VENDOR_SIGNED). Lifecycle never changes in
		// this test; only trust flips, via AttachVendorSignature alone.
		art := []byte("id: cv-signature-coverage\nname: G\nlocal_check: true\n")
		vid, _, err := reg.createVersion(ctx, newVersion{
			contentID: "cv-signature-coverage", artifact: art,
			analysis: mustAnalyze(t, string(art)),
			actor: ActorIntake, source: SourceBuiltin, origin: OriginVendor,
			trust: TrustUntrusted, lifecycle: LifecyclePublished,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO content_version_threats
			(content_version_id, threat_id, relationship_kind, provenance_type, provenance_ref)
			VALUES ($1, $2, 'emulates', 'vendor_signed_metadata', 'G0016')`, vid, threatID); err != nil {
			t.Fatal(err)
		}

		sig := signer.Sign(art)
		if err := reg.AttachVendorSignature(ctx, vid, sig, "admin"); err != nil {
			t.Fatal(err)
		}

		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM threat_coverage_firsts WHERE threat_id = $1 AND relationship_kind = 'emulates'`,
			threatID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("threat_coverage_firsts rows = %d, want 1 (lifecycle never changed; only AttachVendorSignature's trust flip made this executable)", count)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/contentregistry/... -run TestAttachVendorSignature_RecordsCoverageFirstOnTrustFlipAlone -v`
Expected: FAIL — `threat_coverage_firsts` has 0 rows (the finding this task fixes: `AttachVendorSignature` never called the coverage check).

- [ ] **Step 3: Write minimal implementation**

Modify `internal/contentregistry/gate.go`'s `AttachVendorSignature` — insert the call right before the commit:

```go
	if _, err := tx.Exec(ctx,
		`INSERT INTO content_version_events (content_version_id, from_lifecycle, to_lifecycle, from_trust, to_trust, actor, reason)
		 VALUES ($1, $2, $2, $3, 'VENDOR_SIGNED', $4, 'vendor signature attached')`,
		versionID, lc, trust, actor); err != nil {
		return err
	}
	if err := r.recordCoverageIfExecutable(ctx, tx, versionID, OriginVendor, TrustVendorSigned, Lifecycle(lc)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/contentregistry/... -v`
Expected: PASS, all tests in the package (no regressions in Phase 1's existing gate/transition suite).

- [ ] **Step 5: Commit**

```bash
git add internal/contentregistry/gate.go internal/contentregistry/tcv_test.go
git commit -m "feat(tcf2c): wire recordCoverageIfExecutable into AttachVendorSignature (spec §10.3 Review Focus)"
```

---

### Task 8: Wire `recordCoverageIfExecutable` into `createVersion`

**Files:**
- Modify: `internal/contentregistry/store.go:260-294`
- Test: `internal/contentregistry/tcv_test.go` (add to the file from Task 6)

**Interfaces:**
- Consumes: `(*Registry).recordCoverageIfExecutable` (Task 6).

- [ ] **Step 1: Write the failing test**

```go
// append to internal/contentregistry/tcv_test.go
func TestCreateVersion_RecordsCoverageFirstWhenAlreadyExecutableAtCreation(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		signer := testutil.NewTestSigner(t)
		reg := New(pool, signer.Verifier())
		threatID := seedThreatForTCVTest(t, pool, "APT-createversion-coverage")

		// A signature-verified builtin is created already PUBLISHED +
		// VENDOR_SIGNED -- executable from the moment createVersion commits,
		// with no later Transition/AttachVendorSignature call at all.
		art := []byte("id: cv-createversion-coverage\nname: G\nlocal_check: true\n")
		vid, _, err := reg.createVersion(ctx, newVersion{
			contentID: "cv-createversion-coverage", artifact: art, signature: signer.Sign(art),
			analysis: mustAnalyze(t, string(art)),
			actor: ActorIntake, source: SourceBuiltin, origin: OriginVendor,
			trust: TrustVendorSigned, lifecycle: LifecyclePublished,
			emulatesLinks: []emulatesLink{{threatID: threatID, provenanceRef: "G0016"}},
		})
		if err != nil {
			t.Fatal(err)
		}

		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM threat_coverage_firsts WHERE threat_id = $1 AND relationship_kind = 'emulates'`,
			threatID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("threat_coverage_firsts rows = %d, want 1 (version %s was executable at the moment it was created)", count, vid)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/contentregistry/... -run TestCreateVersion_RecordsCoverageFirstWhenAlreadyExecutableAtCreation -v`
Expected: FAIL — compile error, `unknown field emulatesLinks in struct literal of type newVersion`.

- [ ] **Step 3: Write minimal implementation**

Modify `internal/contentregistry/store.go` — add the field to `newVersion` (next to `threatID`/`generationRef`):

```go
	threatID      string
	generationRef string
	// emulatesLinks are written as `emulates` content_version_threats rows
	// in this same transaction (spec §9.1-§9.2); resolved by the caller
	// (Intake, Task 9) before createVersion ever begins, since resolution
	// needs its own transaction via threatidentity.Store.
	emulatesLinks []emulatesLink
}

type emulatesLink struct {
	threatID      string
	provenanceRef string // the external_id (e.g. MITRE group "G0016") this threat was resolved from
}
```

Write the links and the coverage check, right after the existing `generated_for` block and right before the final return:

```go
	if nv.threatID != "" {
		if _, err := tx.Exec(ctx, `INSERT INTO content_version_threats
			   (content_version_id, threat_id, relationship_kind, provenance_type, provenance_ref)
			 VALUES ($1, $2, 'generated_for', 'generator', $3)`, vid, nv.threatID, nv.generationRef); err != nil {
			return "", false, err
		}
	}
	for _, el := range nv.emulatesLinks {
		if _, err := tx.Exec(ctx, `INSERT INTO content_version_threats
			   (content_version_id, threat_id, relationship_kind, provenance_type, provenance_ref)
			 VALUES ($1, $2, 'emulates', 'vendor_signed_metadata', $3)
			 ON CONFLICT (content_version_id, threat_id, relationship_kind) DO NOTHING`,
			vid, el.threatID, el.provenanceRef); err != nil {
			return "", false, err
		}
	}
```

...and, immediately before the function's final `return vid, true, tx.Commit(ctx)`:

```go
	if err := r.recordCoverageIfExecutable(ctx, tx, vid, nv.origin, nv.trust, nv.lifecycle); err != nil {
		return "", false, err
	}
	return vid, true, tx.Commit(ctx)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/contentregistry/... -v`
Expected: PASS, all tests in the package.

- [ ] **Step 5: Commit**

```bash
git add internal/contentregistry/store.go internal/contentregistry/tcv_test.go
git commit -m "feat(tcf2c): emulatesLinks on newVersion; wire recordCoverageIfExecutable into createVersion (spec §9.1, §10.3)"
```

---

### Task 9: Builtin `emulates` metadata — parsing and resolution at intake

**Files:**
- Modify: `internal/scenario/types.go` (add `Emulates`, `EmulatesRef`)
- Modify: `internal/threatidentity/decide.go` (add `QueueEmulatesCandidate`)
- Modify: `internal/contentregistry/intake.go` (add `resolveEmulatesMetadata`, call site)
- Test: `internal/contentregistry/intake_emulates_test.go`
- Test: `internal/threatidentity/decide_test.go` (add a case)

**Interfaces:**
- Consumes: `attackdata.GroupByID` (existing, `internal/reporting/attackdata`), `threatidentity.Store.ResolveAndPersist`/`Incoming` (existing), `emulatesLink` (Task 8).
- Produces: `scenario.EmulatesRef`, `Scenario.Emulates`, `(*threatidentity.Store).QueueEmulatesCandidate(ctx, contentVersionID, externalID, reason string) (string, error)` — consumed by Task 13.

- [ ] **Step 1: Write the failing test**

```go
// internal/threatidentity/decide_test.go -- add this test
func TestQueueEmulatesCandidate_CreatesAndDeduplicates(t *testing.T) {
	ctx := context.Background()
	s := NewStore(sharedDB.Pool)

	id1, err := s.QueueEmulatesCandidate(ctx, "cv-emulates-candidate", "G9998", "not found in catalog")
	if err != nil {
		t.Fatal(err)
	}
	if id1 == "" {
		t.Fatal("QueueEmulatesCandidate returned empty id")
	}
	// Same (external_id, ref_entity_id) while still unresolved -- no duplicate row.
	id2, err := s.QueueEmulatesCandidate(ctx, "cv-emulates-candidate", "G9998", "not found in catalog")
	if err != nil {
		t.Fatal(err)
	}
	if id2 != id1 {
		t.Fatalf("second call id = %q, want the same %q (dedup while unresolved)", id2, id1)
	}

	var count int
	if err := sharedDB.Pool.QueryRow(ctx, `SELECT count(*) FROM actor_resolution_candidates WHERE id = $1 AND kind = 'content_emulates_ref'`,
		id1).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("candidate row count = %d, want 1", count)
	}
}
```

`scenario.IntakeFile.SignatureVerified` is a caller-supplied fact (the actual cryptographic check happens outside `Registry`, before a file reaches `Intake` -- confirmed by reading `Intake`'s builtin branch: it never calls `r.verifier.Verify`, only `AttachVendorSignature` does). These tests can therefore use `testutil.DevVerifier()` and simply set `SignatureVerified: true` directly, with no real signature needed.

```go
// internal/contentregistry/intake_emulates_test.go
package contentregistry

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"gopkg.in/yaml.v3"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/testutil"
)

// builtinIntakeFileWithEmulates builds a minimal, signature-accepted
// builtin IntakeFile declaring the given emulates references.
func builtinIntakeFileWithEmulates(t *testing.T, contentID string, refs []scenario.EmulatesRef) scenario.IntakeFile {
	t.Helper()
	sc := scenario.Scenario{ID: contentID, Name: "G", LocalCheck: true, Emulates: refs}
	b, err := yaml.Marshal(sc)
	if err != nil {
		t.Fatal(err)
	}
	return scenario.IntakeFile{Path: contentID + ".yaml", Source: "builtin", Artifact: b,
		Signature: []byte("sig"), SignatureVerified: true}
}

// TestIntake_BuiltinEmulatesResolvesKnownGroupToThreat pins acceptance
// test 25: a signed builtin scenario declaring emulates: G0016 resolves
// to a real threat via the canonical actor registry, never free text.
func TestIntake_BuiltinEmulatesResolvesKnownGroupToThreat(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		reg := New(pool, testutil.DevVerifier())

		f := builtinIntakeFileWithEmulates(t, "cv-emulates-g0016", []scenario.EmulatesRef{
			{SubjectType: "actor", ExternalID: "G0016"},
		})
		decision, err := reg.Intake(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		if !decision.Accepted {
			t.Fatalf("intake refused: %s", decision.Reason)
		}

		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM content_version_threats cvt
			JOIN content_versions cv ON cv.id = cvt.content_version_id
			WHERE cv.content_id = $1 AND cvt.relationship_kind = 'emulates' AND cvt.provenance_type = 'vendor_signed_metadata'`,
			"cv-emulates-g0016").Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("emulates link rows = %d, want 1", count)
		}
	})
}

// TestIntake_BuiltinEmulatesUnknownGroupQueuesCandidateNoLink pins
// acceptance test 26: an external_id that isn't a real MITRE group
// produces no link and a queued resolution candidate, not an error.
func TestIntake_BuiltinEmulatesUnknownGroupQueuesCandidateNoLink(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		reg := New(pool, testutil.DevVerifier())

		f := builtinIntakeFileWithEmulates(t, "cv-emulates-unknown", []scenario.EmulatesRef{
			{SubjectType: "actor", ExternalID: "G9999"},
		})
		decision, err := reg.Intake(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		if !decision.Accepted {
			t.Fatalf("intake must still succeed despite the unresolvable emulates reference: %s", decision.Reason)
		}

		var linkCount int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM content_version_threats cvt
			JOIN content_versions cv ON cv.id = cvt.content_version_id
			WHERE cv.content_id = $1 AND cvt.relationship_kind = 'emulates'`,
			"cv-emulates-unknown").Scan(&linkCount); err != nil {
			t.Fatal(err)
		}
		if linkCount != 0 {
			t.Fatalf("emulates link rows = %d, want 0 (G9999 is not a real MITRE group)", linkCount)
		}

		var candidateCount int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM actor_resolution_candidates
			WHERE kind = 'content_emulates_ref' AND external_id = 'G9999' AND status = 'unresolved'`).Scan(&candidateCount); err != nil {
			t.Fatal(err)
		}
		if candidateCount != 1 {
			t.Fatalf("queued candidate rows = %d, want 1", candidateCount)
		}
	})
}
```

If `intake_test.go` already has a builtin-artifact builder with a similar shape, check it first and extend it with an optional `emulates` parameter instead of keeping a second, near-duplicate one -- ledger that as a `Ruling:` if so.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/contentregistry/... -run 'TestIntake_BuiltinEmulates' -v` and `go test ./internal/threatidentity/... -run TestQueueEmulatesCandidate -v`
Expected: both FAIL — `scenario.EmulatesRef` and `(*Store).QueueEmulatesCandidate` undefined.

- [ ] **Step 3: Write minimal implementation**

Modify `internal/scenario/types.go` — add, right after `MITREPhases`:

```go
	MITREPhases        []string `yaml:"mitre_phases"                   json:"mitrePhases"`
	// Emulates declares which real-world threat actors/groups this
	// scenario emulates (spec §9.2). Signature-covered on builtin
	// scenarios; resolved at intake via the canonical actor registry
	// (external_id -> threat_id), never via free-text name matching.
	Emulates           []EmulatesRef `yaml:"emulates,omitempty"          json:"emulates,omitempty"`
	Steps              []Step   `yaml:"steps"                          json:"steps"`
```

...and, near the other small referenced types in the file:

```go
// EmulatesRef is one declared threat-actor emulation target (spec §9.2).
// SubjectType is "actor" today; ExternalID is a MITRE ATT&CK group id
// (e.g. "G0016"), resolved via attackdata.GroupByID.
type EmulatesRef struct {
	SubjectType string `yaml:"subject_type" json:"subjectType"`
	ExternalID  string `yaml:"external_id"  json:"externalId"`
}
```

Modify `internal/threatidentity/decide.go` — add:

```go
// QueueEmulatesCandidate records a builtin scenario's declared `emulates`
// reference that attackdata.GroupByID could not resolve to a known MITRE
// ATT&CK group (spec §9.2, acceptance test 26) -- an admin later resolves
// it through the same actor_resolution_candidates review flow as any
// other identity candidate. Deduplicates against an already-queued,
// still-unresolved candidate for the same (external_id, content version).
func (s *Store) QueueEmulatesCandidate(ctx context.Context, contentVersionID, externalID, reason string) (string, error) {
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO actor_resolution_candidates
		   (kind, source, external_id, raw_name, ref_entity_id, reason, resolver_context, resolver_context_hash)
		 VALUES ('content_emulates_ref', 'attackdata', $1, $1, $2, $3, '{}'::jsonb, '')
		 ON CONFLICT (kind, source, external_id, raw_name, ref_entity_id) WHERE status = 'unresolved' DO NOTHING`,
		externalID, contentVersionID, reason); err != nil {
		return "", err
	}
	var id string
	err := s.pool.QueryRow(ctx, `
		SELECT id FROM actor_resolution_candidates
		 WHERE kind = 'content_emulates_ref' AND source = 'attackdata' AND external_id = $1
		   AND raw_name = $1 AND ref_entity_id = $2 AND status = 'unresolved'`,
		externalID, contentVersionID).Scan(&id)
	return id, err
}
```

Modify `internal/contentregistry/intake.go` — add the resolution function and wire it into `Intake`'s `SourceBuiltin` branch:

```go
import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/reporting/attackdata"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/threatidentity"
)

// resolveEmulatesMetadata resolves a builtin scenario's declared
// `emulates` references (spec §9.2) against the canonical actor registry
// -- never free text. A resolved external_id becomes an `emulates` link
// written inside createVersion's own transaction (nv.emulatesLinks); an
// external_id that attackdata doesn't recognize at all queues a
// resolution candidate (acceptance test 26). An external_id that
// attackdata recognizes but whose name resolution is itself ambiguous
// against existing actors is handled by ResolveAndPersist's own existing
// candidate mechanism -- ThreatID comes back empty and this function
// skips it without creating a second, redundant candidate.
func (r *Registry) resolveEmulatesMetadata(ctx context.Context, contentID string, refs []scenario.EmulatesRef, nv *newVersion) error {
	if len(refs) == 0 {
		return nil
	}
	idStore := threatidentity.NewStore(r.pool)
	for _, ref := range refs {
		if ref.SubjectType != "actor" {
			continue
		}
		group := attackdata.GroupByID(ref.ExternalID)
		if group == nil {
			if _, err := idStore.QueueEmulatesCandidate(ctx, contentID, ref.ExternalID,
				fmt.Sprintf("builtin scenario %s declares emulates %s, not found in the ATT&CK group catalog", contentID, ref.ExternalID)); err != nil {
				return err
			}
			continue
		}
		resolved, err := idStore.ResolveAndPersist(ctx,
			threatidentity.Incoming{Name: group.Name, CanonicalGroupID: ref.ExternalID},
			threatidentity.ProfileFields{})
		if err != nil {
			return err
		}
		if resolved.ThreatID == "" {
			continue // ambiguous; ResolveAndPersist already queued its own candidate
		}
		nv.emulatesLinks = append(nv.emulatesLinks, emulatesLink{threatID: resolved.ThreatID, provenanceRef: ref.ExternalID})
	}
	return nil
}
```

In `Intake`, inside the `case SourceBuiltin:` branch, after the trust/signature switch:

```go
	case SourceBuiltin:
		nv.lifecycle = LifecyclePublished
		switch {
		case f.SignatureVerified && len(f.Signature) > 0:
			nv.trust, nv.signature = TrustVendorSigned, f.Signature
		case r.devBuild():
			nv.trust = TrustUntrusted
		default:
			return r.refuse(f, a.contentID, "builtin signature not verified"), nil
		}
		if err := r.resolveEmulatesMetadata(ctx, a.contentID, a.sc.Emulates, &nv); err != nil {
			return scenario.IntakeDecision{}, err
		}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/threatidentity/... ./internal/contentregistry/... ./internal/scenario/... -v`
Expected: PASS, all tests in all three packages (no regressions in existing builtin-intake tests).

- [ ] **Step 5: Commit**

```bash
git add internal/scenario/types.go internal/threatidentity/decide.go internal/threatidentity/decide_test.go internal/contentregistry/intake.go internal/contentregistry/intake_emulates_test.go
git commit -m "feat(tcf2c): builtin emulates metadata, resolved via canonical actor registry at intake (spec §9.2, acceptance tests 25-27)"
```

---

### Task 10: Admin custom-content `emulates` link API

**Files:**
- Create: `internal/contentregistry/content_threats.go`
- Modify: `internal/contentregistry/types.go` (add `ErrThreatNotFound`)
- Create: `internal/api/content_threats_handlers.go`
- Modify: `internal/auth/permissions.go` (new `CanLinkContentThreat`)
- Modify: `internal/auth/permissions_test.go`
- Modify: `internal/api/routes.go`
- Test: `internal/contentregistry/content_threats_test.go`
- Test: `internal/api/content_threats_handlers_test.go`

**Interfaces:**
- Consumes: `(*Registry).recordCoverageIfExecutable` (Task 6), `auth.RequirePermission`, `h.registry`, `actorFor`, `h.auditLog` (existing, `internal/api`).
- Produces: `(*Registry).LinkThreat(ctx, contentID string, version int, threatID, actor, reason string) error`, `POST /api/content/{contentId}/versions/{n}/threats`.

- [ ] **Step 1: Write the failing test**

```go
// internal/contentregistry/content_threats_test.go
package contentregistry

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

// TestLinkThreat_AlreadyExecutableRecordsCoverageFirstImmediately pins
// acceptance test 33: linking emulates on a version that is already
// executable must stop the clock at link time, not wait for a future
// transition.
func TestLinkThreat_AlreadyExecutableRecordsCoverageFirstImmediately(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		reg := New(pool, testutil.DevVerifier())
		threatID := seedThreatForTCVTest(t, pool, "APT-link-threat-executable")

		art := []byte("id: cv-link-threat-executable\nname: G\nlocal_check: true\n")
		vid, _, err := reg.createVersion(ctx, newVersion{
			contentID: "cv-link-threat-executable", artifact: art,
			analysis: mustAnalyze(t, string(art)),
			actor: ActorMigration, source: SourceCustom, origin: OriginLocal,
			trust: TrustLocalTrusted, lifecycle: LifecyclePublishedLocal, exclusiveLocalSource: true,
		})
		if err != nil {
			t.Fatal(err)
		}

		if err := reg.LinkThreat(ctx, "cv-link-threat-executable", 1, threatID, "admin", "confirmed emulation"); err != nil {
			t.Fatal(err)
		}

		var linkCount int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM content_version_threats WHERE content_version_id = $1 AND relationship_kind = 'emulates' AND provenance_type = 'admin'`,
			vid).Scan(&linkCount); err != nil {
			t.Fatal(err)
		}
		if linkCount != 1 {
			t.Fatalf("emulates link rows = %d, want 1", linkCount)
		}

		var coverageCount int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM threat_coverage_firsts WHERE threat_id = $1 AND relationship_kind = 'emulates'`,
			threatID).Scan(&coverageCount); err != nil {
			t.Fatal(err)
		}
		if coverageCount != 1 {
			t.Fatalf("threat_coverage_firsts rows = %d, want 1 (version was already executable when linked)", coverageCount)
		}
	})
}

func TestLinkThreat_UnknownThreatRefused(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		reg := New(pool, testutil.DevVerifier())
		art := []byte("id: cv-link-threat-unknown\nname: G\nlocal_check: true\n")
		_, _, err := reg.createVersion(ctx, newVersion{
			contentID: "cv-link-threat-unknown", artifact: art,
			analysis: mustAnalyze(t, string(art)),
			actor: ActorMigration, source: SourceCustom, origin: OriginLocal,
			trust: TrustUntrusted, lifecycle: LifecycleDraft, exclusiveLocalSource: true,
		})
		if err != nil {
			t.Fatal(err)
		}

		err = reg.LinkThreat(ctx, "cv-link-threat-unknown", 1, "thr-does-not-exist", "admin", "reason")
		if !errors.Is(err, ErrThreatNotFound) {
			t.Fatalf("err = %v, want ErrThreatNotFound", err)
		}
	})
}
```

The handler-level test below reuses `registryEngine`, `withRole`, and the grandfather-migration path (writing a file under `<dir>/custom/` then calling `e.Load()`, exactly as `content_gate_test.go`'s existing tests do) rather than calling the unexported `createVersion` from `package api`.

```go
// internal/api/content_threats_handlers_test.go
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/ws"
)

func contentThreatsRequest(method, contentID, version string, body any) *http.Request {
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, "/x", rd)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("contentId", contentID)
	rctx.URLParams.Add("n", version)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

// TestLinkContentThreat_AdminLinksAlreadyExecutableCustomVersion exercises
// the full HTTP path for acceptance test 33: a grandfathered custom
// scenario is executable immediately (LOCAL_TRUSTED + PUBLISHED_LOCAL),
// so linking it must record the TCV stop within the same request.
func TestLinkContentThreat_AdminLinksAlreadyExecutableCustomVersion(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		e, reg, dir := registryEngine(t, pool)
		_ = os.MkdirAll(filepath.Join(dir, "custom"), 0o755)
		_ = os.WriteFile(filepath.Join(dir, "custom", "link-test.yaml"), []byte("id: link-test\nname: G\nlocal_check: true\n"), 0o644)
		if err := e.Load(); err != nil {
			t.Fatal(err)
		}
		vs, err := reg.ListVersions(ctx, "link-test")
		if err != nil || len(vs) != 1 {
			t.Fatalf("ListVersions: %v %+v", err, vs)
		}

		var threatID string
		if err := pool.QueryRow(ctx, `INSERT INTO threat_actor_profiles (name, aliases) VALUES ('APT-link-handler', '{}') RETURNING id`).Scan(&threatID); err == nil {
			pool.QueryRow(ctx, `INSERT INTO threats (id, subject_type, subject_id, actor_id, title)
				VALUES ('thr-' || gen_random_uuid()::text, 'actor', $1, $1, 'APT-link-handler') RETURNING id`, threatID).Scan(&threatID)
		}

		h := New(pool, ws.NewHub(), e, "")
		req := withRole(contentThreatsRequest(http.MethodPost, "link-test", "1",
			map[string]string{"threatId": threatID, "reason": "confirmed emulation"}), "admin1", auth.RoleAdmin)
		rec := httptest.NewRecorder()
		h.LinkContentThreat(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
		}

		var coverageCount int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM threat_coverage_firsts WHERE threat_id = $1 AND relationship_kind = 'emulates'`,
			threatID).Scan(&coverageCount); err != nil {
			t.Fatal(err)
		}
		if coverageCount != 1 {
			t.Fatalf("threat_coverage_firsts rows = %d, want 1", coverageCount)
		}
	})
}

func TestLinkContentThreat_UnknownVersionIs404(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, _, _ := registryEngine(t, pool)
		h := New(pool, ws.NewHub(), e, "")
		req := withRole(contentThreatsRequest(http.MethodPost, "no-such-content", "1",
			map[string]string{"threatId": "thr-x", "reason": "x"}), "admin1", auth.RoleAdmin)
		rec := httptest.NewRecorder()
		h.LinkContentThreat(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("code=%d, want 404", rec.Code)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/contentregistry/... -run TestLinkThreat -v`
Expected: FAIL — `(*Registry).LinkThreat` undefined.

- [ ] **Step 3: Write minimal implementation**

Modify `internal/contentregistry/types.go` — add next to the other sentinel errors:

```go
ErrThreatNotFound = errors.New("threat not found")
```

```go
// internal/contentregistry/content_threats.go
package contentregistry

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// LinkThreat creates an admin-asserted `emulates` link between a custom
// content version and a canonical threat (spec §9.3, acceptance test 33).
// threatID must already exist -- no fuzzy or free-text actor-name
// inference is ever used. If the version is already executable, the
// coverage-first stop is recorded immediately in this same transaction,
// not deferred to a future lifecycle/trust transition.
func (r *Registry) LinkThreat(ctx context.Context, contentID string, version int, threatID, actor, reason string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var vid, origin, trust, lc string
	err = tx.QueryRow(ctx, `SELECT id, origin, trust_level, lifecycle FROM content_versions
		WHERE content_id = $1 AND version = $2 FOR UPDATE`, contentID, version).Scan(&vid, &origin, &trust, &lc)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrVersionNotFound
	}
	if err != nil {
		return err
	}

	var threatExists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM threats WHERE id = $1)`, threatID).Scan(&threatExists); err != nil {
		return err
	}
	if !threatExists {
		return ErrThreatNotFound
	}

	if _, err := tx.Exec(ctx, `INSERT INTO content_version_threats
		   (content_version_id, threat_id, relationship_kind, provenance_type, provenance_ref)
		 VALUES ($1, $2, 'emulates', 'admin', $3)
		 ON CONFLICT (content_version_id, threat_id, relationship_kind) DO NOTHING`,
		vid, threatID, actor); err != nil {
		return err
	}
	if err := r.recordCoverageIfExecutable(ctx, tx, vid, Origin(origin), Trust(trust), Lifecycle(lc)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO content_version_events (content_version_id, from_lifecycle, to_lifecycle, from_trust, to_trust, actor, reason)
		 VALUES ($1, $2, $2, $3, $3, $4, $5)`,
		vid, lc, trust, actor, reason); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
```

Modify `internal/auth/permissions.go` — add `CanLinkContentThreat Permission = "content:link-threat"` next to `CanManageSourceTrust`, grant it in `RoleAdmin` only, and append it to the admin permission-ordering slice (same spot `CanManageSourceTrust` was added in 2B).

Modify `internal/auth/permissions_test.go` — add the matching row in `TestHasPermission_FullMatrix`'s `tested` map and `TestPermissions_Ordering`'s `want` slice, immediately after `CanManageSourceTrust` in both (same lesson as this branch's earlier regression: both tests must be updated together).

```go
// internal/api/content_threats_handlers.go
package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/contentregistry"
)

// LinkContentThreat -- POST /api/content/{contentId}/versions/{n}/threats
// {threatId, reason}. Admin-only, audited (spec §9.3).
func (h *Handler) LinkContentThreat(w http.ResponseWriter, r *http.Request) {
	reg, ok := h.registry(w)
	if !ok {
		return
	}
	version, err := strconv.Atoi(chi.URLParam(r, "n"))
	if err != nil {
		jsonError(w, "version must be an integer", http.StatusBadRequest)
		return
	}
	var req struct {
		ThreatID string `json:"threatId"`
		Reason   string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil || req.ThreatID == "" || req.Reason == "" {
		jsonError(w, "body must be {threatId, reason}", http.StatusBadRequest)
		return
	}
	contentID := chi.URLParam(r, "contentId")
	err = reg.LinkThreat(r.Context(), contentID, version, req.ThreatID, actorFor(r), req.Reason)
	switch {
	case err == contentregistry.ErrVersionNotFound:
		jsonError(w, "content version not found", http.StatusNotFound)
		return
	case err == contentregistry.ErrThreatNotFound:
		jsonError(w, "threat not found", http.StatusNotFound)
		return
	case err != nil:
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "content_registry.link_threat", contentID, map[string]any{
		"version": version, "threatId": req.ThreatID, "reason": req.Reason}, "ok")
	respond(w, map[string]any{"contentId": contentID, "version": version, "threatId": req.ThreatID})
}
```

Modify `internal/api/routes.go` — register next to the other admin content-registry routes:

```go
r.With(auth.RequirePermission(auth.CanLinkContentThreat)).Post("/api/content/{contentId}/versions/{n}/threats", h.LinkContentThreat)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/contentregistry/... ./internal/auth/... ./internal/api/... -v`
Expected: PASS, all tests in all three packages.

- [ ] **Step 5: Commit**

```bash
git add internal/contentregistry/content_threats.go internal/contentregistry/content_threats_test.go internal/contentregistry/types.go internal/auth/permissions.go internal/auth/permissions_test.go internal/api/content_threats_handlers.go internal/api/content_threats_handlers_test.go internal/api/routes.go
git commit -m "feat(tcf2c): admin custom-content emulates link API, immediate coverage-first on an already-executable version (spec §9.3, acceptance test 33)"
```

---

### Task 11: Scheduler wiring — clock-start recording

**Files:**
- Modify: `internal/connector/scheduler.go` (`pendingClaim`, `recordSourceSync`, `resolvePendingClaims`)
- Test: `internal/connector/scheduler_evidence_test.go` (add to the file from 2B)

**Interfaces:**
- Consumes: `tcv.RecordThreatClockStart`, `tcv.RecordIntelligenceClockStart` (Task 3), `evidence.TrustState`, `evidence.TrustTrusted` (2B), `evidence.Store.SyncCompletedAt` (new, see below).
- Produces: nothing new consumed by a later task in this plan; closes the loop so 2B's claim-resolution path also starts TCV clocks.

**A small 2B addition this task needs first:** `internal/evidence/sync.go` gains `(*Store) SyncCompletedAt(ctx, syncID string) (time.Time, error)` -- a single-row read of `source_syncs.completed_at`, letting the scheduler look up a sync's completion time without threading a new return value through 2B's already-shipped `RecordSync` signature.

- [ ] **Step 1: Write the failing test**

```go
// append to internal/connector/scheduler_evidence_test.go

// TestScheduler_Sync_StartsThreatAndIntelligenceClocksOnTrustedClaim closes
// spec §10.2: resolving a trusted claim through the live scheduler path
// must start both the threat clock (at the claim's observed_at) and the
// intelligence clock (at the sync's completed_at).
func TestScheduler_Sync_StartsThreatAndIntelligenceClocksOnTrustedClaim(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		observedAt := time.Now().Add(-6 * time.Hour)
		src := &stubEvidenceSource{
			name: "misp",
			actors: []ThreatActor{
				{Name: "APT-clock-sched", Source: "misp", SourceID: "evt-1",
					Techniques: []TechniqueRef{{ID: "T1059"}, {ID: "T1055"}}},
			},
			claims: []evidence.RawClaim{
				{ActorName: "APT-clock-sched", TechniqueID: "T1059", ExternalID: "evt-1", ObservedAt: observedAt, RawConfidence: "high"},
			},
		}
		s := &Scheduler{pool: pool, sources: []Source{src}, generator: NewGenerator(t.TempDir(), nil, nil, nil), engine: scenarioEngineForTest(t)}
		s.WithIdentityStore(threatidentity.NewStore(pool))
		s.WithEvidenceStore(evidence.NewStore(pool))

		s.sync()

		var threatID string
		if err := pool.QueryRow(ctx, `SELECT t.id FROM threats t JOIN threat_actor_profiles p ON p.id = t.actor_id
			WHERE p.name = 'APT-clock-sched'`).Scan(&threatID); err != nil {
			t.Fatalf("resolved threat not found: %v", err)
		}

		var threatClockCount, intelClockCount int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM threat_clock_starts WHERE threat_id = $1 AND clock = 'threat'`, threatID).Scan(&threatClockCount); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM threat_clock_starts WHERE threat_id = $1 AND clock = 'intelligence'`, threatID).Scan(&intelClockCount); err != nil {
			t.Fatal(err)
		}
		if threatClockCount != 1 || intelClockCount != 1 {
			t.Fatalf("threat clock rows = %d, intelligence clock rows = %d, want 1 each", threatClockCount, intelClockCount)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/connector/... -run TestScheduler_Sync_StartsThreatAndIntelligenceClocksOnTrustedClaim -v`
Expected: FAIL — `threat_clock_starts` has 0 rows (nothing calls `tcv.RecordThreatClockStart`/`RecordIntelligenceClockStart` yet).

- [ ] **Step 3: Write minimal implementation**

Modify `internal/evidence/sync.go` — add:

```go
// SyncCompletedAt returns one sync's completed_at, recorded by RecordSync.
// Lets a caller that only has a syncID (the connector scheduler) start the
// intelligence clock without RecordSync threading a new return value
// through every 2B call site.
func (s *Store) SyncCompletedAt(ctx context.Context, syncID string) (time.Time, error) {
	var completedAt time.Time
	err := s.pool.QueryRow(ctx, `SELECT completed_at FROM source_syncs WHERE id = $1`, syncID).Scan(&completedAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("evidence: sync completed_at for %s: %w", syncID, err)
	}
	return completedAt, nil
}
```

Modify `internal/connector/scheduler.go` — add a `trustState` field to `pendingClaim` and populate it in `recordSourceSync` from `CurrentTrust`'s first return value (currently discarded):

```go
	_, trustVersionID, err := s.evidence.CurrentTrust(ctx, name)
```
becomes
```go
	trustState, trustVersionID, err := s.evidence.CurrentTrust(ctx, name)
```

and the `pendingClaim{...}` literal built from it gains `trustState: trustState,`.

Find `pendingClaim`'s struct definition and add the field next to `trustVersionID`:

```go
	trustVersionID int64
	trustState     evidence.TrustState
```

In `resolvePendingClaims`, inside the per-`pc` loop, right after `touched[threatID] = true` (the line that already marks the threat touched for the asserted-claim case):

```go
		touched[threatID] = true
		if currentByInstance[pc.instanceID] == nil {
			currentByInstance[pc.instanceID] = map[string]bool{}
		}
		currentByInstance[pc.instanceID][threatID+"|"+pc.techniqueID] = true
		if pc.trustState == evidence.TrustTrusted {
			if err := tcv.RecordThreatClockStart(ctx, s.pool, threatID, pc.observedAt, pc.syncID); err != nil {
				log.Printf("[connector/tcv] record threat clock start %s: %v", threatID, err)
			}
			if completedAt, err := s.evidence.SyncCompletedAt(ctx, pc.syncID); err != nil {
				log.Printf("[connector/tcv] sync completed_at %s: %v", pc.syncID, err)
			} else if err := tcv.RecordIntelligenceClockStart(ctx, s.pool, threatID, completedAt, pc.syncID); err != nil {
				log.Printf("[connector/tcv] record intelligence clock start %s: %v", threatID, err)
			}
		}
```

Add `"github.com/audspect/bas/internal/tcv"` to `scheduler.go`'s import block.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/connector/... ./internal/evidence/... -v`
Expected: PASS, all tests in both packages (no regressions in 2B's suite).

- [ ] **Step 5: Commit**

```bash
git add internal/evidence/sync.go internal/connector/scheduler.go internal/connector/scheduler_evidence_test.go
git commit -m "feat(tcf2c): scheduler starts threat and intelligence TCV clocks on a trusted claim (spec §10.2)"
```

---

### Task 12: Read-only TCV API

**Files:**
- Modify: `internal/api/content_threats_handlers.go`
- Modify: `internal/api/routes.go`
- Test: `internal/api/content_threats_handlers_test.go` (add to the file from Task 10)

**Interfaces:**
- Consumes: `tcv.Store.Metrics` (Task 5).
- Produces: `GET /api/intel/threats/{id}/tcv`.

- [ ] **Step 1: Write the failing test**

```go
// append to internal/api/content_threats_handlers_test.go
func TestGetThreatTCV_NoClocksStartedReturnsNoClockForAllFour(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		var threatID string
		if err := pool.QueryRow(ctx, `INSERT INTO threat_actor_profiles (name, aliases) VALUES ('APT-tcv-handler', '{}') RETURNING id`).Scan(&threatID); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `INSERT INTO threats (id, subject_type, subject_id, actor_id, title)
			VALUES ('thr-' || gen_random_uuid()::text, 'actor', $1, $1, 'APT-tcv-handler') RETURNING id`, threatID).Scan(&threatID); err != nil {
			t.Fatal(err)
		}

		h := New(pool, ws.NewHub(), nil, "")
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", threatID)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		rec := httptest.NewRecorder()
		h.GetThreatTCV(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
		}
		var m tcv.ThreatTCV
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		for name, metric := range map[string]tcv.Metric{
			"threatToEmulation": m.ThreatToEmulation, "threatToGeneration": m.ThreatToGeneration,
			"intelligenceToEmulation": m.IntelligenceToEmulation, "intelligenceToGeneration": m.IntelligenceToGeneration,
		} {
			if metric.State != tcv.StateNoClock {
				t.Errorf("%s.State = %q, want no_clock", name, metric.State)
			}
		}
	})
}
```

Add `"github.com/audspect/bas/internal/tcv"` to this test file's import block.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/api/... -run TestGetThreatTCV_NoClocksStartedReturnsNoClockForAllFour -v`
Expected: FAIL — `h.GetThreatTCV` undefined (the route handler referenced by this task's Step 3 code doesn't exist until written).

- [ ] **Step 3: Write minimal implementation**

Modify `internal/api/content_threats_handlers.go` — add:

```go
// GetThreatTCV -- GET /api/intel/threats/{id}/tcv. Read-only reporting,
// same access level as the sibling threat-intel summary endpoints (spec
// §10.4).
func (h *Handler) GetThreatTCV(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		jsonError(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	m, err := tcv.NewStore(h.db).Metrics(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, m)
}
```

Add `"github.com/audspect/bas/internal/tcv"` to this file's import block.

Modify `internal/api/routes.go` — register next to `GetThreatIntelSummary`, with no fine-grained permission (matching that sibling reporting endpoint's own access level):

```go
r.Get("/api/intel/threats/{id}/tcv", h.GetThreatTCV)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go build ./... && go test ./internal/api/... -v`
Expected: build succeeds; PASS for the new test; no regressions.

- [ ] **Step 5: Commit**

```bash
git add internal/api/content_threats_handlers.go internal/api/content_threats_handlers_test.go internal/api/routes.go
git commit -m "feat(tcf2c): read-only GET /api/intel/threats/{id}/tcv (spec §10.4)"
```

---

### Task 13: Integration tests closing the remaining acceptance-test gaps

**Acceptance-test coverage map** (spec §13, items 25-33): 25/26/27 (Task 9), 29/30 (Task 5), 33 (Task 10) are each already pinned by an earlier task's test. **28** (a DRAFT version never stops a clock; the first executable one does; a later revocation doesn't move it), **31** (retraction then reappearance of a technique never restarts a clock), and **32** (the dev-only executable combination never writes a stop) are cross-cutting, full-stack sequences that need their own end-to-end tests here.

**Files:**
- Test: `internal/contentregistry/tcv_integration_test.go`

**Interfaces:**
- Consumes: `Registry` (full public API), `tcv.Store.Metrics` (Task 5), `evidence.Store` (2B, for the retraction/reappearance sequence in acceptance test 31 — this test spans `internal/evidence` and `internal/contentregistry`, so it imports both).

- [ ] **Step 1: Write the failing test**

```go
// internal/contentregistry/tcv_integration_test.go
package contentregistry

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

// TestIntegration_DraftNeverStopsClockFirstExecutableDoesLaterRevocationDoesNot
// pins acceptance test 28.
func TestIntegration_DraftNeverStopsClockFirstExecutableDoesLaterRevocationDoesNot(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		reg := New(pool, testutil.DevVerifier())
		threatID := seedThreatForTCVTest(t, pool, "APT-acceptance-28")

		art := []byte("id: cv-acceptance-28\nname: G\nlocal_check: true\n")
		vid, _, err := reg.createVersion(ctx, newVersion{
			contentID: "cv-acceptance-28", artifact: art,
			analysis: mustAnalyze(t, string(art)),
			actor: ActorMigration, source: SourceCustom, origin: OriginLocal,
			trust: TrustUntrusted, lifecycle: LifecycleDraft, exclusiveLocalSource: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := reg.LinkThreat(ctx, "cv-acceptance-28", 1, threatID, "admin", "setup"); err != nil {
			t.Fatal(err)
		}

		assertCoverageCount(t, pool, threatID, 0) // still DRAFT -- no stop yet

		if err := reg.Transition(ctx, vid, LifecyclePublishedLocal, "admin", "approved"); err != nil {
			t.Fatal(err)
		}
		assertCoverageCount(t, pool, threatID, 1) // now executable -- stop recorded

		var firstAt time.Time
		if err := pool.QueryRow(ctx, `SELECT first_executable_at FROM threat_coverage_firsts WHERE threat_id = $1 AND relationship_kind = 'emulates'`,
			threatID).Scan(&firstAt); err != nil {
			t.Fatal(err)
		}

		// Retire it -- revocation must not move the already-written stop.
		if err := reg.Transition(ctx, vid, LifecycleRetired, "admin", "retired"); err != nil {
			t.Fatal(err)
		}
		var firstAtAfterRetire time.Time
		if err := pool.QueryRow(ctx, `SELECT first_executable_at FROM threat_coverage_firsts WHERE threat_id = $1 AND relationship_kind = 'emulates'`,
			threatID).Scan(&firstAtAfterRetire); err != nil {
			t.Fatal(err)
		}
		if !firstAtAfterRetire.Equal(firstAt) {
			t.Fatalf("first_executable_at moved from %v to %v after retirement", firstAt, firstAtAfterRetire)
		}
	})
}

// TestIntegration_DevOnlyExecutableNeverStopsClock pins acceptance test 32.
func TestIntegration_DevOnlyExecutableNeverStopsClock(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		reg := New(pool, testutil.DevVerifier()) // devBuild() == true
		threatID := seedThreatForTCVTest(t, pool, "APT-acceptance-32")

		art := []byte("id: cv-acceptance-32\nname: G\nlocal_check: true\n")
		_, _, err := reg.createVersion(ctx, newVersion{
			contentID: "cv-acceptance-32", artifact: art,
			analysis: mustAnalyze(t, string(art)),
			actor: ActorIntake, source: SourceBuiltin, origin: OriginVendor,
			trust: TrustUntrusted, lifecycle: LifecyclePublished, // the dev-only combo
			emulatesLinks: []emulatesLink{{threatID: threatID, provenanceRef: "G0016"}},
		})
		if err != nil {
			t.Fatal(err)
		}

		assertCoverageCount(t, pool, threatID, 0) // dev-only combo must never qualify
	})
}

func assertCoverageCount(t *testing.T, pool *pgxpool.Pool, threatID string, want int) {
	t.Helper()
	var got int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM threat_coverage_firsts WHERE threat_id = $1 AND relationship_kind = 'emulates'`, threatID).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("threat_coverage_firsts rows = %d, want %d", got, want)
	}
}
```

```go
// internal/evidence/tcv_integration_test.go
package evidence

import (
	"context"
	"testing"
	"time"

	"github.com/audspect/bas/internal/tcv"
)

// TestIntegration_ClockStartNotRestartedByRetractionThenReappearance pins
// acceptance test 31: a technique that is claimed, retracted, and then
// re-claimed must not restart its already-written clock.
func TestIntegration_ClockStartNotRestartedByRetractionThenReappearance(t *testing.T) {
	ctx := context.Background()
	store, syncID, instanceID, tvID, mkObs := claimsFixture(t, "misp-tcv-reappear", TrustTrusted, Complete)
	threatID := seedThreat(t, sharedDB.Pool, "APT-acceptance-31")
	firstSeen := time.Now().Add(-72 * time.Hour)

	if err := store.RecordClaims(ctx, []Claim{{
		ObservationID: mkObs(threatID, "reappear-1"), SyncID: syncID, InstanceID: instanceID, ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimAsserted, Source: "misp", TrustVersionID: tvID, ObservedAt: firstSeen, RecordHash: "reappear-1",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := tcv.RecordThreatClockStart(ctx, sharedDB.Pool, threatID, firstSeen, syncID); err != nil {
		t.Fatal(err)
	}

	if err := store.RecordClaims(ctx, []Claim{{
		ObservationID: mkObs(threatID, "reappear-2"), SyncID: syncID, InstanceID: instanceID, ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimRetracted, Source: "misp", TrustVersionID: tvID, ObservedAt: firstSeen.Add(24 * time.Hour), RecordHash: "reappear-2",
	}}); err != nil {
		t.Fatal(err)
	}
	reappeared := time.Now()
	if err := store.RecordClaims(ctx, []Claim{{
		ObservationID: mkObs(threatID, "reappear-3"), SyncID: syncID, InstanceID: instanceID, ThreatID: threatID,
		TechniqueID: "T1059", Kind: ClaimAsserted, Source: "misp", TrustVersionID: tvID, ObservedAt: reappeared, RecordHash: "reappear-3",
	}}); err != nil {
		t.Fatal(err)
	}
	// The scheduler's real wiring (Task 11) would call this again on
	// reappearance; simulate that here directly against the package.
	if err := tcv.RecordThreatClockStart(ctx, sharedDB.Pool, threatID, reappeared, syncID); err != nil {
		t.Fatal(err)
	}

	var startedAt time.Time
	if err := sharedDB.Pool.QueryRow(ctx, `SELECT started_at FROM threat_clock_starts WHERE threat_id = $1 AND clock = 'threat'`,
		threatID).Scan(&startedAt); err != nil {
		t.Fatal(err)
	}
	if diff := startedAt.Sub(firstSeen); diff < -time.Second || diff > time.Second {
		t.Fatalf("started_at = %v, want the ORIGINAL first observation %v (reappearance must not restart the clock)", startedAt, firstSeen)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/contentregistry/... -run TestIntegration -v` and `go test ./internal/evidence/... -run TestIntegration_ClockStartNotRestartedByRetractionThenReappearance -v`
Expected: at this point every function these tests call already exists (Tasks 1-12 are all committed), so a "fail" here is a genuine behavioral check, not a compile error — run it once before trusting it, per this plan's TDD discipline. If it fails, the fix belongs in whichever earlier task's file the failure actually points to; amend that file directly and note the fix here as a ruling.

- [ ] **Step 3: Write minimal implementation**

No new implementation code is expected for this task — if Step 2 passes immediately, skip to Step 4. If it fails, fix the pointed-to file and ledger the ruling.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/contentregistry/... ./internal/evidence/... ./internal/tcv/... ./internal/connector/... ./internal/auth/... ./internal/api/... ./internal/threatidentity/... ./internal/scenario/... ./internal/db/... -v` (every package this plan touched, module-end full gate for this plan)
Expected: PASS, every test in every package.

- [ ] **Step 5: Commit**

```bash
git add internal/contentregistry/tcv_integration_test.go internal/evidence/tcv_integration_test.go
git commit -m "test(tcf2c): integration tests for draft/executable/revocation sequencing, dev-only exclusion, and clock non-restart (spec §13 acceptance tests 28, 31, 32)"
```
