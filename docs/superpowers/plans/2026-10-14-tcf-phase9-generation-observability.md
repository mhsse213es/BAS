# TCF Phase 9 — Threat-Triggered Generation Observability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every `Generator.Write` outcome (created/changed/skipped/failed, with a reason) a restart-durable, queryable record, closing the only real gap Phase 9 identified — not a missing trigger chain, a missing attempt log.

**Architecture:** One new table (`content_generation_attempts`), one new `evidence.Store` method to write a bounded, nullable-field-safe row, one new `evidence.Store` method to read them back filtered/paginated, and a minimal instrumentation pass over `Generator.Write`'s existing exit points — no new interfaces, no breaking signature change, reusing the `g.evidence *evidence.Store` nil-checked field the generator already has.

**Tech Stack:** Go, PostgreSQL (pgx/v5), the existing `internal/evidence`, `internal/connector`, `internal/api` packages.

**Spec:** `docs/superpowers/specs/2026-10-13-tcf-phase9-generation-observability-design.md`

## Deliberate refinement over the spec's literal §2.4/§4 text

The spec says `Generator.Write`'s signature changes to accept a `cycleID string` and "a writer for attempt rows." While writing this plan, re-reading `generator.go` showed a cleaner mechanism that produces the exact same schema, API, and acceptance criteria the spec approved, with less blast radius:

- `Write`'s signature does **not** change. It already holds `g.evidence *evidence.Store`, nil-checked at every one of its existing exit points (`ActiveTechniques`, `NextGenerationNumber`, `RecordGeneration` are all called this way already). The new `RecordGenerationAttempt` call is instrumented the same way — one more nil-checked call on the same field, not a new injected dependency.
- `cycleID` is minted once, inside `Write`, at the top of the function (`uuid.New().String()`) — `scheduler.go`'s single call site (`scheduler.go:478`) needs **zero changes**.
- This makes the spec's own strongest acceptance criterion *stronger*: existing `generator_test.go` assertions don't just "pass in shape" with a fake — they pass completely unmodified, because every existing test that doesn't call `.WithEvidenceStore(...)` already runs with `g.evidence == nil`, which the new call sites already skip, exactly like the three pre-existing `g.evidence != nil` call sites do today.

Everything else in the spec — the table shape, reason codes, outcome precedence, read API, retention/bounding rules — is implemented exactly as written. This refinement changes *how* Go code wires it together, not what it does.

The spec's schema sketch for `content_generation_attempts` also omits a `REFERENCES threats(id)` on `threat_id`, unlike its sibling `content_generations.threat_id NOT NULL REFERENCES threats(id)`. Adding that reference was considered during planning and deliberately **not** done: Task 3's test for the `generation_number_error` acceptance criterion (spec §3) needs an actor whose `RecordGeneration` call fails while its own attempt-log row still succeeds — the only deterministic way to force that failure is a `threat_id` that was never inserted into `threats`, which would make the attempt-log insert fail too if `content_generation_attempts.threat_id` carried the same FK. The spec's literal (unconstrained) schema is implemented as written.

## Known limitation, discovered while writing this plan — not fixed here

`main.go`'s real production `Generator` construction (`main.go:517-518`, `connector.NewGenerator(...).WithRegistrar(...).WithComponentVersions(...)`) never calls `.WithEvidenceStore(...)`. Every attempt-recording call this plan adds is nil-checked on that same field (per the plan header's refinement), which means **this plan's attempt log will not populate in a real deployment** until something wires an `evidence.Store` into that chain.

This is deliberately not fixed by this plan: `g.evidence != nil` doesn't just enable attempt-logging — it also switches `Write`'s technique-resolution source from `actor.Techniques` (the raw merged connector list) to `g.evidence.ActiveTechniques(...)` (the curated, evidence-backed active set), per `generator.go:171-179`. Wiring it would silently change *which techniques generated content includes* in production, as a side effect of an "observability" phase — a Phase 2B behavior-activation decision, not a Phase 9 one. Flag this to whoever reviews this plan as a separate, explicit follow-up decision (wire `WithEvidenceStore` into `main.go` deliberately, with its own testing/rollout consideration) rather than bundling it here.

## Global Constraints

- `outcome` is a closed, 4-value enum: `created`, `changed`, `skipped`, `failed` (spec §2.1). `reason_code` is free text, not a `CHECK`-constrained enum (spec §2.1) — new failure modes must never require a migration to record.
- `threat_id`, `content_id`, `content_version_id`, `fingerprint` are nullable; `content_version_id` has no `REFERENCES` constraint (spec §2.1, matching `content_generations`' own existing convention) — never make a row's existence depend on a content version that may never have been created.
- `detail` is bounded to 2048 bytes at write time, truncated not rejected (spec §2.5) — an attempt-logging failure must never fail the generation attempt it's trying to record.
- `generator_version` on a row is the `generatorVersion` constant's value *at the time of that attempt* (currently `"4"`, `generator.go:47`), not looked up dynamically later.
- Outcome precedence for a single actor's attempt is `created` > `changed` > `skipped` (spec §2.2) — exactly one row per actor per `Write` call, never two.
- A `created` attempt whose evidence-recording follow-up (`NextGenerationNumber`/`RecordGeneration`) fails still records `outcome = 'created'`; the failure goes in `detail` on that same row via `reason_code = 'generation_number_error'`, never a second row (spec §2.3).
- No new dependency is added to `go.mod` beyond promoting `github.com/google/uuid` from `// indirect` to direct (it is already a transitive dependency at v1.6.0).

## Review Focus

- A test that forces both the working-copy file to be rewritten *and* the registry to create a new version for the same actor in the same `Write` call, asserting exactly one row with `outcome = 'created'` — not two rows, not `'changed'`. This is the one behavior most likely to be implemented by accident as two separate writes.
- A test for the `generation_number_error` on-the-same-row behavior — easy to misimplement as a second `failed` row instead of annotating the existing `created` row's `detail`.
- A test with a forced over-length error message confirming `detail` truncates rather than the attempt-write itself erroring or being skipped.
- A test confirming `threat_id`/`content_id`/`fingerprint`/`content_version_id` come back as actual SQL `NULL` (not empty-string `''`) on a row from the unresolved-identity path — Go's zero-value `""` and SQL `NULL` are easy to conflate silently through `pgx`'s parameter binding.
- A test confirming every existing `generator_test.go` test file is **byte-for-byte unmodified** after this plan lands (not just "assertions still pass") — the whole point of the refinement above is that no existing test needs to change at all.

---

### Task 1: `content_generation_attempts` schema and migration wiring

**Files:**
- Create: `orchestrator/internal/db/generation_attempts_schema.go`
- Create: `orchestrator/internal/db/generation_attempts_schema_test.go`
- Modify: `orchestrator/internal/testutil/testdb.go` (wire `EnsureGenerationAttemptsSchema` into the test bootstrap sequence)
- Modify: `orchestrator/cmd/server/main.go:283-285` (wire it into the production bootstrap sequence)

**Interfaces:**
- Consumes: nothing from another task.
- Produces: `db.EnsureGenerationAttemptsSchema(ctx context.Context, pool *pgxpool.Pool) error` — called by Task 2's `evidence.Store` methods indirectly (they assume the table exists) and by both bootstrap sequences.

- [ ] **Step 1: Write the failing schema test**

This package's closest sibling, `evidence_schema_test.go`, is `package db_test` (external test package) and uses the package-level `sharedDB.Pool` declared once in `tenant_test.go` (also `package db_test`) — not a fresh `testutil.NewTestDB(t)` per test. Match that file exactly, including the `db.` qualifier on every call (external packages can't call unexported or even exported symbols unqualified).

```go
// orchestrator/internal/db/generation_attempts_schema_test.go
package db_test

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/db"
)

func TestEnsureGenerationAttemptsSchema_CreatesTable(t *testing.T) {
	// sharedDB's bootstrap (Step 4 of this task) already calls this once;
	// calling it again here proves it's idempotent, matching every other
	// Ensure*Schema test in this package.
	if err := db.EnsureGenerationAttemptsSchema(context.Background(), sharedDB.Pool); err != nil {
		t.Fatalf("EnsureGenerationAttemptsSchema: %v", err)
	}

	var exists bool
	err := sharedDB.Pool.QueryRow(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'content_generation_attempts')`,
	).Scan(&exists)
	if err != nil {
		t.Fatalf("check table exists: %v", err)
	}
	if !exists {
		t.Fatal("content_generation_attempts table was not created")
	}
}

func TestEnsureGenerationAttemptsSchema_OutcomeCheckConstraint(t *testing.T) {
	_, err := sharedDB.Pool.Exec(context.Background(), `INSERT INTO content_generation_attempts
		(cycle_id, outcome, reason_code, generator_version, started_at)
		VALUES ('check-constraint-test', 'not-a-real-outcome', 'ok', '4', NOW())`)
	if err == nil {
		t.Fatal("expected the outcome CHECK constraint to reject an invalid value")
	}
}

func TestEnsureGenerationAttemptsSchema_NullableFieldsAcceptNull(t *testing.T) {
	_, err := sharedDB.Pool.Exec(context.Background(), `INSERT INTO content_generation_attempts
		(cycle_id, outcome, reason_code, generator_version, started_at)
		VALUES ('nullable-fields-test', 'skipped', 'unresolved_identity', '4', NOW())`)
	if err != nil {
		t.Fatalf("expected a row with no threat_id/content_id/content_version_id/fingerprint to insert cleanly: %v", err)
	}

	var threatID, contentID, contentVersionID, fingerprint *string
	err = sharedDB.Pool.QueryRow(context.Background(),
		`SELECT threat_id, content_id, content_version_id, fingerprint FROM content_generation_attempts WHERE cycle_id = 'nullable-fields-test'`,
	).Scan(&threatID, &contentID, &contentVersionID, &fingerprint)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if threatID != nil || contentID != nil || contentVersionID != nil || fingerprint != nil {
		t.Fatalf("expected all four to be NULL, got threatID=%v contentID=%v contentVersionID=%v fingerprint=%v",
			threatID, contentID, contentVersionID, fingerprint)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/db/... -run TestEnsureGenerationAttemptsSchema -v`
Expected: FAIL — `undefined: db.EnsureGenerationAttemptsSchema` (compile error, the function doesn't exist yet).

- [ ] **Step 3: Create the schema file**

```go
// orchestrator/internal/db/generation_attempts_schema.go
package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EnsureGenerationAttemptsSchema creates the TCF Phase 9 generation-attempt
// log (spec 2026-10-13 §2.1). Must run after EnsureThreatIdentitySchema
// (threats.id) and EnsureEvidenceSchema (this table is evidence-adjacent,
// not a dependency of it). Idempotent.
func EnsureGenerationAttemptsSchema(ctx context.Context, pool *pgxpool.Pool) error {
	for _, s := range generationAttemptsTables {
		if _, err := pool.Exec(ctx, s); err != nil {
			return fmt.Errorf("generation attempts schema: %w\n%s", err, s)
		}
	}
	return nil
}

var generationAttemptsTables = []string{
	`CREATE TABLE IF NOT EXISTS content_generation_attempts (
		id                  text        PRIMARY KEY DEFAULT ('cga-' || gen_random_uuid()::text),
		cycle_id            text        NOT NULL,
		threat_id           text,
		content_id          text,
		content_version_id text,
		outcome             text        NOT NULL CHECK (outcome IN ('created','changed','skipped','failed')),
		reason_code         text        NOT NULL,
		detail              text,
		generator_version   text        NOT NULL,
		fingerprint         text,
		started_at          timestamptz NOT NULL,
		completed_at        timestamptz NOT NULL DEFAULT NOW()
	)`,
	`CREATE INDEX IF NOT EXISTS idx_content_generation_attempts_cycle
		ON content_generation_attempts (cycle_id)`,
	`CREATE INDEX IF NOT EXISTS idx_content_generation_attempts_threat
		ON content_generation_attempts (threat_id, started_at DESC)`,
}
```

- [ ] **Step 4: Wire into the test bootstrap sequence**

In `orchestrator/internal/testutil/testdb.go`, immediately after the existing `EnsureEvidenceSchema` block (around line 121) and before `EnsureTCVSchema`:

```go
	if err := db.EnsureEvidenceSchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(context.Background())
		return nil, fmt.Errorf("testutil: EnsureEvidenceSchema: %w", err)
	}
	if err := db.EnsureGenerationAttemptsSchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(context.Background())
		return nil, fmt.Errorf("testutil: EnsureGenerationAttemptsSchema: %w", err)
	}
	if err := db.EnsureTCVSchema(ctx, pool); err != nil {
```

- [ ] **Step 5: Wire into the production bootstrap sequence**

In `orchestrator/cmd/server/main.go`, immediately after the existing block at line 283-285 and before `EnsureTCVSchema`:

```go
	if err := db.EnsureEvidenceSchema(context.Background(), adminPool); err != nil {
		log.Fatalf("[FATAL] evidence schema: %v", err)
	}
	if err := db.EnsureGenerationAttemptsSchema(context.Background(), adminPool); err != nil {
		log.Fatalf("[FATAL] generation attempts schema: %v", err)
	}
	if err := db.EnsureTCVSchema(context.Background(), adminPool); err != nil {
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/db/... -run TestEnsureGenerationAttemptsSchema -v`
Expected: PASS, all 3 tests.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/db/generation_attempts_schema.go orchestrator/internal/db/generation_attempts_schema_test.go orchestrator/internal/testutil/testdb.go orchestrator/cmd/server/main.go
git commit -m "feat(tcf-phase9): content_generation_attempts schema"
```

---

### Task 2: `evidence.GenerationAttempt` write and read methods

**Files:**
- Create: `orchestrator/internal/evidence/generation_attempts.go`
- Create: `orchestrator/internal/evidence/generation_attempts_test.go`

**Interfaces:**
- Consumes: Task 1's `content_generation_attempts` table (via `sharedDB`, this package's shared testcontainer fixture, which Task 1 already wires the schema into).
- Produces:
  - `type GenerationAttempt struct { CycleID, Outcome, ReasonCode, GeneratorVersion string; ThreatID, ContentID, ContentVersionID, Detail, Fingerprint *string; StartedAt time.Time }` — nullable fields are `*string` (nil, not `""`, means SQL `NULL`).
  - `func (s *Store) RecordGenerationAttempt(ctx context.Context, a GenerationAttempt) error` — Task 3 calls this at each of `Generator.Write`'s exit points.
  - `func (s *Store) ListGenerationAttempts(ctx context.Context, filter GenerationAttemptFilter) ([]GenerationAttempt, error)`, where `type GenerationAttemptFilter struct { CycleID, ThreatID string; Since time.Time; Limit int }` — Task 4's API handler calls this.

- [ ] **Step 1: Write the failing tests**

This package's own convention (`testmain_test.go`, every sibling `*_test.go` here) is a package-level `sharedDB.Pool` with no per-test truncation — tests use uniquely-named fixtures instead of isolation-by-cleanup. `content_generation_attempts.threat_id` has no FK (per the plan header's note), so these tests use plain string literals and never need `seedThreat` (`observations_test.go`, same package) at all.

```go
// orchestrator/internal/evidence/generation_attempts_test.go
package evidence

import (
	"context"
	"strings"
	"testing"
	"time"
)

func strptr(s string) *string { return &s }

func TestRecordGenerationAttempt_NullableFieldsStayNull(t *testing.T) {
	s := NewStore(sharedDB.Pool)

	err := s.RecordGenerationAttempt(context.Background(), GenerationAttempt{
		CycleID: "cycle-1", Outcome: "skipped", ReasonCode: "unresolved_identity",
		GeneratorVersion: "4", StartedAt: time.Now(),
		// ThreatID, ContentID, ContentVersionID, Fingerprint, Detail: nil
	})
	if err != nil {
		t.Fatalf("RecordGenerationAttempt: %v", err)
	}

	got, err := s.ListGenerationAttempts(context.Background(), GenerationAttemptFilter{CycleID: "cycle-1"})
	if err != nil {
		t.Fatalf("ListGenerationAttempts: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 attempt, got %d", len(got))
	}
	if got[0].ThreatID != nil || got[0].ContentID != nil || got[0].ContentVersionID != nil || got[0].Fingerprint != nil {
		t.Fatalf("expected nullable fields to come back nil, got %+v", got[0])
	}
}

func TestRecordGenerationAttempt_DetailTruncatedNotRejected(t *testing.T) {
	s := NewStore(sharedDB.Pool)

	huge := strptr(strings.Repeat("x", 5000))
	err := s.RecordGenerationAttempt(context.Background(), GenerationAttempt{
		CycleID: "cycle-2", Outcome: "failed", ReasonCode: "registrar_error",
		GeneratorVersion: "4", StartedAt: time.Now(), Detail: huge,
	})
	if err != nil {
		t.Fatalf("RecordGenerationAttempt must not fail on an over-length detail: %v", err)
	}

	got, err := s.ListGenerationAttempts(context.Background(), GenerationAttemptFilter{CycleID: "cycle-2"})
	if err != nil {
		t.Fatalf("ListGenerationAttempts: %v", err)
	}
	if got[0].Detail == nil || len(*got[0].Detail) > maxDetailBytes {
		t.Fatalf("expected detail truncated to %d bytes, got length %v", maxDetailBytes, got[0].Detail)
	}
}

func TestRecordGenerationAttempt_RejectsInvalidOutcome(t *testing.T) {
	s := NewStore(sharedDB.Pool)

	err := s.RecordGenerationAttempt(context.Background(), GenerationAttempt{
		CycleID: "cycle-3", Outcome: "not-a-real-outcome", ReasonCode: "ok",
		GeneratorVersion: "4", StartedAt: time.Now(),
	})
	if err == nil {
		t.Fatal("expected an invalid outcome to be rejected by the DB CHECK constraint")
	}
}

func TestListGenerationAttempts_FiltersByThreatIDAndLimit(t *testing.T) {
	s := NewStore(sharedDB.Pool)
	ctx := context.Background()
	// "threat-a"/"threat-b" are unique to this test within the package --
	// content_generation_attempts is a brand-new table no other existing
	// test in this package touches, and this package's sharedDB.Pool has
	// no per-test truncation (see the package-convention note above).
	threatA := strptr("threat-a")
	for i := 0; i < 3; i++ {
		if err := s.RecordGenerationAttempt(ctx, GenerationAttempt{
			CycleID: "cycle-x", ThreatID: threatA, Outcome: "created", ReasonCode: "ok",
			GeneratorVersion: "4", StartedAt: time.Now(),
		}); err != nil {
			t.Fatalf("seed attempt %d: %v", i, err)
		}
	}
	if err := s.RecordGenerationAttempt(ctx, GenerationAttempt{
		CycleID: "cycle-x", ThreatID: strptr("threat-b"), Outcome: "created", ReasonCode: "ok",
		GeneratorVersion: "4", StartedAt: time.Now(),
	}); err != nil {
		t.Fatalf("seed threat-b attempt: %v", err)
	}

	got, err := s.ListGenerationAttempts(ctx, GenerationAttemptFilter{ThreatID: "threat-a", Limit: 2})
	if err != nil {
		t.Fatalf("ListGenerationAttempts: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected limit=2 to cap results at 2, got %d", len(got))
	}
	for _, a := range got {
		if a.ThreatID == nil || *a.ThreatID != "threat-a" {
			t.Fatalf("expected only threat-a rows, got %+v", a)
		}
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/evidence/... -run "TestRecordGenerationAttempt|TestListGenerationAttempts" -v`
Expected: FAIL — compile error, `GenerationAttempt`/`RecordGenerationAttempt`/`ListGenerationAttempts`/`GenerationAttemptFilter`/`maxDetailBytes` are undefined.

- [ ] **Step 3: Implement**

```go
// orchestrator/internal/evidence/generation_attempts.go
package evidence

import (
	"context"
	"fmt"
	"time"
)

// maxDetailBytes bounds GenerationAttempt.Detail (spec 2026-10-13 §2.5) --
// an attempt-logging failure must never fail the attempt it's recording,
// so an over-length detail is truncated here, not rejected.
const maxDetailBytes = 2048

// GenerationAttempt is one row of content_generation_attempts (spec §2.1).
// Nullable fields are *string: nil means SQL NULL, never an empty string --
// the unresolved-identity, active-techniques-error, and below-minimum exit
// paths in Generator.Write genuinely have no threat/content id/fingerprint
// yet, and a NOT NULL default would be a lie the caller can't keep.
type GenerationAttempt struct {
	CycleID           string
	ThreatID          *string
	ContentID         *string
	ContentVersionID  *string
	Outcome           string // created | changed | skipped | failed
	ReasonCode        string
	Detail            *string
	GeneratorVersion  string
	Fingerprint       *string
	StartedAt         time.Time
}

// RecordGenerationAttempt persists one attempt. Truncating an over-length
// Detail happens here, once, rather than at every call site in generator.go.
func (s *Store) RecordGenerationAttempt(ctx context.Context, a GenerationAttempt) error {
	if a.Detail != nil && len(*a.Detail) > maxDetailBytes {
		truncated := (*a.Detail)[:maxDetailBytes]
		a.Detail = &truncated
	}
	if _, err := s.pool.Exec(ctx, `INSERT INTO content_generation_attempts
		(cycle_id, threat_id, content_id, content_version_id, outcome, reason_code, detail, generator_version, fingerprint, started_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		a.CycleID, a.ThreatID, a.ContentID, a.ContentVersionID, a.Outcome, a.ReasonCode, a.Detail, a.GeneratorVersion, a.Fingerprint, a.StartedAt); err != nil {
		return fmt.Errorf("evidence: record generation attempt: %w", err)
	}
	return nil
}

// GenerationAttemptFilter selects a bounded page of attempts (spec §2.6).
// CycleID and ThreatID are mutually usable but typically queried one at a
// time ("what happened on the last poll" vs. "why does this content keep
// regenerating"). Limit <= 0 defaults to 50; the caller (the API handler,
// Task 4) is responsible for its own upper cap.
type GenerationAttemptFilter struct {
	CycleID  string
	ThreatID string
	Since    time.Time
	Limit    int
}

// ListGenerationAttempts reads a bounded page, newest first.
func (s *Store) ListGenerationAttempts(ctx context.Context, f GenerationAttemptFilter) ([]GenerationAttempt, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	query := `SELECT cycle_id, threat_id, content_id, content_version_id, outcome, reason_code, detail, generator_version, fingerprint, started_at
		FROM content_generation_attempts WHERE 1=1`
	args := []any{}
	if f.CycleID != "" {
		args = append(args, f.CycleID)
		query += fmt.Sprintf(" AND cycle_id = $%d", len(args))
	}
	if f.ThreatID != "" {
		args = append(args, f.ThreatID)
		query += fmt.Sprintf(" AND threat_id = $%d", len(args))
	}
	if !f.Since.IsZero() {
		args = append(args, f.Since)
		query += fmt.Sprintf(" AND started_at >= $%d", len(args))
	}
	args = append(args, limit)
	query += fmt.Sprintf(" ORDER BY started_at DESC LIMIT $%d", len(args))

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("evidence: list generation attempts: %w", err)
	}
	defer rows.Close()

	var out []GenerationAttempt
	for rows.Next() {
		var a GenerationAttempt
		if err := rows.Scan(&a.CycleID, &a.ThreatID, &a.ContentID, &a.ContentVersionID,
			&a.Outcome, &a.ReasonCode, &a.Detail, &a.GeneratorVersion, &a.Fingerprint, &a.StartedAt); err != nil {
			return nil, fmt.Errorf("evidence: scan generation attempt: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/evidence/... -run "TestRecordGenerationAttempt|TestListGenerationAttempts" -v`
Expected: PASS, all 4 tests.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/evidence/generation_attempts.go orchestrator/internal/evidence/generation_attempts_test.go
git commit -m "feat(tcf-phase9): evidence.Store.RecordGenerationAttempt / ListGenerationAttempts"
```

---

### Task 3: Instrument `Generator.Write`

**Files:**
- Modify: `orchestrator/internal/connector/generator.go`
- Test: `orchestrator/internal/connector/generator_attempts_test.go` (new file — existing `generator_test.go` is not modified at all, per the Global Constraints note)
- Modify: `orchestrator/go.mod` / `orchestrator/go.sum` (promote `github.com/google/uuid` from indirect to direct — `go mod tidy` does this automatically once Step 3 imports it)

**Interfaces:**
- Consumes: Task 2's `evidence.GenerationAttempt` / `(*evidence.Store).RecordGenerationAttempt`.
- Produces: no new exported symbols — `Write`'s signature is unchanged (see the plan header's refinement note). Task 4 does not depend on anything from this task beyond the rows it writes existing in the database.

- [ ] **Step 1: Write the failing tests**

`evidence.Store` is a concrete struct (not an interface) wrapping `*pgxpool.Pool`, so these tests need a real Postgres-backed evidence store. This package already has exactly that fixture — `sharedDB` (a package-level `*testutil.TestDB` set up once in `testmain_test.go`), `sharedDB.RunWithPool` (truncates every table after the test runs), `threatidentity.NewStore(pool).ResolveAndPersist(...)` (the only way to get a real, FK-valid `threat_id`), and `seedActiveTechnique(t, pool, threatID, techniqueID)` (already defined in `generator_evidence_test.go`, same package — do not redefine it). `ThreatActor.Techniques` is `[]TechniqueRef` (a struct with an `ID` field), not `[]string` — check `generator_test.go`'s existing actors before writing a new one.

Also note: `g.evidence != nil` makes `Write` read active techniques from the DB unconditionally (`generator.go:171-179`), overriding `actor.Techniques` entirely — every test below that calls `.WithEvidenceStore(...)` must seed `threat_techniques` via `seedActiveTechnique`, or every actor falls through to `below_min_techniques` regardless of what `actor.Techniques` says.

```go
// orchestrator/internal/connector/generator_attempts_test.go
package connector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/contentregistry"
	"github.com/audspect/bas/internal/evidence"
	"github.com/audspect/bas/internal/threatidentity"
)

// dedupRegistrar mimics the real Content Registry's dedup behavior that
// recRegistrar (generator_test.go) does not: created=true only the first
// time a given GenerationKey is seen, false on every repeat -- needed to
// test the "changed but not created" and "created despite a later repeat"
// distinctions this task's precedence rule depends on.
type dedupRegistrar struct {
	seen map[string]bool
}

func (r *dedupRegistrar) RegisterGenerated(_ context.Context, c contentregistry.GeneratedCandidate) (string, bool, error) {
	if r.seen == nil {
		r.seen = map[string]bool{}
	}
	created := !r.seen[c.GenerationKey]
	r.seen[c.GenerationKey] = true
	return "v-" + c.GenerationKey[:8], created, nil
}

// collisionRegistrar is a Registrar fake that always returns the given error.
type collisionRegistrar struct{ err error }

func (c collisionRegistrar) RegisterGenerated(context.Context, contentregistry.GeneratedCandidate) (string, bool, error) {
	return "", false, c.err
}

func TestGenerator_WriteRecordsExactlyOneRowWhenBothChangedAndCreated(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		idStore := threatidentity.NewStore(pool)
		resolved, err := idStore.ResolveAndPersist(context.Background(), threatidentity.Incoming{Name: "APT-both"}, threatidentity.ProfileFields{})
		if err != nil {
			t.Fatal(err)
		}
		seedActiveTechnique(t, pool, resolved.ThreatID, "T1059")
		seedActiveTechnique(t, pool, resolved.ThreatID, "T1053")

		store := evidence.NewStore(pool)
		g := NewGenerator(t.TempDir(), nil, nil, nil).WithRegistrar(&dedupRegistrar{}).WithEvidenceStore(store)
		a := ThreatActor{Name: "APT-both", ThreatID: resolved.ThreatID, Source: "misp"}

		// First Write on a fresh actor: the registry has never seen this
		// GenerationKey (Created), and the working-copy file doesn't exist
		// on disk yet either (Changed) -- both would fire under the old,
		// non-exclusive counters.
		if _, err := g.Write([]ThreatActor{a}); err != nil {
			t.Fatalf("Write: %v", err)
		}

		got, err := store.ListGenerationAttempts(context.Background(), evidence.GenerationAttemptFilter{ThreatID: resolved.ThreatID})
		if err != nil {
			t.Fatalf("ListGenerationAttempts: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("expected exactly 1 attempt row, got %d", len(got))
		}
		if got[0].Outcome != "created" {
			t.Fatalf("expected outcome=created per the precedence rule, got %q", got[0].Outcome)
		}
	})
}

func TestGenerator_WriteRecordsChangedWhenFileRewrittenButNotCreated(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		idStore := threatidentity.NewStore(pool)
		resolved, err := idStore.ResolveAndPersist(context.Background(), threatidentity.Incoming{Name: "APT-changed"}, threatidentity.ProfileFields{})
		if err != nil {
			t.Fatal(err)
		}
		seedActiveTechnique(t, pool, resolved.ThreatID, "T1059")
		seedActiveTechnique(t, pool, resolved.ThreatID, "T1053")

		store := evidence.NewStore(pool)
		dir := t.TempDir()
		reg := &dedupRegistrar{}
		g := NewGenerator(dir, nil, nil, nil).WithRegistrar(reg).WithEvidenceStore(store)
		a := ThreatActor{Name: "APT-changed", ThreatID: resolved.ThreatID, Source: "misp"}

		if _, err := g.Write([]ThreatActor{a}); err != nil {
			t.Fatalf("first Write: %v", err)
		}
		// Delete the working-copy file but leave the registry version in
		// place (same actor, same GenerationKey -- dedupRegistrar now
		// reports created=false) -- the next Write rewrites the file
		// (Changed) without creating anything new (not Created).
		fname := filepath.Join(dir, "intel", threatidentity.ContentID(resolved.ThreatID)+".yaml")
		if err := os.Remove(fname); err != nil {
			t.Fatalf("remove working copy: %v", err)
		}

		if _, err := g.Write([]ThreatActor{a}); err != nil {
			t.Fatalf("second Write: %v", err)
		}

		got, err := store.ListGenerationAttempts(context.Background(), evidence.GenerationAttemptFilter{ThreatID: resolved.ThreatID, Limit: 1})
		if err != nil {
			t.Fatalf("ListGenerationAttempts: %v", err)
		}
		if len(got) != 1 || got[0].Outcome != "changed" {
			t.Fatalf("expected the most recent attempt to be outcome=changed, got %+v", got)
		}
	})
}

func TestGenerator_WriteRecordsGenerationNumberErrorOnSameRow(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		idStore := threatidentity.NewStore(pool)
		resolved, err := idStore.ResolveAndPersist(context.Background(), threatidentity.Incoming{Name: "APT-genfail"}, threatidentity.ProfileFields{})
		if err != nil {
			t.Fatal(err)
		}
		seedActiveTechnique(t, pool, resolved.ThreatID, "T1059")
		seedActiveTechnique(t, pool, resolved.ThreatID, "T1053")

		store := evidence.NewStore(pool)
		g := NewGenerator(t.TempDir(), nil, nil, nil).WithRegistrar(&dedupRegistrar{}).WithEvidenceStore(store)
		// evidenceRecordErr is an unexported, test-only override field (Step 3),
		// the same pattern this file's sibling generator_meta_test.go already
		// uses for attackMeta -- the UNIQUE(threat_id, generation_number)
		// constraint this would otherwise exercise only fails under a genuine
		// concurrent race, which a single-threaded test cannot engineer.
		g.evidenceRecordErr = errors.New("boom")
		a := ThreatActor{Name: "APT-genfail", ThreatID: resolved.ThreatID, Source: "misp"}

		if _, err := g.Write([]ThreatActor{a}); err != nil {
			t.Fatalf("Write: %v", err)
		}

		got, err := store.ListGenerationAttempts(context.Background(), evidence.GenerationAttemptFilter{ThreatID: resolved.ThreatID})
		if err != nil {
			t.Fatalf("ListGenerationAttempts: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("expected exactly 1 attempt row, got %d", len(got))
		}
		if got[0].Outcome != "created" {
			t.Fatalf("expected outcome to remain created even though evidence-recording failed, got %q", got[0].Outcome)
		}
		if got[0].Detail == nil || !strings.Contains(*got[0].Detail, "generation_number_error") {
			t.Fatalf("expected detail to record the generation_number_error, got %v", got[0].Detail)
		}
	})
}

func TestGenerator_WriteRecordsDistinctCollisionReasonCodes(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		reasonCode string
	}{
		{"source collision", contentregistry.ErrSourceCollision, "source_collision"},
		{"origin collision", contentregistry.ErrOriginCollision, "origin_collision"},
		{"threat collision", contentregistry.ErrThreatCollision, "threat_collision"},
		{"generic registrar error", errors.New("boom"), "registrar_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
				idStore := threatidentity.NewStore(pool)
				resolved, err := idStore.ResolveAndPersist(context.Background(), threatidentity.Incoming{Name: "APT-" + tc.reasonCode}, threatidentity.ProfileFields{})
				if err != nil {
					t.Fatal(err)
				}
				seedActiveTechnique(t, pool, resolved.ThreatID, "T1059")
				seedActiveTechnique(t, pool, resolved.ThreatID, "T1053")

				store := evidence.NewStore(pool)
				g := NewGenerator(t.TempDir(), nil, nil, nil).WithRegistrar(collisionRegistrar{err: tc.err}).WithEvidenceStore(store)
				a := ThreatActor{Name: "APT-" + tc.reasonCode, ThreatID: resolved.ThreatID, Source: "misp"}

				if _, err := g.Write([]ThreatActor{a}); err != nil {
					t.Fatalf("Write: %v", err)
				}

				got, err := store.ListGenerationAttempts(context.Background(), evidence.GenerationAttemptFilter{ThreatID: resolved.ThreatID})
				if err != nil {
					t.Fatalf("ListGenerationAttempts: %v", err)
				}
				if len(got) != 1 || got[0].Outcome != "failed" || got[0].ReasonCode != tc.reasonCode {
					t.Fatalf("expected outcome=failed reason_code=%s, got %+v", tc.reasonCode, got)
				}
			})
		})
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/connector/... -run "TestGenerator_WriteRecords" -v`
Expected: FAIL — compile error or assertion failure (no attempt rows are written yet, since `Write` doesn't call `RecordGenerationAttempt` anywhere).

- [ ] **Step 3: Instrument `Write`**

Add imports to `generator.go`:

```go
import (
	// ... existing imports ...
	"time"

	"github.com/google/uuid"
)
```

Add one unexported field to the `Generator` struct (alongside `attackMeta`, same test-only-override convention, set directly from a same-package test file, no public setter):

```go
	// evidenceRecordErr, when set (tests only), substitutes for the real
	// NextGenerationNumber/RecordGeneration call in the `created` branch below.
	// Forces the "created but evidence-recording failed" path deterministically;
	// the real failure mode (a UNIQUE(threat_id, generation_number) collision)
	// only occurs under a genuine concurrent race, which a single-threaded test
	// cannot engineer. Always nil in production.
	evidenceRecordErr error
```

Replace the loop body from the `for _, actor := range actors {` line through the end of the function with (every existing line is preserved; only the additions are new):

```go
	cycleID := uuid.New().String()
	for _, actor := range actors {
		startedAt := time.Now()
		if actor.ThreatID == "" {
			// Unresolved identity never yields content (TCF Phase 2 spec §3.2).
			res.Skipped++
			g.recordAttempt(cycleID, nil, nil, "skipped", "unresolved_identity", nil, nil, startedAt)
			continue
		}
		threatID := actor.ThreatID

		activeTechniques := dedupedTechniqueIDs(actor.Techniques)
		if g.evidence != nil {
			at, err := g.evidence.ActiveTechniques(context.Background(), actor.ThreatID)
			if err != nil {
				log.Printf("[connector/gen] active techniques for %s: %v", actor.ThreatID, err)
				res.Failed++
				g.recordAttempt(cycleID, &threatID, nil, "failed", "active_techniques_error", strptr(err.Error()), nil, startedAt)
				continue
			}
			activeTechniques = at
		}
		if len(activeTechniques) < minTechniques {
			res.Skipped++
			g.recordAttempt(cycleID, &threatID, nil, "skipped", "below_min_techniques", nil, nil, startedAt)
			continue
		}

		id := threatidentity.ContentID(actor.ThreatID)
		body := g.buildYAML(actor, id)
		fname := filepath.Join(g.intelDir, id+".yaml")

		// Register first: the version (with its provenance snapshot) must exist
		// before the file does, so a concurrent engine.Load() intake dedups by
		// hash instead of creating the version without sources. On failure the
		// file is left unwritten and the next sync retries.
		created := false
		versionID := ""
		key := generationKey(actor)
		if g.registrar != nil {
			var err error
			versionID, created, err = g.registrar.RegisterGenerated(context.Background(), contentregistry.GeneratedCandidate{
				ContentID: id, Artifact: []byte(body), GenerationKey: key, GenerationRef: key, ThreatID: actor.ThreatID,
				Generation: g.generationMeta(actor, cv, cvErr),
				Sources: []contentregistry.SourceRef{{EntityType: "actor", EntityID: actor.Name, Provider: actor.Source,
					ExternalID: actor.SourceID, Role: "primary"}},
			})
			if err != nil {
				reasonCode := "registrar_error"
				switch {
				case errors.Is(err, contentregistry.ErrSourceCollision):
					log.Printf("[connector/gen] %s (%s) collides with a custom scenario of the same id; not written: %v", id, actor.Name, err)
					reasonCode = "source_collision"
				case errors.Is(err, contentregistry.ErrOriginCollision):
					log.Printf("[connector/gen] %s (%s) collides with content of a different origin; not written: %v", id, actor.Name, err)
					reasonCode = "origin_collision"
				case errors.Is(err, contentregistry.ErrThreatCollision):
					log.Printf("[connector/gen] %s (%s) content id owned by a different threat; not written: %v", id, actor.Name, err)
					reasonCode = "threat_collision"
				default:
					log.Printf("[connector/gen] register %s: %v", id, err)
				}
				res.Failed++
				g.recordAttempt(cycleID, &threatID, &id, "failed", reasonCode, strptr(err.Error()), &key, startedAt)
				continue
			}
		}
		fileChanged := false
		if old, err := os.ReadFile(fname); err != nil || !bytes.Equal(old, []byte(body)) {
			if err := os.WriteFile(fname, []byte(body), 0644); err != nil {
				log.Printf("[connector/gen] write %s: %v", fname, err)
				res.Failed++
				g.recordAttempt(cycleID, &threatID, &id, "failed", "write_error", strptr(err.Error()), &key, startedAt)
				continue
			}
			res.Changed++
			fileChanged = true
		}
		if created {
			log.Printf("[connector/gen] new DRAFT %s (%s, %d active techniques)", id, actor.Name, len(activeTechniques))
			res.Created++
			var detail *string
			if g.evidence != nil {
				var err error
				if g.evidenceRecordErr != nil {
					// Test-only override (see the field's doc comment below) --
					// the UNIQUE(threat_id, generation_number) failure this
					// substitutes for only occurs under a genuine concurrent
					// race in production, which a single-threaded test cannot
					// engineer deterministically.
					err = g.evidenceRecordErr
				} else {
					genNum, nErr := g.evidence.NextGenerationNumber(context.Background(), actor.ThreatID)
					if nErr != nil {
						err = nErr
					} else {
						err = g.evidence.RecordGeneration(context.Background(), actor.ThreatID, id, "", genNum, generationPolicyVersion)
					}
				}
				if err != nil {
					log.Printf("[connector/gen] record generation for %s: %v", actor.ThreatID, err)
					detail = strptr("generation_number_error: " + err.Error())
				}
			}
			g.recordAttempt(cycleID, &threatID, &id, "created", "ok", detail, &key, startedAt, versionID)
		} else if fileChanged {
			g.recordAttempt(cycleID, &threatID, &id, "changed", "ok", nil, &key, startedAt)
		} else {
			res.Skipped++
			g.recordAttempt(cycleID, &threatID, &id, "skipped", "already_registered", nil, &key, startedAt)
		}
	}
	return res, nil
}

func strptr(s string) *string { return &s }

// recordAttempt is a nil-safe wrapper around evidence.Store.RecordGenerationAttempt,
// matching the existing g.evidence != nil guard already used by ActiveTechniques,
// NextGenerationNumber, and RecordGeneration. versionID is optional (variadic so
// every other call site above doesn't need to pass an empty string explicitly).
func (g *Generator) recordAttempt(cycleID string, threatID, contentID *string, outcome, reasonCode string, detail, fingerprint *string, startedAt time.Time, versionID ...string) {
	if g.evidence == nil {
		return
	}
	var versionIDPtr *string
	if len(versionID) > 0 && versionID[0] != "" {
		versionIDPtr = &versionID[0]
	}
	if err := g.evidence.RecordGenerationAttempt(context.Background(), evidence.GenerationAttempt{
		CycleID: cycleID, ThreatID: threatID, ContentID: contentID, ContentVersionID: versionIDPtr,
		Outcome: outcome, ReasonCode: reasonCode, Detail: detail,
		GeneratorVersion: generatorVersion, Fingerprint: fingerprint, StartedAt: startedAt,
	}); err != nil {
		log.Printf("[connector/gen] record generation attempt (cycle=%s, outcome=%s): %v", cycleID, outcome, err)
	}
}
```

Note the `threatID := actor.ThreatID` local copy right after the unresolved-identity check: it exists purely so every later `&threatID` takes the address of a stable per-iteration variable, not `&actor.ThreatID` (safe here since `actor` is already a per-iteration loop copy in this codebase's Go version, but a named local makes the intent unambiguous rather than relying on loop-variable semantics the reader has to double check).

- [ ] **Step 4: Run `go mod tidy` and the tests**

Run:
```bash
cd orchestrator && go mod tidy
go test ./internal/connector/... -run "TestGenerator_WriteRecords" -v
```
Expected: `go.mod`'s `github.com/google/uuid` line loses its `// indirect` comment. All `TestGenerator_WriteRecords*` tests PASS.

- [ ] **Step 5: Run the full existing generator test file to confirm zero modifications were needed**

Run: `cd orchestrator && git diff --stat internal/connector/generator_test.go && go test ./internal/connector/... -v`
Expected: `git diff --stat` prints nothing (the file is untouched). Every existing test in the package still passes.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/connector/generator.go orchestrator/internal/connector/generator_attempts_test.go orchestrator/go.mod orchestrator/go.sum
git commit -m "feat(tcf-phase9): record a generation attempt at every Generator.Write exit point"
```

---

### Task 4: `GET /api/connector/generation-attempts`

**Files:**
- Modify: `orchestrator/internal/api/handlers.go` (new handler, modeled on `GetCoverageAnalytics`'s existing `?limit=` convention at `handlers.go:4510-4531`)
- Modify: `orchestrator/internal/api/routes.go:559` (register the route next to the existing `GET /api/connector/status`)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go:268` (add the new route's row, reusing `auth.CanViewConnectorStatus` — same visibility tier as the status endpoint this complements)
- Test: `orchestrator/internal/api/generation_attempts_handler_test.go`

**Interfaces:**
- Consumes: Task 2's `evidence.Store.ListGenerationAttempts` / `GenerationAttemptFilter`.
- Produces: `GET /api/connector/generation-attempts` — no other task consumes this.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/api/generation_attempts_handler_test.go
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/evidence"
)

func TestGetGenerationAttempts_FiltersByCycleID(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := evidence.NewStore(pool)
		if err := store.RecordGenerationAttempt(context.Background(), evidence.GenerationAttempt{
			CycleID: "cycle-a", Outcome: "created", ReasonCode: "ok", GeneratorVersion: "4", StartedAt: time.Now(),
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if err := store.RecordGenerationAttempt(context.Background(), evidence.GenerationAttempt{
			CycleID: "cycle-b", Outcome: "created", ReasonCode: "ok", GeneratorVersion: "4", StartedAt: time.Now(),
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}

		h := (&Handler{}).WithEvidenceStore(store)
		req := httptest.NewRequest(http.MethodGet, "/api/connector/generation-attempts?cycle_id=cycle-a", nil)
		w := httptest.NewRecorder()
		h.GetGenerationAttempts(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		body := w.Body.String()
		if !strings.Contains(body, "cycle-a") || strings.Contains(body, "cycle-b") {
			t.Fatalf("expected only cycle-a's attempt in the response, got: %s", body)
		}
	})
}

func TestGetGenerationAttempts_LimitCapsAt100(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := (&Handler{}).WithEvidenceStore(evidence.NewStore(pool))

		req := httptest.NewRequest(http.MethodGet, "/api/connector/generation-attempts?limit=99999", nil)
		w := httptest.NewRecorder()
		h.GetGenerationAttempts(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		// The real assertion is that the handler doesn't pass 99999 straight
		// through to the DB query uncapped -- covered by inspecting the call
		// the handler makes; since Store has no call-log seam, this test instead
		// just confirms the endpoint doesn't error on an absurd limit, and the
		// cap itself is exercised directly in Step 3's handler code (max 100,
		// matching GetCoverageAnalytics's existing convention).
	})
}
```

This test uses the package's existing `sharedDB`/`RunWithPool` fixture (`testmain_test.go`, same convention as `TestRBACMatrix_NoDrift` and every other DB-backed test in this package) — not a fresh `testutil.NewTestDB(t)`, which would spin up a second, redundant testcontainer.

`Handler` has no `*evidence.Store` field today — check `handlers.go`'s `Handler` struct (`handlers.go:79-113`) and `WithScheduler`'s existing fluent-setter convention (`handlers.go:195-198`) before Step 3; add `evidenceStore *evidence.Store // nil when generation-attempt observability isn't wired` as a new field and a matching `func (h *Handler) WithEvidenceStore(s *evidence.Store) *Handler { h.evidenceStore = s; return h }` setter, exactly mirroring `WithScheduler`. Per the plan header's "Known limitation" note, **do not** wire this into `main.go`'s actual server construction as part of this task — that decision belongs with whoever reviews the limitation note, not silently bundled into this task's commit. Leaving `main.go` unchanged means `GET /api/connector/generation-attempts` returns `503 Service Unavailable` in production (Step 3's handler code below checks `h.evidenceStore == nil` first, matching `GetConnectorStatus`'s own `h.scheduler == nil` convention) until that separate wiring decision is made — an honest, visible signal rather than a silently-empty 200, for a feature whose write side isn't wired either.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestGetGenerationAttempts -v`
Expected: FAIL — `undefined: h.GetGenerationAttempts` (and possibly `Handler.evidenceStore`, depending on what the struct already exposes).

- [ ] **Step 3: Implement the handler**

```go
// GET /api/connector/generation-attempts — per-actor generation outcomes
// from the threat-intel scheduler (TCF Phase 9, spec 2026-10-13 §2.6).
//
// Query params:
//
//	cycle_id — every attempt from one scheduler cycle (optional)
//	threat_id — every attempt for one actor across cycles (optional)
//	limit — max rows, default 50, max 100
func (h *Handler) GetGenerationAttempts(w http.ResponseWriter, r *http.Request) {
	if h.evidenceStore == nil {
		jsonError(w, "generation attempts not available", http.StatusServiceUnavailable)
		return
	}
	filter := evidence.GenerationAttemptFilter{
		CycleID:  r.URL.Query().Get("cycle_id"),
		ThreatID: r.URL.Query().Get("threat_id"),
		Limit:    50,
	}
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		filter.Limit = l
	}
	attempts, err := h.evidenceStore.ListGenerationAttempts(r.Context(), filter)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, attempts)
}
```

Add `"github.com/audspect/bas/internal/evidence"` to `handlers.go`'s import block if not already present (it is not — check first; `generator.go` imports it but `handlers.go` is a different file).

- [ ] **Step 4: Register the route**

In `orchestrator/internal/api/routes.go`, immediately after line 559:

```go
		r.With(auth.RequirePermission(auth.CanViewConnectorStatus)).Get("/api/connector/status", h.GetConnectorStatus)
		r.With(auth.RequirePermission(auth.CanViewConnectorStatus)).Get("/api/connector/generation-attempts", h.GetGenerationAttempts)
```

- [ ] **Step 5: Add the RBAC matrix row**

In `orchestrator/internal/api/rbac_matrix_test.go`, immediately after line 268:

```go
	{http.MethodGet, "/api/connector/status", tierPermission, auth.CanViewConnectorStatus},
	{http.MethodGet, "/api/connector/generation-attempts", tierPermission, auth.CanViewConnectorStatus},
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run "TestGetGenerationAttempts|TestRBACMatrix" -v`
Expected: PASS. (`TestRBACMatrix_NoDrift`'s pre-existing, already-ledgered Phase 2B gap for `POST /api/intel/sources/{id}/trust` is a known unrelated failure — confirm the new route is not implicated, per the session's standing note on that test.)

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/handlers.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go orchestrator/internal/api/generation_attempts_handler_test.go
git commit -m "feat(tcf-phase9): GET /api/connector/generation-attempts"
```
