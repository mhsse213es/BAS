# Test Generation Phase 1 — verification + relationships Store Tests Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Write comprehensive store-layer tests for `internal/verification.Store` and `internal/relationships.Store` against a real Postgres instance, using the `internal/testutil` harness built in Phase 0.

**Architecture:** Each package gets one `TestMain` (via `testutil.MustSharedTestDB`, one container per package) and splits tests along the existing CRUD/evidence boundary in each `store.go`. `relationships` additionally needs a local `seedTechniqueCVE` helper because `technique_cve_relationships` has real foreign keys to `techniques`/`cves` (unlike `verification_history`, which has none).

**Tech Stack:** Go 1.26, `internal/testutil.TestDB` (Phase 0), `pgx/v5`, `postgres:16-alpine`.

## Global Constraints

- **This phase is test-only.** No changes to `internal/verification/store.go` or `internal/relationships/store.go`. Every test in this plan is expected to PASS on the first run against the existing implementation — this is characterization testing of code that already works, not TDD of new behavior. If a test fails, the test's understanding of the code is wrong, not the code (stop and re-read the store before "fixing" anything).
- **Do not touch `internal/api/verification_handlers.go` or `internal/api/relationship_handlers.go`.** Those are Phase 3's scope.
- Both `Store` types wrap `*pgxpool.Pool` directly (`type Store struct { db *pgxpool.Pool }`) — neither can be constructed from a `pgx.Tx`. **This means every test in this plan uses `sharedDB.RunWithPool`, not `RunInTx`** — the Phase 0 spec's `RunInTx` (rollback isolation) only fits tests that call `tx.Exec`/`tx.QueryRow` directly; it can't be used with a `Store` at all. `RunWithPool` gives isolation via truncate-after instead.
- Every DB-backed test function starts with:
  ```go
  if testing.Short() {
      t.Skip("skipping container-backed test in -short mode")
  }
  ```
  so `go test ./... -short` (no Docker required) still passes cleanly.
- `technique_cve_relationships` has `FOREIGN KEY` constraints to `techniques(technique_id)` and `cves(cve_id)` (`orchestrator/internal/db/content_schema.go:134-135`) — every `relationships` test that creates a relationship must first seed a `techniques` row and a `cves` row via the `seedTechniqueCVE` helper (Task 4). `verification_history` has no FK constraints — arbitrary string ids are fine there.
- Coverage target: 95-98% for both packages (per `docs/superpowers/specs/2026-07-09-test-phase1-verification-relationships-design.md`).

---

### Task 1: verification package — TestMain + core store tests

**Files:**
- Create: `orchestrator/internal/verification/store_test.go`

**Interfaces:**
- Consumes: `testutil.MustSharedTestDB() *testutil.TestDB` (`orchestrator/internal/testutil/testdb.go`), `(*testutil.TestDB).RunWithPool(t *testing.T, fn func(pool *pgxpool.Pool))`.
- Produces: package-level `var sharedDB *testutil.TestDB`, reused by Tasks 2-3 (same package, same test binary).

- [ ] **Step 1: Write the test file**

`orchestrator/internal/verification/store_test.go`:
```go
package verification

import (
	"context"
	"errors"
	"flag"
	"os"
	"testing"

	"github.com/audspect/bas/internal/testutil"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

func TestAttest_DefaultsWorkflowStateAndSource(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		rec, err := store.Attest(context.Background(), AttestInput{
			RunID: "run-1", ExpectationID: "exp-1", VerifiedBy: "alice",
		})
		if err != nil {
			t.Fatalf("Attest: %v", err)
		}
		if rec.WorkflowState != StateApproved {
			t.Fatalf("WorkflowState = %q, want %q", rec.WorkflowState, StateApproved)
		}
		if rec.Source != SourceManual {
			t.Fatalf("Source = %q, want %q", rec.Source, SourceManual)
		}
		if rec.SupersedesID != "" {
			t.Fatalf("SupersedesID = %q, want empty for first attestation", rec.SupersedesID)
		}
		if !rec.Active {
			t.Fatal("expected Active = true")
		}
	})
}

func TestAttest_SecondAttestationSupersedesFirst(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()

		first, err := store.Attest(ctx, AttestInput{
			RunID: "run-2", ExpectationID: "exp-2", Result: ResultDetected, VerifiedBy: "alice",
		})
		if err != nil {
			t.Fatalf("first Attest: %v", err)
		}

		second, err := store.Attest(ctx, AttestInput{
			RunID: "run-2", ExpectationID: "exp-2", Result: ResultNotDetected, VerifiedBy: "bob",
		})
		if err != nil {
			t.Fatalf("second Attest: %v", err)
		}

		if second.SupersedesID != first.ID {
			t.Fatalf("second.SupersedesID = %q, want %q", second.SupersedesID, first.ID)
		}
		if !second.Active {
			t.Fatal("expected second record to be Active")
		}

		reloadedFirst, ok, err := store.Get(ctx, first.ID)
		if err != nil || !ok {
			t.Fatalf("Get(first.ID): ok=%v err=%v", ok, err)
		}
		if reloadedFirst.Active {
			t.Fatal("expected first record to be superseded (Active=false)")
		}

		history, err := store.History(ctx, "run-2", "exp-2")
		if err != nil {
			t.Fatalf("History: %v", err)
		}
		if len(history) != 2 {
			t.Fatalf("History returned %d records, want 2", len(history))
		}
		if history[0].ID != second.ID {
			t.Fatalf("History[0].ID = %q, want newest (%q) first", history[0].ID, second.ID)
		}
	})
}

func TestCurrentForRun_OnlyActiveRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()

		if _, err := store.Attest(ctx, AttestInput{RunID: "run-3", ExpectationID: "exp-a", VerifiedBy: "alice"}); err != nil {
			t.Fatalf("Attest exp-a: %v", err)
		}
		if _, err := store.Attest(ctx, AttestInput{RunID: "run-3", ExpectationID: "exp-b", VerifiedBy: "alice"}); err != nil {
			t.Fatalf("Attest exp-b: %v", err)
		}
		if _, err := store.Attest(ctx, AttestInput{RunID: "run-3", ExpectationID: "exp-a", VerifiedBy: "bob"}); err != nil {
			t.Fatalf("supersede exp-a: %v", err)
		}

		current, err := store.CurrentForRun(ctx, "run-3")
		if err != nil {
			t.Fatalf("CurrentForRun: %v", err)
		}
		if len(current) != 2 {
			t.Fatalf("CurrentForRun returned %d entries, want 2", len(current))
		}
		if current["exp-a"].VerifiedBy != "bob" {
			t.Fatalf("exp-a.VerifiedBy = %q, want bob (the superseding attestation)", current["exp-a"].VerifiedBy)
		}
	})
}

func TestGet_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		_, ok, err := store.Get(context.Background(), "does-not-exist")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if ok {
			t.Fatal("expected ok=false for missing id")
		}
	})
}

func TestIsUniqueViolation(t *testing.T) {
	if isUniqueViolation(errors.New("plain error")) {
		t.Fatal("plain error should not be a unique violation")
	}
	if isUniqueViolation(pgx.ErrNoRows) {
		t.Fatal("pgx.ErrNoRows should not be a unique violation")
	}
	if !isUniqueViolation(fakeSQLStateErr{state: "23505"}) {
		t.Fatal("23505 SQLSTATE should be detected as a unique violation")
	}
	if isUniqueViolation(fakeSQLStateErr{state: "23503"}) {
		t.Fatal("23503 (foreign key violation) should not match unique violation")
	}
}

type fakeSQLStateErr struct{ state string }

func (e fakeSQLStateErr) Error() string    { return "fake: " + e.state }
func (e fakeSQLStateErr) SQLState() string { return e.state }
```

- [ ] **Step 2: Run the tests**

Run: `go test ./internal/verification/... -v` (from `orchestrator/`; requires Docker running)
Expected: all 5 tests PASS.

- [ ] **Step 3: Confirm -short mode skips cleanly**

Run: `go test ./internal/verification/... -short -v`
Expected: `TestAttest_*`, `TestCurrentForRun_*`, `TestGet_NotFound` report SKIP; `TestIsUniqueViolation` (pure function) still runs and PASSes; exit 0.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/verification/store_test.go
git commit -m "test(verification): add core store tests (Attest, supersede chain, CurrentForRun, Get)"
```

---

### Task 2: verification package — evidence tests

**Files:**
- Create: `orchestrator/internal/verification/evidence_test.go`

**Interfaces:**
- Consumes: `sharedDB` (Task 1), `Store.Attest`/`AddEvidence`/`ListEvidence`/`EvidenceByID`/`EvidenceBytes`/`SoftDeleteEvidence`/`EvidenceCountsForRun` (`orchestrator/internal/verification/store.go`).

- [ ] **Step 1: Write the test file**

`orchestrator/internal/verification/evidence_test.go`:
```go
package verification

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAddEvidence_HashesBytesAndDefaultsDisplayFilename(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()

		rec, err := store.Attest(ctx, AttestInput{RunID: "run-e1", ExpectationID: "exp-e1", VerifiedBy: "alice"})
		if err != nil {
			t.Fatalf("Attest: %v", err)
		}

		payload := []byte("evidence bytes")
		ev, err := store.AddEvidence(ctx, EvidenceInput{
			VerificationID:   rec.ID,
			OriginalFilename: "screenshot.png",
			MIME:             "image/png",
			UploadedBy:       "alice",
			Bytes:            payload,
		})
		if err != nil {
			t.Fatalf("AddEvidence: %v", err)
		}

		sum := sha256.Sum256(payload)
		want := hex.EncodeToString(sum[:])
		if ev.ContentHash != want {
			t.Fatalf("ContentHash = %q, want %q", ev.ContentHash, want)
		}
		if ev.HashAlgorithm != HashSHA256 {
			t.Fatalf("HashAlgorithm = %q, want %q", ev.HashAlgorithm, HashSHA256)
		}
		if ev.DisplayFilename != "screenshot.png" {
			t.Fatalf("DisplayFilename = %q, want defaulted to OriginalFilename", ev.DisplayFilename)
		}

		gotBytes, err := store.EvidenceBytes(ctx, ev)
		if err != nil {
			t.Fatalf("EvidenceBytes: %v", err)
		}
		if !bytes.Equal(gotBytes, payload) {
			t.Fatalf("EvidenceBytes = %q, want %q", gotBytes, payload)
		}
	})
}

func TestAddEvidence_ExplicitDisplayFilenameNotOverridden(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()

		rec, err := store.Attest(ctx, AttestInput{RunID: "run-e2", ExpectationID: "exp-e2", VerifiedBy: "alice"})
		if err != nil {
			t.Fatalf("Attest: %v", err)
		}

		ev, err := store.AddEvidence(ctx, EvidenceInput{
			VerificationID:   rec.ID,
			OriginalFilename: "raw-name.png",
			DisplayFilename:  "Nice Display Name.png",
			UploadedBy:       "alice",
			Bytes:            []byte("x"),
		})
		if err != nil {
			t.Fatalf("AddEvidence: %v", err)
		}
		if ev.DisplayFilename != "Nice Display Name.png" {
			t.Fatalf("DisplayFilename = %q, want explicit value preserved", ev.DisplayFilename)
		}
	})
}

func TestListEvidence_ExcludesSoftDeleted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()

		rec, err := store.Attest(ctx, AttestInput{RunID: "run-e3", ExpectationID: "exp-e3", VerifiedBy: "alice"})
		if err != nil {
			t.Fatalf("Attest: %v", err)
		}

		ev1, err := store.AddEvidence(ctx, EvidenceInput{VerificationID: rec.ID, OriginalFilename: "a.png", UploadedBy: "alice", Bytes: []byte("a")})
		if err != nil {
			t.Fatalf("AddEvidence 1: %v", err)
		}
		ev2, err := store.AddEvidence(ctx, EvidenceInput{VerificationID: rec.ID, OriginalFilename: "b.png", UploadedBy: "alice", Bytes: []byte("b")})
		if err != nil {
			t.Fatalf("AddEvidence 2: %v", err)
		}

		if err := store.SoftDeleteEvidence(ctx, ev1.ID, "alice"); err != nil {
			t.Fatalf("SoftDeleteEvidence: %v", err)
		}

		list, err := store.ListEvidence(ctx, rec.ID)
		if err != nil {
			t.Fatalf("ListEvidence: %v", err)
		}
		if len(list) != 1 || list[0].ID != ev2.ID {
			t.Fatalf("ListEvidence = %+v, want only ev2", list)
		}
	})
}

func TestEvidenceByID_FoundIncludingDeletedAndMissing(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()

		rec, err := store.Attest(ctx, AttestInput{RunID: "run-e4", ExpectationID: "exp-e4", VerifiedBy: "alice"})
		if err != nil {
			t.Fatalf("Attest: %v", err)
		}
		ev, err := store.AddEvidence(ctx, EvidenceInput{VerificationID: rec.ID, OriginalFilename: "a.png", UploadedBy: "alice", Bytes: []byte("a")})
		if err != nil {
			t.Fatalf("AddEvidence: %v", err)
		}
		if err := store.SoftDeleteEvidence(ctx, ev.ID, "alice"); err != nil {
			t.Fatalf("SoftDeleteEvidence: %v", err)
		}

		got, ok, err := store.EvidenceByID(ctx, ev.ID)
		if err != nil || !ok {
			t.Fatalf("EvidenceByID: ok=%v err=%v", ok, err)
		}
		if !got.Deleted {
			t.Fatal("expected Deleted=true to be visible via EvidenceByID")
		}

		_, ok, err = store.EvidenceByID(ctx, "does-not-exist")
		if err != nil {
			t.Fatalf("EvidenceByID missing: %v", err)
		}
		if ok {
			t.Fatal("expected ok=false for missing evidence id")
		}
	})
}

func TestEvidenceBytes_ErrorsForNonDatabaseStorage(t *testing.T) {
	store := NewStore(nil)
	ev := Evidence{StorageType: StorageFilesystem}
	if _, err := store.EvidenceBytes(context.Background(), ev); err == nil {
		t.Fatal("expected error for non-database storage type")
	}
}

func TestSoftDeleteEvidence_IdempotentSecondCallNoError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()

		rec, err := store.Attest(ctx, AttestInput{RunID: "run-e5", ExpectationID: "exp-e5", VerifiedBy: "alice"})
		if err != nil {
			t.Fatalf("Attest: %v", err)
		}
		ev, err := store.AddEvidence(ctx, EvidenceInput{VerificationID: rec.ID, OriginalFilename: "a.png", UploadedBy: "alice", Bytes: []byte("a")})
		if err != nil {
			t.Fatalf("AddEvidence: %v", err)
		}

		if err := store.SoftDeleteEvidence(ctx, ev.ID, "alice"); err != nil {
			t.Fatalf("first SoftDeleteEvidence: %v", err)
		}
		if err := store.SoftDeleteEvidence(ctx, ev.ID, "bob"); err != nil {
			t.Fatalf("second SoftDeleteEvidence should not error: %v", err)
		}

		got, ok, err := store.EvidenceByID(ctx, ev.ID)
		if err != nil || !ok {
			t.Fatalf("EvidenceByID: ok=%v err=%v", ok, err)
		}
		if got.DeletedBy != "alice" {
			t.Fatalf("DeletedBy = %q, want %q (first delete wins, second is a no-op)", got.DeletedBy, "alice")
		}
	})
}

func TestEvidenceCountsForRun_OnlyActiveAndNonDeleted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()

		rec, err := store.Attest(ctx, AttestInput{RunID: "run-e6", ExpectationID: "exp-e6", VerifiedBy: "alice"})
		if err != nil {
			t.Fatalf("Attest: %v", err)
		}
		if _, err := store.AddEvidence(ctx, EvidenceInput{VerificationID: rec.ID, OriginalFilename: "a.png", UploadedBy: "alice", Bytes: []byte("a")}); err != nil {
			t.Fatalf("AddEvidence 1: %v", err)
		}
		ev2, err := store.AddEvidence(ctx, EvidenceInput{VerificationID: rec.ID, OriginalFilename: "b.png", UploadedBy: "alice", Bytes: []byte("b")})
		if err != nil {
			t.Fatalf("AddEvidence 2: %v", err)
		}
		if err := store.SoftDeleteEvidence(ctx, ev2.ID, "alice"); err != nil {
			t.Fatalf("SoftDeleteEvidence: %v", err)
		}

		counts, err := store.EvidenceCountsForRun(ctx, "run-e6")
		if err != nil {
			t.Fatalf("EvidenceCountsForRun: %v", err)
		}
		if counts[rec.ID] != 1 {
			t.Fatalf("counts[rec.ID] = %d, want 1 (soft-deleted excluded)", counts[rec.ID])
		}
	})
}
```

- [ ] **Step 2: Run the tests**

Run: `go test ./internal/verification/... -run 'TestAddEvidence|TestListEvidence|TestEvidenceByID|TestEvidenceBytes|TestSoftDeleteEvidence|TestEvidenceCountsForRun' -v`
Expected: all 7 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/verification/evidence_test.go
git commit -m "test(verification): add evidence lifecycle tests (hash, defaults, soft-delete, counts)"
```

---

### Task 3: verification package — concurrency tests

**Files:**
- Create: `orchestrator/internal/verification/concurrency_test.go`

**Interfaces:**
- Consumes: `sharedDB` (Task 1), `Store.Attest`, `Store.CurrentForRun`, `ErrConflict`.

**Note on the invariant being tested:** regardless of whether a prior active row exists before the race, Postgres's partial unique index on `(run_id, expectation_id) WHERE active` guarantees exactly one concurrent `Attest` call can commit an active row for a given pair — every other concurrent caller gets `ErrConflict`. This holds even when a prior row exists and gets superseded: the `FOR UPDATE` lock only serializes the *first* racer through; once it commits (flipping the old row to `active=false`), every other blocked racer re-evaluates its `SELECT ... FOR UPDATE ... WHERE active` under Postgres's READ COMMITTED semantics, finds 0 matching rows (the old row is no longer active), and falls through to its own `INSERT` — which now collides with the first racer's newly-committed active row and fails with `ErrConflict`, exactly like the no-prior-row case. There is no scenario where two concurrent `Attest` calls both succeed for the same pair.

- [ ] **Step 1: Write the test file**

`orchestrator/internal/verification/concurrency_test.go`:
```go
package verification

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAttest_ConcurrentRace_NoPriorRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		const n = 5
		var wg sync.WaitGroup
		results := make(chan error, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := store.Attest(context.Background(), AttestInput{
					RunID: "race-run", ExpectationID: "race-exp", VerifiedBy: "tester",
				})
				results <- err
			}()
		}
		wg.Wait()
		close(results)

		var succeeded, conflicts int
		for err := range results {
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, ErrConflict):
				conflicts++
			default:
				t.Fatalf("unexpected error: %v", err)
			}
		}
		if succeeded != 1 {
			t.Fatalf("succeeded = %d, want exactly 1", succeeded)
		}
		if conflicts != n-1 {
			t.Fatalf("conflicts = %d, want %d", conflicts, n-1)
		}

		current, err := store.CurrentForRun(context.Background(), "race-run")
		if err != nil {
			t.Fatalf("CurrentForRun: %v", err)
		}
		if len(current) != 1 {
			t.Fatalf("CurrentForRun returned %d active records, want 1", len(current))
		}
	})
}

func TestAttest_ConcurrentRace_WithPriorRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()

		if _, err := store.Attest(ctx, AttestInput{
			RunID: "race-run-2", ExpectationID: "race-exp-2", VerifiedBy: "seed",
		}); err != nil {
			t.Fatalf("seed Attest: %v", err)
		}

		const n = 5
		var wg sync.WaitGroup
		results := make(chan error, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := store.Attest(ctx, AttestInput{
					RunID: "race-run-2", ExpectationID: "race-exp-2", VerifiedBy: "racer",
				})
				results <- err
			}()
		}
		wg.Wait()
		close(results)

		var succeeded, conflicts int
		for err := range results {
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, ErrConflict):
				conflicts++
			default:
				t.Fatalf("unexpected error: %v", err)
			}
		}
		if succeeded != 1 {
			t.Fatalf("succeeded = %d, want exactly 1", succeeded)
		}
		if conflicts != n-1 {
			t.Fatalf("conflicts = %d, want %d", conflicts, n-1)
		}

		current, err := store.CurrentForRun(ctx, "race-run-2")
		if err != nil {
			t.Fatalf("CurrentForRun: %v", err)
		}
		if len(current) != 1 {
			t.Fatalf("CurrentForRun returned %d active records, want 1", len(current))
		}
	})
}
```

- [ ] **Step 2: Run the tests**

Run: `go test ./internal/verification/... -run TestAttest_ConcurrentRace -v`
Expected: both tests PASS. (If either ever flakes with `succeeded != 1`, that is a real finding — stop and report it rather than retrying into a pass.)

- [ ] **Step 3: Run with the race detector if available**

Run: `go test ./internal/verification/... -run TestAttest_ConcurrentRace -race -v` — skip this step with a note if the local machine has no C toolchain (`go env CGO_ENABLED` = 0); CI will run it on every push regardless.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/verification/concurrency_test.go
git commit -m "test(verification): add concurrent Attest race tests for ErrConflict"
```

---

### Task 4: relationships package — TestMain + core store tests

**Files:**
- Create: `orchestrator/internal/relationships/store_test.go`

**Interfaces:**
- Consumes: `testutil.MustSharedTestDB`, `(*testutil.TestDB).RunWithPool` (same as Task 1).
- Produces: package-level `var sharedDB *testutil.TestDB` and `func seedTechniqueCVE(t *testing.T, pool *pgxpool.Pool, techniqueID, cveID string)`, both reused by Task 5.

- [ ] **Step 1: Write the test file**

`orchestrator/internal/relationships/store_test.go`:
```go
package relationships

import (
	"context"
	"errors"
	"flag"
	"os"
	"testing"

	"github.com/audspect/bas/internal/testutil"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

// seedTechniqueCVE inserts a minimal techniques row and cves row so a
// relationship can be created against them — technique_cve_relationships
// has real foreign keys to both tables. Idempotent: safe to call multiple
// times with the same technique_id or cve_id (e.g. two CVEs for one
// technique).
func seedTechniqueCVE(t *testing.T, pool *pgxpool.Pool, techniqueID, cveID string) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx,
		`INSERT INTO techniques (technique_id) VALUES ($1) ON CONFLICT (technique_id) DO NOTHING`,
		techniqueID); err != nil {
		t.Fatalf("seed technique %s: %v", techniqueID, err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO cves (cve_id) VALUES ($1) ON CONFLICT (cve_id) DO NOTHING`,
		cveID); err != nil {
		t.Fatalf("seed cve %s: %v", cveID, err)
	}
}

func TestCreate_DefaultsConfidenceAndSource(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechniqueCVE(t, pool, "T1059", "CVE-2024-0001")
		store := NewStore(pool)

		r, err := store.Create(context.Background(), CreateInput{
			TechniqueID: "T1059", CVEID: "CVE-2024-0001",
			RelationshipType: TypeDirectExploitation, CreatedBy: "alice",
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if r.ProposedConfidence != ConfidenceMedium {
			t.Fatalf("ProposedConfidence = %q, want %q", r.ProposedConfidence, ConfidenceMedium)
		}
		if r.PrimarySource != SourceAnalyst {
			t.Fatalf("PrimarySource = %q, want %q", r.PrimarySource, SourceAnalyst)
		}
		if r.EffectiveConfidence != r.ProposedConfidence {
			t.Fatalf("EffectiveConfidence = %q, want equal to ProposedConfidence %q", r.EffectiveConfidence, r.ProposedConfidence)
		}
		if r.Status != StatusActive {
			t.Fatalf("Status = %q, want %q", r.Status, StatusActive)
		}
	})
}

func TestCreate_DuplicateTripleRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechniqueCVE(t, pool, "T1059", "CVE-2024-0002")
		store := NewStore(pool)
		ctx := context.Background()

		in := CreateInput{TechniqueID: "T1059", CVEID: "CVE-2024-0002", RelationshipType: TypeDirectExploitation, CreatedBy: "alice"}
		if _, err := store.Create(ctx, in); err != nil {
			t.Fatalf("first Create: %v", err)
		}
		_, err := store.Create(ctx, in)
		if !errors.Is(err, ErrDuplicate) {
			t.Fatalf("second Create error = %v, want ErrDuplicate", err)
		}
	})
}

func TestCreate_DifferentTypeSamePairSucceeds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechniqueCVE(t, pool, "T1059", "CVE-2024-0003")
		store := NewStore(pool)
		ctx := context.Background()

		if _, err := store.Create(ctx, CreateInput{
			TechniqueID: "T1059", CVEID: "CVE-2024-0003", RelationshipType: TypeDirectExploitation, CreatedBy: "alice",
		}); err != nil {
			t.Fatalf("first Create: %v", err)
		}
		_, err := store.Create(ctx, CreateInput{
			TechniqueID: "T1059", CVEID: "CVE-2024-0003", RelationshipType: TypePostExploitation, CreatedBy: "alice",
		})
		if err != nil {
			t.Fatalf("second Create with different type should succeed: %v", err)
		}
	})
}

func TestUpdate_ChangesDescriptiveFieldsOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechniqueCVE(t, pool, "T1059", "CVE-2024-0004")
		store := NewStore(pool)
		ctx := context.Background()

		r, err := store.Create(ctx, CreateInput{
			TechniqueID: "T1059", CVEID: "CVE-2024-0004", RelationshipType: TypeDirectExploitation,
			ProposedConfidence: ConfidenceLow, Rationale: "initial hypothesis", CreatedBy: "alice",
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		if _, err := store.Review(ctx, r.ID, ConfidenceHigh, "reviewer"); err != nil {
			t.Fatalf("Review: %v", err)
		}

		result, err := store.Update(ctx, r.ID, UpdateInput{
			RelationshipType: TypeDirectExploitation, ProposedConfidence: ConfidenceMedium,
			PrimarySource: SourceCISA, Rationale: "confirmed by CISA advisory", UpdatedBy: "bob",
		})
		if err != nil {
			t.Fatalf("Update: %v", err)
		}
		if result.OldConfidence != ConfidenceLow {
			t.Fatalf("OldConfidence = %q, want %q", result.OldConfidence, ConfidenceLow)
		}
		if result.OldRationale != "initial hypothesis" {
			t.Fatalf("OldRationale = %q, want %q", result.OldRationale, "initial hypothesis")
		}
		if result.Relationship.ProposedConfidence != ConfidenceMedium {
			t.Fatalf("ProposedConfidence = %q, want %q", result.Relationship.ProposedConfidence, ConfidenceMedium)
		}
		if result.Relationship.EffectiveConfidence != ConfidenceHigh {
			t.Fatalf("EffectiveConfidence = %q, want unchanged %q (Update must not touch it)", result.Relationship.EffectiveConfidence, ConfidenceHigh)
		}
		if result.Relationship.Status != StatusActive {
			t.Fatalf("Status = %q, want unchanged %q", result.Relationship.Status, StatusActive)
		}
	})
}

func TestUpdate_MissingID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		_, err := store.Update(context.Background(), "does-not-exist", UpdateInput{
			RelationshipType: TypeDirectExploitation, ProposedConfidence: ConfidenceMedium, UpdatedBy: "alice",
		})
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("Update missing id error = %v, want pgx.ErrNoRows", err)
		}
	})
}

func TestUpdate_CollidesWithAnotherRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechniqueCVE(t, pool, "T1059", "CVE-2024-0005")
		store := NewStore(pool)
		ctx := context.Background()

		if _, err := store.Create(ctx, CreateInput{
			TechniqueID: "T1059", CVEID: "CVE-2024-0005", RelationshipType: TypeDirectExploitation, CreatedBy: "alice",
		}); err != nil {
			t.Fatalf("first Create: %v", err)
		}
		second, err := store.Create(ctx, CreateInput{
			TechniqueID: "T1059", CVEID: "CVE-2024-0005", RelationshipType: TypePostExploitation, CreatedBy: "alice",
		})
		if err != nil {
			t.Fatalf("second Create: %v", err)
		}

		_, err = store.Update(ctx, second.ID, UpdateInput{
			RelationshipType: TypeDirectExploitation, ProposedConfidence: ConfidenceMedium, UpdatedBy: "bob",
		})
		if !errors.Is(err, ErrDuplicate) {
			t.Fatalf("Update collision error = %v, want ErrDuplicate", err)
		}
	})
}

func TestReview_DivergesEffectiveFromProposed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechniqueCVE(t, pool, "T1059", "CVE-2024-0006")
		store := NewStore(pool)
		ctx := context.Background()

		r, err := store.Create(ctx, CreateInput{
			TechniqueID: "T1059", CVEID: "CVE-2024-0006", RelationshipType: TypeDirectExploitation,
			ProposedConfidence: ConfidenceHigh, CreatedBy: "alice",
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		reviewed, err := store.Review(ctx, r.ID, ConfidenceLow, "reviewer-bob")
		if err != nil {
			t.Fatalf("Review: %v", err)
		}
		if reviewed.EffectiveConfidence != ConfidenceLow {
			t.Fatalf("EffectiveConfidence = %q, want %q", reviewed.EffectiveConfidence, ConfidenceLow)
		}
		if reviewed.ProposedConfidence != ConfidenceHigh {
			t.Fatalf("ProposedConfidence = %q, want unchanged %q", reviewed.ProposedConfidence, ConfidenceHigh)
		}
		if reviewed.ReviewedBy != "reviewer-bob" {
			t.Fatalf("ReviewedBy = %q, want %q", reviewed.ReviewedBy, "reviewer-bob")
		}
		if reviewed.LastReviewedAt == nil {
			t.Fatal("expected LastReviewedAt to be set")
		}
	})
}

func TestSetStatus_LifecycleTransitions(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechniqueCVE(t, pool, "T1059", "CVE-2024-0007")
		store := NewStore(pool)
		ctx := context.Background()

		r, err := store.Create(ctx, CreateInput{
			TechniqueID: "T1059", CVEID: "CVE-2024-0007", RelationshipType: TypeDirectExploitation, CreatedBy: "alice",
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		for _, status := range []string{StatusDeprecated, StatusDisputed, StatusRetired, StatusActive} {
			updated, err := store.SetStatus(ctx, r.ID, status, "reviewer", "transition to "+status)
			if err != nil {
				t.Fatalf("SetStatus(%s): %v", status, err)
			}
			if updated.Status != status {
				t.Fatalf("Status = %q, want %q", updated.Status, status)
			}
			if updated.StatusChangedBy != "reviewer" {
				t.Fatalf("StatusChangedBy = %q, want %q", updated.StatusChangedBy, "reviewer")
			}
			if updated.StatusChangedAt == nil {
				t.Fatal("expected StatusChangedAt to be set")
			}
			if updated.StatusReason != "transition to "+status {
				t.Fatalf("StatusReason = %q, want %q", updated.StatusReason, "transition to "+status)
			}
		}
	})
}

func TestForTechnique_AllStatusesReturnedNewestFirst(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechniqueCVE(t, pool, "T1059", "CVE-2024-0008")
		seedTechniqueCVE(t, pool, "T1059", "CVE-2024-0009")
		store := NewStore(pool)
		ctx := context.Background()

		first, err := store.Create(ctx, CreateInput{
			TechniqueID: "T1059", CVEID: "CVE-2024-0008", RelationshipType: TypeDirectExploitation, CreatedBy: "alice",
		})
		if err != nil {
			t.Fatalf("first Create: %v", err)
		}
		second, err := store.Create(ctx, CreateInput{
			TechniqueID: "T1059", CVEID: "CVE-2024-0009", RelationshipType: TypeObservedInTheWild, CreatedBy: "alice",
		})
		if err != nil {
			t.Fatalf("second Create: %v", err)
		}
		if _, err := store.SetStatus(ctx, first.ID, StatusRetired, "reviewer", "no longer relevant"); err != nil {
			t.Fatalf("SetStatus: %v", err)
		}

		all, err := store.ForTechnique(ctx, "T1059")
		if err != nil {
			t.Fatalf("ForTechnique: %v", err)
		}
		if len(all) != 2 {
			t.Fatalf("ForTechnique returned %d relationships, want 2 (including retired)", len(all))
		}
		if all[0].ID != second.ID {
			t.Fatalf("ForTechnique[0].ID = %q, want newest (%q) first", all[0].ID, second.ID)
		}
	})
}

func TestGet_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		_, ok, err := store.Get(context.Background(), "does-not-exist")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if ok {
			t.Fatal("expected ok=false for missing id")
		}
	})
}

func TestIsUniqueViolation(t *testing.T) {
	if isUniqueViolation(errors.New("plain error")) {
		t.Fatal("plain error should not be a unique violation")
	}
	if !isUniqueViolation(fakeSQLStateErr{state: "23505"}) {
		t.Fatal("23505 SQLSTATE should be detected as a unique violation")
	}
	if isUniqueViolation(fakeSQLStateErr{state: "23503"}) {
		t.Fatal("23503 (foreign key violation) should not match unique violation")
	}
}

type fakeSQLStateErr struct{ state string }

func (e fakeSQLStateErr) Error() string    { return "fake: " + e.state }
func (e fakeSQLStateErr) SQLState() string { return e.state }
```

- [ ] **Step 2: Run the tests**

Run: `go test ./internal/relationships/... -v` (from `orchestrator/`; requires Docker running)
Expected: all 10 tests PASS.

- [ ] **Step 3: Confirm -short mode skips cleanly**

Run: `go test ./internal/relationships/... -short -v`
Expected: DB-backed tests SKIP, `TestIsUniqueViolation` PASSes, exit 0.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/relationships/store_test.go
git commit -m "test(relationships): add core store tests (Create, Update, Review, SetStatus, ForTechnique)"
```

---

### Task 5: relationships package — evidence tests

**Files:**
- Create: `orchestrator/internal/relationships/evidence_test.go`

**Interfaces:**
- Consumes: `sharedDB`, `seedTechniqueCVE` (Task 4), `Store.AddEvidence`/`ListEvidence`/`EvidenceByID`/`SoftDeleteEvidence`/`EvidenceCounts` (`orchestrator/internal/relationships/store.go`).

- [ ] **Step 1: Write the test file**

`orchestrator/internal/relationships/evidence_test.go`:
```go
package relationships

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAddEvidence_Defaults(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechniqueCVE(t, pool, "T1059", "CVE-2024-1001")
		store := NewStore(pool)
		ctx := context.Background()

		r, err := store.Create(ctx, CreateInput{
			TechniqueID: "T1059", CVEID: "CVE-2024-1001", RelationshipType: TypeDirectExploitation, CreatedBy: "alice",
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		ev, err := store.AddEvidence(ctx, EvidenceInput{
			RelationshipID: r.ID, ReferenceValue: "https://example.com/advisory", AddedBy: "alice",
		})
		if err != nil {
			t.Fatalf("AddEvidence: %v", err)
		}
		if ev.Source != SourceAnalyst {
			t.Fatalf("Source = %q, want default %q", ev.Source, SourceAnalyst)
		}
		if ev.ReferenceType != ReferenceURL {
			t.Fatalf("ReferenceType = %q, want default %q", ev.ReferenceType, ReferenceURL)
		}
	})
}

func TestListEvidence_OrderedByPriorityThenAddedAt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechniqueCVE(t, pool, "T1059", "CVE-2024-1002")
		store := NewStore(pool)
		ctx := context.Background()

		r, err := store.Create(ctx, CreateInput{
			TechniqueID: "T1059", CVEID: "CVE-2024-1002", RelationshipType: TypeDirectExploitation, CreatedBy: "alice",
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		low, err := store.AddEvidence(ctx, EvidenceInput{RelationshipID: r.ID, ReferenceValue: "low-priority", Priority: 5, AddedBy: "alice"})
		if err != nil {
			t.Fatalf("AddEvidence low: %v", err)
		}
		high, err := store.AddEvidence(ctx, EvidenceInput{RelationshipID: r.ID, ReferenceValue: "high-priority", Priority: 1, AddedBy: "alice"})
		if err != nil {
			t.Fatalf("AddEvidence high: %v", err)
		}

		list, err := store.ListEvidence(ctx, r.ID)
		if err != nil {
			t.Fatalf("ListEvidence: %v", err)
		}
		if len(list) != 2 || list[0].ID != high.ID || list[1].ID != low.ID {
			t.Fatalf("ListEvidence order = %+v, want [high, low] by priority ascending", list)
		}
	})
}

func TestListEvidence_ExcludesSoftDeleted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechniqueCVE(t, pool, "T1059", "CVE-2024-1003")
		store := NewStore(pool)
		ctx := context.Background()

		r, err := store.Create(ctx, CreateInput{
			TechniqueID: "T1059", CVEID: "CVE-2024-1003", RelationshipType: TypeDirectExploitation, CreatedBy: "alice",
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		ev1, err := store.AddEvidence(ctx, EvidenceInput{RelationshipID: r.ID, ReferenceValue: "a", AddedBy: "alice"})
		if err != nil {
			t.Fatalf("AddEvidence 1: %v", err)
		}
		ev2, err := store.AddEvidence(ctx, EvidenceInput{RelationshipID: r.ID, ReferenceValue: "b", AddedBy: "alice"})
		if err != nil {
			t.Fatalf("AddEvidence 2: %v", err)
		}

		if err := store.SoftDeleteEvidence(ctx, ev1.ID, "alice"); err != nil {
			t.Fatalf("SoftDeleteEvidence: %v", err)
		}

		list, err := store.ListEvidence(ctx, r.ID)
		if err != nil {
			t.Fatalf("ListEvidence: %v", err)
		}
		if len(list) != 1 || list[0].ID != ev2.ID {
			t.Fatalf("ListEvidence = %+v, want only ev2", list)
		}
	})
}

func TestEvidenceByID_FoundIncludingDeletedAndMissing(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechniqueCVE(t, pool, "T1059", "CVE-2024-1004")
		store := NewStore(pool)
		ctx := context.Background()

		r, err := store.Create(ctx, CreateInput{
			TechniqueID: "T1059", CVEID: "CVE-2024-1004", RelationshipType: TypeDirectExploitation, CreatedBy: "alice",
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		ev, err := store.AddEvidence(ctx, EvidenceInput{RelationshipID: r.ID, ReferenceValue: "a", AddedBy: "alice"})
		if err != nil {
			t.Fatalf("AddEvidence: %v", err)
		}
		if err := store.SoftDeleteEvidence(ctx, ev.ID, "alice"); err != nil {
			t.Fatalf("SoftDeleteEvidence: %v", err)
		}

		got, ok, err := store.EvidenceByID(ctx, ev.ID)
		if err != nil || !ok {
			t.Fatalf("EvidenceByID: ok=%v err=%v", ok, err)
		}
		if !got.Deleted {
			t.Fatal("expected Deleted=true visible via EvidenceByID")
		}

		_, ok, err = store.EvidenceByID(ctx, "does-not-exist")
		if err != nil {
			t.Fatalf("EvidenceByID missing: %v", err)
		}
		if ok {
			t.Fatal("expected ok=false for missing evidence id")
		}
	})
}

func TestEvidenceCounts_BatchAndEmptySliceShortCircuit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedTechniqueCVE(t, pool, "T1059", "CVE-2024-1005")
		seedTechniqueCVE(t, pool, "T1059", "CVE-2024-1006")
		store := NewStore(pool)
		ctx := context.Background()

		r1, err := store.Create(ctx, CreateInput{TechniqueID: "T1059", CVEID: "CVE-2024-1005", RelationshipType: TypeDirectExploitation, CreatedBy: "alice"})
		if err != nil {
			t.Fatalf("Create r1: %v", err)
		}
		r2, err := store.Create(ctx, CreateInput{TechniqueID: "T1059", CVEID: "CVE-2024-1006", RelationshipType: TypeDirectExploitation, CreatedBy: "alice"})
		if err != nil {
			t.Fatalf("Create r2: %v", err)
		}
		if _, err := store.AddEvidence(ctx, EvidenceInput{RelationshipID: r1.ID, ReferenceValue: "a", AddedBy: "alice"}); err != nil {
			t.Fatalf("AddEvidence r1: %v", err)
		}

		counts, err := store.EvidenceCounts(ctx, []string{r1.ID, r2.ID})
		if err != nil {
			t.Fatalf("EvidenceCounts: %v", err)
		}
		if counts[r1.ID] != 1 {
			t.Fatalf("counts[r1.ID] = %d, want 1", counts[r1.ID])
		}
		if _, ok := counts[r2.ID]; ok {
			t.Fatalf("counts[r2.ID] should be absent (no evidence rows), got %d", counts[r2.ID])
		}

		empty, err := store.EvidenceCounts(ctx, nil)
		if err != nil {
			t.Fatalf("EvidenceCounts(nil): %v", err)
		}
		if len(empty) != 0 {
			t.Fatalf("EvidenceCounts(nil) = %+v, want empty map", empty)
		}
	})
}
```

- [ ] **Step 2: Run the tests**

Run: `go test ./internal/relationships/... -run 'TestAddEvidence|TestListEvidence|TestEvidenceByID|TestEvidenceCounts' -v`
Expected: all 5 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/relationships/evidence_test.go
git commit -m "test(relationships): add evidence lifecycle tests (defaults, ordering, soft-delete, batch counts)"
```

---

### Task 6: Coverage verification + full module check

**Files:** none created — verification only.

- [ ] **Step 1: Check per-package coverage against target**

Run (from `orchestrator/`):
```bash
go test ./internal/verification/... ./internal/relationships/... -cover
```
Expected: both packages report `ok` with coverage ≥ 90% (target is 95-98%; if either lands below 90%, use `go test ./internal/verification/... -coverprofile=/tmp/v.out && go tool cover -html=/tmp/v.out` — or the equivalent for relationships — to see which lines are uncovered and add a targeted test, rather than padding).

- [ ] **Step 2: Run the full module test suite**

Run: `go test ./... 2>&1 | tail -40`
Expected: every package still reports `ok` or `[no test files]` — Phase 1 must not have broken anything elsewhere.

- [ ] **Step 3: Run fmt/vet/staticcheck/build**

Run (from `orchestrator/`):
```bash
gofmt -l internal/verification internal/relationships
go vet ./...
staticcheck ./...
go build ./...
```
Expected: `gofmt -l` prints nothing for the two new packages' files (they were written with correct formatting; any CRLF noise from other pre-existing files is the known Phase 0 artifact, not new), `vet`/`staticcheck`/`build` all clean.

- [ ] **Step 4: Push**

```bash
git push
```
