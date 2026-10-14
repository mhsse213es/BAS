# Backup Assurance Engine — Design

## Why

The ransomware-mastery roadmap names Backup Assurance as its own capability
(`ransomware.txt` lines 48-64, deliverable: "a Backup Assurance engine that
can integrate with backup platforms, storage APIs, and customer-approved
recovery test environments"), separate from `rwevidence`'s per-attempt
capability model (sub-project #1) and `rwscore`'s weighted scoring
(sub-project #2, done). Confirmed via grep: no backup-assurance package
exists anywhere in `internal/` — the only "backup" hit,
`internal/api/backup_handlers.go`, is Audspect's own platform self-backup
(DB/config archival), unrelated to validating a *customer's* backup
infrastructure against ransomware.

This is sub-project #4 of the master roadmap, depending only on #1.

**Naming discrepancy in the roadmap's own frozen table** (flagged during
brainstorming, not silently resolved): the decomposition table
(`ransomware.txt:310-311`) says "6 sub-checks" but names only 5 — it drops
the narrative's first bullet (protection against unauthorized deletion)
from its own list. The narrative (lines 51-55) is authoritative here: all
6 checks below are in scope, including deletion protection.

## Scope

- **In scope**: a standalone Go package (`internal/backupassurance`) that
  models the 6 checks as a closed enum, fake-backed observers for each,
  an `AssessBackup` orchestrator, its own persistence (one new table,
  independent of `scenario_runs`/`rw_capability_results`), and two new
  endpoints (trigger + retrieve).
- **Out of scope, deliberately deferred**:
  - Any real backup-platform/storage-API integration (AWS S3 Object Lock,
    Veeam, Azure Backup, or any other vendor) — each is its own later,
    lab-gated sub-project, selected per the customer's actual
    infrastructure.
  - A 6th `rwscore` dimension, or any change to `rwscore.ScoreRun`/
    `weights`/`CoverageRow` — Backup Assurance evaluates infrastructure
    posture, not a specific attack attempt's outcome, and stays
    structurally separate (same boundary the Control-Efficacy Validation
    Layer kept from AD mastery's own scoring).
  - Any tie to scenario dispatch, `run_id`, or `rw_capability_results` —
    these 6 checks are not outcomes of any particular MITRE technique
    attempt.
  - A list/latest-assessments endpoint or any UI — UI-surface scope,
    deliberately out of this sub-project (same boundary #2 kept from #3).

## A. The six checks

A closed `Check` enum (narrative order, `ransomware.txt` lines 51-55):

```go
type Check string

const (
    CheckDeletionProtection  Check = "deletion_protection"  // backup repositories protected against unauthorized deletion
    CheckImmutability        Check = "immutability"          // immutability/object-lock policies reject unauthorized modification
    CheckOfflineIsolation    Check = "offline_isolation"      // offline/logically-isolated copies unreachable via the tested compromised identity
    CheckPrivilegeSeparation Check = "privilege_separation"   // backup administration uses appropriate privilege separation and authentication
    CheckRestoreIntegrity    Check = "restore_integrity"      // restored files pass integrity checks and application-level validation
    CheckRPORTO              Check = "rpo_rto"                // recovery meets the customer's defined RPO/RTO
)
```

## B. Observer interfaces

One interface per check, each a 5-tuple `(tested, outcome bool,
observerID, reason string, err error)` — `outcome` is named meaningfully
per check (`protected`, `immutable`, `isolated`, `separated`, `valid`,
`met`); `observerID` is the implementation's own self-reported identity (e.g.
`"fake:deletion-protection-v1"`), never assigned by `AssessBackup` itself,
so swapping in a real observer later changes provenance without touching
dispatch code:

```go
type DeletionProtectionObserver interface {
    ObserveDeletionProtection(ctx context.Context) (tested, protected bool, observerID, reason string, err error)
}
// ImmutabilityObserver.ObserveImmutability, OfflineIsolationObserver.ObserveOfflineIsolation,
// PrivilegeSeparationObserver.ObservePrivilegeSeparation, RestoreIntegrityObserver.ObserveRestoreIntegrity,
// RPORTOObserver.ObserveRPORTO -- same 5-tuple shape, one method each.
```

Fake implementations follow the exact discipline `rwevidence.FakeRecoveryObserver`/
`FakeDetectionLookup` already established: an uncaptured key means "never
evaluated" (`tested=false`), never a guessed outcome.

## C. Observer-result classification (Adjustment 1: unambiguous truth table)

```
err != nil                          -> ERROR   ("observer failed: " + err)
err == nil, !tested &&  outcome     -> ERROR   ("observer contract violation: outcome=true but tested=false")
err == nil, !tested && !outcome     -> SKIPPED / not_tested
err == nil,  tested &&  outcome     -> PASS
err == nil,  tested && !outcome     -> FAIL
```

An observer error always takes precedence over `tested`/`outcome` — a
failed lookup must never produce a PASS. The second line is a distinct,
explicit rejection of a malformed observer response (claiming a successful
outcome while also claiming the check never ran) — it is validated, not
silently accepted as either PASS or SKIPPED.

## D. `AssessBackup` — the six-result guarantee (Adjustment 2)

`AssessBackup(ctx context.Context, deps Dependencies) []CheckResult`
always returns exactly 6 results, in the fixed enum order above, under
every failure mode:

- **Missing observer** (nil interface value in `Dependencies`): `ERROR`,
  `"no observer configured for this check"`, `observerID = "unconfigured"`
  — distinct operational cause from an observer that ran and failed.
- **Observer returns `err`**: `ERROR` per section C.
- **Observer panics**: recovered per-check (one check's panic must never
  take down the other 5) — `ERROR`, `"observer panicked: <value>"`,
  `observerID = "panicked"`.
- **Fake observer has no captured test value**: `SKIPPED`/`not_tested`,
  never a defaulted successful outcome.

A missing implementation (not configured) and an unavailable observation
(configured but returned nothing usable) are kept as distinct causes —
same ERROR verdict, different `Reason` text — since a standalone posture
assessment needs to tell an operator *why* a check didn't produce a
result, not just that it didn't.

Implementation shape: one shared helper,
`evaluate(check Check, observerNil bool, call func() (tested, outcome bool, observerID, reason string, err error)) CheckResult`,
carries the classify+recover+nil-check logic once; six explicit call
sites (not a generic polymorphic dispatch loop — 6 is a closed, final
set, not worth a reflection-based abstraction) each pass `deps.X == nil`
for `observerNil` and a closure wrapping that check's distinctly-named
observer method for `call`.

## E. `CheckResult` and the simulated-evidence invariant (Adjustment 4)

```go
type CheckResult struct {
    Check      Check
    Verdict    controlval.Verdict     // reused as a value type only
    SkipReason controlval.SkipReason  // reused as a value type only
    Reason     string
    Simulated  bool   // hardcoded true by this package in this sub-project -- never observer-controlled
    Observer   string // non-empty always: a real observerID, or "unconfigured"/"panicked"
}
```

`Simulated` is a package-level constant (`const simulated = true`) stamped
onto every `CheckResult` by `AssessBackup` itself — **never** sourced from
the observer's return value. This is deliberate: if `Simulated` were
observer-controlled, a buggy or malicious observer implementation could
silently claim real evidence. Making it structurally true everywhere in
this sub-project means flipping it requires a visible, reviewed code
change (and, per below, a reviewed migration) — not a runtime behavior
switch. **Future real observers are introduced through a separately
reviewed change that deliberately revises this constant and the
database constraint below** — not a parameter, not a config flag.

`not_applicable` stays in the reused `SkipReason` vocabulary for a future
real observer that can determine a check genuinely doesn't apply to a
customer's actual setup; no fake observer in this sub-project is expected
to produce it.

## F. Persistence (Adjustment 3: atomicity and the 6-row guarantee)

One flat table, no separate assessment-header table — the 6 rows sharing
one `assessment_id` *is* the assessment:

```sql
CREATE TABLE IF NOT EXISTS backup_assurance_results (
    id              bigserial   PRIMARY KEY,
    assessment_id   text        NOT NULL,
    check_name      text        NOT NULL,
    verdict         text        NOT NULL CHECK (verdict IN ('PASS','FAIL','ERROR','SKIPPED')),
    skip_reason     text        CHECK (skip_reason IN ('insufficient_evidence','not_applicable','not_tested') OR skip_reason IS NULL),
    reason          text        NOT NULL DEFAULT '',
    simulated       boolean     NOT NULL DEFAULT true CHECK (simulated = TRUE),
    observer        text        NOT NULL CHECK (observer <> ''),
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT backup_assurance_identity UNIQUE (assessment_id, check_name),
    CONSTRAINT backup_assurance_skip_ck CHECK (
        (verdict = 'SKIPPED' AND skip_reason IS NOT NULL) OR
        (verdict != 'SKIPPED' AND skip_reason IS NULL)
    )
);
```

`CHECK (simulated = TRUE)` enforces Adjustment 4's invariant at the
database layer, not merely in the Go caller — exactly the request: "a
future code path [must not] accidentally write real-looking evidence
without the corresponding observer and validation work." Removing or
loosening this constraint requires its own reviewed migration.

**Write path**: `WriteBackupAssuranceAssessment(ctx, pool, results
[]CheckResult) (assessmentID string, err error)` mints one UUID (via
`uuid.New()`) once per invocation, then inserts all 6 rows inside a single
`pool.Begin()`/6×`tx.Exec()`/`tx.Commit()`/`defer tx.Rollback()`
transaction. A failed write leaves **zero** rows for that assessment ID —
never a partial 3-of-6 assessment that looks complete. The function
returns the assessment ID only after a successful commit; the caller
(API handler) must not report success until this function returns a nil
error.

**Read path**: `ReadBackupAssuranceAssessment(ctx, pool, assessmentID
string) ([]CheckResult, error)` fetches every row for that ID and
explicitly checks the count:
- `0` rows → a sentinel "not found" error (handler returns 404 — this ID
  was never written).
- `1-5` rows → a distinct "incomplete assessment" error (handler returns
  500 — this should never happen given atomic writes, but if it does
  through direct DB tampering or a future bug, it must surface as a data
  integrity failure, not silently return a partial-but-successful-looking
  array of fewer than 6 results).
- `6` rows → success.

## G. Endpoints and authorization

```
POST /api/backup-assurance/assessments          (auth.CanRunScenario)
GET  /api/backup-assurance/assessments/{assessmentId}   (tierAny, read-only)
```

`POST` calls `AssessBackup` with the fake-backed `Dependencies` wired in,
writes via `WriteBackupAssuranceAssessment`, and returns the assessment ID
+ all 6 results only after a successful commit (per F). `auth.CanRunScenario`
is reused rather than a new permission invented for one endpoint — it
already gates operator-triggered security actions beyond literal scenario
runs (e.g. `GET /api/technique-verification-runs/{id}` requires it too).

`GET` calls `ReadBackupAssuranceAssessment` and maps its 3-way result (per
F) to 404 / 500 / 200 — never silently returning an arbitrary subset as if
it were a complete assessment.

No list/latest endpoint, no UI — out of scope (section "Scope" above).

## Acceptance criteria

1. Every classification-truth-table row in section C is pinned by its own
   test, including the malformed-combo rejection (`!tested && outcome`).
2. An observer error always wins over `tested`/`outcome`, even when both
   conditions could independently apply.
3. `AssessBackup` returns exactly 6 results, in the fixed enum order,
   under all 4 failure modes in section D (missing observer, observer
   error, observer panic, uncaptured fake key) — plus the normal all-6-
   succeed case.
4. A panicking observer never propagates the panic out of `AssessBackup`
   and never prevents the other 5 checks from producing their own result.
5. Every `CheckResult` `AssessBackup` produces has `Simulated == true` and
   a non-empty `Observer`.
6. `WriteBackupAssuranceAssessment`: a successful call persists all 6 rows
   under one freshly-minted assessment ID; a simulated mid-transaction
   failure (e.g. the 4th insert erroring) leaves 0 rows for that ID, not 3.
7. `WriteBackupAssuranceAssessment` rejects a result set that violates the
   DB's `ValidSkipPair`-equivalent pairing before ever opening a
   transaction (same discipline as sub-project #1's `WriteRWCapabilityResults`).
8. `ReadBackupAssuranceAssessment` distinguishes all 3 cases in section F
   (0 rows / 1-5 rows / 6 rows) with different, correct outcomes.
9. `GET .../assessments/{assessmentId}` for a never-written ID returns 404;
   for an ID with a simulated incomplete row set returns 500; for a real
   6-row assessment returns 200 with all 6 results.
10. `POST .../assessments` requires `auth.CanRunScenario` — an
    unauthenticated or under-permissioned request never reaches
    `AssessBackup`.
11. The `backup_assurance_results` table rejects an INSERT with
    `simulated = FALSE` at the database layer (proving the DB-level
    enforcement, not just a Go-side check).

## Review Focus (for the implementation plan to pin with tests)

- The malformed-combo branch (`!tested && outcome`) in section C is the
  one row in the truth table an implementer could plausibly skip,
  treating it as equivalent to either SKIPPED or PASS — a test must prove
  it is neither.
- The panic-recovery requirement in section D is easy to leave untested
  (nothing else in this codebase's fake-backed observers panics on
  purpose) — a test that makes a fake observer panic and asserts the
  other 5 checks still produce results is the only thing that catches a
  missing `recover()`.
- The atomic-write failure contract in section F (zero rows on partial
  failure) needs a test that forces a failure partway through the 6
  inserts (e.g. a duplicate-key collision on a pre-seeded row) and proves
  the whole transaction rolled back — not just that the function returned
  an error.
- The DB-level `CHECK (simulated = TRUE)` constraint (section F) needs a
  test that attempts a direct `simulated = FALSE` insert and asserts the
  database itself rejects it — a Go-side-only test would miss a dropped
  or mistyped constraint in a future migration.
