# Test Generation Phase 1 — verification + relationships Store Tests — Design

**Status:** Approved (2026-07-09).

## Problem

`internal/verification` (SP2 Verification Store) and `internal/relationships`
(CVE-ATT&CK Relationship Store) are both zero-test packages implementing
non-trivial state machines over Postgres: append-only attestation history
with optimistic-concurrency supersede logic, and confidence/lifecycle
tracking with a proposed-vs-effective split. Per the Phase 0 test generation
strategy (`docs/superpowers/specs/2026-07-09-test-generation-strategy-design.md`),
these are Phase 1 — the first packages tested, chosen to prove the
`internal/testutil` Postgres harness on small, well-understood state
machines before the much larger `api` package (Phase 3).

## Scope

Store-layer only: `internal/verification.Store` and
`internal/relationships.Store`. `internal/api/verification_handlers.go` and
`internal/api/relationship_handlers.go` (RBAC, request validation, HTTP
wiring around these same stores) are explicitly Phase 3's scope — repository
correctness is proven here first, so Phase 3 can focus purely on HTTP/RBAC
behavior without re-deriving DB correctness.

## Architecture

Both packages get one `TestMain` (via `testutil.MustSharedTestDB`, one
container per package, matching the Phase 0 pattern) and split their tests
by the same CRUD/evidence boundary already present in each `store.go`:

```
internal/verification/
  store_test.go        — Attest, CurrentForRun, History, Get, isUniqueViolation
  evidence_test.go      — AddEvidence, ListEvidence, EvidenceByID, EvidenceBytes,
                           SoftDeleteEvidence, EvidenceCountsForRun
  concurrency_test.go    — real concurrent Attest() races

internal/relationships/
  store_test.go         — Create, Update, Review, SetStatus, ForTechnique, Get,
                           isUniqueViolation
  evidence_test.go      — AddEvidence, ListEvidence, EvidenceByID,
                           SoftDeleteEvidence, EvidenceCounts
```

Most tests use `sharedDB.RunInTx` (rollback isolation). The concurrency
tests need real committed transactions to trigger a genuine Postgres unique
violation, so they use `sharedDB.RunWithPool` instead, with explicit
per-subtest cleanup via truncation (already built into `RunWithPool`).

## Test Coverage (per method)

**`verification.Store`**

- `Attest`: default-filling (empty `WorkflowState`→`Approved`, empty
  `Source`→`Manual`); first attestation for a pair (`SupersedesID` empty);
  second attestation supersedes the first (old `Active` flips false, new row
  `Active=true`, `SupersedesID`=old ID); `History` returns both, newest
  first; **two goroutines racing `Attest` with no prior row for the same
  `(run_id, expectation_id)`** — exactly one succeeds, the other gets
  `ErrConflict`; **two goroutines racing a second `Attest` when a prior
  active row exists** — the `FOR UPDATE` lock serializes them, both succeed
  but produce a single linear supersede chain (no double-active state).
- `CurrentForRun`: only active rows, keyed by `ExpectationID`, superseded
  rows excluded.
- `Get`: found vs `ok=false`.
- `AddEvidence`: SHA-256 hash matches a local recomputation of the same
  bytes; `DisplayFilename` defaults to `OriginalFilename` when empty; blob +
  metadata land together (verified via `EvidenceBytes` round-trip).
- `ListEvidence` / `EvidenceCountsForRun`: soft-deleted rows excluded from
  both.
- `EvidenceBytes`: errors for a non-`StorageDatabase` `Evidence` (construct
  one directly with `StorageType: StorageFilesystem`).
- `SoftDeleteEvidence`: idempotent — a second delete call is a no-op, not an
  error.
- `isUniqueViolation`: pure-function test, no DB — a fake error implementing
  `SQLState() string` covers both the 23505-match and non-match branches.

**`relationships.Store`**

- `Create`: default-filling (`ProposedConfidence`→Medium,
  `PrimarySource`→Analyst); `EffectiveConfidence` starts equal to
  `ProposedConfidence`; `ErrDuplicate` on a second `Create` with the same
  `(technique_id, cve_id, relationship_type)`; a *different*
  `relationship_type` for the same pair succeeds (proves the constraint is
  on the triple).
- `Update`: descriptive fields change; `EffectiveConfidence`/`Status`
  untouched; `UpdateResult.OldConfidence`/`OldRationale` reflect the
  pre-update row; `pgx.ErrNoRows` for a missing id; `ErrDuplicate` when an
  update's new `relationship_type` collides with another existing row for
  the same pair.
- `Review`: `EffectiveConfidence` diverges from `ProposedConfidence`
  independently; `ReviewedBy`/`LastReviewedAt` set.
- `SetStatus`: each lifecycle transition (Active→Deprecated/Disputed/
  Retired, and back to Active); `StatusChangedBy/At/Reason` recorded.
- `ForTechnique`: all relationships regardless of status, newest first.
- `Get`: found vs `ok=false`.
- `AddEvidence`/`ListEvidence`/`EvidenceByID`/`SoftDeleteEvidence`/
  `EvidenceCounts`: same shape as verification's evidence tests, plus
  `EvidenceCounts`'s batch (multi-id) behavior and its empty-slice
  short-circuit (`len(relationshipIDs) == 0` returns `{}` with no query).
- `isUniqueViolation`: pure-function test, same pattern as verification's.

## Coverage Target

95-98%, per the Phase 0 strategy doc's table for these two packages —
realistic given both stores are small (428/387 lines), single-responsibility,
and every branch above is independently triggerable through real Postgres.

## Testing

This entire spec *is* a testing plan — no separate "how this gets tested"
section applies. Verification is `go test ./internal/verification/...
./internal/relationships/... -v -cover` passing with coverage at or above
target, plus the existing module-wide `gofmt`/`vet`/`staticcheck`/`build`
gates from Phase 0's CI workflow staying green.
