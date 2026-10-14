# Backup Assurance Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A standalone, fake-backed Backup Assurance engine: 6 independent infrastructure-posture checks, persisted as atomic assessments, reachable through a trigger + retrieve API pair — fully independent of `rwscore` and scenario dispatch.

**Architecture:** A new pure-Go package `internal/backupassurance` models the 6 checks as a closed enum with one observer interface each, classifies each observer's result through an explicit 5-branch truth table, and always returns exactly 6 results via `AssessBackup`. A new `internal/db` store mints one shared ID per invocation (via Postgres's own `gen_random_uuid()`, the same mechanism `rw_capability_results.id` already uses) and writes all 6 rows in one transaction. Two new `internal/api` handlers wire fake observers in and expose trigger/retrieve endpoints.

**Tech Stack:** Go, `controlval.Verdict`/`SkipReason` (value types only), pgx/pgxpool, chi router — all already in this codebase; no new dependency.

**Spec:** `docs/superpowers/specs/2026-10-11-backup-assurance-engine-design.md`

## Global Constraints

- Exactly 6 checks, this fixed order: `deletion_protection`, `immutability`, `offline_isolation`, `privilege_separation`, `restore_integrity`, `rpo_rto` (spec section A).
- Classification is a 5-branch decision tree, `err` always wins first, the malformed `!tested && outcome` combo is its own ERROR branch, never silently treated as PASS/SKIPPED (spec section C).
- `AssessBackup` always returns exactly 6 results, in fixed order, under every failure mode: missing observer (ERROR, `"no observer configured for this check"`, `Observer="unconfigured"`), observer error (ERROR), observer panic (recovered per-check, ERROR, `Observer="panicked"`), uncaptured fake key (SKIPPED/not_tested) (spec section D).
- `Simulated` is a package-level constant stamped by `AssessBackup` itself — never observer-controlled, never a parameter (spec section E).
- `Observer` is always non-empty (spec section E).
- One flat table, no header table; `UNIQUE(assessment_id, check_name)`; DB-level `CHECK (simulated = TRUE)`; DB-level verdict/skip_reason pairing CHECK (spec section F).
- A failed write leaves zero rows for that assessment, never a partial set; a read of 1-5 rows is a data-integrity error, never a silently-returned subset (spec section F).
- `POST /api/backup-assurance/assessments` requires `auth.CanRunScenario`; `GET .../assessments/{assessmentId}` is `tierAny` (spec section G).
- No list/latest endpoint, no UI, no real backup-platform integration — all deliberately out of scope (spec "Scope").

## Review Focus

- The malformed-combo branch (`!tested && outcome`) is the one truth-table row an implementation could plausibly collapse into SKIPPED or PASS — Task 2's tests must prove it is neither.
- The panic-recovery requirement in `AssessBackup` is easy to leave untested since nothing else in this codebase's fake observers panics on purpose — Task 3 pins it with a fake that panics on demand.
- The atomic-write failure contract (zero rows on partial failure) needs a test that forces a real mid-transaction failure, not just a function call that returns an error — Task 4 forces a duplicate-key collision on the 2nd insert and checks the row count afterward.
- The DB-level `CHECK (simulated = TRUE)` constraint needs a test that attempts a direct `simulated = FALSE` insert and asserts Postgres itself rejects it — a Go-side-only test would miss a dropped or mistyped constraint in a future migration. Task 4 pins this.
- A nonexistent `assessmentId` (404) and an incomplete-row-count assessment (500) are different failure causes that a naive implementation could collapse into the same response — Task 5's tests pin both as distinct outcomes.

---

### Task 1: `backupassurance` package — types, the 6 observer interfaces, fake implementations

**Files:**
- Create: `orchestrator/internal/backupassurance/types.go`
- Create: `orchestrator/internal/backupassurance/observers.go`
- Create: `orchestrator/internal/backupassurance/observers_test.go`

**Interfaces:**
- Consumes: `controlval.Verdict`, `controlval.SkipReason`, `controlval.ValidSkipPair` (existing, `internal/controlval/controlval.go`).
- Produces: `Check` (6 constants), `CheckResult{Check, Verdict, SkipReason, Reason, Simulated, Observer}` + its `Valid() error` method, 6 observer interfaces (`DeletionProtectionObserver`, `ImmutabilityObserver`, `OfflineIsolationObserver`, `PrivilegeSeparationObserver`, `RestoreIntegrityObserver`, `RPORTOObserver`) each with one distinctly-named method, 6 fake implementations (`FakeDeletionProtectionObserver`, etc.) — Task 3 constructs and wires these directly.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/backupassurance/observers_test.go`:

```go
package backupassurance

import (
	"context"
	"testing"
)

func TestFakeDeletionProtectionObserver_UncapturedKeyIsNeverTested(t *testing.T) {
	f := &FakeDeletionProtectionObserver{}
	tested, protected, observerID, _, err := f.ObserveDeletionProtection(context.Background())
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if tested {
		t.Fatal("tested = true, want false -- an uncaptured key must never be treated as evaluated")
	}
	if protected {
		t.Fatal("protected = true, want false -- an untested check must never default to a successful outcome")
	}
	if observerID == "" {
		t.Fatal("observerID is empty, want a non-empty self-reported identity even for an untested fake")
	}
}

func TestFakeDeletionProtectionObserver_CapturedValueIsReturnedVerbatim(t *testing.T) {
	f := &FakeDeletionProtectionObserver{Tested: true, Protected: true, Reason: "object lock enabled"}
	tested, protected, _, reason, err := f.ObserveDeletionProtection(context.Background())
	if err != nil || !tested || !protected || reason != "object lock enabled" {
		t.Fatalf("got tested=%v protected=%v reason=%q err=%v, want tested=true protected=true reason=%q err=nil", tested, protected, reason, err, "object lock enabled")
	}
}

func TestCheckResult_ValidRejectsSkippedWithoutSkipReason(t *testing.T) {
	cr := CheckResult{Check: CheckDeletionProtection, Verdict: "SKIPPED", Simulated: true, Observer: "x"}
	if err := cr.Valid(); err == nil {
		t.Fatal("Valid() = nil, want an error -- SKIPPED must carry one of the 3 recognized SkipReasons")
	}
}

func TestCheckResult_ValidAcceptsPassWithNoSkipReason(t *testing.T) {
	cr := CheckResult{Check: CheckDeletionProtection, Verdict: "PASS", Simulated: true, Observer: "x"}
	if err := cr.Valid(); err != nil {
		t.Fatalf("Valid() = %v, want nil", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/backupassurance/ -v`
Expected: FAIL — `undefined: FakeDeletionProtectionObserver`, `undefined: CheckResult`, `undefined: CheckDeletionProtection` (compile error; the package doesn't exist yet)

- [ ] **Step 3: Implement `types.go` and `observers.go`**

Create `orchestrator/internal/backupassurance/types.go`:

```go
// Package backupassurance is a standalone infrastructure-posture engine:
// 6 independent checks against a customer's backup/recovery setup,
// structurally separate from rwevidence (per-attack-attempt outcomes) and
// rwscore (weighted scoring over those outcomes). Pure Go, no DB import --
// controlval.Verdict/SkipReason are reused as value types only, never its
// Provider/CorrelationKey machinery, which assumes an attack-attempt shape
// these checks don't have.
package backupassurance

import "github.com/audspect/bas/internal/controlval"

// Check names one of the 6 backup-assurance checks (ransomware.txt lines
// 51-55 -- the narrative's own order, which is authoritative: the
// decomposition table's "6 sub-checks" row names only 5, dropping
// deletion_protection from its own list while still claiming 6).
type Check string

const (
	CheckDeletionProtection  Check = "deletion_protection"
	CheckImmutability        Check = "immutability"
	CheckOfflineIsolation    Check = "offline_isolation"
	CheckPrivilegeSeparation Check = "privilege_separation"
	CheckRestoreIntegrity    Check = "restore_integrity"
	CheckRPORTO              Check = "rpo_rto"
)

// allChecks is the fixed enum order AssessBackup always returns in.
var allChecks = []Check{
	CheckDeletionProtection, CheckImmutability, CheckOfflineIsolation,
	CheckPrivilegeSeparation, CheckRestoreIntegrity, CheckRPORTO,
}

// simulated is hardcoded for this entire sub-project -- never observer-
// controlled, never a parameter. A future real observer is introduced
// through a separately reviewed change that deliberately revises this
// constant and the database's own CHECK (simulated = TRUE) constraint
// (Task 4) -- not a runtime config flag.
const simulated = true

// CheckResult is one check's classified outcome.
type CheckResult struct {
	Check      Check
	Verdict    controlval.Verdict
	SkipReason controlval.SkipReason
	Reason     string
	Simulated  bool
	Observer   string // always non-empty: a real observerID, or "unconfigured"/"panicked"
}

// Valid delegates to controlval.ValidSkipPair -- the single, shared place
// that catches an invalid Verdict/SkipReason combination, never a second
// copy of the rule.
func (cr CheckResult) Valid() error {
	return controlval.ValidSkipPair(cr.Verdict, cr.SkipReason)
}
```

Create `orchestrator/internal/backupassurance/observers.go`:

```go
package backupassurance

import "context"

// Each observer interface is a 5-tuple (tested, outcome bool, observerID,
// reason string, err error) -- outcome is named meaningfully per check.
// observerID is the implementation's own self-reported identity (never
// assigned by AssessBackup), so swapping in a real observer later changes
// provenance without touching dispatch code.

type DeletionProtectionObserver interface {
	ObserveDeletionProtection(ctx context.Context) (tested, protected bool, observerID, reason string, err error)
}

type ImmutabilityObserver interface {
	ObserveImmutability(ctx context.Context) (tested, immutable bool, observerID, reason string, err error)
}

type OfflineIsolationObserver interface {
	ObserveOfflineIsolation(ctx context.Context) (tested, isolated bool, observerID, reason string, err error)
}

type PrivilegeSeparationObserver interface {
	ObservePrivilegeSeparation(ctx context.Context) (tested, separated bool, observerID, reason string, err error)
}

type RestoreIntegrityObserver interface {
	ObserveRestoreIntegrity(ctx context.Context) (tested, valid bool, observerID, reason string, err error)
}

type RPORTOObserver interface {
	ObserveRPORTO(ctx context.Context) (tested, met bool, observerID, reason string, err error)
}

// Fake implementations: an uncaptured key (the zero value, Tested=false)
// means "never evaluated" -- never a guessed outcome. Same discipline as
// rwevidence.FakeRecoveryObserver/FakeDetectionLookup.

type FakeDeletionProtectionObserver struct {
	Tested, Protected bool
	Reason, Observer  string
	Err               error
}

func (f *FakeDeletionProtectionObserver) ObserveDeletionProtection(_ context.Context) (bool, bool, string, string, error) {
	obs := f.Observer
	if obs == "" {
		obs = "fake:deletion-protection-v1"
	}
	return f.Tested, f.Protected, obs, f.Reason, f.Err
}

type FakeImmutabilityObserver struct {
	Tested, Immutable bool
	Reason, Observer  string
	Err               error
}

func (f *FakeImmutabilityObserver) ObserveImmutability(_ context.Context) (bool, bool, string, string, error) {
	obs := f.Observer
	if obs == "" {
		obs = "fake:immutability-v1"
	}
	return f.Tested, f.Immutable, obs, f.Reason, f.Err
}

type FakeOfflineIsolationObserver struct {
	Tested, Isolated bool
	Reason, Observer string
	Err              error
}

func (f *FakeOfflineIsolationObserver) ObserveOfflineIsolation(_ context.Context) (bool, bool, string, string, error) {
	obs := f.Observer
	if obs == "" {
		obs = "fake:offline-isolation-v1"
	}
	return f.Tested, f.Isolated, obs, f.Reason, f.Err
}

type FakePrivilegeSeparationObserver struct {
	Tested, Separated bool
	Reason, Observer  string
	Err               error
}

func (f *FakePrivilegeSeparationObserver) ObservePrivilegeSeparation(_ context.Context) (bool, bool, string, string, error) {
	obs := f.Observer
	if obs == "" {
		obs = "fake:privilege-separation-v1"
	}
	return f.Tested, f.Separated, obs, f.Reason, f.Err
}

type FakeRestoreIntegrityObserver struct {
	Tested, ValidResult bool
	Reason, Observer    string
	Err                 error
}

func (f *FakeRestoreIntegrityObserver) ObserveRestoreIntegrity(_ context.Context) (bool, bool, string, string, error) {
	obs := f.Observer
	if obs == "" {
		obs = "fake:restore-integrity-v1"
	}
	return f.Tested, f.ValidResult, obs, f.Reason, f.Err
}

type FakeRPORTOObserver struct {
	Tested, Met      bool
	Reason, Observer string
	Err              error
}

func (f *FakeRPORTOObserver) ObserveRPORTO(_ context.Context) (bool, bool, string, string, error) {
	obs := f.Observer
	if obs == "" {
		obs = "fake:rpo-rto-v1"
	}
	return f.Tested, f.Met, obs, f.Reason, f.Err
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/backupassurance/ -v`
Expected: PASS (4/4)

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/backupassurance/types.go internal/backupassurance/observers.go internal/backupassurance/observers_test.go
git commit -m "feat(backupassurance): package skeleton -- 6 checks, observer interfaces, fakes

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 2: Classification truth table

**Files:**
- Create: `orchestrator/internal/backupassurance/classify.go`
- Create: `orchestrator/internal/backupassurance/classify_test.go`

**Interfaces:**
- Consumes: `controlval.Verdict`/`SkipReason` constants (existing).
- Produces: `classifyObserverResult(tested, outcome bool, reason string, err error) (controlval.Verdict, controlval.SkipReason, string)` — Task 3's `evaluate` helper calls this directly (same package).

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/backupassurance/classify_test.go`:

```go
package backupassurance

import (
	"errors"
	"testing"

	"github.com/audspect/bas/internal/controlval"
)

func TestClassify_ErrorTakesPrecedenceOverEverything(t *testing.T) {
	v, sr, reason := classifyObserverResult(true, true, "looks fine", errors.New("connection reset"))
	if v != controlval.VerdictError {
		t.Fatalf("Verdict = %q, want ERROR -- an observer error must always win, even when tested=true and outcome=true", v)
	}
	if sr != "" {
		t.Fatalf("SkipReason = %q, want empty for an ERROR verdict", sr)
	}
	if reason == "" {
		t.Fatal("reason is empty, want the wrapped error text")
	}
}

func TestClassify_MalformedComboIsRejectedAsErrorNotSkippedOrPass(t *testing.T) {
	// The one row a naive implementation could collapse into SKIPPED (since
	// tested=false) or PASS (since outcome=true) -- it must be neither.
	v, sr, _ := classifyObserverResult(false, true, "", nil)
	if v != controlval.VerdictError {
		t.Fatalf("Verdict = %q, want ERROR for the malformed tested=false/outcome=true combo", v)
	}
	if sr != "" {
		t.Fatalf("SkipReason = %q, want empty for an ERROR verdict", sr)
	}
}

func TestClassify_NotTestedIsSkippedNotTested(t *testing.T) {
	v, sr, _ := classifyObserverResult(false, false, "", nil)
	if v != controlval.VerdictSkipped || sr != controlval.SkipNotTested {
		t.Fatalf("got Verdict=%q SkipReason=%q, want SKIPPED/not_tested", v, sr)
	}
}

func TestClassify_TestedAndOutcomeIsPass(t *testing.T) {
	v, sr, _ := classifyObserverResult(true, true, "", nil)
	if v != controlval.VerdictPass || sr != "" {
		t.Fatalf("got Verdict=%q SkipReason=%q, want PASS/empty", v, sr)
	}
}

func TestClassify_TestedWithoutOutcomeIsFail(t *testing.T) {
	v, sr, _ := classifyObserverResult(true, false, "", nil)
	if v != controlval.VerdictFail || sr != "" {
		t.Fatalf("got Verdict=%q SkipReason=%q, want FAIL/empty", v, sr)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/backupassurance/ -run TestClassify -v`
Expected: FAIL — `undefined: classifyObserverResult` (compile error)

- [ ] **Step 3: Implement `classify.go`**

Create `orchestrator/internal/backupassurance/classify.go`:

```go
package backupassurance

import (
	"fmt"

	"github.com/audspect/bas/internal/controlval"
)

// classifyObserverResult is the 5-branch decision tree (spec section C).
// An observer error always wins over tested/outcome -- a failed lookup
// must never produce a PASS. The second branch is a deliberate rejection
// of a malformed observer response (claiming a successful outcome while
// also claiming the check never ran) -- validated, never silently
// accepted as either SKIPPED or PASS.
func classifyObserverResult(tested, outcome bool, reason string, err error) (controlval.Verdict, controlval.SkipReason, string) {
	if err != nil {
		return controlval.VerdictError, "", "observer failed: " + err.Error()
	}
	if !tested && outcome {
		return controlval.VerdictError, "", fmt.Sprintf("observer contract violation: outcome=true but tested=false (reason=%q)", reason)
	}
	if !tested {
		return controlval.VerdictSkipped, controlval.SkipNotTested, reason
	}
	if outcome {
		return controlval.VerdictPass, "", reason
	}
	return controlval.VerdictFail, "", reason
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/backupassurance/ -run TestClassify -v`
Expected: PASS (5/5)

- [ ] **Step 5: Run the full package to verify nothing else broke**

Run: `cd orchestrator && go test ./internal/backupassurance/ -v`
Expected: PASS (9/9 — Task 1's 4 + Task 2's 5)

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add internal/backupassurance/classify.go internal/backupassurance/classify_test.go
git commit -m "feat(backupassurance): classifyObserverResult -- the 5-branch truth table

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 3: `AssessBackup` — the six-result guarantee under every failure mode

**Files:**
- Create: `orchestrator/internal/backupassurance/assess.go`
- Create: `orchestrator/internal/backupassurance/assess_test.go`

**Interfaces:**
- Consumes: `Check`, `allChecks`, `CheckResult`, `classifyObserverResult` (Tasks 1-2), all 6 observer interfaces and fakes (Task 1).
- Produces: `Dependencies{DeletionProtection, Immutability, OfflineIsolation, PrivilegeSeparation, RestoreIntegrity, RPORTO}` (one field per observer interface), `AssessBackup(ctx context.Context, deps Dependencies) []CheckResult` — Task 5's handler calls this directly.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/backupassurance/assess_test.go`:

```go
package backupassurance

import (
	"context"
	"errors"
	"testing"
)

func allFakesPassing() Dependencies {
	return Dependencies{
		DeletionProtection:  &FakeDeletionProtectionObserver{Tested: true, Protected: true},
		Immutability:        &FakeImmutabilityObserver{Tested: true, Immutable: true},
		OfflineIsolation:    &FakeOfflineIsolationObserver{Tested: true, Isolated: true},
		PrivilegeSeparation: &FakePrivilegeSeparationObserver{Tested: true, Separated: true},
		RestoreIntegrity:    &FakeRestoreIntegrityObserver{Tested: true, ValidResult: true},
		RPORTO:              &FakeRPORTOObserver{Tested: true, Met: true},
	}
}

func TestAssessBackup_AllPassingReturnsSixResultsInFixedOrder(t *testing.T) {
	results := AssessBackup(context.Background(), allFakesPassing())
	if len(results) != 6 {
		t.Fatalf("got %d results, want 6", len(results))
	}
	want := []Check{CheckDeletionProtection, CheckImmutability, CheckOfflineIsolation, CheckPrivilegeSeparation, CheckRestoreIntegrity, CheckRPORTO}
	for i, r := range results {
		if r.Check != want[i] {
			t.Fatalf("results[%d].Check = %q, want %q -- order must be fixed", i, r.Check, want[i])
		}
		if r.Verdict != "PASS" {
			t.Fatalf("results[%d].Verdict = %q, want PASS", i, r.Verdict)
		}
		if !r.Simulated {
			t.Fatalf("results[%d].Simulated = false, want true", i)
		}
		if r.Observer == "" {
			t.Fatalf("results[%d].Observer is empty, want non-empty", i)
		}
	}
}

func TestAssessBackup_MissingObserverIsErrorNotPanic(t *testing.T) {
	deps := allFakesPassing()
	deps.RPORTO = nil // missing dependency
	results := AssessBackup(context.Background(), deps)
	if len(results) != 6 {
		t.Fatalf("got %d results, want 6 even with a missing dependency", len(results))
	}
	var rpo CheckResult
	for _, r := range results {
		if r.Check == CheckRPORTO {
			rpo = r
		}
	}
	if rpo.Verdict != "ERROR" {
		t.Fatalf("RPORTO Verdict = %q, want ERROR for a missing observer", rpo.Verdict)
	}
	if rpo.Observer != "unconfigured" {
		t.Fatalf("RPORTO Observer = %q, want \"unconfigured\"", rpo.Observer)
	}
}

func TestAssessBackup_ObserverErrorIsError(t *testing.T) {
	deps := allFakesPassing()
	deps.Immutability = &FakeImmutabilityObserver{Err: errors.New("storage API unreachable")}
	results := AssessBackup(context.Background(), deps)
	for _, r := range results {
		if r.Check == CheckImmutability && r.Verdict != "ERROR" {
			t.Fatalf("Immutability Verdict = %q, want ERROR", r.Verdict)
		}
	}
}

// panickingObserver always panics -- used only to prove AssessBackup
// recovers per-check and the other 5 checks still produce results.
type panickingObserver struct{}

func (panickingObserver) ObserveOfflineIsolation(context.Context) (bool, bool, string, string, error) {
	panic("simulated observer crash")
}

func TestAssessBackup_PanickingObserverIsRecoveredAndOthersStillRun(t *testing.T) {
	deps := allFakesPassing()
	deps.OfflineIsolation = panickingObserver{}
	results := AssessBackup(context.Background(), deps)
	if len(results) != 6 {
		t.Fatalf("got %d results, want 6 even when one observer panics", len(results))
	}
	for _, r := range results {
		if r.Check == CheckOfflineIsolation {
			if r.Verdict != "ERROR" || r.Observer != "panicked" {
				t.Fatalf("OfflineIsolation got Verdict=%q Observer=%q, want ERROR/\"panicked\"", r.Verdict, r.Observer)
			}
			continue
		}
		if r.Verdict != "PASS" {
			t.Fatalf("%s Verdict = %q, want PASS -- one panicking check must never affect the other 5", r.Check, r.Verdict)
		}
	}
}

func TestAssessBackup_UncapturedFakeKeyIsSkippedNotTested(t *testing.T) {
	deps := allFakesPassing()
	deps.DeletionProtection = &FakeDeletionProtectionObserver{} // zero value: never captured
	results := AssessBackup(context.Background(), deps)
	for _, r := range results {
		if r.Check == CheckDeletionProtection {
			if r.Verdict != "SKIPPED" || r.SkipReason != "not_tested" {
				t.Fatalf("got Verdict=%q SkipReason=%q, want SKIPPED/not_tested", r.Verdict, r.SkipReason)
			}
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/backupassurance/ -run TestAssessBackup -v`
Expected: FAIL — `undefined: AssessBackup`, `undefined: Dependencies` (compile error)

- [ ] **Step 3: Implement `assess.go`**

Create `orchestrator/internal/backupassurance/assess.go`:

```go
package backupassurance

import (
	"context"
	"fmt"

	"github.com/audspect/bas/internal/controlval"
)

// Dependencies bundles the 6 fake-backed observers AssessBackup needs. A
// nil field means "no observer configured for this check" -- distinct
// from an observer that ran and returned an error (different operational
// cause, same ERROR verdict).
type Dependencies struct {
	DeletionProtection  DeletionProtectionObserver
	Immutability        ImmutabilityObserver
	OfflineIsolation    OfflineIsolationObserver
	PrivilegeSeparation PrivilegeSeparationObserver
	RestoreIntegrity    RestoreIntegrityObserver
	RPORTO              RPORTOObserver
}

// AssessBackup always returns exactly 6 results, in allChecks' fixed
// order, under every failure mode (spec section D). Not a generic
// reflection-based dispatch loop -- 6 is a closed, final set, so each
// check gets its own explicit call site; the shared evaluate() helper
// carries the nil-check, panic-recovery, and classification logic once.
func AssessBackup(ctx context.Context, deps Dependencies) []CheckResult {
	return []CheckResult{
		evaluate(CheckDeletionProtection, deps.DeletionProtection == nil, func() (bool, bool, string, string, error) {
			return deps.DeletionProtection.ObserveDeletionProtection(ctx)
		}),
		evaluate(CheckImmutability, deps.Immutability == nil, func() (bool, bool, string, string, error) {
			return deps.Immutability.ObserveImmutability(ctx)
		}),
		evaluate(CheckOfflineIsolation, deps.OfflineIsolation == nil, func() (bool, bool, string, string, error) {
			return deps.OfflineIsolation.ObserveOfflineIsolation(ctx)
		}),
		evaluate(CheckPrivilegeSeparation, deps.PrivilegeSeparation == nil, func() (bool, bool, string, string, error) {
			return deps.PrivilegeSeparation.ObservePrivilegeSeparation(ctx)
		}),
		evaluate(CheckRestoreIntegrity, deps.RestoreIntegrity == nil, func() (bool, bool, string, string, error) {
			return deps.RestoreIntegrity.ObserveRestoreIntegrity(ctx)
		}),
		evaluate(CheckRPORTO, deps.RPORTO == nil, func() (bool, bool, string, string, error) {
			return deps.RPORTO.ObserveRPORTO(ctx)
		}),
	}
}

// evaluate carries the nil-check, panic-recovery, and classification
// logic shared by all 6 checks. call's signature is (tested, outcome
// bool, observerID, reason string, err error).
func evaluate(check Check, observerNil bool, call func() (bool, bool, string, string, error)) (result CheckResult) {
	defer func() {
		if r := recover(); r != nil {
			result = CheckResult{Check: check, Verdict: controlval.VerdictError, Reason: fmt.Sprintf("observer panicked: %v", r), Simulated: simulated, Observer: "panicked"}
		}
	}()
	if observerNil {
		return CheckResult{Check: check, Verdict: controlval.VerdictError, Reason: "no observer configured for this check", Simulated: simulated, Observer: "unconfigured"}
	}
	tested, outcome, observerID, reason, err := call()
	verdict, skipReason, finalReason := classifyObserverResult(tested, outcome, reason, err)
	return CheckResult{Check: check, Verdict: verdict, SkipReason: skipReason, Reason: finalReason, Simulated: simulated, Observer: observerID}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/backupassurance/ -run TestAssessBackup -v`
Expected: PASS (5/5)

- [ ] **Step 5: Run the full package to verify nothing else broke**

Run: `cd orchestrator && go test ./internal/backupassurance/ -v`
Expected: PASS (14/14 — Tasks 1-3's 4+5+5)

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add internal/backupassurance/assess.go internal/backupassurance/assess_test.go
git commit -m "feat(backupassurance): AssessBackup -- six-result guarantee under every failure mode

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 4: Persistence — migration, atomic write, 3-way read

**Files:**
- Modify: `orchestrator/internal/db/postgres.go` (add `backup_assurance_results` to `EnsureSchema`, right after the `rw_capability_results` block at line ~1846)
- Create: `orchestrator/internal/db/backupassurance_store.go`
- Create: `orchestrator/internal/db/backupassurance_store_test.go`

**Interfaces:**
- Consumes: `backupassurance.Check`, `backupassurance.CheckResult` (Tasks 1-3).
- Produces: `db.WriteBackupAssuranceAssessment(ctx, pool, results []backupassurance.CheckResult) (assessmentID string, err error)`, `db.ErrAssessmentNotFound`, `db.ErrAssessmentIncomplete` (sentinel errors), `db.ReadBackupAssuranceAssessment(ctx, pool, assessmentID string) ([]backupassurance.CheckResult, error)` — Task 5's handler calls both directly.

This package's tests need a real Postgres connection, same container-backed pattern as sub-project #1/#2's `internal/db` tests (`sharedDB`/`testutil.TestDB`).

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/db/backupassurance_store_test.go`:

```go
package db_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/backupassurance"
	"github.com/audspect/bas/internal/db"
)

func sixPassingResults() []backupassurance.CheckResult {
	out := make([]backupassurance.CheckResult, 0, 6)
	for _, c := range []backupassurance.Check{
		backupassurance.CheckDeletionProtection, backupassurance.CheckImmutability, backupassurance.CheckOfflineIsolation,
		backupassurance.CheckPrivilegeSeparation, backupassurance.CheckRestoreIntegrity, backupassurance.CheckRPORTO,
	} {
		out = append(out, backupassurance.CheckResult{Check: c, Verdict: "PASS", Simulated: true, Observer: "fake:test-v1"})
	}
	return out
}

func TestWriteBackupAssuranceAssessment_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		assessmentID, err := db.WriteBackupAssuranceAssessment(context.Background(), pool, sixPassingResults())
		if err != nil {
			t.Fatalf("write: %v", err)
		}
		if assessmentID == "" {
			t.Fatal("assessmentID is empty, want a fresh non-empty ID")
		}
		got, err := db.ReadBackupAssuranceAssessment(context.Background(), pool, assessmentID)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if len(got) != 6 {
			t.Fatalf("got %d results, want 6", len(got))
		}
	})
}

func TestWriteBackupAssuranceAssessment_RejectsInvalidSkipPairBeforeOpeningTransaction(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		bad := sixPassingResults()
		bad[0].Verdict = "SKIPPED" // no SkipReason set -- invalid pair
		_, err := db.WriteBackupAssuranceAssessment(context.Background(), pool, bad)
		if err == nil {
			t.Fatal("err = nil, want a validation error for an invalid Verdict/SkipReason pair")
		}
	})
}

func TestWriteBackupAssuranceAssessment_MidTransactionFailureLeavesZeroRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		var before int
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM backup_assurance_results`).Scan(&before); err != nil {
			t.Fatalf("count before: %v", err)
		}

		// An empty check_name would NOT violate the NOT NULL constraint (an
		// empty string is still non-null), so that can't force a real
		// mid-transaction failure. Instead duplicate check 3's name onto
		// check 4: both land under the SAME freshly-minted assessment_id
		// inside the same transaction, so the 4th insert collides with the
		// UNIQUE(assessment_id, check_name) constraint the 3rd insert just
		// satisfied -- a genuine SQL-level failure partway through the 6.
		bad := sixPassingResults()
		bad[3].Check = bad[2].Check
		_, err := db.WriteBackupAssuranceAssessment(context.Background(), pool, bad)
		if err == nil {
			t.Fatal("err = nil, want a write failure from the duplicate check_name within one assessment")
		}

		var after int
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM backup_assurance_results`).Scan(&after); err != nil {
			t.Fatalf("count after: %v", err)
		}
		if after != before {
			t.Fatalf("row count changed from %d to %d -- a failed write must leave zero new rows, not a partial 3-of-6 assessment", before, after)
		}
	})
}

func TestReadBackupAssuranceAssessment_NonexistentIDReturnsNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := db.ReadBackupAssuranceAssessment(context.Background(), pool, "does-not-exist")
		if !errors.Is(err, db.ErrAssessmentNotFound) {
			t.Fatalf("err = %v, want ErrAssessmentNotFound", err)
		}
	})
}

func TestReadBackupAssuranceAssessment_IncompleteRowCountIsDataIntegrityError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		assessmentID, err := db.WriteBackupAssuranceAssessment(context.Background(), pool, sixPassingResults())
		if err != nil {
			t.Fatalf("write: %v", err)
		}
		// Simulate corruption: delete one of the 6 rows directly.
		if _, err := pool.Exec(context.Background(), `DELETE FROM backup_assurance_results WHERE assessment_id = $1 AND check_name = 'rpo_rto'`, assessmentID); err != nil {
			t.Fatalf("corrupt: %v", err)
		}
		_, err = db.ReadBackupAssuranceAssessment(context.Background(), pool, assessmentID)
		if !errors.Is(err, db.ErrAssessmentIncomplete) {
			t.Fatalf("err = %v, want ErrAssessmentIncomplete for a 5-of-6 row count", err)
		}
	})
}

func TestBackupAssuranceResults_DatabaseRejectsSimulatedFalse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := pool.Exec(context.Background(), `
			INSERT INTO backup_assurance_results (assessment_id, check_name, verdict, simulated, observer)
			VALUES ('ba-direct-insert-test', 'deletion_protection', 'PASS', FALSE, 'direct-insert')`)
		if err == nil {
			t.Fatal("direct insert with simulated=FALSE succeeded, want the database's own CHECK (simulated = TRUE) to reject it")
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/db/ -run "TestWriteBackupAssuranceAssessment|TestReadBackupAssuranceAssessment|TestBackupAssuranceResults" -v`
Expected: FAIL — `undefined: db.WriteBackupAssuranceAssessment` (compile error)

- [ ] **Step 3: Implement the migration and the store**

Modify `orchestrator/internal/db/postgres.go` — insert immediately after the `rw_capability_results` block (after the line `)`,` that closes `CONSTRAINT rw_capres_identity UNIQUE (run_id, action, capability)`):

```go
		// ── Backup Assurance Engine (sub-project #4) ──────────────────────────
		// Standalone infrastructure-posture assessments -- independent of
		// scenario_runs/rw_capability_results (these 6 checks are not outcomes
		// of any particular MITRE technique attempt) and of rwscore (this
		// stays a separate engine, never a 6th scoring dimension).
		`CREATE TABLE IF NOT EXISTS backup_assurance_results (
			id             text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			assessment_id  text        NOT NULL,
			check_name     text        NOT NULL,
			verdict        text        NOT NULL CHECK (verdict IN ('PASS','FAIL','ERROR','SKIPPED')),
			skip_reason    text        CHECK (skip_reason IN ('insufficient_evidence','not_applicable','not_tested') OR skip_reason IS NULL),
			reason         text        NOT NULL DEFAULT '',
			simulated      boolean     NOT NULL DEFAULT true CHECK (simulated = TRUE),
			observer       text        NOT NULL CHECK (observer <> ''),
			created_at     timestamptz NOT NULL DEFAULT NOW(),

			CONSTRAINT backup_assurance_skip_ck CHECK (
				(verdict = 'SKIPPED' AND skip_reason IS NOT NULL) OR
				(verdict <> 'SKIPPED' AND skip_reason IS NULL)),
			CONSTRAINT backup_assurance_identity UNIQUE (assessment_id, check_name)
		)`,
```

Create `orchestrator/internal/db/backupassurance_store.go`:

```go
package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/backupassurance"
)

// ErrAssessmentNotFound: the given assessmentID was never written (0 rows).
var ErrAssessmentNotFound = errors.New("backup assurance assessment not found")

// ErrAssessmentIncomplete: 1-5 rows exist for the assessmentID, never 6 --
// this should be unreachable given WriteBackupAssuranceAssessment's atomic
// write, so it signals a data-integrity problem (direct tampering, a bug
// elsewhere), not a normal "not found" case. A reader must surface this,
// never silently return the partial subset as if it were complete.
var ErrAssessmentIncomplete = errors.New("backup assurance assessment has an incomplete row count")

// WriteBackupAssuranceAssessment validates every result's Verdict/SkipReason
// pairing before opening a transaction (same discipline as
// WriteRWCapabilityResults), then mints one fresh assessment_id via
// Postgres's own gen_random_uuid() (the same mechanism rw_capability_results.id
// already uses) and inserts all 6 rows under that one shared ID inside a
// single transaction -- a failure on any row rolls back every row, so a
// failed write never leaves a partial assessment that looks complete.
func WriteBackupAssuranceAssessment(ctx context.Context, pool *pgxpool.Pool, results []backupassurance.CheckResult) (string, error) {
	for _, r := range results {
		if err := r.Valid(); err != nil {
			return "", fmt.Errorf("backup_assurance_results: refusing to write invalid result for %s: %w", r.Check, err)
		}
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("backup_assurance_results: begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	var assessmentID string
	if err := tx.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&assessmentID); err != nil {
		return "", fmt.Errorf("backup_assurance_results: mint assessment id: %w", err)
	}

	for _, r := range results {
		var skipReason *string
		if r.SkipReason != "" {
			s := string(r.SkipReason)
			skipReason = &s
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO backup_assurance_results
				(assessment_id, check_name, verdict, skip_reason, reason, simulated, observer)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			assessmentID, string(r.Check), string(r.Verdict), skipReason, r.Reason, r.Simulated, r.Observer)
		if err != nil {
			return "", fmt.Errorf("backup_assurance_results: write failed for check=%s: %w", r.Check, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("backup_assurance_results: commit: %w", err)
	}
	return assessmentID, nil
}

// ReadBackupAssuranceAssessment fetches every row for assessmentID and
// explicitly checks the count: 0 rows is ErrAssessmentNotFound, 1-5 rows
// is ErrAssessmentIncomplete (a data-integrity failure, never silently
// returned as a shorter-than-expected success), 6 rows is success.
func ReadBackupAssuranceAssessment(ctx context.Context, pool *pgxpool.Pool, assessmentID string) ([]backupassurance.CheckResult, error) {
	rows, err := pool.Query(ctx, `
		SELECT check_name, verdict, COALESCE(skip_reason, ''), reason, simulated, observer
		  FROM backup_assurance_results
		 WHERE assessment_id = $1`, assessmentID)
	if err != nil {
		return nil, fmt.Errorf("backup_assurance_results: query failed for assessment=%s: %w", assessmentID, err)
	}
	defer rows.Close()

	var out []backupassurance.CheckResult
	for rows.Next() {
		var checkName, verdict, skipReason, reason, observer string
		var sim bool
		if err := rows.Scan(&checkName, &verdict, &skipReason, &reason, &sim, &observer); err != nil {
			return nil, fmt.Errorf("backup_assurance_results: scan failed for assessment=%s: %w", assessmentID, err)
		}
		out = append(out, backupassurance.CheckResult{
			Check: backupassurance.Check(checkName), Verdict: controlVerdict(verdict), SkipReason: controlSkipReason(skipReason),
			Reason: reason, Simulated: sim, Observer: observer,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("backup_assurance_results: row iteration failed for assessment=%s: %w", assessmentID, err)
	}
	switch len(out) {
	case 0:
		return nil, fmt.Errorf("%w: assessment_id=%s", ErrAssessmentNotFound, assessmentID)
	case 6:
		return out, nil
	default:
		return nil, fmt.Errorf("%w: assessment_id=%s has %d of 6 expected rows", ErrAssessmentIncomplete, assessmentID, len(out))
	}
}
```

Add two tiny local helpers to the same file (avoids importing `controlval` into this file just for two one-line conversions, while still using its exported types correctly):

```go
import "github.com/audspect/bas/internal/controlval"

func controlVerdict(s string) controlval.Verdict { return controlval.Verdict(s) }
func controlSkipReason(s string) controlval.SkipReason { return controlval.SkipReason(s) }
```

(Fold this import and these two one-line functions into the same `import`/top-of-file block shown above rather than a separate file.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/db/ -run "TestWriteBackupAssuranceAssessment|TestReadBackupAssuranceAssessment|TestBackupAssuranceResults" -v`
Expected: PASS (6/6)

- [ ] **Step 5: Run the full db package to verify nothing else broke**

Run: `cd orchestrator && go test ./internal/db/ -v 2>&1 | tail -50`
Expected: PASS — existing tables/tests unaffected (additive migration only)

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add internal/db/postgres.go internal/db/backupassurance_store.go internal/db/backupassurance_store_test.go
git commit -m "feat(db): backup_assurance_results -- atomic write, 3-way read, DB-level simulated=TRUE

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 5: API endpoints, route registration, RBAC matrix

**Files:**
- Create: `orchestrator/internal/api/backupassurance_handlers.go`
- Create: `orchestrator/internal/api/backupassurance_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go` (two new routes, inside the existing JWT-authenticated `r.Group`)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go` (two new `routeMatrix` entries — sub-project #2's Task 3 hit a real `TestRBACMatrix_NoDrift` failure from forgetting this; do not repeat it)

**Interfaces:**
- Consumes: `backupassurance.AssessBackup`, `backupassurance.Dependencies`, 6 fakes (Tasks 1-3); `db.WriteBackupAssuranceAssessment`, `db.ReadBackupAssuranceAssessment`, `db.ErrAssessmentNotFound`, `db.ErrAssessmentIncomplete` (Task 4).
- Produces: nothing new for later tasks — this is the integration point itself.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/api/backupassurance_handlers_test.go`:

```go
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestTriggerBackupAssuranceAssessment_ReturnsSixCamelCaseResults(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodPost, "/api/backup-assurance/assessments", nil)
		rec := httptest.NewRecorder()

		h.TriggerBackupAssuranceAssessment(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		for _, key := range []string{`"assessmentId"`, `"results"`, `"check"`, `"verdict"`, `"simulated"`, `"observer"`} {
			if !strings.Contains(body, key) {
				t.Fatalf("response body missing camelCase key %s; got: %s", key, body)
			}
		}
		var got struct {
			AssessmentID string `json:"assessmentId"`
			Results      []struct {
				Check     string `json:"check"`
				Simulated bool   `json:"simulated"`
			} `json:"results"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.AssessmentID == "" {
			t.Fatal("assessmentId is empty")
		}
		if len(got.Results) != 6 {
			t.Fatalf("got %d results, want 6", len(got.Results))
		}
		for _, r := range got.Results {
			if !r.Simulated {
				t.Fatalf("check %s has simulated=false, want true", r.Check)
			}
		}
	})
}

func TestGetBackupAssuranceAssessment_RealAssessmentReturnsSixResults(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")

		triggerReq := httptest.NewRequest(http.MethodPost, "/api/backup-assurance/assessments", nil)
		triggerRec := httptest.NewRecorder()
		h.TriggerBackupAssuranceAssessment(triggerRec, triggerReq)
		var triggered struct {
			AssessmentID string `json:"assessmentId"`
		}
		if err := json.Unmarshal(triggerRec.Body.Bytes(), &triggered); err != nil {
			t.Fatalf("decode trigger response: %v", err)
		}

		getReq := httptest.NewRequest(http.MethodGet, "/api/backup-assurance/assessments/"+triggered.AssessmentID, nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("assessmentId", triggered.AssessmentID)
		getReq = getReq.WithContext(context.WithValue(getReq.Context(), chi.RouteCtxKey, rctx))
		getRec := httptest.NewRecorder()

		h.GetBackupAssuranceAssessment(getRec, getReq)

		if getRec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", getRec.Code, getRec.Body.String())
		}
	})
}

func TestGetBackupAssuranceAssessment_NonexistentIDReturns404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/api/backup-assurance/assessments/does-not-exist", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("assessmentId", "does-not-exist")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		rec := httptest.NewRecorder()

		h.GetBackupAssuranceAssessment(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestGetBackupAssuranceAssessment_IncompleteRowCountReturns500(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")

		triggerReq := httptest.NewRequest(http.MethodPost, "/api/backup-assurance/assessments", nil)
		triggerRec := httptest.NewRecorder()
		h.TriggerBackupAssuranceAssessment(triggerRec, triggerReq)
		var triggered struct {
			AssessmentID string `json:"assessmentId"`
		}
		if err := json.Unmarshal(triggerRec.Body.Bytes(), &triggered); err != nil {
			t.Fatalf("decode trigger response: %v", err)
		}
		if _, err := pool.Exec(context.Background(), `DELETE FROM backup_assurance_results WHERE assessment_id = $1 AND check_name = 'rpo_rto'`, triggered.AssessmentID); err != nil {
			t.Fatalf("corrupt: %v", err)
		}

		getReq := httptest.NewRequest(http.MethodGet, "/api/backup-assurance/assessments/"+triggered.AssessmentID, nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("assessmentId", triggered.AssessmentID)
		getReq = getReq.WithContext(context.WithValue(getReq.Context(), chi.RouteCtxKey, rctx))
		getRec := httptest.NewRecorder()

		h.GetBackupAssuranceAssessment(getRec, getReq)

		if getRec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500 for an incomplete (5-of-6) assessment", getRec.Code)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/ -run "TestTriggerBackupAssuranceAssessment|TestGetBackupAssuranceAssessment" -v`
Expected: FAIL — `undefined: h.TriggerBackupAssuranceAssessment` (compile error)

- [ ] **Step 3: Implement the handlers**

Create `orchestrator/internal/api/backupassurance_handlers.go`:

```go
package api

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/backupassurance"
	"github.com/audspect/bas/internal/db"
)

// ── POST /api/backup-assurance/assessments ────────────────────────────────

type backupAssuranceCheckJSON struct {
	Check      string `json:"check"`
	Verdict    string `json:"verdict"`
	SkipReason string `json:"skipReason,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Simulated  bool   `json:"simulated"`
	Observer   string `json:"observer"`
}

type backupAssuranceAssessmentJSON struct {
	AssessmentID string                      `json:"assessmentId"`
	Results      []backupAssuranceCheckJSON `json:"results"`
}

func toAssessmentJSON(assessmentID string, results []backupassurance.CheckResult) backupAssuranceAssessmentJSON {
	out := backupAssuranceAssessmentJSON{AssessmentID: assessmentID, Results: make([]backupAssuranceCheckJSON, len(results))}
	for i, r := range results {
		out.Results[i] = backupAssuranceCheckJSON{
			Check: string(r.Check), Verdict: string(r.Verdict), SkipReason: string(r.SkipReason),
			Reason: r.Reason, Simulated: r.Simulated, Observer: r.Observer,
		}
	}
	return out
}

// fakeBackupAssuranceDependencies wires an all-fake-backed Dependencies for
// this sub-project -- every observer here returns a fixed captured value,
// standing in until a real backup-platform integration is a separately
// reviewed, lab-gated sub-project. Never promoted beyond this slice.
func fakeBackupAssuranceDependencies() backupassurance.Dependencies {
	return backupassurance.Dependencies{
		DeletionProtection:  &backupassurance.FakeDeletionProtectionObserver{Tested: true, Protected: true, Reason: "simulated: object-lock policy present"},
		Immutability:        &backupassurance.FakeImmutabilityObserver{Tested: true, Immutable: true, Reason: "simulated: immutability enabled"},
		OfflineIsolation:    &backupassurance.FakeOfflineIsolationObserver{Tested: true, Isolated: true, Reason: "simulated: offline copy unreachable from tested identity"},
		PrivilegeSeparation: &backupassurance.FakePrivilegeSeparationObserver{Tested: true, Separated: true, Reason: "simulated: backup admin uses separate credentials"},
		RestoreIntegrity:    &backupassurance.FakeRestoreIntegrityObserver{Tested: true, ValidResult: true, Reason: "simulated: restored files passed integrity checks"},
		RPORTO:              &backupassurance.FakeRPORTOObserver{Tested: true, Met: true, Reason: "simulated: recovery met defined RPO/RTO"},
	}
}

func (h *Handler) TriggerBackupAssuranceAssessment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	results := backupassurance.AssessBackup(ctx, fakeBackupAssuranceDependencies())

	assessmentID, err := db.WriteBackupAssuranceAssessment(ctx, h.db, results)
	if err != nil {
		jsonError(w, "failed to persist assessment", http.StatusInternalServerError)
		return
	}
	jsonOK(w, toAssessmentJSON(assessmentID, results))
}

// ── GET /api/backup-assurance/assessments/{assessmentId} ──────────────────

func (h *Handler) GetBackupAssuranceAssessment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	assessmentID := chi.URLParam(r, "assessmentId")

	results, err := db.ReadBackupAssuranceAssessment(ctx, h.db, assessmentID)
	switch {
	case errors.Is(err, db.ErrAssessmentNotFound):
		jsonError(w, "assessment not found", http.StatusNotFound)
		return
	case errors.Is(err, db.ErrAssessmentIncomplete):
		jsonError(w, "assessment data is incomplete", http.StatusInternalServerError)
		return
	case err != nil:
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, toAssessmentJSON(assessmentID, results))
}
```

Modify `orchestrator/internal/api/routes.go` — insert right after the existing `r.With(auth.RequirePermission(auth.CanRunScenario)).Post("/api/scenarios/{id}/run", h.RunScenario)` line (or any line inside the same JWT-authenticated `r.Group`):

```go
		r.With(auth.RequirePermission(auth.CanRunScenario)).Post("/api/backup-assurance/assessments", h.TriggerBackupAssuranceAssessment)
		r.Get("/api/backup-assurance/assessments/{assessmentId}", h.GetBackupAssuranceAssessment)
```

Modify `orchestrator/internal/api/rbac_matrix_test.go` — add both new routes to `routeMatrix` (mirroring the exact precedent at line 192 for the permission-gated POST, and the plain-`tierAny` GET precedent used throughout):

```go
	{http.MethodPost, "/api/backup-assurance/assessments", tierPermission, auth.CanRunScenario},
	{http.MethodGet, "/api/backup-assurance/assessments/{assessmentId}", tierAny, ""},
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/ -run "TestTriggerBackupAssuranceAssessment|TestGetBackupAssuranceAssessment" -v`
Expected: PASS (4/4)

- [ ] **Step 5: Run the two RBAC matrix tests explicitly**

Run: `cd orchestrator && go test ./internal/api/ -run "TestRBACMatrix_NoDrift|TestRBACMatrix_AuthorizationBoundary" -v`
Expected: PASS — `TestRBACMatrix_NoDrift` confirms both new routes are reflected in `routeMatrix` (sub-project #2 missed this on its first pass; this step exists specifically so this plan doesn't repeat it). `TestRBACMatrix_AuthorizationBoundary` is the one that actually proves acceptance criterion 10 (an under-permissioned request never reaches `AssessBackup`): it generically fires anonymous/viewer/analyst/admin requests at every `routeMatrix` entry, including both new rows, and asserts 401/403/pass-through — no new test code needed in this task, since adding the rows to `routeMatrix` is what wires this sub-project's routes into that existing generic check.

- [ ] **Step 6: Run the full api package to verify nothing else broke**

Run: `cd orchestrator && go test ./internal/api/ -timeout 20m -v 2>&1 | tail -50`
Expected: PASS — existing routes/tests unaffected (additive route registration only)

- [ ] **Step 7: Commit**

```bash
cd orchestrator
git add internal/api/backupassurance_handlers.go internal/api/backupassurance_handlers_test.go internal/api/routes.go internal/api/rbac_matrix_test.go
git commit -m "feat(api): backup-assurance trigger + retrieve endpoints

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 6: Full regression gate across all three touched packages

**Files:**
- None (verification-only task; no new code).

**Interfaces:**
- Consumes: everything from Tasks 1-5.
- Produces: nothing — this is the plan's terminal verification layer.

- [ ] **Step 1: Run the combined regression**

Run: `cd orchestrator && go test ./internal/backupassurance/ ./internal/db/ ./internal/api/ -timeout 20m -v 2>&1 | tail -80`
Expected: all three packages `ok`, 0 FAIL lines across the combined run

- [ ] **Step 2: If everything passes, there is nothing to commit for this task** — it exists only to catch anything Task 5's own narrower run might have missed from cross-package interaction between `backupassurance`, `db`, and `api` together in one invocation.
