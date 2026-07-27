# BAS → Exercise Detection Bridge — Design Spec

**Status:** Approved for planning — **depends on Phase A0**
**Author:** Audspect (brainstormed 2026-07-27)
**Scope:** Phase A1 of the "Purple Team packs" roadmap item ([[project_scenario_roadmap]]). Product-agnostic infrastructure fix + enrichment; no new scenario/template *content* beyond repairing two already-shipped built-in templates. Phase B (a curated library of Purple Team exercise templates) is a separate future spec.

**Correction (post-approval):** while writing this plan, tracing every call
site of `verification.Store.Attest` showed automatic on-host verification
results are never persisted to `verification_history` at all — only manual
and SP3 API-connector attestations are. `CurrentApprovedForRun` as
originally spec'd here would therefore return nothing for the common case
(a BAS run with no analyst/connector involvement). This is fixed by a new
prerequisite, `docs/superpowers/specs/2026-07-27-automatic-verdict-persistence-design.md`
("Phase A0"), which also takes over ownership of adding `RuleIDs` (Component
1 below is superseded by that spec — kept here struck through for the
record, not implemented as part of this plan).

## Problem

The Exercise Engine (`internal/exercise`) ships two built-in templates —
`builtin-ransomware-response` and `builtin-soc-drill` — that chain an
`agent_task` step (triggers a BAS run) into a `wait_for_detection` step
(waits for EDR/SIEM evidence before continuing to a SOC approval gate).

Tracing every writer of the exercise evidence table shows this link is
**silently dead**: `triggerWaitForDetection` only fires when
`edr_detected`/`siem_alerted` evidence rows exist in the exercise's own
evidence table, and the only evidence `handleAgentTask` ever auto-records is
`agent_task_dispatched`. Nothing today converts a completed BAS run's
Detection Validation verification results (`internal/verification.Store`)
into exercise evidence. In production, both templates' `wait_for_detection`
step can only ever fire via an external webhook or manual evidence entry —
never from the BAS run the template itself triggered. It will silently time
out on every real run.

Separately, `scenario.ExpectedDetection.RuleIDs` — a field meant to link a
detection expectation to a Detection Rule Library (`internal/rulelib`) Sigma
rule — is fully dormant: no content populates it, and nothing renders it
anywhere, including the verification/report pipeline that already has the
live value in hand.

This spec fixes both: a **verification→exercise evidence bridge** that makes
`wait_for_detection` actually observe real BAS detections, and threads
`RuleIDs` through the persisted verification record so that bridge (and any
future consumer) can surface the Sigma linkage.

## Non-goals

- No new scenario content, no new exercise templates beyond fixing the two
  existing ones' configuration.
- No general plan-reference validation framework (`DependsOn`,
  `AgentTaskStepID`, and other step-ID references stay exactly as
  permissive/lazy as they are today — see "Bad `ExecutionStepID` reference"
  below for why `ExecutionStepID` itself gets a narrower, local fix instead).
- No vendor query-language rendering of Sigma rules in the exercise UI —
  `RuleIDs` is carried as data (IDs only); rendering the full rule detail is
  Phase B or later.
- No change to `builtin-bec`'s `wait_detection` step — its detection source
  is a phishing-report/mail-security webhook, not a BAS run, so
  `ExecutionStepID` correctly stays unset there.

## Architecture

```
BAS run completes (agent_task step)
  → Phase A0's poller persists automatic verdicts into verification.Store
    (Source=automatic, WorkflowState=Approved) — without A0 this step never
    happens and the store stays empty for purely-automatic expectations
  → wait_for_detection's trigger (ticking, same cadence as today) resolves
    ExecutionStepID's bas_run_id
  → calls verification.Store.CurrentApprovedForRun(runID)
  → ResolveDetectionEvidence (pure translation) filters Result=="Detected",
    dedups against evidence already recorded for this step, maps
    Domain → evidence type
  → Executor appends one exercise evidence row per newly observed detection
  → existing CountEvidenceForExec(...) gating fires the step once minCount
    is met, completely unchanged
```

Three layers, one responsibility each:

- **`verification.Store`** — persistence only. Answers "what verification
  records exist," including workflow-state filtering. Knows nothing about
  exercises.
- **`exercise` bridge** (`ResolveDetectionEvidence`) — pure function, no I/O.
  Translates verification records into pending exercise evidence. Knows
  nothing about the database or HTTP.
- **`Executor`** — orchestration. Resolves the run ID, calls the store, calls
  the bridge, writes the results through the existing hash-chained
  `EvidenceChain.Append`.

### Domain → evidence type mapping

Four evidence types total (unchanged additions to the existing
`edr_detected`/`siem_alerted`/`phishing_reported` set, plus one new type):

| `verification.Record.Domain` | Evidence type |
|---|---|
| `endpoint` | `edr_detected` |
| `siem` | `siem_alerted` |
| `identity`, `network`, `cloud`, `email`, `dlp` | `security_control_detected` |

Rationale: an evidence *type* answers "what kind of control produced this,"
not "where did it get collected." Collapsing DLP/identity/cloud/email/network
detections into `siem_alerted` would permanently lose which control actually
fired (a DLP block from Trellix is not a SIEM alert). Conversely, one
evidence type per domain over-models the exercise engine, which only needs
to know "a control fired," not which of 7 domains — and the domain count
will keep growing. `security_control_detected` is the single generic type
for "some non-endpoint, non-SIEM control fired," with the real domain,
product, and rule linkage carried as **payload metadata**, not encoded into
the type:

```json
{
  "expectation_id": "dlp-usb-block",
  "run_id": "run_abc123",
  "technique_id": "T1052.001",
  "control_domain": "dlp",
  "provider": "trellix_dlp",
  "rule_ids": ["AUDRULE-000042"]
}
```

`Evidence.Payload` is already `map[string]interface{}`, hash-chained
(`SHA256`/`PrevHash`) — no schema change needed for this metadata.

## Components

### 1. ~~`verification.Record` gains `RuleIDs`~~ — superseded, see Phase A0

This component (adding `RuleIDs` to `verification.Record`/`AttestInput`/the
`rule_ids` column/`recordCols`/`scanRecord`) is now implemented by the
Phase A0 plan instead, since A0's poller needs the field threaded through
`VerificationResult` before it can ever reach `Attest`. This plan consumes
`Record.RuleIDs` (already populated by the time this plan's tasks run) —
it does not add it.

### 2. `verification.Store.CurrentApprovedForRun`

`orchestrator/internal/verification/store.go`, new method sibling to the
existing `CurrentForRun`:

```go
// CurrentApprovedForRun returns the active, Approved attestation for every
// expectation in a run, as a slice (not a map — callers decide how to key
// or group; a map would bake in "one record per expectation" as an
// assumption this method should not own). Unlike CurrentForRun (all
// workflow states, used by reporting's manual/API overlay), this
// pre-filters to Approved so callers never repeat that filter.
func (s *Store) CurrentApprovedForRun(ctx context.Context, runID string) ([]Record, error) {
	rows, err := s.db.Query(ctx, `SELECT `+recordCols+`
		FROM verification_history WHERE run_id=$1 AND active AND workflow_state=$2`,
		runID, StateApproved)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
```

### 3. `WaitForDetectionConfig.ExecutionStepID`

`orchestrator/internal/exercise/types.go`:

```go
type WaitForDetectionConfig struct {
	// ...existing fields (DetectionTypes, MinCount) unchanged...

	// ExecutionStepID is the step ID (in the same plan) whose result holds
	// bas_run_id — the BAS run this detection step validates. Named
	// ExecutionStepID rather than AgentTaskStepID (unlike
	// WaitForAgentConfig's field) because the producer of that run ID may
	// not always be an agent_task step in the future; this field answers
	// "which step produced the verification records I consume," not "was
	// it specifically an agent task." Empty preserves today's exact
	// behavior: external/webhook/manual evidence only, no BAS-run lookup —
	// this is the correct (unchanged) setting for detection sources that
	// aren't BAS runs at all, e.g. builtin-bec's phishing-report flow.
	ExecutionStepID string `json:"execution_step_id,omitempty"`
}
```

### 4. `ResolveDetectionEvidence` — the pure translation bridge

New file `orchestrator/internal/exercise/detectionbridge.go`:

```go
package exercise

import "github.com/audspect/bas/internal/verification"

// PendingEvidence is one exercise evidence row ResolveDetectionEvidence
// determined should be written. The Executor is responsible for the actual
// (stateful, hash-chained) write via EvidenceChain.Append.
type PendingEvidence struct {
	EvidenceType string
	Payload      map[string]any
}

// ResolveDetectionEvidence translates newly-approved verification records
// into exercise evidence. records is everything currently approved for the
// run (from verification.Store.CurrentApprovedForRun); alreadyRecorded is
// the set of expectation IDs this step execution has already emitted
// evidence for — dedup is an exercise concern (what counts as "already
// handled" for this step), not a verification-store concern, so it lives
// here, not in Store. Records with Result != "Detected" produce no
// evidence — this is translation, not gating; a NotDetected or
// NotApplicable record simply isn't evidence of anything happening yet.
func ResolveDetectionEvidence(records []verification.Record, alreadyRecorded map[string]bool) []PendingEvidence {
	var out []PendingEvidence
	for _, r := range records {
		if r.Result != "Detected" || alreadyRecorded[r.ExpectationID] {
			continue
		}
		evType := "security_control_detected"
		switch r.Domain {
		case "endpoint":
			evType = "edr_detected"
		case "siem":
			evType = "siem_alerted"
		}
		out = append(out, PendingEvidence{
			EvidenceType: evType,
			Payload: map[string]any{
				"expectation_id": r.ExpectationID,
				"run_id":         r.RunID,
				"technique_id":   r.TechniqueID,
				"control_domain": r.Domain,
				"provider":       r.Provider,
				"rule_ids":       r.RuleIDs,
			},
		})
	}
	return out
}
```

Domain string literals (`"endpoint"`, `"siem"`) match
`scenario.DomainEndpoint`/`scenario.DomainSIEM` — the `exercise` package
does not import `internal/scenario` today and this spec does not add that
dependency; the two constants' string values (`"endpoint"`, `"siem"`) are
part of `internal/scenario`'s stable, documented wire vocabulary (see
`detection.go`'s domain constants), safe to duplicate as literals the same
way `internal/verification.Record.Domain` already carries them as a bare
`string` field, not the `scenario` type.

### 5. `Executor` orchestration

`orchestrator/internal/exercise/executor.go`. Note: this file's current
import block (`context`, `crand "crypto/rand"`, `encoding/hex`, `log`,
`strings`, `time`) does not include `fmt`, which `bridgeVerifiedDetections`
below needs for `fmt.Sprintf` — add it.

```go
// VerificationReader is the narrow read interface the detection bridge
// needs from internal/verification.Store — kept narrow so internal/exercise
// does not take a hard dependency on the whole verification package
// surface. *verification.Store satisfies it.
type VerificationReader interface {
	CurrentApprovedForRun(ctx context.Context, runID string) ([]verification.Record, error)
}
```

`Executor` gains an unexported `verification VerificationReader` field
(nil-safe: a `wait_for_detection` step with `ExecutionStepID` set but no
verification reader configured behaves as if `ExecutionStepID` were empty —
falls through to today's count-only gating). New setter, matching this
codebase's established `WithRuleLibrary`/`WithVerifications` additive-config
convention rather than changing `NewExecutor`'s existing positional
signature (which `cmd/server/main.go:314` already calls with 5 positional
args):

```go
func (e *Executor) WithVerification(v VerificationReader) *Executor {
	e.verification = v
	return e
}
```

`triggerWaitForDetection` rewritten:

```go
func (e *Executor) triggerWaitForDetection(ctx context.Context, ex *Execution, ps *PlanStep, se *StepExecution) (bool, map[string]any, error) {
	cfg := ps.Config.WaitForDetection
	if cfg != nil && cfg.ExecutionStepID != "" && e.verification != nil {
		if err := e.bridgeVerifiedDetections(ctx, ex, ps, se, cfg.ExecutionStepID); err != nil {
			return false, nil, err
		}
	}

	var types []string
	minCount := 1
	if cfg != nil {
		types = cfg.DetectionTypes
		if cfg.MinCount > 0 {
			minCount = cfg.MinCount
		}
	}
	n, err := e.store.CountEvidenceForExec(ctx, ex.ID, types)
	if err != nil {
		return false, nil, err
	}
	if n >= minCount {
		return true, map[string]any{"detection_count": n}, nil
	}
	return false, nil, nil
}

// bridgeVerifiedDetections resolves executionStepID's BAS run, reads its
// approved verification records, translates them into exercise evidence via
// ResolveDetectionEvidence, and appends any new evidence. Returns an error
// (via SetStepStatus to StepFailed, not a bare returned error — see below)
// only for permanent misconfiguration; a run that simply hasn't produced
// results yet is not an error.
func (e *Executor) bridgeVerifiedDetections(ctx context.Context, ex *Execution, ps *PlanStep, se *StepExecution, executionStepID string) error {
	plan, err := e.store.GetPlan(ctx, ex.PlanID)
	if err != nil {
		return err
	}
	found := false
	for _, s := range plan.Steps {
		if s.ID == executionStepID {
			found = true
			break
		}
	}
	if !found {
		return e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepFailed,
			fmt.Sprintf("wait_for_detection: execution_step_id %q does not reference a valid plan step", executionStepID))
	}

	srcSE, err := e.store.GetStepExecByStepID(ctx, ex.ID, executionStepID)
	if err != nil {
		// Referenced step is valid but hasn't started/produced a
		// StepExecution row yet — not an error, just not ready.
		return nil
	}
	if srcSE.Status != StepCompleted {
		return nil // still running — not an error, just not ready.
	}
	runID, _ := srcSE.Result["bas_run_id"].(string)
	if runID == "" {
		return e.store.SetStepStatus(ctx, ex.ID, ps.ID, StepFailed,
			fmt.Sprintf("wait_for_detection: execution step %q completed but produced no bas_run_id", executionStepID))
	}

	records, err := e.verification.CurrentApprovedForRun(ctx, runID)
	if err != nil {
		return err
	}
	existing, err := e.store.ListEvidence(ctx, ex.ID)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, ev := range existing {
		if ev.StepExecutionID != se.ID {
			continue
		}
		if id, _ := ev.Payload["expectation_id"].(string); id != "" {
			seen[id] = true
		}
	}
	for _, p := range ResolveDetectionEvidence(records, seen) {
		if _, err := e.evidence.Append(ctx, ex.ID, se.ID, p.EvidenceType, "system", "verification_bridge", p.Payload); err != nil {
			return err
		}
	}
	return nil
}
```

`SetStepStatus` failures inside `bridgeVerifiedDetections` return `nil` from
the function itself (the failure was already recorded on the step via
`SetStepStatus`) — not a Go error propagated to `triggerWaitForDetection`'s
caller, because that caller (`triggers.Check` in `advance()`) only
`log.Printf`s a returned error and retries next tick, which would leave the
step stuck in `StepWaiting` while silently logging forever. Calling
`SetStepStatus(..., StepFailed, ...)` directly makes the failure visible in
the step's own status (the same place an operator already looks — matches
`handleAgentTask`'s existing `SetStepStatus(..., StepFailed, err.Error())`
pattern for its own permanent failures) and naturally stops further
`advance()` iterations from re-checking this step, since line 131's
`se.Status != StepWaiting` guard now skips it.

## Fixing the existing templates

`orchestrator/internal/exercise/templates.go`:

- `builtin-ransomware-response`'s `wait_edr` step:
  `Config.WaitForDetection.ExecutionStepID: "sim"` (the `agent_task` step's
  ID in that same template).
- `builtin-soc-drill`'s `wait_detect` step:
  `Config.WaitForDetection.ExecutionStepID: "drill_sim"`.
- `builtin-bec`'s `wait_detection` step: **unchanged** — its detection
  source is a phishing-report/mail-security webhook, not a BAS run.

`cmd/server/main.go`: the `exExecutor := exercise.NewExecutor(...)` call
site (line 314) gains `.WithVerification(verificationStore)` (the same
`*verification.Store` instance already constructed and passed to the
reporting engine elsewhere in `main.go`).

## Edge cases

- **`ExecutionStepID` references a step with no `StepExecution` yet**
  (not started) → `GetStepExecByStepID` returns an error (no row) →
  treated as "not ready yet," no status change, same shape as
  `triggerWaitForAgent`'s existing "not done yet" handling.
- **Referenced step still running** → `Status != StepCompleted` → same "not
  ready yet," no error.
- **`ExecutionStepID` doesn't match any step in the plan at all** (typo) →
  permanent misconfiguration → step fails visibly with a diagnostic message
  (see "5. Executor orchestration" above) rather than waiting forever with
  no operator-visible signal.
- **Referenced step completed but never produced a `bas_run_id`** (e.g.
  pointed at a non-`agent_task` step, or dispatch failed before recording
  one) → same visible-failure treatment.
- **BAS run has expected detections but none verified `Detected` yet**
  (verifier hasn't run, or genuinely `NotDetected`) →
  `CurrentApprovedForRun` returns them, `ResolveDetectionEvidence` filters
  them out (not `Detected`), zero evidence appended, step keeps waiting —
  correct; never overclaims a detection that didn't happen.
- **Multiple expected detections resolve across different ticks** (e.g. EDR
  fires immediately, a SIEM correlation lags 10 minutes) → dedup by
  `expectation_id` means each tick only appends what's newly `Detected` and
  not already recorded in this step's evidence; no duplicate rows, hash
  chain stays consistent.
- **`ExecutionStepID` empty** → `bridgeVerifiedDetections` is skipped
  entirely; behavior is byte-for-byte identical to today (`builtin-bec`
  regression guard).
- **`e.verification` nil** (an `Executor` built without `WithVerification`,
  e.g. in an existing test that doesn't need it) → same skip, same
  unchanged fallback behavior — nil-safe, not a required wiring change for
  every existing call site.
- **Global step timeout** (`ps.TimeoutSecs`) — unaffected, already handles
  "detection never came" independent of this bridge; no new timeout logic
  needed.

## Testing approach

- **`ResolveDetectionEvidence`** (pure, no I/O): table-driven — `Detected`+
  not-yet-recorded → evidence with correct type per domain (`endpoint`→
  `edr_detected`, `siem`→`siem_alerted`, `identity`/`network`/`cloud`/
  `email`/`dlp`→`security_control_detected`); `NotDetected`/`NotApplicable`
  → no evidence; already-recorded `expectation_id` → skipped; empty
  `RuleIDs` → `Payload["rule_ids"]` is an empty (not nil-panicking) slice.
- **`verification.Store.CurrentApprovedForRun`**: extend the existing
  Docker/Postgres-testcontainer suite in `internal/verification` — seed one
  `Approved`, one `Pending`, one `Approved`-but-`NotDetected` record for the
  same run; assert only the `Approved` rows return (both `Detected` and
  `NotDetected` — filtering by `Result` is `ResolveDetectionEvidence`'s job,
  not `Store`'s).
- **`Attest` threading `RuleIDs`**: extend the existing `automaticVerifier`/
  `dlpVerifier` tests in `internal/reporting` to assert the field round-trips
  from `ExpectedDetection.RuleIDs` into the `Record` passed to `Attest`.
- **`triggerWaitForDetection` / `bridgeVerifiedDetections` integration**:
  extend `internal/exercise`'s existing executor test suite — happy path
  (approved `Detected` record → evidence appended with correct type/payload
  → step fires once `minCount` met); `NotDetected` record present (step
  keeps waiting, no evidence); missing plan-step reference (step transitions
  to `StepFailed` with the documented message); completed step with no
  `bas_run_id` (same); `ExecutionStepID` empty (unchanged regression guard);
  `e.verification` nil (unchanged regression guard); two detections arriving
  on different ticks (no duplicate evidence, dedup verified).
- **Template fixes**: a test asserting `builtin-ransomware-response`'s
  `wait_edr` and `builtin-soc-drill`'s `wait_detect` steps carry the
  documented `ExecutionStepID` values (guards against future template edits
  silently breaking the wiring).
- **Backward compatibility**: existing `internal/exercise` and
  `internal/verification` test suites must pass unmodified except for the
  additive extensions above — no existing test's expected values change.

## Migration

New column `verification_history.rule_ids text[]` (nullable, no default
needed — existing rows simply have `NULL`/empty, identical in effect to the
field being absent). Follows this codebase's existing additive-column
migration pattern; no backfill required since the field was never populated
before this change.
