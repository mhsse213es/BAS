# B5 Destructive-Action Guardrail — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the agent an independent, non-bypassable veto over destructive-action scenario steps, backed by an Audspect-controlled execution-classification catalog covering the entire existing technique library, with zero grant/escape-hatch mechanism yet (Phase 2).

**Architecture:** Every `ScenarioStep` gets a per-step `(technique_id, action_key)` → execution-class resolution at server-side compilation time (mirroring the existing `resource.go`/`AttachProfiles` pattern exactly), carried inside the B4-signed envelope. The agent combines that signed classification with its own vendor-curated, binary-compiled local rule backstop (most-restrictive-wins) at each step's execution boundary, immediately before invoking the executor. A `destructive` step is unconditionally vetoed in this phase — there is no grant mechanism yet, so `destructive` always means "does not run." A vetoed step gets a new `VETOED` verdict, deliberately excluded from every scoring/prevention-percentage calculation the existing `OutcomeBlocked`/`ResultBlocked` ("customer's own control stopped it") concept feeds.

**Tech Stack:** Go (orchestrator module `github.com/audspect/bas`, agent module `audspect/agent`), existing WS/B4 signing infrastructure, no new external dependencies.

**Spec:** `docs/superpowers/specs/2026-09-29-destructive-action-guardrail-b5-design.md`

## Global Constraints

- The classification catalog is Audspect-controlled (curated Go code), never scenario-author-declared. `production_safe`/`risk`/`reversible` in scenario YAML remain informational only and can never downgrade a catalog classification.
- `action_key` is a lookup key only, never a safety assertion. A `(technique_id, action_key)` pair with no catalog entry resolves to `destructive` — no fallback to a technique-wide generic classification, ever.
- A step's own `ExecutionClass` (from the signed envelope) and the agent's local rule-backstop evaluation of the actual command text are combined **most-restrictive-wins**. Neither is trusted alone.
- The local rule backstop is vendor-curated Go code compiled into the agent binary. It is never modifiable via orchestrator command, scenario YAML, environment variable, or (in a later phase) a local grant.
- A vetoed step does **not** abort the scenario run — execution continues to the next scheduled step.
- The new `VETOED` verdict must never be confused with, mapped onto, or counted alongside the existing `OutcomeBlocked`/`models.ResultBlocked` concept (customer's own security control intercepted the technique → scores as PASS). `VETOED` means Audspect's own agent refused to attempt the step; it asserts nothing about the customer's defenses and must never contribute to `PreventionScore`/`PreventionPct`/`BypassRate` or any equivalent aggregate, in either the numerator or the denominator.
- Every wire-shape change (`ScenarioStep`, `CommandEnvelope`) must stay byte-identical in JSON tag name and field order between `orchestrator/internal/scenario`/`orchestrator/internal/models` and `agent/protocol`, verified by a real test — the same discipline B4's `CommandEnvelope` cross-module work already established (see `agent/protocol/golden_vector_test.go` / `orchestrator/internal/cmdsigning/golden_vector_test.go` for the existing pattern to extend).
- This phase ships **no grant/CLI/audit mechanism**. A `destructive`-classified step is always vetoed in this phase, full stop — do not build a stub or placeholder grant check; the absence of one is the correct Phase 1 state.

## Review Focus

- **A scenario step whose command legitimately needs to run but has no catalog entry at all** (a technique never audited) — must fail closed to `destructive`/`VETOED`, not silently execute. Pinned by Task 1's resolver tests and Task 10's audit completeness check.
- **A step correctly classified `non_destructive` by the catalog, but whose actual command text matches the local backstop's dangerous-pattern rules** (a catalog under-classification) — must still be vetoed via most-restrictive-wins. Pinned in Task 7.
- **A multi-step scenario mixing safe and destructive steps** (the em-07 shape exactly) — safe steps must execute and destructive steps must be vetoed independently, with the run continuing past the veto. `runScenario` itself has no pre-existing direct unit tests in this codebase to extend (it's exercised only indirectly), so this is pinned at the scheduler level instead: Task 7 adds a `sched` package test proving a job whose `Run` closure returns `false` (the veto's exact signal) never prevents sibling jobs' `Run` closures from executing — the same structural guarantee the existing circuit-breaker and payload-quarantine `return false` paths in `runScenario` already rely on, which this plan's veto check becomes a third instance of.
- **`VETOED` steps must not silently disappear from, or silently count toward, existing scoring/reporting aggregates** that already treat unrecognized `CheckResult` values inconsistently across call sites (some skip them defensively, e.g. `internal/reporting/pdf.go:1337`; none currently know about `VETOED` specifically). Pinned in Task 9.
- **An envelope's aggregate `execution_class` must never be read as authoritative** by anything other than dispatch-time logging — a test asserting the per-step field, not the aggregate, is what the agent's gate actually consults. Pinned in Task 7's combination-logic test.

---

## Task 1: Execution-Classification Catalog and Resolver

**Files:**
- Create: `orchestrator/internal/scenario/execclass.go`
- Test: `orchestrator/internal/scenario/execclass_test.go`

**Interfaces:**
- Consumes: nothing new (standalone).
- Produces: `type ExecutionClass string` with constants `ClassNonDestructive`, `ClassPotentiallyDestructive`, `ClassDestructive`; `type ExecutionClassification struct { Class ExecutionClass; DestructiveAction string; BlastRadius string }`; `func ResolveExecutionClass(techniqueID, actionKey string) ExecutionClassification` — used by Task 3's `AttachExecutionClassifications`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/scenario/execclass_test.go
package scenario

import "testing"

func TestResolveExecutionClass_ExactMatch(t *testing.T) {
	got := ResolveExecutionClass("T1490", "vss_delete")
	if got.Class != ClassDestructive {
		t.Errorf("T1490:vss_delete class = %q, want %q", got.Class, ClassDestructive)
	}
	if got.DestructiveAction != "vss_delete" {
		t.Errorf("DestructiveAction = %q, want %q", got.DestructiveAction, "vss_delete")
	}
	if got.BlastRadius == "" {
		t.Error("BlastRadius is empty for a destructive action -- must describe the real impact")
	}
}

func TestResolveExecutionClass_NoActionKeyFallsBackToDefault(t *testing.T) {
	// Seed a technique with only a "default" entry, via a technique known to
	// have exactly one behavior. T1082 (System Information Discovery) is
	// already proven read-only in resource.go's discoveryProfiles.
	got := ResolveExecutionClass("T1082", "")
	if got.Class != ClassNonDestructive {
		t.Errorf("T1082 (no action_key) class = %q, want %q", got.Class, ClassNonDestructive)
	}
}

func TestResolveExecutionClass_UnknownActionKeyFailsClosed(t *testing.T) {
	// T1490 has curated entries, but not this action_key -- must NOT fall
	// back to a technique-wide default. This is the exact ambiguity the
	// catalog exists to eliminate.
	got := ResolveExecutionClass("T1490", "totally_unreviewed_action")
	if got.Class != ClassDestructive {
		t.Errorf("unknown action_key under a partially-catalogued technique = %q, want %q (fail closed)", got.Class, ClassDestructive)
	}
}

func TestResolveExecutionClass_UnknownTechniqueFailsClosed(t *testing.T) {
	got := ResolveExecutionClass("T9999", "anything")
	if got.Class != ClassDestructive {
		t.Errorf("wholly unknown technique class = %q, want %q (fail closed)", got.Class, ClassDestructive)
	}
}

func TestResolveExecutionClass_CaseNormalization(t *testing.T) {
	// Mirrors ResourceProfileFor's existing strings.ToUpper/TrimSpace handling
	// for technique IDs (resource.go) -- action_key normalization is new here.
	got := ResolveExecutionClass("t1490", "VSS_DELETE")
	if got.Class != ClassDestructive {
		t.Errorf("case-insensitive lookup failed: class = %q, want %q", got.Class, ClassDestructive)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/scenario/... -run TestResolveExecutionClass -v` (from `orchestrator/`)
Expected: FAIL with "undefined: ResolveExecutionClass" (and the other undefined identifiers).

- [ ] **Step 3: Write the implementation**

```go
// orchestrator/internal/scenario/execclass.go
package scenario

import "strings"

// ExecutionClass is the destructiveness tier B5 (the agent-side
// destructive-action guardrail) enforces per step. See
// docs/superpowers/specs/2026-09-29-destructive-action-guardrail-b5-design.md.
//
// This is a SEPARATE concern from ResourceProfile's Risk field
// (resource.go) -- that classifies concurrency-locking risk
// (observation/modification/persistence); this classifies whether
// executing the step can cause irreversible real-world damage. The two
// catalogs are deliberately never merged.
type ExecutionClass string

const (
	ClassNonDestructive          ExecutionClass = "non_destructive"
	ClassPotentiallyDestructive  ExecutionClass = "potentially_destructive"
	ClassDestructive             ExecutionClass = "destructive"
)

// ExecutionClassification is the catalog's resolved answer for one
// (technique_id, action_key) pair.
type ExecutionClassification struct {
	Class ExecutionClass
	// DestructiveAction is a stable, audit/report-facing identifier for
	// what this action does (often just the action_key itself).
	DestructiveAction string
	// BlastRadius is a human-readable description for audit/reporting --
	// never itself consulted for enforcement.
	BlastRadius string
}

// unclassified is the fail-closed answer for any (technique_id,
// action_key) pair this catalog has no entry for -- see the spec's
// "Resolution rules": no fallback from an unknown pair to a
// technique-wide generic classification, ever.
var unclassified = ExecutionClassification{
	Class:             ClassDestructive,
	DestructiveAction: "unclassified",
	BlastRadius:       "No catalog entry exists for this technique/action -- treated as destructive per the fail-closed default.",
}

// executionClassifications is the Audspect-controlled catalog, keyed
// technique_id -> action_key -> classification. Populated exhaustively by
// Task 10's full-library audit; this task seeds it only with the entries
// already verified against real scenario command text during this
// plan's own design investigation.
var executionClassifications = map[string]map[string]*ExecutionClassification{
	"T1490": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Read-only enumeration of VSS shadow copies / backup catalog (vssadmin list shadows, wbadmin get versions). No state changed.",
		},
		"vss_delete": {
			Class:             ClassDestructive,
			DestructiveAction: "vss_delete",
			BlastRadius:       "Deletes VSS shadow copies (vssadmin/wbadmin/WMI Win32_ShadowCopy.Delete()) -- irreversible, removes the ransomware-recovery path.",
		},
		"wbadmin_delete_catalog": {
			Class:             ClassDestructive,
			DestructiveAction: "wbadmin_delete_catalog",
			BlastRadius:       "Deletes the Windows Server Backup catalog (wbadmin delete catalog) -- irreversible.",
		},
		"bootloader_recovery_disable": {
			Class:             ClassDestructive,
			DestructiveAction: "bootloader_recovery_disable",
			BlastRadius:       "Disables Windows Recovery Environment via bcdedit (recoveryenabled no / bootstatuspolicy ignoreallfailures) -- removes the final recovery path.",
		},
	},
	// T1082 seeded here as the resolver test's "default" example --
	// mirrors resource.go's own discoveryProfiles entry for the same
	// technique (already proven read-only there). Real coverage of every
	// discoveryProfiles technique is Task 10's job, not duplicated by hand
	// here for each one.
	"T1082": {
		"default": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Read-only system information query.",
		},
	},
}

// ResolveExecutionClass returns the catalog's classification for a step's
// (technique_id, action_key) pair. An empty action_key resolves against
// the technique's own "default" entry. Any miss -- unknown technique,
// unknown action_key under a known technique, or no "default" entry for
// an empty action_key -- fails closed to ClassDestructive. No fallback to
// a technique-wide generic classification exists at any point in this
// resolution.
func ResolveExecutionClass(techniqueID, actionKey string) ExecutionClassification {
	tid := strings.ToUpper(strings.TrimSpace(techniqueID))
	key := strings.ToLower(strings.TrimSpace(actionKey))
	if key == "" {
		key = "default"
	}
	actions, ok := executionClassifications[tid]
	if !ok {
		return unclassified
	}
	c, ok := actions[key]
	if !ok {
		return unclassified
	}
	return *c
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/scenario/... -run TestResolveExecutionClass -v`
Expected: PASS (all 5 tests).

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/scenario/execclass.go internal/scenario/execclass_test.go
git commit -m "feat(b5): execution-classification catalog and resolver"
```

---

## Task 2: Wire Schema — `ScenarioStep` Classification Fields (Both Modules)

**Files:**
- Modify: `orchestrator/internal/scenario/types.go:301` (right after the existing `Timeout *TimeoutProfile` field)
- Modify: `agent/protocol/messages.go:83` (right after the existing `Timeout json.RawMessage` field)
- Test: `agent/protocol/messages_test.go` (create if it doesn't exist) or add to an existing scenario-command wire test

**Interfaces:**
- Consumes: Task 1's `ExecutionClass` type (orchestrator side only -- the agent side carries the same value as a plain `string`, matching how `Risk`/`Scope` already cross the wire as strings in `ResourceProfile` today, so an older agent build degrades to an unrecognized string rather than an unmarshal failure).
- Produces: `ScenarioStep.ActionKey`, `.ExecutionClass`, `.DestructiveAction`, `.BlastRadius` on both structs -- consumed by Task 3 (orchestrator attach step) and Task 7 (agent gate).

- [ ] **Step 1: Write the failing test**

```go
// agent/protocol/messages_test.go (new file, or append if one already covers ScenarioStep)
package protocol

import (
	"encoding/json"
	"testing"
)

func TestScenarioStep_DecodesExecutionClassificationFields(t *testing.T) {
	wire := `{
		"taskId": "task-1",
		"techniqueId": "T1490",
		"name": "VSS Delete",
		"executor": "powershell",
		"command": "vssadmin delete shadows /all /quiet",
		"timeoutSec": 30,
		"actionKey": "vss_delete",
		"executionClass": "destructive",
		"destructiveAction": "vss_delete",
		"blastRadius": "Deletes VSS shadow copies -- irreversible."
	}`
	var step ScenarioStep
	if err := json.Unmarshal([]byte(wire), &step); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if step.ActionKey != "vss_delete" {
		t.Errorf("ActionKey = %q, want %q", step.ActionKey, "vss_delete")
	}
	if step.ExecutionClass != "destructive" {
		t.Errorf("ExecutionClass = %q, want %q", step.ExecutionClass, "destructive")
	}
	if step.DestructiveAction != "vss_delete" {
		t.Errorf("DestructiveAction = %q, want %q", step.DestructiveAction, "vss_delete")
	}
	if step.BlastRadius == "" {
		t.Error("BlastRadius did not decode")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./protocol/... -run TestScenarioStep_DecodesExecutionClassificationFields -v` (from `agent/`)
Expected: FAIL with "unknown field" or the fields reading as zero values (compile succeeds since `ScenarioStep` exists, but the new JSON keys have nowhere to land).

- [ ] **Step 3: Add the fields**

`agent/protocol/messages.go`, immediately after line 83 (`Timeout json.RawMessage \`json:"timeout,omitempty"\`,`):

```go
	ActionKey            string            `json:"actionKey,omitempty"`
	ExecutionClass       string            `json:"executionClass,omitempty"`
	DestructiveAction    string            `json:"destructiveAction,omitempty"`
	BlastRadius          string            `json:"blastRadius,omitempty"`
```

`orchestrator/internal/scenario/types.go`, immediately after line 301 (`Timeout *TimeoutProfile \`json:"timeout,omitempty"\``):

```go
	// ActionKey/ExecutionClass/DestructiveAction/BlastRadius are set by
	// AttachExecutionClassifications (execclass.go) at compile time.
	// ActionKey is scenario-author-set (a lookup key only -- see
	// execclass.go's doc comment; never a safety assertion). The other
	// three are ALWAYS catalog-resolved, never scenario-author-set, even
	// though ExecutionClass shares a name with nothing else on this
	// struct -- there is no legacy field this could be confused with.
	ActionKey         string         `json:"actionKey,omitempty"`
	ExecutionClass    ExecutionClass `json:"executionClass,omitempty"`
	DestructiveAction string         `json:"destructiveAction,omitempty"`
	BlastRadius       string         `json:"blastRadius,omitempty"`
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./protocol/... -run TestScenarioStep_DecodesExecutionClassificationFields -v`
Expected: PASS.

Also run, to confirm the orchestrator side still builds and its own existing `ScenarioStep` tests still pass:

Run (from `orchestrator/`): `go build ./... && go test ./internal/scenario/... -v`
Expected: clean build, all pre-existing tests still pass.

- [ ] **Step 5: Commit**

```bash
git add agent/protocol/messages.go agent/protocol/messages_test.go
git -C agent commit -m "feat(b5): add execution-classification fields to agent ScenarioStep"
cd ../orchestrator
git add internal/scenario/types.go
git commit -m "feat(b5): add execution-classification fields to orchestrator ScenarioStep"
```

(Two commits, one per module -- matches this project's existing convention of separate commits per Go module even for a single logical change, established during the B4 work.)

---

## Task 3: Attach Classifications at Compilation Time

**Files:**
- Create: (adds to) `orchestrator/internal/scenario/execclass.go`
- Modify: `orchestrator/internal/scenario/builder.go:120` (`BuildSteps`, right after the existing `AttachProfiles(steps)` call)
- Test: `orchestrator/internal/scenario/execclass_test.go`

**Interfaces:**
- Consumes: Task 1's `ResolveExecutionClass`; Task 2's new `ScenarioStep` fields.
- Produces: `func AttachExecutionClassifications(steps []ScenarioStep)` -- called from `BuildSteps`, so every step reaching an agent (hand-authored, ART-sourced, or Caldera-sourced -- `BuildSteps` is the single choke point for all three) has been classified before dispatch.

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/scenario/execclass_test.go (append)
func TestAttachExecutionClassifications(t *testing.T) {
	steps := []ScenarioStep{
		{TechniqueID: "T1490", ActionKey: "vss_delete"},
		{TechniqueID: "T1082"}, // no action_key -> "default"
		{TechniqueID: "T9999"}, // wholly unknown -> fail closed
	}
	AttachExecutionClassifications(steps)

	if steps[0].ExecutionClass != ClassDestructive {
		t.Errorf("steps[0].ExecutionClass = %q, want %q", steps[0].ExecutionClass, ClassDestructive)
	}
	if steps[0].DestructiveAction != "vss_delete" {
		t.Errorf("steps[0].DestructiveAction = %q, want %q", steps[0].DestructiveAction, "vss_delete")
	}
	if steps[1].ExecutionClass != ClassNonDestructive {
		t.Errorf("steps[1].ExecutionClass = %q, want %q", steps[1].ExecutionClass, ClassNonDestructive)
	}
	if steps[2].ExecutionClass != ClassDestructive {
		t.Errorf("steps[2].ExecutionClass = %q, want %q (fail closed)", steps[2].ExecutionClass, ClassDestructive)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/scenario/... -run TestAttachExecutionClassifications -v`
Expected: FAIL with "undefined: AttachExecutionClassifications".

- [ ] **Step 3: Write the implementation**

Append to `orchestrator/internal/scenario/execclass.go`:

```go
// AttachExecutionClassifications labels every step with its resolved
// execution classification in place, mirroring AttachProfiles
// (resource.go) exactly. Called from BuildSteps immediately after
// AttachProfiles -- the single compilation choke point every step
// (hand-authored, ART-sourced, Caldera-sourced) passes through before
// ever reaching an agent.
func AttachExecutionClassifications(steps []ScenarioStep) {
	for i := range steps {
		c := ResolveExecutionClass(steps[i].TechniqueID, steps[i].ActionKey)
		steps[i].ExecutionClass = c.Class
		steps[i].DestructiveAction = c.DestructiveAction
		steps[i].BlastRadius = c.BlastRadius
	}
}
```

`orchestrator/internal/scenario/builder.go`, line 120, change:

```go
	dedupeStepIdentity(steps)
	AttachProfiles(steps)
	return steps, skipped, nil
```

to:

```go
	dedupeStepIdentity(steps)
	AttachProfiles(steps)
	AttachExecutionClassifications(steps)
	return steps, skipped, nil
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/scenario/... -v`
Expected: PASS, including `TestAttachExecutionClassifications` and every pre-existing test in the package (confirms this addition didn't disturb `AttachProfiles`/`BuildSteps`'s existing behavior).

- [ ] **Step 5: Commit**

```bash
git add internal/scenario/execclass.go internal/scenario/execclass_test.go internal/scenario/builder.go
git commit -m "feat(b5): attach execution classifications at scenario compilation"
```

---

## Task 4: `action_key` Authoring in Scenario YAML

**Files:**
- Modify: `orchestrator/internal/scenario/types.go:149-159` (the `Step` YAML struct's metadata block, alongside `Risk`/`BlastRadius`/`Reversible`/`ProductionSafe`)
- Modify: `orchestrator/internal/scenario/builder.go:216` (`buildStep`, around line 282 where `TechniqueID: s.TechniqueID` is set)
- Test: `orchestrator/internal/scenario/builder_test.go` (add to existing `buildStep`-adjacent tests)

**Interfaces:**
- Consumes: nothing new.
- Produces: `Step.ActionKey` (YAML `action_key:`) threaded through into `ScenarioStep.ActionKey` for hand-authored steps, so Task 3's `AttachExecutionClassifications` has something author-set to resolve against for techniques with more than one real action (T1490 being the concrete example).

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/scenario/builder_test.go (append near existing buildStep tests)
func TestBuildStep_CarriesActionKeyThrough(t *testing.T) {
	s := Step{
		Name:        "VSS Delete",
		TechniqueID: "T1490",
		ActionKey:   "vss_delete",
		Framework:   "custom",
		Executor:    "powershell",
		Command:     "vssadmin delete shadows /all /quiet",
	}
	step, err := buildStep(s, "", "", nil, "windows")
	if err != nil {
		t.Fatalf("buildStep: %v", err)
	}
	if step.ActionKey != "vss_delete" {
		t.Errorf("ActionKey = %q, want %q", step.ActionKey, "vss_delete")
	}
}
```

(If `buildStep`'s real signature differs from the 5-arg form assumed here, read the function at `builder.go:216` first and match its actual parameters -- do not guess.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/scenario/... -run TestBuildStep_CarriesActionKeyThrough -v`
Expected: FAIL — `Step` has no field `ActionKey` (compile error), or the assertion fails once it compiles with an empty `ActionKey`.

- [ ] **Step 3: Write the implementation**

`orchestrator/internal/scenario/types.go`, in the `Step` struct, alongside the existing `Risk`/`BlastRadius`/`Reversible`/`ProductionSafe` block (after line 151's `Reversible bool` field):

```go
	// ActionKey selects which catalog entry (execclass.go) classifies this
	// step's destructiveness, alongside TechniqueID. It is a LOOKUP KEY
	// ONLY -- see execclass.go's doc comment. The author cannot make a
	// step safe by choosing a reassuring-sounding key; an unrecognized
	// (technique_id, action_key) pair fails closed to destructive. Needed
	// whenever a technique has more than one materially different
	// behavior (T1490's enumerate vs. vss_delete is the canonical
	// example); omit it for a technique with exactly one behavior, which
	// resolves against that technique's "default" catalog entry.
	ActionKey string `yaml:"action_key,omitempty" json:"actionKey,omitempty"`
```

`orchestrator/internal/scenario/builder.go`, in `buildStep` (around line 282, alongside the existing `TechniqueID: s.TechniqueID`):

```go
		TechniqueID: s.TechniqueID,
		ActionKey:   s.ActionKey,
```

(Read the surrounding 10 lines of the real `buildStep` function first to place this in the correct struct-literal position alongside the other field assignments -- do not assume the exact line layout without checking, since this plan's investigation read `builder.go:282` as a single-field reference, not the full literal.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/scenario/... -v`
Expected: PASS, including the new test and every pre-existing `builder_test.go` test.

- [ ] **Step 5: Commit**

```bash
git add internal/scenario/types.go internal/scenario/builder.go internal/scenario/builder_test.go
git commit -m "feat(b5): add action_key scenario-authoring field"
```

---

## Task 5: `CommandEnvelope` Aggregate Fields (Both Modules) + Golden Vector Regeneration

**Files:**
- Modify: `orchestrator/internal/models/command_envelope.go`
- Modify: `agent/protocol/command_envelope.go`
- Modify: `orchestrator/internal/ws/hub.go:213-263` (`signCommand`)
- Modify: `orchestrator/internal/cmdsigning/golden_vector_test.go`
- Modify: `agent/protocol/golden_vector_test.go`
- Test: `orchestrator/internal/models/command_envelope_test.go`, `agent/protocol/command_envelope_test.go` (existing files -- extend)

**Interfaces:**
- Consumes: nothing new.
- Produces: `CommandEnvelope.ExecutionClass`/`.DestructiveAction`/`.BlastRadius` (both modules) -- aggregate, informational/audit-only fields; NOT consumed by Task 7's agent gate (which reads the per-step fields from Task 2 instead).

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/models/command_envelope_test.go (append)
func TestCommandEnvelope_CanonicalJSONIncludesExecutionClassAggregate(t *testing.T) {
	env := CommandEnvelope{
		Version: CommandEnvelopeVersion, CommandID: "c1", CommandType: "command_scenario",
		AgentID: "a1", IssuedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC), Nonce: "n1",
		Payload:           json.RawMessage(`{}`),
		ExecutionClass:    "destructive",
		DestructiveAction: "vss_delete",
		BlastRadius:       "Deletes VSS shadow copies.",
	}
	canon, err := env.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if !strings.Contains(string(canon), `"executionClass":"destructive"`) {
		t.Errorf("canonical JSON missing executionClass: %s", canon)
	}
	if !strings.Contains(string(canon), `"destructiveAction":"vss_delete"`) {
		t.Errorf("canonical JSON missing destructiveAction: %s", canon)
	}
}
```

Write the identical test (adjusted for package/import path) in `agent/protocol/command_envelope_test.go`.

- [ ] **Step 2: Run tests to verify they fail**

Run (orchestrator): `go test ./internal/models/... -run TestCommandEnvelope_CanonicalJSONIncludesExecutionClassAggregate -v`
Run (agent): `go test ./protocol/... -run TestCommandEnvelope_CanonicalJSONIncludesExecutionClassAggregate -v`
Expected: both FAIL — the new fields don't exist yet on either struct, or `CanonicalJSON`'s output doesn't include them.

- [ ] **Step 3: Add the fields to both `CommandEnvelope` structs and both `CanonicalJSON` methods**

In both `orchestrator/internal/models/command_envelope.go` and `agent/protocol/command_envelope.go`, add to the main struct (immediately after the existing `Payload json.RawMessage \`json:"payload"\`` field, before `Signature`):

```go
	// ExecutionClass/DestructiveAction/BlastRadius are the AGGREGATE
	// (most-restrictive-across-Steps) classification, for dispatch-level
	// audit visibility only -- see docs/superpowers/specs/
	// 2026-09-29-destructive-action-guardrail-b5-design.md. NEVER the
	// authorization signal: the agent's B5 gate reads each ScenarioStep's
	// own ExecutionClass (agent/protocol.ScenarioStep, Task 2), not this
	// field.
	ExecutionClass    string `json:"executionClass,omitempty"`
	DestructiveAction string `json:"destructiveAction,omitempty"`
	BlastRadius       string `json:"blastRadius,omitempty"`
```

And add the same three fields, in the same position, to BOTH `CanonicalJSON`'s anonymous struct definition AND its literal construction (in both files) -- e.g. in `orchestrator/internal/models/command_envelope.go`:

```go
		Payload           json.RawMessage `json:"payload"`
		ExecutionClass    string          `json:"executionClass,omitempty"`
		DestructiveAction string          `json:"destructiveAction,omitempty"`
		BlastRadius       string          `json:"blastRadius,omitempty"`
	}{
		Version: unsigned.Version, CommandID: unsigned.CommandID, CommandType: unsigned.CommandType,
		AgentID: unsigned.AgentID, RunID: unsigned.RunID, ScenarioID: unsigned.ScenarioID,
		StepID: unsigned.StepID, Mode: unsigned.Mode, Policy: unsigned.Policy,
		IssuedAt: unsigned.IssuedAt, ExpiresAt: unsigned.ExpiresAt, Nonce: unsigned.Nonce,
		Payload: unsigned.Payload,
		ExecutionClass: unsigned.ExecutionClass, DestructiveAction: unsigned.DestructiveAction,
		BlastRadius: unsigned.BlastRadius,
	})
```

Apply the identical change (same field names, same JSON tags, same position) to `agent/protocol/command_envelope.go`'s `CanonicalJSON`.

- [ ] **Step 4: Compute the aggregate in `signCommand`**

`orchestrator/internal/ws/hub.go`, in `signCommand` (around line 244-255), extend the existing "best-effort extraction" `ctx` struct:

```go
	// Best-effort extraction of the optional context fields from
	// ScenarioCommand-shaped payloads -- see scenario.ScenarioCommand.
	var ctx struct {
		RunID      string `json:"runId"`
		ScenarioID string `json:"scenarioId"`
		Mode       string `json:"mode"`
		Steps      []struct {
			ExecutionClass    string `json:"executionClass"`
			DestructiveAction string `json:"destructiveAction"`
			BlastRadius       string `json:"blastRadius"`
		} `json:"steps"`
	}
	if json.Unmarshal(payload, &ctx) == nil {
		env.RunID = ctx.RunID
		env.ScenarioID = ctx.ScenarioID
		env.Mode = ctx.Mode
		env.ExecutionClass, env.DestructiveAction, env.BlastRadius = mostRestrictiveStep(ctx.Steps)
	}
```

Add the helper (same file):

```go
// mostRestrictiveStep returns the aggregate execution_class/destructive_action/
// blast_radius across a dispatch's steps -- "destructive" beats
// "potentially_destructive" beats "non_destructive" beats "" (no steps,
// or a non-scenario command type). Informational/audit-only, per the
// spec -- never consulted by the agent's B5 gate.
func mostRestrictiveStep(steps []struct {
	ExecutionClass    string `json:"executionClass"`
	DestructiveAction string `json:"destructiveAction"`
	BlastRadius       string `json:"blastRadius"`
}) (class, action, blast string) {
	rank := map[string]int{"": 0, "non_destructive": 1, "potentially_destructive": 2, "destructive": 3}
	best := -1
	for _, s := range steps {
		if r := rank[s.ExecutionClass]; r > best {
			best = r
			class, action, blast = s.ExecutionClass, s.DestructiveAction, s.BlastRadius
		}
	}
	return class, action, blast
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run (orchestrator): `go test ./internal/models/... ./internal/ws/... -v`
Run (agent): `go test ./protocol/... -v`
Expected: PASS, including the two new tests and every pre-existing test in both packages (in particular the existing `TestSendToAgent_*` tests in `internal/ws`, confirming `signCommand` still signs correctly for non-scenario command types where `ctx.Steps` stays empty).

- [ ] **Step 6: Regenerate the B4 golden vectors**

The canonical JSON byte sequence changed (new fields), so the golden-vector constants pinned during B4's final-review fix wave are now stale and must be regenerated, not left pointing at pre-B5 bytes.

Read `orchestrator/internal/cmdsigning/golden_vector_test.go` and `agent/protocol/golden_vector_test.go` in full first -- they contain a frozen RSA private/public keypair and a fixed `CommandEnvelope`. Using that SAME keypair (do not generate a new one), build a `models.CommandEnvelope` with the same fixed field values as today's golden vector PLUS `ExecutionClass: "non_destructive"` (a neutral, representative value -- the golden vector's job is proving byte-identical shape, not exercising B5's own logic), call `.CanonicalJSON()`, and `cmdsigning.SignEnvelope` with the frozen key to get the new expected canonical JSON and signature bytes. Update both files' `goldenCanonicalJSON` and `goldenSignatureB64` constants to the new values (write a small throwaway generator, exactly like Task 5 of the B4 fix-wave did with `orchestrator/cmd/gengolden/main.go`, run it once, capture the output, delete the generator -- do not hand-compute the expected bytes).

Run (orchestrator): `go test ./internal/cmdsigning/... -run TestGoldenVector -v`
Run (agent): `go test ./protocol/... -run TestGoldenVector -v`
Expected: PASS with the regenerated constants.

- [ ] **Step 7: Commit**

```bash
git add internal/models/command_envelope.go internal/models/command_envelope_test.go internal/ws/hub.go internal/cmdsigning/golden_vector_test.go
git commit -m "feat(b5): add CommandEnvelope execution-class aggregate, regenerate golden vectors"
cd ../agent
git add protocol/command_envelope.go protocol/command_envelope_test.go protocol/golden_vector_test.go
git commit -m "feat(b5): add CommandEnvelope execution-class aggregate, regenerate golden vectors"
```

---

## Task 6: Agent Local Rule Backstop

**Files:**
- Create: `agent/destructiveguard/rules.go`
- Create: `agent/destructiveguard/rules_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces: `type Class string` with `ClassNonDestructive`/`ClassPotentiallyDestructive`/`ClassDestructive` (agent-side mirror of Task 1's orchestrator constants, as plain string values -- no cross-package Go dependency, since `agent/destructiveguard` must not import orchestrator code); `func Classify(command string) Class` -- consumed by Task 7's agent gate.

- [ ] **Step 1: Write the failing tests**

```go
// agent/destructiveguard/rules_test.go
package destructiveguard

import "testing"

func TestClassify_VssadminDeleteShadows(t *testing.T) {
	for _, cmd := range []string{
		`vssadmin delete shadows /all /quiet`,
		`vssadmin.exe delete shadows /Shadow={id} /Quiet`,
		`& "vssadmin.exe" DELETE SHADOWS /all`,      // case/quoting variation
		`  vssadmin   delete   shadows  /all  `,      // whitespace variation
	} {
		if got := Classify(cmd); got != ClassDestructive {
			t.Errorf("Classify(%q) = %q, want %q", cmd, got, ClassDestructive)
		}
	}
}

func TestClassify_WbadminDeleteCatalog(t *testing.T) {
	if got := Classify(`wbadmin.exe delete catalog -quiet`); got != ClassDestructive {
		t.Errorf("Classify(wbadmin delete catalog) = %q, want %q", got, ClassDestructive)
	}
}

func TestClassify_BcdeditRecoveryDisable(t *testing.T) {
	if got := Classify(`bcdedit /set {default} recoveryenabled no`); got != ClassDestructive {
		t.Errorf("Classify(bcdedit recoveryenabled no) = %q, want %q", got, ClassDestructive)
	}
}

func TestClassify_CipherWipe(t *testing.T) {
	if got := Classify(`cipher /w:C:\`); got != ClassDestructive {
		t.Errorf("Classify(cipher /w) = %q, want %q", got, ClassDestructive)
	}
}

func TestClassify_SafeEnumerationIsNonDestructive(t *testing.T) {
	if got := Classify(`vssadmin list shadows`); got != ClassNonDestructive {
		t.Errorf("Classify(vssadmin list shadows) = %q, want %q", got, ClassNonDestructive)
	}
	if got := Classify(`Get-Process | Select-Object Name`); got != ClassNonDestructive {
		t.Errorf("Classify(Get-Process) = %q, want %q", got, ClassNonDestructive)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./destructiveguard/... -v` (from `agent/`)
Expected: FAIL — package doesn't exist yet.

- [ ] **Step 3: Write the implementation**

```go
// agent/destructiveguard/rules.go
//
// Package destructiveguard is the agent's independent, vendor-curated,
// binary-compiled local backstop against catastrophic commands -- the
// second of B5's two defense-in-depth layers (see
// docs/superpowers/specs/2026-09-29-destructive-action-guardrail-b5-design.md).
// This package is NEVER modifiable through an orchestrator command, a
// B4-signed envelope field, scenario YAML, an environment variable, or
// (in a later phase) a local grant -- the grant authorizes a
// catalog-defined action; it never redefines what this package
// considers catastrophic.
//
// Deliberately NOT a PowerShell/shell semantic parser -- that's brittle
// and creates a false sense of completeness. A small, deterministic rule
// set matched against the normalized executable + arguments instead.
package destructiveguard

import (
	"regexp"
	"strings"
)

type Class string

const (
	ClassNonDestructive         Class = "non_destructive"
	ClassPotentiallyDestructive Class = "potentially_destructive"
	ClassDestructive            Class = "destructive"
)

// rule pairs a compiled pattern with what it means. Patterns match
// against the NORMALIZED command (see normalize below), so they never
// need to account for casing, quoting, or a leading "& " call-operator
// by themselves.
type rule struct {
	pattern *regexp.Regexp
	class   Class
}

// rules is the seed set. Each pattern is deliberately narrow and
// anchored to a real, verified destructive command found in this
// codebase's own scenario library during the B5 design investigation
// (see the design spec's "Local backstop rule engine" section) --
// extend it with the same rigor (a real verified command, not a guess)
// as this list grows.
var rules = []rule{
	{regexp.MustCompile(`\bvssadmin(\.exe)?\b.*\bdelete\b.*\bshadows\b`), ClassDestructive},
	{regexp.MustCompile(`\bwbadmin(\.exe)?\b.*\bdelete\b.*\bcatalog\b`), ClassDestructive},
	{regexp.MustCompile(`\bwbadmin(\.exe)?\b.*\bdelete\b.*\bsystemstatebackup\b`), ClassDestructive},
	{regexp.MustCompile(`\bbcdedit(\.exe)?\b.*\brecoveryenabled\b\s+no\b`), ClassDestructive},
	{regexp.MustCompile(`\bbcdedit(\.exe)?\b.*\bbootstatuspolicy\b\s+ignoreallfailures\b`), ClassDestructive},
	{regexp.MustCompile(`\bcipher(\.exe)?\b.*(^|\s)/w\b`), ClassDestructive},
	{regexp.MustCompile(`\bformat\b.*[a-z]:`), ClassDestructive},
}

// normalize case-folds and collapses whitespace so trivial quoting/
// casing/spacing variations can't defeat a pattern. Deliberately does
// NOT attempt real shell tokenization (that's the semantic-parser
// approach this package exists to avoid) -- it only strips the
// characters a scenario author or attacker would plausibly vary without
// changing what the command actually does: surrounding quotes/call
// operators and repeated whitespace.
func normalize(command string) string {
	s := strings.ToLower(command)
	s = strings.ReplaceAll(s, "&", " ")
	s = strings.ReplaceAll(s, `"`, " ")
	s = strings.ReplaceAll(s, "'", " ")
	s = strings.Join(strings.Fields(s), " ")
	return s
}

// Classify evaluates command against the local rule set and returns the
// most restrictive matching class, or ClassNonDestructive if nothing
// matches. Combined most-restrictive-wins with the signed catalog
// classification by the caller (agent/agent.go's B5 gate, Task 7) --
// this function never sees or considers that signed classification
// itself.
func Classify(command string) Class {
	n := normalize(command)
	for _, r := range rules {
		if r.pattern.MatchString(n) {
			return r.class
		}
	}
	return ClassNonDestructive
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./destructiveguard/... -v`
Expected: PASS (all cases, including the case/quoting/whitespace variations).

- [ ] **Step 5: Commit**

```bash
git add destructiveguard/rules.go destructiveguard/rules_test.go
git commit -m "feat(b5): agent-side vendor-curated local destructive-action rule backstop"
```

---

## Task 7: Agent B5 Gate — Per-Step Veto

**Files:**
- Modify: `agent/protocol/messages.go` (`ExecResult`, after the existing `TimedOut bool` field around line 105)
- Modify: `orchestrator/internal/scenario/types.go` (`ExecResult`, mirroring the same new fields -- around line 365, after `TimedOut`)
- Modify: `agent/agent.go` (`runScenario`'s per-step `Run` closure, immediately before line 897's `r := execStep(ctx, step, pool)`)
- Test: `agent/agent_b5_gate_test.go` (new file)

**Interfaces:**
- Consumes: Task 2's `ScenarioStep.ExecutionClass` (string); Task 6's `destructiveguard.Classify`.
- Produces: `ExecResult.Vetoed`/`.VetoedActionKey`/`.VetoedExecutionClass`/`.VetoedBlockSource` -- consumed by Task 8's orchestrator-side outcome classification.

- [ ] **Step 1: Write the failing tests**

```go
// agent/agent_b5_gate_test.go
package main

import (
	"testing"

	"audspect/agent/protocol"
)

// mostRestrictiveClass and evaluateB5Gate are the functions this task
// introduces -- see Step 3.

func TestEvaluateB5Gate_SignedDestructiveIsVetoed(t *testing.T) {
	step := protocol.ScenarioStep{
		TechniqueID: "T1490", ActionKey: "vss_delete",
		ExecutionClass: "destructive",
		Command:        "vssadmin delete shadows /all /quiet",
	}
	vetoed, source := evaluateB5Gate(step)
	if !vetoed {
		t.Fatal("expected veto for a signed-destructive step")
	}
	if source != "catalog" {
		t.Errorf("block_source = %q, want %q", source, "catalog")
	}
}

func TestEvaluateB5Gate_LocalBackstopCatchesUnderclassifiedStep(t *testing.T) {
	// Signed classification claims non_destructive (a compiled-in
	// mistake or catalog gap), but the actual command matches the local
	// backstop's known-catastrophic pattern -- must still be vetoed.
	step := protocol.ScenarioStep{
		TechniqueID: "T1490", ActionKey: "vss_delete",
		ExecutionClass: "non_destructive", // WRONG on purpose for this test
		Command:        "vssadmin delete shadows /all /quiet",
	}
	vetoed, source := evaluateB5Gate(step)
	if !vetoed {
		t.Fatal("expected the local backstop to override an under-classified signed field")
	}
	if source != "local_backstop" {
		t.Errorf("block_source = %q, want %q", source, "local_backstop")
	}
}

func TestEvaluateB5Gate_NonDestructiveExecutesNormally(t *testing.T) {
	step := protocol.ScenarioStep{
		TechniqueID: "T1082", ExecutionClass: "non_destructive",
		Command: "Get-ComputerInfo",
	}
	vetoed, _ := evaluateB5Gate(step)
	if vetoed {
		t.Error("expected a genuinely non-destructive step to execute")
	}
}

func TestEvaluateB5Gate_PotentiallyDestructiveExecutesNormally(t *testing.T) {
	step := protocol.ScenarioStep{
		TechniqueID: "T1003", ExecutionClass: "potentially_destructive",
		Command: "Get-Process lsass",
	}
	vetoed, _ := evaluateB5Gate(step)
	if vetoed {
		t.Error("expected potentially_destructive to execute (no grant required in this phase's semantics, and this phase has no grant mechanism to check anyway)")
	}
}

func TestEvaluateB5Gate_UnclassifiedIsVetoed(t *testing.T) {
	step := protocol.ScenarioStep{
		TechniqueID: "T9999", ExecutionClass: "", // never resolved / unknown to this agent build
		Command: "something",
	}
	vetoed, _ := evaluateB5Gate(step)
	if !vetoed {
		t.Fatal("expected an unclassified step to fail closed to vetoed")
	}
}
```

Also add, in `agent/sched/veto_continuation_test.go` (new file) -- this locks in the scheduler-level guarantee the veto gate depends on: a job whose `Run` closure returns `false` never prevents sibling jobs from having their own `Run` closures invoked. This characterizes EXISTING `sched.Run` behavior (nothing in this task changes it), so it should pass immediately once written, not require new scheduler code:

```go
// agent/sched/veto_continuation_test.go
package sched

import (
	"context"
	"sync/atomic"
	"testing"
)

// TestRun_FalseReturnFromOneJobDoesNotPreventSiblingsFromRunning locks in
// the exact scheduler guarantee agent.go's B5 veto check (and its
// existing circuit-breaker/payload-quarantine neighbors) relies on: a
// job's Run closure returning false only marks THAT job non-retrying --
// it never stops the scheduler from invoking every other job's Run
// closure. Read this file's neighboring tests (e.g. equiv_test.go) for
// the real Job/LockManager/Gate construction pattern this codebase
// already uses before writing the fixture below -- do not invent a
// different one.
func TestRun_FalseReturnFromOneJobDoesNotPreventSiblingsFromRunning(t *testing.T) {
	var vetoedRan, siblingRan int32
	// Construct jobs (adapt to the real Job/LockManager/Gate fixture
	// pattern from equiv_test.go/limiter_test.go): job[0]'s Run always
	// returns false (simulating a veto); job[1]'s Run returns true and
	// must still be observed to run.
	jobs := []Job{
		{Run: func(ctx context.Context) bool {
			atomic.AddInt32(&vetoedRan, 1)
			return false
		}},
		{Run: func(ctx context.Context) bool {
			atomic.AddInt32(&siblingRan, 1)
			return true
		}},
	}
	// Call Run(...) with the real signature (context.go/scheduler.go's
	// Run(ctx, workers, lm, jobs, gate, opts...)) -- construct a
	// LockManager/Gate the same way an existing sched test does.
	_ = jobs // replace with the real Run(...) call once the fixture is built

	if atomic.LoadInt32(&vetoedRan) != 1 {
		t.Error("the vetoed job's Run was not invoked")
	}
	if atomic.LoadInt32(&siblingRan) != 1 {
		t.Error("a false return from one job's Run prevented a sibling job's Run from executing")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test . -run TestEvaluateB5Gate -v` (from `agent/`)
Expected: FAIL — `evaluateB5Gate` undefined.

Run: `go test ./sched/... -run TestRun_FalseReturnFromOneJobDoesNotPreventSiblingsFromRunning -v`
Expected: this one should already PASS once the fixture is filled in against the real `Job`/`LockManager`/`Gate` construction (it's a characterization test of existing behavior) -- if it instead reveals sibling jobs are NOT invoked, that is a real, separate scheduler bug outside this plan's scope; stop and flag it rather than silently working around it in the B5 gate.

- [ ] **Step 3: Write the implementation**

New file `agent/destructiveguard_gate.go` (kept in `package main` since it needs `protocol.ScenarioStep`, unlike the standalone `destructiveguard` package):

```go
// agent/destructiveguard_gate.go
//
// B5's per-step gate: combines the signed, catalog-resolved
// ExecutionClass carried on each ScenarioStep with this agent's own
// independent destructiveguard.Classify evaluation of the actual
// command text, most-restrictive-wins. See
// docs/superpowers/specs/2026-09-29-destructive-action-guardrail-b5-design.md.
//
// Phase 1 has no grant mechanism (that's Phase 2) -- a step this gate
// classifies as destructive is unconditionally vetoed. Do not add a
// bypass here; the absence of one is this phase's correct behavior.
package main

import (
	"audspect/agent/destructiveguard"
	"audspect/agent/protocol"
)

// classRank orders classes for most-restrictive-wins comparison. An
// empty/unrecognized ExecutionClass ranks as destructive (fail closed) --
// see rank's own default case.
func classRank(c string) int {
	switch c {
	case "non_destructive":
		return 1
	case "potentially_destructive":
		return 2
	case "destructive":
		return 3
	default:
		return 3 // unclassified/unrecognized -- fail closed
	}
}

// evaluateB5Gate returns whether step is vetoed, and which layer decided
// it (for BLOCKED/VETOED audit reporting, Task 8): "catalog" (the
// signed classification alone was destructive), "local_backstop" (the
// agent's own rule engine caught it independently of, or despite, the
// signed classification), or "both".
func evaluateB5Gate(step protocol.ScenarioStep) (vetoed bool, blockSource string) {
	signedRank := classRank(step.ExecutionClass)
	localClass := destructiveguard.Classify(step.Command)
	localRank := classRank(string(localClass))

	signedDestructive := signedRank >= classRank("destructive")
	localDestructive := localRank >= classRank("destructive")

	switch {
	case signedDestructive && localDestructive:
		return true, "both"
	case signedDestructive:
		return true, "catalog"
	case localDestructive:
		return true, "local_backstop"
	default:
		return false, ""
	}
}
```

Add to `agent/protocol/messages.go`'s `ExecResult`, immediately after line 105 (`TimedOut bool \`json:"timedOut,omitempty"\``) -- deliberately distinct names from the existing `Blocked`/`BlockedReason` fields (those already mean "the customer's own EDR/AV quarantined something," see `agent/agent.go`'s payload-quarantine block around line 877-889 -- reusing them for B5 would silently conflate an Audspect-side refusal with a customer-defense event):

```go
	Vetoed               bool   `json:"vetoed,omitempty"`
	VetoedActionKey      string `json:"vetoedActionKey,omitempty"`
	VetoedExecutionClass string `json:"vetoedExecutionClass,omitempty"`
	VetoedBlockSource    string `json:"vetoedBlockSource,omitempty"`
```

Mirror the same four fields, same JSON tags, in `orchestrator/internal/scenario/types.go`'s `ExecResult` (around line 365, after `TimedOut bool`).

Wire the gate into `agent/agent.go`'s `runScenario`, immediately before line 897 (`r := execStep(ctx, step, pool)`), in the same style as the existing payload-quarantine block at lines 877-889:

```go
				if vetoed, source := evaluateB5Gate(step); vetoed {
					log.Printf("[!]   [%d/%d] %s VETOED — destructive-action policy (class=%s, action=%s, source=%s)",
						i+1, total, step.TechniqueID, step.ExecutionClass, step.ActionKey, source)
					results[i] = protocol.ExecResult{
						TaskID:               step.TaskID,
						ExitCode:             -1,
						Vetoed:               true,
						VetoedActionKey:       step.ActionKey,
						VetoedExecutionClass: step.ExecutionClass,
						VetoedBlockSource:    source,
						ExecutedAt:           time.Now(),
					}
					ran[i] = true
					emit(RunEvent{Type: "completed", TaskID: step.TaskID, TechniqueID: step.TechniqueID, StepName: step.Name,
						Payload: map[string]any{"verdict": "vetoed"}})
					return false
				}

				step.PayloadDir = stepDir
				step.Env = policyEnv
				r := execStep(ctx, step, pool)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test . -run TestEvaluateB5Gate -v` (from `agent/`)
Expected: PASS (all 5 cases).

Run: `go test ./sched/... -run TestRun_FalseReturnFromOneJobDoesNotPreventSiblingsFromRunning -v`
Expected: PASS.

Run the full agent package suite to confirm the `runScenario` wiring didn't disturb the existing payload-quarantine/circuit-breaker paths it now sits alongside:

Run: `go test . -v`
Expected: PASS across the whole package (this includes real, possibly slow scenario-execution tests -- allow several minutes; do not truncate the run early).

- [ ] **Step 5: Commit**

```bash
git add destructiveguard_gate.go agent_b5_gate_test.go protocol/messages.go agent.go sched/veto_continuation_test.go
git commit -m "feat(b5): agent-side per-step destructive-action veto gate"
cd ../orchestrator
git add internal/scenario/types.go
git commit -m "feat(b5): mirror agent Vetoed* ExecResult fields server-side"
```

---

## Task 8: `VETOED` Outcome — Model and Classification

**Files:**
- Modify: `orchestrator/internal/models/schema.go:13-23` (`CheckResult` constants)
- Modify: `orchestrator/internal/scenario/outcome.go:17-22` (`ExecutionOutcome` constants) and `outcome.go`'s `classifyExecution` (around line 235-253)
- Modify: `orchestrator/internal/scenario/interpreter.go:145-157` (`interpretART`)
- Test: `orchestrator/internal/scenario/outcome_test.go`, `orchestrator/internal/scenario/interpreter_test.go` (extend existing)

**Interfaces:**
- Consumes: Task 7's `ExecResult.Vetoed`/`.VetoedActionKey`/`.VetoedExecutionClass`/`.VetoedBlockSource`.
- Produces: `models.ResultVetoed`, `scenario.OutcomeVetoed` -- consumed by Task 9's scoring-exclusion audit.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/scenario/outcome_test.go (append)
func TestClassifyExecution_VetoedStepTakesPriorityOverEverything(t *testing.T) {
	r := ExecResult{
		Vetoed: true, VetoedActionKey: "vss_delete",
		VetoedExecutionClass: "destructive", VetoedBlockSource: "catalog",
		ExitCode: -1,
	}
	outcome, reason, detail := classifyExecution(r, "")
	if outcome != OutcomeVetoed {
		t.Errorf("outcome = %v, want OutcomeVetoed", outcome)
	}
	if reason != ErrNone {
		t.Errorf("reason = %v, want ErrNone -- a veto is not a BAS execution error", reason)
	}
	if !strings.Contains(detail, "VETOED") || !strings.Contains(detail, "not tested") {
		t.Errorf("detail = %q, must clearly state the customer's defenses were not tested", detail)
	}
}
```

```go
// orchestrator/internal/scenario/interpreter_test.go (append)
func TestInterpretART_VetoedMapsToResultVetoedNeverResultPass(t *testing.T) {
	r := ExecResult{Vetoed: true, VetoedActionKey: "vss_delete", VetoedExecutionClass: "destructive"}
	result, _ := interpretART(r, "")
	if result != models.ResultVetoed {
		t.Errorf("result = %v, want models.ResultVetoed", result)
	}
	if result == models.ResultPass || result == models.ResultBlocked {
		t.Fatal("a B5 veto must NEVER map to ResultPass or ResultBlocked -- that would falsely report a customer-defense success for a technique that was never attempted")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/scenario/... -run "TestClassifyExecution_VetoedStepTakesPriorityOverEverything|TestInterpretART_VetoedMapsToResultVetoedNeverResultPass" -v`
Expected: FAIL — `OutcomeVetoed`/`models.ResultVetoed` undefined.

- [ ] **Step 3: Write the implementation**

`orchestrator/internal/models/schema.go`, in the `CheckResult` const block (after line 23's `ResultError`):

```go
	// ResultVetoed means Audspect's own agent refused to execute this
	// step under its local destructive-action policy (B5). Deliberately
	// distinct from ResultBlocked (the CUSTOMER's own security control
	// intercepted the technique -- scores as a defense success) --
	// conflating the two would report a technique as tested-and-stopped
	// when it was never attempted at all. Must be excluded from every
	// PreventionScore/PreventionPct/BypassRate calculation; see
	// docs/superpowers/specs/2026-09-29-destructive-action-guardrail-b5-design.md.
	ResultVetoed CheckResult = "vetoed"
```

`orchestrator/internal/scenario/outcome.go`, in the `ExecutionOutcome` const block (after line 21's `OutcomeSkipped`):

```go
	// OutcomeVetoed: Audspect's own agent refused to execute this step
	// under B5's local destructive-action policy -- the technique was
	// never attempted. NEVER maps to OutcomeBlocked (customer defense
	// success) or any other existing outcome.
	OutcomeVetoed
```

`outcome.go`'s `classifyExecution`, as the very first check (before the existing `r.TimedOut` check):

```go
func classifyExecution(r ExecResult, combined string) (ExecutionOutcome, ErrorReason, string) {
	if r.Vetoed {
		return OutcomeVetoed, ErrNone, fmt.Sprintf(
			"VETOED — Audspect prevented execution under its local destructive-action policy (action=%s, class=%s, source=%s). Customer defensive controls were not tested by this step.",
			r.VetoedActionKey, r.VetoedExecutionClass, r.VetoedBlockSource)
	}

	lower := strings.ToLower(combined)
	// ... existing body unchanged from here
```

`interpreter.go`'s `interpretART`, add a case (the switch's existing `default: // OutcomeExecuted` must stay last):

```go
	switch outcome {
	case OutcomeVetoed:
		return models.ResultVetoed, detail
	case OutcomeSkipped:
		return models.ResultSkipped, detail
	case OutcomeBlocked:
		return models.ResultPass, detail
	case OutcomeError:
		return models.ResultError, detail
	default: // OutcomeExecuted
		return models.ResultFail, detail
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/scenario/... -v`
Expected: PASS, including both new tests and every pre-existing test in `internal/scenario` (particularly `outcome_test.go`'s and `interpreter_test.go`'s full existing suites, confirming the new priority-ordered `Vetoed` check didn't change classification for any non-vetoed result).

- [ ] **Step 5: Commit**

```bash
git add internal/models/schema.go internal/scenario/outcome.go internal/scenario/outcome_test.go internal/scenario/interpreter.go internal/scenario/interpreter_test.go
git commit -m "feat(b5): add VETOED outcome, kept distinct from OutcomeBlocked/ResultPass"
```

---

## Task 9: Audit Every `CheckResult` Consumer for Safe `VETOED` Handling

**Files:**
- Investigate and, where needed, modify each of (found via `grep -rn "ResultBlocked" orchestrator/` during this plan's own investigation -- re-run this grep at task start, since it may have drifted):
  - `orchestrator/internal/driftanalytics/driftanalytics.go`
  - `orchestrator/internal/siem/correlator.go`
  - `orchestrator/internal/models/helpers.go:283`
  - `orchestrator/internal/models/score.go:103`
  - `orchestrator/internal/detecteffectiveness/detecteffectiveness.go:204`
  - `orchestrator/internal/compliance/mapper.go:179`
  - `orchestrator/internal/api/bas_revalidation_dispatch.go:77`
  - `orchestrator/internal/api/finding_handlers.go:77,339`
  - `orchestrator/internal/api/endpointrisk_aggregations.go:79`
  - `orchestrator/internal/campaign/campaign_test.go` (test file -- check whether production `campaign.go` has the equivalent logic under test)
  - `orchestrator/internal/reporting/pdf.go:1337,1369`
  - `orchestrator/internal/reporting/engine.go` (the `Blocked`/`Detected`/`Bypassed`/`PreventionScore`/`BypassRate` aggregation found at approximately lines 840-850, 1000-1030, 2545-2555, 3405-3465 during this plan's investigation)
  - `orchestrator/internal/detectverify/orchestrate_test.go` (test file -- check the production code it exercises)
- Test: extend each file's existing test suite with one case proving `ResultVetoed` is excluded from that file's scoring/pass-equivalence logic.

**Interfaces:**
- Consumes: Task 8's `models.ResultVetoed`.
- Produces: nothing new -- this task only audits and, where a real gap is found, fixes existing call sites.

**This task cannot be fully pre-written** -- each file's exact handling must be read before judging whether it's already safe (most `case ResultPass, ResultBlocked:` exhaustive switches are safe by construction: a new, unmatched `ResultVetoed` value simply falls through to that switch's own default/else, which in most files found during investigation means "not counted" rather than "counted as pass") or needs an explicit exclusion added (this is confirmed necessary at minimum for `internal/reporting/engine.go`'s `Blocked`/`Detected`/`Bypassed` counters, which directly compute `PreventionScore`/`BypassRate` -- verified during this plan's own investigation, see `engine.go:3459-3462`).

- [ ] **Step 1: Re-run the discovery grep and diff against the file list above**

Run (from `orchestrator/`): `grep -rn "ResultBlocked\|ResultPass" --include="*.go" internal/ | grep -v _test.go`

Confirm the file list above is still accurate (files may have moved/merged since this plan was written); note any new or removed call sites.

- [ ] **Step 2: For each file, write a test proving `ResultVetoed` is excluded from that file's pass/prevention-equivalence logic**

Pattern (adapt per file -- shown for `internal/reporting/engine.go`, the confirmed-necessary case):

```go
// orchestrator/internal/reporting/engine_test.go (append)
func TestVariantCoverage_VetoedExcludedFromPreventionScore(t *testing.T) {
	// Build a fixture where one result is ResultVetoed and the rest are a
	// known mix of ResultBlocked/ResultFail -- assert PreventionScore/
	// BypassRate compute identically whether or not the vetoed result is
	// present, proving it contributes to neither numerator nor
	// denominator. (Read the real fixture-construction pattern this
	// file's existing tests already use -- e.g. TestVariantCoverage_* --
	// before writing this; do not invent a fixture shape that doesn't
	// match how summaries are actually built in this package.)
}
```

For every file in the list where the existing `case ResultPass, ResultBlocked:` (or equivalent) pattern is confirmed exhaustive and safe by inspection (an unmatched `ResultVetoed` falls to a default that does NOT count it as pass/fail), add a short comment at that switch noting the exclusion is intentional and verified, rather than silently leaving it unremarked -- a future reader must not "fix" it into an exhaustive switch that accidentally adds `ResultVetoed` to the pass bucket.

- [ ] **Step 3: Fix `internal/reporting/engine.go`'s confirmed gap**

Read `engine.go` around the four line ranges above in full. The `blocked`/`detected`/`bypassed` counts that feed `VariantTechRow`/`VariantCoverageSection` are populated from a SQL query's result rows (`summaries`) -- find that query (search for where `s.blocked`/`s.detected`/`s.bypassed` are populated, likely a `SELECT ... FILTER (WHERE result = 'blocked') ...`-style aggregation) and confirm it does not and will not implicitly capture `'vetoed'` rows into any of the three buckets. Add an explicit `WHERE result != 'vetoed'` (or equivalent) to the query if the query's own WHERE clause is broad enough that a new result string could silently enter one of the existing buckets; if the query already filters by exact result string per bucket (safe by construction), add the verifying comment from Step 2 instead of a code change.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -run "Vetoed" -v` (from `orchestrator/`, across every package touched)
Expected: PASS.

Run the full orchestrator suite once to confirm no regression: `go test ./... 2>&1 | tail -60` (expect the same pre-existing unrelated `internal/observability` build gap noted throughout this project's history, nothing else).

- [ ] **Step 5: Commit**

```bash
git add -A  # only after reviewing `git status` -- this task touches many files across several packages
git commit -m "fix(b5): audit and confirm/fix every CheckResult consumer excludes VETOED from scoring"
```

---

## Task 10: Full Technique-Library Classification Audit

**Files:**
- Modify: `orchestrator/internal/scenario/execclass.go` (the `executionClassifications` map -- extend far beyond Task 1's seed entries)
- Modify: scenario YAML files under `scenarios/` wherever a hand-authored destructive step needs an `action_key` it doesn't have yet (found during this audit)
- Test: `orchestrator/internal/scenario/execclass_test.go` (add coverage-completeness assertions)

**Interfaces:**
- Consumes: Task 1's catalog structure and resolver.
- Produces: a `executionClassifications` map with a real entry for every distinct `(technique_id, action_key)` pair that exists anywhere in the current technique corpus (ART atomics, Caldera abilities, hand-authored scenario `steps:`) -- so that after this task, nothing in the currently-shipped scenario library relies on the fail-closed default by accident (fail-closed remains the correct behavior for anything genuinely never reviewed, e.g. content added after this audit).

**This task's true size is not known from this planning session** -- it requires a live orchestrator database connection (the ART atomic corpus lives in the `art_atomic_tests` table, populated from a source not present in this git checkout; Caldera abilities live in a running Caldera instance) that was not available while writing this plan. Do not skip the steps below to save time; do not guess classifications without reading real command text, matching the rigor `resource.go`'s own `discoveryProfiles` audits (see that file's 2026-08-20 and 2026-08-26 audit comments) already established for a different concern.

- [ ] **Step 1: Enumerate the full corpus**

Against a real orchestrator deployment with its database populated:

```sql
SELECT DISTINCT technique_id, command FROM art_atomic_tests ORDER BY technique_id;
```

Separately enumerate Caldera abilities (via the Caldera API's `/api/v2/abilities` endpoint, or however `orchestrator/internal/scenario/caldera_store.go` already fetches them for `buildCalderaAdversarySteps`/`buildCalderaAbilitiesSteps` -- reuse that existing client rather than writing a new one) and every hand-authored `steps:` entry across `scenarios/*.yaml` and `scenarios/**/*.yaml` (a plain `grep -rn "command:" scenarios/` plus reading each match's surrounding step is sufficient; this set is small and version-controlled, unlike the ART/Caldera corpora).

Export the full `(technique_id, action_key-if-any, command)` corpus to a working file for the remaining steps.

- [ ] **Step 2: Triage tier 1 — reuse the existing discovery audit**

Every technique already present in `orchestrator/internal/scenario/resource.go`'s `discoveryProfiles` map has already been individually verified read-only (see that file's own audit comments). Mark each as `ClassNonDestructive`, `action_key: "default"`, citing the existing audit rather than re-reviewing the command text from scratch -- this is a real, already-completed piece of evidence, not a shortcut.

- [ ] **Step 3: Triage tier 2 — ATT&CK Impact-tactic techniques get priority manual review**

Cross-reference the corpus against ATT&CK's Impact tactic (TA0040: T1485 Data Destruction, T1486 Data Encrypted for Impact, T1489 Service Stop, T1490 Inhibit System Recovery, T1491 Defacement, T1495 Firmware Corruption, T1496 Resource Hijacking, T1498/T1499 Denial of Service, T1561 Disk Wipe, T1565 Data Manipulation, and their sub-techniques) -- this project's existing ATT&CK enrichment data (`internal/attack` or wherever the bundled STIX/curated overlay from `project_attack_enrichment` lives, per project history) should already have a technique→tactic mapping to query against rather than hand-maintaining one here. Every technique in this tier gets full manual command-text review before any classification is assigned -- default to `ClassDestructive` for anything not individually confirmed safe, not the other way around.

- [ ] **Step 4: Triage tier 3 — pattern-scan the rest, manually review every hit plus a real sample of the remainder**

Grep the exported corpus (Step 1) for the same dangerous-pattern vocabulary `agent/destructiveguard/rules.go` (Task 6) already encodes, PLUS a wider net appropriate for a one-time audit (Task 6's rules stay narrow/high-confidence for runtime use; this audit pass can and should cast wider and rely on human review to resolve false positives): `Stop-Service`+`sc.exe delete`/`Remove-Service`, `reg delete`, `diskpart`, `del /f /s /q`, `Remove-Item -Recurse -Force` against non-BAS-owned paths, `rm -rf` against non-BAS-owned paths, `Set-MpPreference -DisableRealtimeMonitoring`, `Disable-WindowsOptionalFeature`, mass file-write/encryption loops, `net stop`, `taskkill /f` against security-product process names. Manually review every match. For everything with no match, review a real sample (not a rubber-stamp "no pattern hit, mark safe") before assigning `ClassNonDestructive` -- matching `resource.go`'s own standard of checking real command text, not assuming.

- [ ] **Step 5: Write every real finding into `execclass.go`**

Extend `executionClassifications`. Every entry needs a real `BlastRadius` description grounded in what the reviewed command text actually does (not a generic placeholder). Add `action_key` values (and, where the underlying scenario is hand-authored, add the corresponding `action_key:` YAML field from Task 4) for every technique found to have more than one materially different behavior -- T1490 (already seeded in Task 1) is the confirmed example; this audit may find others (e.g., a technique with both a safe-enumerate and a destructive-execute atomic, mirroring T1490's shape).

- [ ] **Step 6: Add a coverage-completeness test**

```go
// orchestrator/internal/scenario/execclass_test.go (append)
func TestExecutionClassifications_NoTechniqueInCorpusIsUnclassified(t *testing.T) {
	// This test's real body depends on Step 1's exported corpus, which
	// doesn't exist at plan-writing time -- write it against whatever
	// concrete list of (technique_id, action_key) pairs Step 1 actually
	// produced, asserting ResolveExecutionClass returns something other
	// than the `unclassified` fail-closed default for every one of them.
	// A pair genuinely absent from the corpus is fine to leave
	// unclassified (fail-closed remains correct for anything never
	// reviewed); a pair PRESENT in the corpus with no real catalog entry
	// is this test's failure condition.
}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `go test ./internal/scenario/... -v`
Expected: PASS, including the new completeness test.

- [ ] **Step 8: Commit**

```bash
git add internal/scenario/execclass.go internal/scenario/execclass_test.go
git commit -m "feat(b5): full technique-library destructive-action classification audit"
```

(If this task's real scope, once Step 1's corpus size is known, turns out too large for one commit/PR to review sensibly, split it into several commits by tactic or content source -- e.g. one for Impact-tactic techniques, one for the pattern-scan-flagged set, one for the bulk "reviewed, confirmed safe" remainder -- rather than one enormous diff. Use judgment once the real size is visible; this plan cannot decide that in advance.)

---

## Final Verification

Run the full test suite for both modules:

```bash
cd orchestrator && go build ./... && go vet ./... && go test ./... 2>&1 | tail -80
cd ../agent && go build ./... && go vet ./... && go test ./... 2>&1 | tail -80
```

Expected: clean builds, `go vet` clean except the pre-existing unrelated `internal/observability` gap noted throughout this project's history, all tests passing.

Manually confirm the end-to-end em-07 case this whole design exists to fix: with a real (or test-fixture) deployment, dispatch `scenarios/endpoint-mastery/em-07-ransomware-readiness.yaml` and confirm Stages 4A/4B (`vssadmin delete shadows`, `wbadmin delete catalog`) are reported `VETOED`, not executed, while the scenario's other (safe) stages still run to completion.
