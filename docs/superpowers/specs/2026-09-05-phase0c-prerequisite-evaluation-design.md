# Phase 0C: Environmental Prerequisite Evaluation — Design

**Spec this argues from:** [docs/superpowers/specs/2026-09-04-phase0b-execution-attempt-design.md](2026-09-04-phase0b-execution-attempt-design.md)
(Phase 0B — the `execution_attempts` table and `skip_reason='prerequisite_unsatisfied'` vocabulary
this phase is the first real producer of.)

## Goal

Before dispatching a technique step whose success genuinely depends on a fact about the target
endpoint (is this machine domain-joined?), check that fact and skip the step with a clear reason
instead of running it, getting a meaningless result, and having someone read tea leaves from a
failed atomic afterward. First and only fact in this phase: `domain_joined`, the exact example
named in Phase 0B's own spec text.

This phase is deliberately narrow. Cross-technique outcome chaining ("effects" — did an earlier
technique's success unlock a later one) is explicitly **not** built here; see
[Explicitly out of scope](#explicitly-out-of-scope-for-phase-0c).

## Context: two existing skip mechanisms, not a new subsystem

Both execution engines already have a working, in-production pattern for excluding a step before
it runs and recording why. This phase extends both by one case each — it does not invent new
plumbing.

**ART/Caldera** (`orchestrator/internal/api/handlers.go`, `dispatchRun`): before dispatch, steps
pass through pre-dispatch filters that pull out ones that shouldn't run and replace them with a
synthesized `Skipped` `SimulationResult` instead — used today for two cases:

- `synthesizePolicySkipResult` (`handlers.go:1613`) — a step's `RequiresPriv` exceeds the run's
  `MaxPrivilege` ceiling. Tags `models.SkipReasonPolicyPrivilege`.
- `synthesizeSkippedContentResult` (`handlers.go:1636`) — a Caldera ability or ART technique has
  no usable content for the target platform. Tags `models.SkipReasonPlatformUnavailable`.

Both route through `scenario.Interpret` (the same interpreter every real result goes through, so
severity/remediation/threat-impact lookups are identical to a real run) and both persist into
`scenario_runs.policy_skipped_results` (`handlers.go:1984`), which already surfaces correctly in
reports, findings, and the Live view. If every step in a run gets excluded this way, the run
completes immediately with only synthesized results (`handlers.go:1989` onward) — and Phase 0B's
final-review fix wave (`3aa728a`) already wired this exact case to call
`markExecutionAttemptSkipped(ctx, runID, models.SkipReasonPrerequisiteUnsatisfied)`, so the
run-level `execution_attempts` row already knows how to represent "every step was
prerequisite-skipped." That skip reason has had zero producers until this phase.

**`internal/exercise`** (`Executor.evalCondition`, `executor.go:733`): a condition-predicate
grammar already gates step dispatch — but every predicate today is `step:<stepID>:<predicate>`,
checking another step's own outcome (`clicked`, `succeeded`, `timeout`, …). A condition that
evaluates false already produces a `skipped` `StepExecution` with `SkipReasonConditionFalse`
through the fully-wired Phase 0B path (`Store.SetStepStatus` → `execution_attempts`, per the
final-review fix). There is no predicate today that checks anything about the *agent* rather than
another step.

**What this means for scope:** neither engine needs new `execution_attempts` schema, no new skip
storage, no new reporting surface. A partial skip (some steps skipped, others real) is per-step
detail that already lives in `scenario_runs.results` / `exercise_step_executions`, exactly like
the two existing ART/Caldera skip families and the exercise engine's condition-skips today.
`execution_attempts`'s run/step-level row is unaffected except in the already-solved
all-steps-skipped edge case.

## The fact: `domain_joined`

**Collection (agent-side, new).** `agent/protocol/heartbeat.go`'s `Heartbeat` struct gains
`DomainJoined *bool` (pointer, not a bare `bool`) so `nil` means "not evaluated on this platform"
and is distinct from a real `false` — domain-join is a Windows/AD concept; POSIX agents report
`nil`, never a fabricated `false`. Collected once at agent startup (like `OSVersion`) and resent
on every heartbeat, so an agent that gets domain-joined mid-lifetime (rare, but real) is reflected
without requiring re-enrollment.

Windows collection: query the machine's domain-membership state via the standard
`NetGetJoinInformation` Win32 API (already the canonical way to answer this without shelling out —
prefer it over parsing `systeminfo`/`wmic` text output, consistent with this codebase's existing
Win32-API-over-shell-parsing convention in `agent/job_windows.go`). POSIX: no collection in this
phase — the field stays `nil`, which the gate below treats as "unknown, do not skip" (see
[Error handling](#error-handling--unknown-facts)).

**Storage (orchestrator-side, new).** `agents` table gains `domain_joined boolean` (nullable,
`NULL` = unknown/not yet reported), refreshed on every heartbeat write alongside `os_version`.

## Write-side integration

### ART/Caldera: a third pre-dispatch filter

`internal/scenario/resource.go` gains `prerequisiteOverrides`, a small curated map — same shape and
same file as the existing evidence-driven `timeoutOverrides` (`resource.go:78`):

```go
type PrerequisiteSpec struct {
	Fact     string // "domain_joined" in this phase; the only fact that exists
	Required bool   // the value the fact must equal for the step to be eligible
}

var prerequisiteOverrides = map[string]PrerequisiteSpec{
	"T1087.002": {Fact: "domain_joined", Required: true}, // Account Discovery: Domain Account —
	// confirmed present in real staging content and traffic (2026-09-05 evidence run); genuinely
	// meaningless against a non-domain-joined host. Further entries added the same way
	// timeoutOverrides was: one evidence-backed technique at a time during implementation, not
	// guessed here.
}

func PrerequisiteFor(techniqueID string) (PrerequisiteSpec, bool) {
	spec, ok := prerequisiteOverrides[techniqueID]
	return spec, ok
}
```

`dispatchRun` fetches per-concern agent facts as small, separate `QueryRow`+`Scan` calls right
where each is needed — the existing `agentState` and `agentOSVersion` fetches earlier in the
function (`handlers.go:1710-1712`, `1721-1723`) are two examples of this same idiom, not a single
loaded agent struct. `domainJoined` follows the identical pattern, fetched right before the new
filter block, which is placed after the existing privilege filter (`handlers.go:1968-1978`) and
before the `len(skippedResults) > 0` persistence check, in the same
`kept := make(...); for _, st := range steps { ... }; steps = kept` shape as its neighbors:

```go
var domainJoined *bool
h.db.QueryRow(ctx,
	`SELECT domain_joined FROM agents WHERE agent_id = $1`, agentID,
).Scan(&domainJoined)

if domainJoined != nil { // nil = unknown, never gate on it — see Error handling
	kept := make([]scenario.ScenarioStep, 0, len(steps))
	for _, st := range steps {
		if spec, ok := scenario.PrerequisiteFor(st.TechniqueID); ok && spec.Fact == "domain_joined" {
			if *domainJoined != spec.Required {
				skippedResults = append(skippedResults, synthesizePrerequisiteSkipResult(st, spec))
				continue
			}
		}
		kept = append(kept, st)
	}
	steps = kept
}
```

`synthesizePrerequisiteSkipResult` (`handlers.go`, next to the two existing `synthesize*`
functions) mirrors `synthesizePolicySkipResult`'s shape exactly:

```go
func synthesizePrerequisiteSkipResult(st scenario.ScenarioStep, spec scenario.PrerequisiteSpec) models.SimulationResult {
	step := scenario.Step{TechniqueID: st.TechniqueID, Name: st.Name, Framework: st.Framework}
	result := scenario.ExecResult{
		TaskID: st.TaskID,
		Stdout: fmt.Sprintf("SKIP: requires %s=%v, agent reports otherwise", spec.Fact, spec.Required),
	}
	sim := scenario.Interpret(step, result)
	sim.SkipReason = models.SkipReasonPrerequisiteUnsatisfied
	return sim
}
```

One small additional query, matching the exact idiom `dispatchRun` already uses twice for
`agentState` and `agentOSVersion` — not a new pattern introduced by this phase.

### `internal/exercise`: a sibling predicate namespace

`evalCondition` (`executor.go:741-746`) currently rejects anything whose first `:`-delimited part
isn't `"step"`. Add a parallel case:

```go
if len(parts) == 2 && parts[0] == "agent" {
	return e.agentFact(ctx, execID, parts[1]) // "agent:domain_joined"
}
```

Agent targeting in `internal/exercise` is per-step, not per-`Execution` — `dispatchStep`
(`executor.go:290`) reads the target agent from the step's own `AgentTaskConfig.AgentID`
(`cfg.AgentID`, `executor.go:429`), so a single exercise plan can address different agents across
its steps. `agentFact` resolves the *current* step's own `AgentTaskConfig.AgentID` the same way and
compares its known `DomainJoined` value against the boolean the condition string encodes —
`evalCondition`'s exact signature may need to grow a parameter to reach that config from where it's
called; that's an implementation-time detail, not a design one. A step whose `Condition` evaluates
false already produces `SkipReasonConditionFalse` through the fully-wired path — no new
`execution_attempts` work needed here either.

## Error handling — unknown facts

`DomainJoined == nil` (never reported: POSIX agent, or a Windows agent that hasn't sent a
post-upgrade heartbeat yet) means **do not gate** — every curated technique dispatches normally,
exactly as it does today. Skipping on missing data would be worse than not checking at all: it
would silently exclude techniques from every POSIX run and from every Windows agent's very first
run after upgrade, for a reason no report would explain clearly. This mirrors Phase 0B's own
discipline (`StepTermination` nil = "not reported", never inferred as a negative signal).

A curated technique's requirement is checked only when the agent has affirmatively reported the
fact at least once.

## Explicitly out of scope for Phase 0C

- **Cross-technique outcome chaining ("effects")** — whether an earlier technique's success or
  failure should gate a later one. Real, and named in the roadmap as the eventual second half of
  this phase's theme, but it's a materially different problem (querying `execution_attempts`
  across steps within a still-in-progress run, not a static fact lookup) and deserves its own
  brainstorm once this narrower slice has shipped and been used.
- **Any fact beyond `domain_joined`.** No generic facts bag, no fact-comparison DSL. If a second
  fact is needed later, it is added the same way this one was: one curated field, one heartbeat
  addition, one column — evolving toward a generic model only if enough facts accumulate to make
  the per-fact migration cost genuinely painful, not speculatively now.
- **Native ART/Caldera `get_prereq_command`/`prereq_command` execution.** A real, standard
  mechanism this codebase's ART importer currently parses and discards — a legitimate future
  phase, but a different one (live agent-side command execution vs. a static fact lookup already
  known from heartbeat).
- **Reusing the existing posture-check (`simulate_*.go`) engine.** Different problem (broader
  hardening/compliance assessment) with a different consumer (BFSI compliance reporting); forcing
  per-technique gating through it would be a conceptual mismatch for most techniques.
- **UI surfacing of prerequisite-skip statistics.** The existing report/findings/Live views
  already render any `Skipped` result with its reason correctly (same code path as the two
  existing skip families) — no new UI work is anticipated, but this phase does not add a
  dedicated "N steps skipped for missing prerequisites" summary tile if one doesn't already exist
  generically.
- **`internal/exercise`'s retry-tracking gap** — a known, separately-accepted gap from Phase 0B,
  untouched here.

## Testing

- **Agent-side:** a Windows-tagged unit test for the domain-join collection function, run natively
  on this Windows build host (no Docker needed) — asserts it returns a non-nil result on this
  machine and doesn't panic/shell out.
- **`internal/scenario`:** a `TestPrerequisiteForT1087002` regression test mirroring
  `TestTimeoutProfileForT1018Override`'s shape — confirms the curated entry resolves and that an
  unrelated technique is unaffected.
- **`internal/api`:** a container-backed `TestDispatchRun_SkipsStepMissingPrerequisite` mirroring
  the existing privilege-skip test's shape — seed an agent with `domain_joined=false`, dispatch a
  scenario containing the curated technique plus one unrelated step, assert the curated step
  appears in `policy_skipped_results` with `SkipReasonPrerequisiteUnsatisfied` while the unrelated
  step dispatches normally. A second test confirms `DomainJoined == nil` gates nothing (the
  Error-handling contract above).
- **`internal/exercise`:** a unit test for `evalCondition`'s new `agent:domain_joined` case,
  covering true/false/unknown-agent the same way the existing `step:` predicate tests do.

## Success criteria

1. A Windows agent reports `domain_joined` on every heartbeat; the `agents` table reflects it.
2. An ART/Caldera run containing a curated technique against a non-domain-joined agent skips that
   one step with `skip_reason='prerequisite_unsatisfied'`, dispatches every other step normally,
   and the run's report shows the skip with a clear reason — not a wasted, confusing failure.
3. The same run against a domain-joined agent dispatches the curated technique normally — zero
   behavior change for the case that already works today.
4. An agent that has never reported `domain_joined` (POSIX, or pre-upgrade) is never gated on it.
5. `internal/exercise` steps can condition on `agent:domain_joined` the same way they already
   condition on another step's outcome.
6. Zero changes to `execution_attempts`'s schema, granularity, or the two existing skip families'
   behavior.
