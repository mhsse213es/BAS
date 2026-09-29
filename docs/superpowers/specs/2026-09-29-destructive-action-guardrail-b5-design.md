# Agent Destructive-Action Guardrail — B5

**Date:** 2026-09-29
**Status:** Approved for planning
**Related:** `2026-09-27-agent-trust-model-b1-b3-b4-design.md`, `2026-09-28-command-envelope-signing-design.md` (B4)

## Context

The 2026-09-26 security assessment (`Assessment/AUDSPECT_ASSESSMENT_REPORT.md`) identified finding B5 — "No destructive-action guardrail" — as NOT FIXED. Confirmed against real code before any design work started:

- `agent/sched/riskgate.go` and `agent/sched/profile.go` exist, but their "risk" (`observation`/`modification`/`persistence`) is a **concurrency-locking** classification — it decides which steps may run in parallel, and has nothing to do with whether an action is destructive. `RiskGate.Allow` is a pressure-aware scheduling throttle, not a safety control.
- No signed local policy or denylist of any kind exists anywhere in the agent. The agent executes whatever `command:` text a step provides.
- The scenario YAML schema already has `production_safe`, `risk`, `reversible`, and `blast_radius` fields, but **none of them reach the agent** — `agent/protocol.ScenarioStep` carries `TaskID`/`TechniqueID`/`Name`/`Executor`/`Command`/`TimeoutSec`/`Payloads`/`Cleanup`/`Resource`/`Timeout`/`RequiresPriv` only. These fields are orchestrator/reporting-side metadata today, stripped before dispatch.

### Concrete evidence: `em-07-ransomware-readiness.yaml`, Stages 4A/4B

`scenarios/endpoint-mastery/em-07-ransomware-readiness.yaml` (lines 268–317) unconditionally launches:

```powershell
Start-Process 'vssadmin.exe' -ArgumentList 'delete shadows /all /quiet' -PassThru -WindowStyle Hidden
...
Start-Process 'wbadmin.exe' -ArgumentList 'delete catalog -quiet' -PassThru -WindowStyle Hidden
```

against the real host, with **only "hope EDR kills the process within 5 seconds" as protection**, and is mislabeled `production_safe: true`, `reversible: true` (shadow-copy/backup-catalog deletion is not reversible). Compare `scenarios/akira-kill-chain.yaml`'s Stage 8, which performs the equivalent operation but correctly marks it `production_safe: false`, `risk: high`, and gates it behind an ad hoc `BAS_CONFIRM_VSS_DELETE=true` environment-variable check written into the step's own PowerShell. `blackcat-kill-chain.yaml`, `lockbit-kill-chain.yaml`, and `play-kill-chain.yaml` narrate the same destructive command in a `blast_radius` description/`Write-Output` string but never actually invoke it (`production_safe: true`, `risk: low` — correctly, since those steps are enumerate-only).

This proves the finding concretely: safety today is 100% ad hoc, per-scenario-author PowerShell convention, unenforced by the agent, and **already inconsistently applied within Audspect's own shipped scenario library** — a scenario author can (and, in em-07, did) mislabel a genuinely destructive step as safe, and nothing stops it from running on a real production endpoint whose EDR is absent, misconfigured, or in monitor-only mode — exactly the gap a BAS platform exists to find.

## Security Invariant

**B4 proves the deployment authorized the command. B5 independently determines whether the agent is permitted to execute it, based on local destructive-action policy. A valid B4 signature is never sufficient to authorize a destructive action.**

```
B4 signature valid?
        │
        ▼
Agent authorized for this deployment?
        │
        ▼
B5 destructive-action policy
        │
   ┌────┴────┐
 ALLOW      VETO
   │          │
execute    refuse
```

## Threat Model

B5's primary threat model is **(a): a command that is correctly, validly B4-signed by the real deployment orchestrator, but destructive by content.** This includes a fully compromised orchestrator that signs an arbitrary destructive command, and a legitimate-but-mislabeled scenario (the em-07 case) reaching a real orchestrator that signs it in good faith. B5 does not trust *who* sent the command to decide *whether* it is safe to run — that question is orthogonal to authentication and is B5's alone to answer, locally, on the endpoint.

Threat model (b) — mislabeled/inconsistent scenario metadata reaching compilation at all — is a **secondary, complementary layer** (server-side classification authority, below), not the security boundary. B5's agent-side veto remains authoritative even if the secondary layer is imperfect or bypassed.

## Architecture Overview

```
Scenario (technique_id, action_key per step)
        ↓
Server compilation
        ↓
Audspect-controlled execution-classification catalog
        ↓
Resolved per-step classification (ScenarioStep fields)
        ↓
B4 signs the complete envelope (Steps[] included in the signed payload)
        ↓
Agent receives command, verifies B4 signature (unchanged)
        ↓
Agent scheduler dispatches each step in turn
        ↓
B5 gate, per step, at the execution boundary:
    resolved execution_class (signed, per-step)
        combined most-restrictive-wins with
    local backstop rule evaluation of the actual command
        ↓
    non_destructive         → execute normally
    potentially_destructive → execute + elevated telemetry
    destructive              → check local grant
                                  granted   → execute
                                  otherwise → VETOED, continue to next step
```

Two independent layers, deliberately not collapsed into one:

1. **Compilation classification** (Audspect-controlled catalog): prevents a scenario author from declaring something safe when Audspect's own catalog says otherwise. Authoritative for what reaches the agent, but the agent does not have to trust it blindly (see layer 2).
2. **Agent B5 enforcement**: prevents even a correctly signed, correctly classified command from executing if the agent's own independent, vendor-controlled rule check disagrees. This is what makes B5 a genuine agent-side security boundary rather than "another metadata validation step one layer up."

## Execution Classification

### Catalog

A new, Audspect-controlled, technique/action-keyed catalog, in the same style as `orchestrator/internal/scenario/resource.go`'s `discoveryProfiles`/`ResourceProfileFor` (curated Go map + resolver function), but a **separate catalog** — resource-locking risk and destructive-action risk are orthogonal concerns and must not share a table:

```go
type ExecutionClassification struct {
	Class            ExecutionClass // destructive | potentially_destructive | non_destructive
	DestructiveAction string        // stable identifier, audit/report-facing, e.g. "vss_delete"
	BlastRadius      string         // human-readable description, audit/report-facing only
}

// keyed (technique_id, action_key) -> classification
var executionClassifications = map[string]map[string]*ExecutionClassification{
	"T1490": {
		"enumerate":  {Class: NonDestructive, DestructiveAction: "", BlastRadius: "Read-only enumeration of VSS shadow copies/backup catalog."},
		"vss_delete": {Class: Destructive, DestructiveAction: "vss_delete", BlastRadius: "Deletes VSS shadow copies -- irreversible, removes ransomware recovery path."},
		"wbadmin_delete_catalog": {Class: Destructive, DestructiveAction: "wbadmin_delete_catalog", BlastRadius: "Deletes the Windows Server Backup catalog -- irreversible."},
	},
	// ...
}
```

### Resolution rules

```
(technique_id, action_key)
        ↓
exact catalog match → classification

no action_key on the step
        ↓
(technique_id, "default")
        ↓
exact match → classification
no match     → destructive

any catalog miss at either step above → destructive (fail closed)
```

There is **no fallback from an unknown `(technique_id, action_key)` pair to a technique-wide generic classification.** T1490 is the reason this rule exists: falling back to "whatever T1490 usually resolves to" would re-create exactly the ambiguity between its enumerate and delete behaviors that this catalog exists to eliminate.

`action_key` is a **lookup key only, never a safety assertion**. A scenario author (including a custom/intel scenario author — no exemption for unsigned scenario content once it reaches compilation) can write `action_key: totally_safe_operation`, but if that pair has no catalog entry, the step is `destructive` regardless. This mirrors `agent/sched.RiskUnknown`'s existing "unlabeled → most restrictive" philosophy exactly.

`production_safe`, `risk`, `reversible`, `blast_radius` as written in scenario YAML remain **informational/validation metadata only**. They can be used by a compile-time linter to flag internal inconsistency (e.g., a step whose catalog classification is `destructive` but whose own YAML claims `production_safe: true` — this is precisely the em-07 bug, and should be a hard compile error once this ships) but **can never downgrade** a catalog classification.

### Per-step resolution, not per-envelope

`command_scenario`'s wire payload (`ScenarioCommand.Steps []ScenarioStep`) carries a whole scenario — potentially dozens of steps — in **one** signed envelope; B4 is not restructured to sign one envelope per step. Classification is therefore resolved and carried **per `ScenarioStep`**, mirroring exactly how `Resource`/`Timeout` are already attached today via `AttachProfiles`:

```go
// orchestrator/internal/scenario — new file, same shape as resource.go
func AttachExecutionClassifications(steps []ScenarioStep) {
	for i := range steps {
		steps[i].ActionKey, steps[i].ExecutionClass, steps[i].DestructiveAction, steps[i].BlastRadius =
			resolveExecutionClass(steps[i].TechniqueID, steps[i].ActionKey)
	}
}
```

The signed `CommandEnvelope`'s **top-level** `execution_class`/`destructive_action`/`blast_radius` fields hold the **aggregate** — `most_restrictive(Steps[].ExecutionClass)` — computed once at signing time. This aggregate is **informational/audit metadata only** (fast dispatch-level visibility, e.g. for logging "this dispatch contains at least one destructive step" without decoding every step) — it is never itself the B5 authorization decision. The authoritative signal is always the individual step's own resolved fields, evaluated at that step's own execution boundary.

## Wire/Schema Changes

### `ScenarioStep` (both `orchestrator/internal/scenario` and `agent/protocol`, byte-identical shape — same cross-module discipline as B4's `CommandEnvelope`)

New fields, added to the existing struct (not a breaking rename of anything present today):

```go
ActionKey         string `json:"actionKey,omitempty"`
ExecutionClass    string `json:"executionClass,omitempty"`     // "destructive" | "potentially_destructive" | "non_destructive"
DestructiveAction string `json:"destructiveAction,omitempty"`
BlastRadius       string `json:"blastRadius,omitempty"`
```

`ExecutionClass` is carried as a plain string on the wire (not a typed enum) for the same reason `Risk`/`Scope` already are in `ResourceProfile` — an agent build that predates a future added class value degrades to treating an unrecognized string as unclassified (fail-closed: `destructive`), rather than failing to unmarshal.

### `CommandEnvelope` (both `orchestrator/internal/models` and `agent/protocol`, `CanonicalJSON()` updated identically on both — same discipline as every other B4 field, re-verified with an extended golden-vector test, see below)

New top-level, aggregate-only fields:

```go
ExecutionClass    string `json:"executionClass,omitempty"`
DestructiveAction string `json:"destructiveAction,omitempty"`
BlastRadius       string `json:"blastRadius,omitempty"`
```

Adding fields to `CanonicalJSON()`'s field list changes the canonical byte sequence — the B4 golden-vector tests (`orchestrator/internal/cmdsigning/golden_vector_test.go`, `agent/protocol/golden_vector_test.go`, added in the B4 final-review fix wave) must be regenerated against the new shape as part of this implementation, not left pointing at stale bytes.

## Agent-Side B5 Gate

### Hook point

`agent/agent.go`'s `runScenario` builds one `sched.Job` per step (around line 771) before dispatching each to the scheduler/executor pipeline — this is where `RiskGate.Allow` already gates each job for concurrency-admission reasons today. B5's veto check is inserted in the same per-step path, immediately before the executor is invoked with `step.Command` — **not** at WS-dispatch time (which only sees the whole scenario at once) and **not** inside `commandsig.go`'s envelope-level verification (which has already run and passed by this point; B5 evaluates a decision the signature check has no opinion about).

### Combination logic — most-restrictive-wins

```go
signed := step.ExecutionClass                        // from the verified, signed envelope
local  := destructiveguard.Classify(step.Command)     // agent's own independent evaluation
final  := mostRestrictive(signed, local)
```

Neither layer is sufficient alone. `signed` defends against a scenario-authoring mistake (the catalog is Audspect-controlled, not author-declared). `local` defends against a catalog gap or an under-classified action reaching the agent regardless of how it got there. If either says `destructive`, the step is `destructive`.

**A local grant authorizes a specific catalog-defined action; it never suppresses the local backstop's own detection.** The grant only participates in the *authorization* decision (below), never in the *classification* computation — so an active grant for `T1490:vss_delete` does not make the local rule engine stop recognizing `vssadmin.exe delete shadows` as destructive; it means that, once classified `destructive`, an unexpired matching grant is found and execution is allowed to proceed.

### Local backstop rule engine

Vendor-curated, **compiled into the agent binary**, immutable at runtime. Not modifiable through:

- orchestrator commands or B4-signed envelope fields
- scenario YAML content
- environment variables
- local policy grants (see below — a grant authorizes; it cannot redefine what counts as catastrophic)
- ordinary agent configuration

Not a general PowerShell/shell semantic parser (explicitly rejected — brittle, and creates a false sense of completeness). A small, deterministic rule set matched against the **normalized executable + arguments**, not naive substring search on raw text — normalization (case-folding, quote-stripping, path-canonicalization for the executable name) exists specifically so trivial quoting/casing/path variations can't defeat the backstop. Seed rule set, derived from real commands already found in the shipped scenario library during this investigation:

- `vssadmin(.exe)? delete shadows` (any arguments)
- `wbadmin(.exe)? delete catalog`
- `wbadmin(.exe)? delete systemstatebackup`
- `bcdedit(.exe)? .* recoveryenabled no`
- `bcdedit(.exe)? .* bootstatuspolicy ignoreallfailures`
- `cipher(.exe)? /w`
- mass recursive delete against OS-critical roots (`Remove-Item -Recurse` / `rm -rf` targeting `/`, `/etc`, `/boot`, `C:\Windows`, `C:\ProgramData`, etc.)
- disk-format invocations (`format` targeting a system volume)

The exact final rule list, its normalization approach, and its home package (proposed: `agent/destructiveguard/rules.go`) are implementation-plan-level detail — the invariant that matters for this spec is that the rule set exists, is vendor-owned, is code (not runtime-editable data), and combines most-restrictive-wins with the signed classification.

### Enforcement per class

| Class | Default behavior | Grant required? |
|---|---|---|
| `non_destructive` | Execute normally | No |
| `potentially_destructive` | Execute, with elevated telemetry/reporting (flagged distinctly, not silently identical to a routine step) | No |
| `destructive` | Check local grant; deny unless an unexpired, matching grant exists | Yes |
| unclassified / catalog miss | Treated as `destructive` | Yes |

A vetoed step does **not** abort the scenario run. It is recorded `VETOED` (see Scoring/Reporting Impact) and execution proceeds to the next scheduled step — exactly as an ordinary step `FAIL` today doesn't abort the run. This is required for the em-07 case itself: the safe enumeration steps around the destructive deletion steps must still run.

## Local Policy Grant Mechanism

The **only** escape hatch for a `destructive`-classified step. Root of trust: **the host OS's own administrative privilege boundary on this specific endpoint** — never the orchestrator, never any field the orchestrator's signed command can carry.

```
Local root/admin
      │
      ▼
bas-agent policy grant \
    --scope <action> [--scenario-id <id>] \
    --reason "<text>" \
    --expires <duration>
      │
      ▼
agent validates OS privilege (root on Linux; elevated
administrator/service-management authority on Windows)
      │
      ▼
signed/HMAC-protected local grant, bound to this agent's
own persistent AgentID
      │
      ▼
B5 policy gate: permits the named destructive action,
on this agent only, until expiry
```

### Grant scope

```yaml
scope:
  action: "T1490:vss_delete"                  # REQUIRED — must exist in the catalog;
                                                # a grant can never name a bare
                                                # execution_class ("destructive") without
                                                # a specific action.
  scenario_id: "em-07-ransomware-readiness"    # OPTIONAL — narrows the grant to this
                                                # scenario only. Omitted = covers the
                                                # action regardless of which scenario
                                                # invokes it.
  # run_id: intentionally absent in v1 — see Explicitly Out of Scope.
```

Plus fields that are never operator-chosen:

- `agent_id` — automatically bound to this agent's own persistent `AgentID` (B3's enrollment identity) at grant-creation time, folded into the grant's integrity protection. A `grants.json` copied verbatim from one agent to another must not validate.
- `reason` — REQUIRED, free text, recorded in the audit trail.
- `issued_at` / `expires_at` — REQUIRED. **No permanent grant is supported.** The agent rejects an expired grant automatically; there is no renewal without a fresh `policy grant` invocation.

**Every destructive grant authorizes exactly one catalog-defined action on exactly one enrolled agent for a bounded period. Scenario binding is optional; run binding is deferred.**

### Storage and integrity

The grant store (not the audit log) is the **authoritative** security state. It is protected against tampering by something other than the CLI tool itself:

- Windows: the grant's integrity key is protected via DPAPI/machine-protected storage (existing agent code should be checked for prior DPAPI usage before building new secure-storage primitives — none was found in this investigation, so this will likely be new).
- Linux: root-owned file permissions as the minimum bar, with an HMAC (keyed by a locally-generated secret, never transmitted over the network) over the grant contents so a hand-edited file that merely has the right shape still fails validation.

### Audit trail

Every lifecycle event is recorded — `grant_created`, `grant_used`, `grant_expired`, `grant_revoked`, `grant_rejected` — with timestamp, local principal/identity where available, scope, reason, expiry, and the relevant command/run ID. **The audit log is evidence, not enforcement** — the grant store alone decides ALLOW/VETO; the log exists so a human can later answer "who authorized this, when, and why," not to be consulted by the gate itself.

## No-Bypass Invariant

None of the following are ever sufficient, alone or in combination, to authorize a `destructive`-classified step:

- a valid B4 signature
- the orchestrator's identity or any claim about its trustworthiness
- scenario-declared metadata (`production_safe: true`, `risk: low`, `reversible: true`, or any future equivalent)
- an environment variable
- a command-line flag
- a server-supplied field of any kind, including a hypothetical `allow_destructive` field on the envelope itself

The only path to executing a `destructive` step is a local, OS-admin-created, narrowly scoped, mandatorily-expiring grant, created entirely outside the orchestrator's reach.

## Scoring/Reporting Impact

This platform's existing execution-outcome model (`orchestrator/internal/scenario/outcome.go`) already has an `OutcomeBlocked` value — but it means **the customer's own EDR/security control intercepted the technique**, and it scores as **PASS** (the defense worked). `internal/reporting/engine.go`'s `Blocked`/`Detected`/`Bypassed` counters feed `PreventionScore`/`BypassRate` directly from this value.

A B5 veto is a **completely different event** — Audspect's own agent refused to attempt the technique at all — and must never be confused with, mapped onto, or allowed to contaminate that scoring path. Reporting a B5 veto as `OutcomeBlocked`/PASS would fabricate evidence that the customer's defenses were tested and worked, when in fact nothing was tested.

**Locked verdict name: `VETOED`** (not `BLOCKED` — that name is already taken by the existing, semantically opposite concept above, and reusing it would risk exactly this contamination).

| Condition | Result | Meaning |
|---|---|---|
| Technique executed, produced an unsuccessful result | `FAIL` | The technique actually ran |
| Customer EDR/security control intercepted it | `OutcomeBlocked` → `PASS` | Customer defense successfully blocked the technique |
| Audspect B5 refused execution | `VETOED` | The technique was never attempted |
| Execution/system problem | `ERROR` | Audspect couldn't execute correctly |
| Normal intentional omission | `SKIPPED` | Not selected/scheduled |

`VETOED` is a new, fifth, top-level/reporting verdict, distinct from `PASS`/`FAIL`/`ERROR`/`SKIPPED`. It must:

- **Never** enter `engine.go`'s `Blocked`/`Detected`/`Bypassed` aggregation, nor any `counted := ...` denominator derived from those three, nor `PreventionScore`/`PreventionPct`/`BypassRate` — a `VETOED` step contributes to none of them, not even as a diluting denominator entry.
- Propagate through the run result, API, UI, reports, and exports carrying enough structure to explain itself without needing to join back to raw envelope data: at minimum `execution_class`, `action_key`, `technique_id`, `block_source` (`"catalog"` / `"local_backstop"` / both), and `grant_status` (`"absent"` / `"expired"` / `"invalid"` / `"scope_mismatch"`).
- Render with explicit, unambiguous wording distinguishing it from a tested-and-passed control, e.g.: *"VETOED — Audspect prevented execution under its local destructive-action policy. Customer defensive controls were not tested by this step."*

The exact call sites in `engine.go`/`outcome.go`/the API/UI that must exclude `VETOED` are implementation-plan-level detail (this investigation found the `Blocked`/`Detected`/`Bypassed`/`PreventionScore` chain in `internal/reporting/engine.go` around lines 3405–3465 and the parallel per-step aggregation around lines 840–850/1000–1030/2545–2555, but did not exhaustively enumerate every consumer).

## Explicitly Out of Scope (v1)

- **`run_id`-level grant scoping.** The two locked scope dimensions (`action`, optional `scenario_id`) cover the real workflow described (pre-authorizing a bounded drill window). Adding run-instance scoping raises unresolved lifecycle questions (retries, resumed runs, fan-out campaigns, recompiled commands) with no current operational need forcing an answer. Revisit only if a real need appears.
- **A deployment-wide/fleet-wide signed policy bundle.** Rejected as the primary mechanism because any distribution path that touches the orchestrator's live process re-opens exactly the "compromised orchestrator can eventually grant itself destructive permission" path B5 exists to close. The local OS-privilege CLI escape hatch is the v1 (and possibly permanent) design; a fleet-scale mechanism, if ever needed, would require its own fully offline trust root (mirroring `internal/integrity`'s vendor key) and its own design pass — not a natural extension of this mechanism.
- **A full PowerShell/shell semantic analyzer** as the local backstop. Deliberately rejected in favor of a small, deterministic, high-confidence rule set — a general parser is brittle and creates a false sense of safety.
- **B5 enforcement for `command_simulate`, `command_attackpath_collect`, or any of the 5 lifecycle command types** (`command_cancel`/`pause`/`resume`/`stop_agent`/`uninstall_agent`). The first two are read-only by nature; the lifecycle commands are already fully governed by B3/B4's authentication and are not ATT&CK-technique execution — forcing them through a technique/action catalog that wasn't designed for them adds complexity with no corresponding safety gain.
- **Restructuring `command_scenario` dispatch** into one signed envelope per step. Classification stays per-step inside the existing one-envelope-per-scenario-run model.
- **A compile-time hard-fail linter** that rejects a scenario outright when its own metadata contradicts the catalog (e.g., em-07's `production_safe: true` on a catalog-`destructive` step). Recommended as a valuable follow-up (and noted above as "should be a hard compile error once this ships") but not required for B5's core security property, which holds regardless of whether the linter exists.

## Open Questions for the Implementation Plan

1. Exact catalog file location/package name (proposed: `orchestrator/internal/scenario/execclass.go`, mirroring `resource.go`'s placement) and initial seed content — a real audit of every `technique_id` currently shipped with a genuinely destructive atomic (starting from the concrete evidence in this doc: T1490's `vss_delete`/`wbadmin_delete_catalog`/bootloader-recovery-disable actions, and a systematic pass over the rest of `scenarios/` for other unflagged destructive commands beyond VSS/backup-catalog deletion — e.g. mass file deletion/encryption, service/AV tampering with no rollback, disk-level operations).
2. Exact local backstop rule engine implementation: normalization approach (how far to canonicalize executable paths/casing/quoting), rule format (Go code vs. an embedded data table compiled into the binary), and the final seed rule list beyond what's enumerated above.
3. Windows secure-storage mechanism for the grant HMAC secret — whether to use DPAPI directly or an existing Go wrapper, and whether any prior art exists elsewhere in this codebase for Windows machine-protected storage (none was found searching the agent module during this investigation).
4. Grant store and audit log exact file formats/locations per OS, and the exact CLI surface (`bas-agent policy grant/list/revoke`, flag names, output format).
5. Exact `VETOED` plumbing: the new value's home in `orchestrator/internal/scenario/outcome.go`'s outcome model (a peer to `OutcomeExecuted`/`OutcomeBlocked`/`OutcomeError`/`OutcomeSkipped`, or a distinct type entirely, given it must never be confusable with `OutcomeBlocked` even at the Go-identifier level), and an exhaustive enumeration of every `engine.go`/API/UI call site that aggregates `Blocked`/`Detected`/`Bypassed`/verdict counts and must exclude it.
6. Whether the compile-time metadata-consistency linter (mentioned above as a recommended but out-of-scope follow-up) should be scheduled as a fast-follow rather than left indefinitely optional, given it would have caught the em-07 mislabeling directly.
7. B4 golden-vector test regeneration (both `orchestrator/internal/cmdsigning/golden_vector_test.go` and `agent/protocol/golden_vector_test.go`) against `CommandEnvelope`'s new aggregate fields, once their exact position in the struct/`CanonicalJSON` field list is finalized.
