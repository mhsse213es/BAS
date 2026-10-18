# Application Control Efficacy Mastery — Design

## Intent and why

The platform's existing "application control" checks (`em-01-control-validation.yaml`'s
AppLocker/WDAC step, `full-scan.yaml`'s AppLocker step) only ask "is some application-control
mechanism present/enabled?" — `Get-AppLockerPolicy -Effective` returning any non-empty rule
collection, or WDAC's `CodeIntegrityPolicyEnforcementStatus >= 1`, is treated as "enforced,"
full stop. A policy that blocks `.exe` files but not scripts, or one with a default-allow rule
for `powershell.exe` specifically, passes this check today. Nothing in the catalog actually
*attempts* execution through an indirect path (cmd.exe, a renamed binary, an alternate
PowerShell host, a LOLBin, a spoofed-parent Office chain) to see whether the policy that
"looks enabled" actually stops it. `lolbin-execution-coverage.yaml`'s own description promises
a "Posture" tier covering exactly this ("LOLBin exposure: AppLocker, WDAC, PS Constrained
Language... parent-child protection") — it was never built; the file only contains its
Telemetry and Lab tiers.

This is a real, demonstrated loophole class, not a hypothetical: an AV/EDR or application-control
policy that blocks `powershell.exe` directly can be, and routinely is in the real world, bypassed
by routing through `cmd.exe`, a renamed copy of the PowerShell binary, an alternate PowerShell
host (PowerShell Core / `pwsh.exe`), in-process `System.Management.Automation.dll` hosting with
no `powershell.exe` process ever created, a living-off-the-land binary acting as a script proxy,
or a spoofed-parent chain (Office/browser masquerading as the process that spawns the shell).
Audspect's job as a BAS platform is to catch exactly this class of misconfiguration — a policy
that *looks* enforced but isn't, across the paths it claims to cover.

## Resolved decisions (approved direction, confirmed against existing seams)

Seams inspected before implementation:
- Verdict parsing: `orchestrator/internal/scenario/interpreter.go` `dominantVerdict()` recognizes
  only `pass:` / `fail:` / `skip:` prefixes; other lines are ignored. `interpretCustom` maps
  exit 0 to pass when no prefix exists. `ResultError` (excluded from scoring) is the existing
  bucket for BAS-side execution problems.
- Schema: `orchestrator/internal/scenario/types.go` `Step` (line 122) already has `CheckID`,
  `Risk`, `BlastRadius`, `Telemetry`, `Detection`, `ExpectedDetections`. No expected-outcome field
  exists.
- Comparator: `orchestrator/internal/reporting/outcome.go` `RegisterComparator` /
  `comparatorFor(family)` is already called from live reporting (`dlp.go:153`,
  `detection_validation.go:152`), so an `appcontrol` family plugs into the same call site.

Decisions:
1. **Expected/observed outcome, v1: no schema change.** The script emits one ordinary
   `pass:`/`fail:`/`skip:` line (keeps existing scoring exactly as today) plus one structured
   line `APPCTL_OUTCOME: <value>` where value is one of `blocked_as_expected`,
   `allowed_unexpectedly`, `allowed_by_policy`, `not_enforced`, `inconclusive`,
   `not_applicable`. `dominantVerdict` ignores the `APPCTL_OUTCOME:` line, so no existing
   scenario changes behavior. The `expected` side comes from an explicit per-step
   `expected_outcome:` value in the YAML (added to `Step` as a typed field only when the
   comparator needs it; until then it lives in the test contract). Escalate to a typed schema
   change if the text line proves ambiguous in practice.
2. **Policy capture: immediately before each behavioral attempt**, via one shared PowerShell
   function used by both posture steps and behavioral steps. Evidence retains: control and
   enforcement mode, rule/policy identity, scope and exceptions, capture timestamp, and whether
   evaluation succeeded. Stored in the existing run evidence output.
3. **Enforcement oracle, v1: self-contained PowerShell.** Each attempt uses a unique test
   identifier in its command line, records the attempting process ID and parent process ID,
   and queries AppLocker (`Microsoft-Windows-AppLocker/EXE and DLL`, 8004 block / 8003 audit;
   `MSI and Script`, 8006 / 8005) and CodeIntegrity (`Microsoft-Windows-CodeIntegrity/Operational`,
   3033 / 3077) only for events that reference the unique identifier or the attempted PID within
   a narrow window. Event-only correlation without an identifier match is inconclusive.
   Shared Go plumbing is deferred until this proves insufficient.
4. **V1 scope and milestones:**
   - **V1:** posture corrections (em-01 AppLocker/WDAC step, full-scan AppLocker step, labeled
     ExecutionPolicy), the missing Posture tier of `lolbin-execution-coverage.yaml`,
     `indirect_execution`, `alternate_binary`, evidence capture, and acceptance tests.
     Completion record must list unimplemented families and unsupported Windows configurations.
   - **V2:** `script_host_proxy`, `parent_child_asr`, `alternate_ps_host` (PS-edition detection
     first).
   - **V3:** `inprocess_hosting`, only after the feasibility spike below supports it.
   - **Full mastery** is not claimed until all families, vendor correlation (Phase 3), and
     regression coverage exist.
5. **In-process hosting: feasibility spike first**, answering: buildable and runnable on
   supported Windows versions; which Windows PowerShell and PowerShell 7 configurations are in
   scope; how assemblies resolve per configuration; whether execution is reliably detectable;
   whether policy and evidence can be attributed; whether it runs repeatably in a disposable lab.
   Output: go/no-go, supported-configuration matrix, evidence assessment, cost estimate. Defer
   the family if the oracle cannot give a defensible result.

## Goals

- Establish, with evidence, whether application control **actually prevents unauthorized
  execution** across the paths it claims to control — not whether a policy or service exists.
- Model the policy's **effective scope** (executable types, scripts, users, directories,
  enforcement mode) rather than a binary enabled/disabled signal.
- Test each execution-path family (indirect execution, alternate binary, alternate PowerShell
  host, in-process hosting, LOLBin proxy, parent-child/ASR) as its own test, with its own
  verdict — one family passing never implies anything about another.
- Build a **real enforcement oracle**: distinguish "the process failed because the control
  blocked it" from "the process failed for an unrelated reason" (missing file, bad syntax,
  permissions, timeout) using correlated OS evidence, not inference from exit code alone.
- Report prevention and detection as **separate, independently evidenced outcomes** — a
  process that ran but was later flagged by the EDR is not the same result as one that never
  ran at all, and neither gets inferred from the other.
- Produce a per-control, per-execution-path coverage matrix with confidence, limitations, and
  remediation guidance a client can act on — never a single "application control score."

## Non-goals / anti-goals

- **Not** claiming universal bypass coverage. Every test names its exact scope (the OS
  build/edition, the specific binary/path tested, the specific policy rule exercised) and its
  unsupported conditions. "We tested these N paths under these conditions" is the honest claim;
  "application control is bypassable" or "application control is effective" as a blanket
  statement is not something this vertical will ever assert.
- **Not** retrofitting the existing `CheckResult` enum (`pass/fail/skipped/blocked/error/vetoed`,
  `orchestrator/internal/models/schema.go`) with new values. It is pattern-matched exhaustively
  across ~18 call sites in scoring, SIEM, compliance, and campaign code; the B5 guardrail's
  addition of `ResultVetoed` already had to touch every one of those sites once. This vertical's
  outcome vocabulary lives entirely in a new Comparator (see Architecture), which is the
  mechanism the Outcome Validation Framework exists for.
- **Not** building a second evidence/provenance system. `internal/reporting/dlp.go`'s
  `DLPEvidence` shape (CollectionMethod/CorrelationID/FixtureID/Limitations) is reused almost
  verbatim as `AppControlEvidence` — this vertical is DLP-POL's sibling, not a parallel
  invention.
- **Not** attempting real malicious payloads, real persistence, or real destructive action.
  Every behavioral test is a benign, `[BAS-SIM]`-tagged, self-cleaning marker — the same safety
  posture as every other scenario in this catalog (see the platform-wide audit from this same
  conversation: the one place the catalog genuinely disables a live control, the Defender RTP
  toggle, is self-healing with verification; nothing in this vertical should be less careful).

## Three-layer structure

1. **Posture mastery** — what did the customer configure, and what does the *effective* policy
   actually cover? (Phase 1)
2. **Behavioral mastery** — controlled, benign execution attempts across distinct execution-path
   families, each against an explicit expected result derived from the effective policy snapshot
   captured in layer 1. (Phase 2)
3. **Detection & response mastery** — when execution is allowed, did the security stack detect it,
   alert, and respond as expected? (Phase 3)

All three layers feed one evidence-backed assessment (Phase 4's coverage matrix), not three
disconnected catalog checks. A test in layer 2 that reports "allowed unexpectedly" is exactly the
trigger layer 3 needs to ask "but did the EDR at least see it?" — these are not independent
scenarios run in isolation; layer 2's result selects what layer 3 checks.

## Outcome taxonomy

Every behavioral test returns one of:

| Outcome | Meaning |
|---|---|
| `blocked_as_expected` | The control the test targets demonstrably prevented execution, with correlated evidence attributing the block to that specific control. |
| `allowed_unexpectedly` | Execution succeeded despite the effective policy snapshot saying it should have been blocked. |
| `allowed_by_policy` | Execution succeeded and the effective policy snapshot explicitly permits this path — not a gap, a configured allowance. |
| `not_enforced` | The relevant policy exists but is audit-only, disabled, or its effective scope doesn't cover the tested path. |
| `inconclusive` | The evidence can't establish what happened — e.g. the process failed but no control-attribution event correlates with the failure. |
| `not_applicable` | The tested mechanism or prerequisite is absent (e.g. no WDAC, no PowerShell Core installed, wrong Windows edition for the control under test). |

**Non-negotiable rule, carried into every test contract below**: `blocked_as_expected` is never
reported from a process-level failure alone, and `allowed_by_policy`/enforcement success is never
reported from a service or policy merely being present. Both directions require the enforcement
oracle's correlated evidence (see Architecture).

## Architecture — reusing what already exists

### Outcome Validation Framework integration (Phase 4, designed now so Phase 2 writes to it directly)

`orchestrator/internal/reporting/outcome.go` already defines:

```go
type ComparisonResult string
const (
    Match ComparisonResult = "Match"
    Mismatch = "Mismatch"
    MissingEvidence = "MissingEvidence"
    NotApplicable = "NotApplicable"
    Unknown = "Unknown"
)
type Comparator interface { Compare(expectedOutcome, observedOutcome string) ComparisonResult }
func RegisterComparator(family string, c Comparator)
```

This vertical registers `appcontrolComparator{}` under family `"appcontrol"`, mirroring
`dlpComparator` (`internal/reporting/dlp.go`, family `"dlp"`). The six-outcome vocabulary above
is this comparator's own domain language; `Compare()` maps it onto `ComparisonResult` (e.g.
`blocked_as_expected` vs `allowed_unexpectedly` → `Mismatch`; `inconclusive` → `MissingEvidence`;
`not_applicable` → `NotApplicable` directly), which then collapses to the existing `CheckResult`
via the framework's own `collapseToStatus` path. **Zero changes to any existing scoring,
SIEM, or compliance call site.**

### AppControlEvidence (Phase 4)

Mirrors `DLPEvidence` (`internal/reporting/dlp.go`):

```go
type AppControlEvidence struct {
    CollectionMethod string // "local-oracle" | "sysmon-correlation" | "vendor-bridge"
    CorrelationID    string // ties a behavioral test's execution attempt to its oracle lookup
    FixtureID        string // which test contract (see Test Contracts) produced this
    EffectivePolicySnapshot string // what Phase 1 captured as "effective" at test time
    Limitations      string // ALWAYS populated — never blank, matching DLPEvidence's convention
}
```

### Test contract shape (the "formal test matrix")

Every behavioral test is specified, before it is implemented, as:

```yaml
test_id: appcontrol-exec-<family>-<NNN>
family: policy_scope | indirect_execution | alternate_binary | alternate_ps_host |
         script_host_proxy | inprocess_hosting | parent_child_asr
control_under_test: <specific rule/policy: AppLocker Script Rule Collection, WDAC CI policy, ASR rule GUID, etc.>
prerequisites:
  - <e.g. requires_windows_build, requires_powershell_core_installed, requires_admin>
expected_result_source: effective_policy_snapshot  # never hand-assumed; always derived from Phase 1's capture for this host
evidence_requirements:
  - process-level: <exit code / stdout marker / observed side effect>
  - control-attribution: <specific Event Log channel + Event ID(s) the oracle checks>
cleanup: <always present, always [BAS-SIM]-tagged>
unsupported_conditions: <exact conditions under which this test reports not_applicable instead of running>
```

Families are modeled as genuinely distinct — a `test_id` under `indirect_execution` passing
`blocked_as_expected` makes zero claims about any `alternate_binary` or `inprocess_hosting`
test; each family gets its own fixtures and its own entries in the coverage matrix.

### Enforcement oracle (the core new mechanism, Phase 2)

For every behavioral test, the oracle correlates two independent signals, never trusting either
alone:

1. **Process-level observable**: did the attempted execution produce its expected `[BAS-SIM]`
   marker/side effect? A silent failure here could mean "blocked by policy" — or a missing file,
   a syntax error, a permissions issue, or a timeout. This signal alone can never produce
   `blocked_as_expected`.
2. **Control-attribution event**: a correlated (by timestamp window + process path/marker) entry
   in the specific control's own event log —
   `Microsoft-Windows-AppLocker/EXE and DLL` (Event ID 8004 block / 8003 audit-warn),
   `Microsoft-Windows-AppLocker/MSI and Script` (8006 block / 8005 audit-warn), or
   `Microsoft-Windows-CodeIntegrity/Operational` (3033/3077 for WDAC blocks).

`blocked_as_expected` requires **both**: process-level failure AND a correlated attribution
event naming the specific control. Process failure with no correlated event → `inconclusive`
(something stopped it, but not provably the control under test — could be a different cause
entirely). A correlated event with no process failure (audit-mode logging without blocking) →
`not_enforced`. This is what makes the oracle "real" rather than inferred.

### Windows-version / PowerShell-edition gating (new; Phase 2)

No PowerShell-edition detection (`$PSVersionTable.PSEdition`, Desktop vs Core, presence of
`pwsh.exe`) exists anywhere in the codebase today — confirmed by search. This vertical adds it
as a prerequisite check: a test in the `alternate_ps_host` family that needs PowerShell Core and
finds it absent reports `not_applicable` (not silently skipped, not a false pass). Likewise,
WDAC-specific tests gate on Windows edition where the relevant CI policy deployment mechanism
differs (Enterprise/Education vs Pro/Home).

## Execution-path families (Phase 2 detail)

| Family | What it tests | Agent-side cost |
|---|---|---|
| `policy_scope` | Effective rule collections, enforcement mode, exceptions, coverage (which types/paths/users) — Phase 1, no new execution | None — PowerShell posture queries only |
| `indirect_execution` | `cmd.exe /c powershell ...` — does a block on direct `powershell.exe` hold when routed through a parent process? (T1202) | **None** — `executor: cmd` already exists in `agent/executor_windows.go`; this is pure scenario content |
| `alternate_binary` | A renamed/copied `powershell.exe` — does a path/hash-scoped rule survive a renamed copy? | None — scenario content using existing executors |
| `alternate_ps_host` | PowerShell Core (`pwsh.exe`) if installed — does the policy cover both PowerShell hosts, or only Desktop edition? | New: PS-edition detection (above) |
| `script_host_proxy` | Existing LOLBin proxy content (regsvr32/Squiblydoo, mshta, rundll32, cscript/wscript) reused as its OWN family with an explicit per-path verdict, not folded into "PowerShell enforcement" | None — reuses `lolbin-execution*.yaml` content, wired through the new oracle/evidence model instead of the ad-hoc `Write-Output "PASS/FAIL"` text it uses today |
| `inprocess_hosting` | "PowerShell without powershell.exe" — hosting `System.Management.Automation` from a compiled helper so no `powershell.exe` process is ever created | New: a small benign .NET helper (Add-Type-compiled at runtime, same pattern as `scenarios/evasion-testing.yaml`'s P/Invoke shim), gated by prerequisite checks for the assembly's availability |
| `parent_child_asr` | Office/browser-masquerade spawning a restricted child — reuses the apt36/black-basta winword-spoof pattern, but as its own test against the specific ASR rule GUID, with a real verdict instead of narration | None — reuses existing spoof pattern, adds the oracle correlation against ASR's own event log (Windows Defender Exploit Guard / ASR, Event ID 1121 block / 1122 audit) |

## Phases

**Phase 1 — Correct existing posture checks, fill the missing tier**
- Rewrite `em-01-control-validation.yaml`'s AppLocker/WDAC step to capture effective scope
  (rule collection contents, enforcement mode per collection, exceptions) instead of a boolean.
- Rewrite `full-scan.yaml`'s AppLocker step (currently just `AppIDSvc` service-running) to the
  same effective-scope capture, or remove it in favor of pointing at the corrected em-01 check.
- Reframe the `ExecutionPolicy` check: keep the signal, but explicitly label it configuration
  posture, not a security boundary (`-ExecutionPolicy Bypass` on the command line overrides it
  regardless) — this check must never be read as "scripts are blocked."
- Implement `lolbin-execution-coverage.yaml`'s missing Posture tier (5 categories from its own
  description), now backed by the effective-scope capture above rather than a presence check.

**Phase 2 — Behavioral harness + enforcement oracle**
- Build the test-contract runner and the enforcement oracle (event-log correlation logic).
- Implement `indirect_execution` first (zero agent-side cost, highest signal value).
- Implement `alternate_binary`, `script_host_proxy` (rewiring existing LOLBin content through
  the new oracle/evidence model), `parent_child_asr` (rewiring existing spoof-chain content the
  same way).
- Implement PS-edition detection, then `alternate_ps_host`.
- Implement `inprocess_hosting` last (highest build cost — the compiled helper).

**Phase 3 — Security-product correlation**
- Wire `allowed_unexpectedly`/`allowed_by_policy` results into the existing AV Mastery
  vendor-bridge pattern (`internal/avdefender`, `internal/avsentinelone`, `avval.CollectionResult`
  /`Observation`/`Prevention` enum) so "did the security stack at least detect what it didn't
  block" is answered with the same evidence rigor as AV Mastery's own detection checks — not a
  new, separate detection mechanism.
- Prevention and detection are reported as two separate fields on the same test result, never
  one inferred from the other.

**Phase 4 — Coverage matrix + reporting**
- `AppControlEvidence` struct (above), `appcontrolComparator` registered with the Outcome
  Validation Framework (above).
- Per-control, per-execution-path-family coverage matrix report section, mirroring
  `internal/reporting/dlp.go`'s shape: outcome, evidence, limitations (always populated),
  remediation guidance. No single "application control score."

## Acceptance criteria

- No posture check reports enforcement from presence/service-running alone; every AppLocker/WDAC/
  ASR check captures and reports effective scope.
- Every behavioral test has a written test contract (family, control under test, prerequisites,
  expected-result source, evidence requirements, cleanup, unsupported conditions) committed
  before its implementation.
- `blocked_as_expected` is never reported without both a process-level failure signal and a
  correlated control-attribution event; a process failure with no correlated event reports
  `inconclusive`, never a pass.
- Execution-path families never generalize into each other in any report — each family's
  coverage is listed separately in the coverage matrix.
- Prevention and detection are separate, independently evidenced fields on every result where
  execution was allowed.
- Every test gated on Windows version, PowerShell edition, or an optional installed component
  reports `not_applicable` (never silently skipped, never a false pass) when the prerequisite
  is absent.
- The coverage-matrix report states its limitations explicitly and never claims universal bypass
  coverage — only the exact families/paths/conditions actually tested.
- `destructiveguard.Classify` is re-verified against every new benign command string introduced
  by this vertical (confirmed, pre-build, that the existing rule set has no accidental collision
  with cmd/powershell proxy-execution text — re-verify per new rule added, same discipline as the
  Defender-RTP fix from this session).
- Zero changes to `CheckResult`, `internal/models/score.go`, or any existing SIEM/compliance call
  site — all new outcome semantics live in the new `appcontrol` Comparator and evidence struct.
