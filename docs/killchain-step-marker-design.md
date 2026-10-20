# Kill chain step marker: design

Status: proposed, not built. Decision needed before implementation.

## Problem

A process-creation record (Security 4688) proves a step ran only if the
evaluator can tell which step produced it. Matching on time alone is not
allowed (see `internal/killchain/hostevents.go`). The step has to leave a
token in the process command line that the orchestrator can search for.

Two facts constrain the design:

1. **Command-line capture is off by default.** On the Windows 10 build this was
   checked on, the 4688 `CommandLine` field for `lsass.exe` was empty. The
   key `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit`
   exists there with no values set, so capture is off. The
   marker only reaches 4688 when command-line auditing is enabled on the host.
   This is a host prerequisite, and it is checked, not assumed.
2. **Steps are wrapped differently per executor.** `agent/executor_windows.go`
   builds `cmd /c <command>`, a PowerShell `-Command` string, a WMI
   `Win32_Process.Create` wrapper that doubles single quotes, and an mshta call
   inside `Start-Process`. Each wrapper changes how the command text appears in
   the child process's command line.

## Options

| | A. Author-declared marker | B. Executor-injected per-run marker | C. Match the command text |
|---|---|---|---|
| Where the token lives | a `marker` field on each scenario step | added by the agent at run time | the step's own `command` string |
| Scenario YAML change | yes, plus re-sign of each changed `.sig` | no | no |
| Agent change | none | yes, in every executor and the WMI and mshta wrappers | none |
| Blast radius | only the steps that declare a marker | every run on every executor | none |
| Survives wrapping | yes, if the marker has only `[a-z0-9-]` (quote doubling does not touch it) | must be verified per wrapper | no: quote doubling and wrapping break the match |
| Ambiguity | low, the author picks a unique token | low, derived from run ID and step | high: the same command can run in several places |
| Verifiable here | static checks yes; the 4688 match needs staging | needs staging for each executor | not reliable |

Option C is rejected. Matching on the command text fails as soon as a wrapper
doubles quotes, and identical commands in different scenarios cannot be told
apart.

Option B changes what every run executes. That is too large a change to make
without staging evidence for each executor.

## Recommendation: Option A

Scenario authors declare a marker on each step that needs execution evidence.

### Format

- `marker` is a string of 8 to 40 characters from `[a-z0-9-]`. Nothing else is
  allowed, so it survives every executor's quoting unchanged.
- It must be unique across the campaign's scenarios. Load-time validation
  checks this.
- Scenarios that don't declare a marker produce no execution evidence. Their
  stages stay named gaps, as now.

### Placement

The author must put the marker literally inside the step's `command`. Load-time
validation checks that `command` contains the marker, so a step cannot declare
a marker it never emits. This check is static and can be tested here.

### Verification at load

- format and uniqueness of `marker`;
- `command` contains `marker` literally;
- the marker is not a substring of another declared marker.

Failures refuse the scenario at load, the same way a bad signature does.

### Evaluator change

`ExecutionMatch.Marker` is set from the step's declared marker, not from a
derived value. The evaluator already matches it case-insensitively against the
command line and the process name, and it already requires the host and the
window. Nothing else changes.

### Prerequisites checked at runtime

- Command-line auditing is enabled on the host. The agent reads the registry
  value `ProcessCreationIncludeCmdLine_Enabled` under
  `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit`.
  The value name is not yet confirmed: it is unset on this host, so it could
  not be read here. Staging must confirm the name the policy writes. If it
  is not set to 1, the host events payload carries that state. The evaluator
  then names it as a gap: "command-line capture is off; a marker cannot be
  seen". This is the same kind of gap as disabled process-creation auditing.
- Process-creation auditing is enabled (already handled).

### Cost

- Scenario YAML changes for each scenario that declares a marker, with the
  `.sig` re-signed for each one (the scenario signature gate refuses an edited
  file without a fresh signature).
- A load-time validation rule in the scenario loader.
- The agent's registry probe for command-line capture.

## What must be verified on staging before any live claim

1. A declared marker appears in the 4688 `CommandLine` for each executor used
   (`cmd`, PowerShell, WMI, mshta). This is the main risk, and it is the reason
   for choosing Option A over B.
2. Command-line capture is enabled by the deployment, not assumed.
3. Event volume and collection cost on a real host.
4. Behaviour when audit policy is enabled by group policy rather than locally.

## Decision needed

1. Approve Option A.
2. Choose which scenarios get markers first. Proposed: the identity step in
   `credential-access` and the lateral step in `caldera-lateral-movement`,
   because those are the two stages that are currently gaps.
3. Confirm that re-signing the changed scenarios with the project key is
   acceptable for this change.

Once these are approved, the implementation order is: the loader validation
and its tests, the marker fields in the two scenarios, re-signing, the
evaluator wiring into stage collection, and the registry probe.
