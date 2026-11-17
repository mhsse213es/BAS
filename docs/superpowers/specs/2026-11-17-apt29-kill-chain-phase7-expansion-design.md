# APT29 Kill Chain (Phase 7) — 30-stage Windows expansion + cloud identity branch

## Intent and why

`scenarios/apt29-kill-chain.yaml` today emulates five APT29 post-compromise stages
(domain recon, encoded-PS loader, run-key persistence, scheduled-task persistence, DNS
C2 beacon). APT29/Cozy Bear tradecraft is far broader and includes extensive documented
cloud-identity abuse (service-principal credential addition, OAuth app-permission
abuse, SAML forgery, mailbox collection). The user wants the Windows side expanded to
30 stages across discovery, execution, defense evasion, persistence, credential access,
lateral movement, collection, C2 and exfiltration, plus a separate cloud-identity
branch, so the scenario is a materially more complete detection-engineering exercise —
without ever claiming to be a complete APT29 emulation, and without weakening the
evidence bar the rest of this repo already holds every scenario to (ADCS ESC audit,
AppControl mastery, etc.): real behavior, independently observed evidence, honest
ERROR/SKIPPED when something can't run.

## Goals

- Expand `scenarios/apt29-kill-chain.yaml` from 5 to 30 Windows stages, covering every
  ATT&CK technique in the table below (stages 6-30; stages 1-5 are the existing ones).

  | # | Scenario | ATT&CK |
  |---|---|---|
  | 6 | Domain privileged group enumeration | T1069.002 |
  | 7 | Domain controller discovery | T1018 |
  | 8 | Remote system discovery | T1018 |
  | 9 | Security product discovery | T1518.001 |
  | 10 | Network configuration discovery | T1016 |
  | 11 | WMI-based process execution simulation | T1047 |
  | 12 | Rundll32 proxy execution | T1218.011 |
  | 13 | PowerShell obfuscation detection | T1027 |
  | 14 | Windows event logging impairment attempt | T1685.001 |
  | 15 | Startup folder persistence | T1547.001 |
  | 16 | WMI event subscription persistence | T1546.003 |
  | 17 | Windows service persistence | T1543.003 |
  | 18 | COM hijacking detection simulation | T1546.015 |
  | 19 | LSASS access attempt | T1003.001 |
  | 20 | Windows Credential Manager access attempt | T1555.004 |
  | 21 | Browser credential store access attempt | T1555.003 |
  | 22 | Kerberos service account enumeration | T1558.003 |
  | 23 | DPAPI credential access simulation | T1555 |
  | 24 | SMB administrative share access | T1021.002 |
  | 25 | WinRM remote execution simulation | T1021.006 |
  | 26 | Remote service execution simulation | T1569.002 |
  | 27 | HTTPS C2 beacon simulation | T1071.001 |
  | 28 | DNS periodic beacon detection | T1071.004 |
  | 29 | Sensitive file discovery and collection | T1005 |
  | 30 | HTTPS exfiltration simulation | T1041 |

  (Stage 15, startup-folder persistence, reuses T1547.001 — same technique ID as the
  existing stage 3's run-key persistence, which is also T1547.001 under a different
  sub-technique path; both stay, since they test different mechanisms.)
- Add `scenarios/apt29-cloud-identity.yaml`: 5 M365/Azure identity stages (service
  principal credential addition, OAuth app-permission abuse, SAML token forgery
  detection, mailbox collection, cloud account discovery). Code-complete, marked
  execution-unverified until a test tenant exists.
- Add the real Graph-API write path this requires: extend `internal/secretstore` and
  `internal/platform/msauth` with a connector capable of authenticated write calls
  (service-principal creation, OAuth permission grant, mailbox search), wired into the
  `Step` model so a cloud stage can invoke it instead of only running local PowerShell.
  This is new engineering, not just new scenario content, and stays unexecutable until
  a tenant and app registration exist — but once one does, it runs a real mutation
  rather than a local condition check.
- Every step performs a real, reversible OS/API operation and records three
  independent outcomes already modeled in this codebase and never collapsed into one:
  - **Execution outcome** — did the real operation run (`scenario.ExecutionOutcome` /
    `classifyExecution`, backing `models.SimulationResult.Result`).
  - **Detection outcome** — did a security control catch it
    (`SimulationResult.DetectionVerdict` + `DetectionAlert`/`BlockingControl`,
    sourced from `detect.Correlate` against real Sysmon/Security Event Log events, not
    from the step's own `Write-Output` text).
  - **Cleanup outcome** — verified restoration (`CleanupVerdict`/`CleanupResidual`).
- Credential-access-themed steps (LSASS, Credential Manager, browser credential
  stores, DPAPI, Kerberos SPN enumeration) implemented at the approved real
  access-attempt tier: real API/OS calls, never reading, extracting, or exposing
  credential material.
- New `detection_profiles`/`ExpectedDetection` entries for every new technique, wired
  the same way the existing 5 stages already are, so detection claims are checkable
  against real telemetry instead of asserted in prose.
- Step-contract ledger and baseline updated; YAML re-signed; `verify-all` green.
- A lab-validation pass once the 30 Windows stages are code-complete (same pattern as
  `docs/adcs-lab-validation-runbook.md`): confirm each step's claimed Sysmon/Security
  event IDs actually fire on the real lab endpoint, and correct any wrong telemetry
  claim found — "don't assume every API call generates the expected EDR event" is an
  explicit requirement, and this repo's own history (ESC10, stage 17 wording) shows
  that assumption breaks in practice.

## Non-goals

- Building a usable credential-dumping capability. No step reads LSASS memory,
  exports a real DPAPI master key, or extracts a real Kerberos ticket, cookie, or
  stored secret.
- Standing up a live EDR/SIEM connector for the `api`-sourced `DetectionVerdict`.
  Sysmon/Security Event Log evidence, independently queried (`Get-WinEvent`, not the
  step's own text), is the bar for this phase — consistent with every other kill-chain
  scenario in this repo, none of which are yet connector-verified either.
- Running the cloud branch against a real tenant in this phase.
- Claiming complete APT29 emulation. The scenario's own description states its
  coverage boundary.

## Anti-goals

- A step that reports PASS when it actually couldn't execute (no target host, no
  privilege, API denied, cloud tenant absent) — must ERROR/SKIPPED with an explicit
  reason. A missing precondition must never read as clean, same rule already enforced
  for the ADCS audit.
- A step whose `Write-Output "FAIL: EDR should alert..."` text is treated as the
  system of record instead of the real `DetectionVerdict` field.
- A step that can't be cleanly reverted, or that leaves a synthetic identity, key,
  registry value, task, service, or service principal behind.
- Reporting an untested cloud scenario as PASS under any circumstance.

## Constraints

- Windows-only execution for the 30-stage file, as today.
- Four of the 25 new Windows stages need a second reachable host: remote system
  discovery (T1018), SMB administrative share access (T1021.002), WinRM remote
  execution (T1021.006), remote service execution (T1569.002). These must SKIP with an
  explicit reason when no target is configured — never silently pass. No existing
  schema field carries this; it reuses the repo's existing env-var-gate convention
  (same shape as `BAS_ADCS_LIVE_PROBE=true` gating the ADCS ESC8 live probe): each of
  the 4 stages checks `$env:BAS_APT29_TARGET_HOST` and SKIPs with an explicit reason
  ("no remote target host configured") when it's unset, rather than adding a new
  scenario schema field.
- Cloud branch requires an Azure AD/M365 app registration with least-privilege Graph
  permissions, synthetic test users/mailboxes, no real OAuth consent against
  production, and explicit cleanup of every service principal/credential/permission it
  creates.
- Must use the existing step-contract ledger/baseline/signer tooling exactly as every
  other kill-chain scenario does — no new tooling.

## Approaches considered (decided in conversation)

1. **Credential-access depth.** Rejected: full technique replication (builds an actual
   credential-dumping tool) and "printed claim only" (not genuinely behavioral).
   **Approved:** real access-attempt tier — LSASS: `OpenProcess` with query-only
   access, never reading memory; Credential Manager: real enumeration APIs, never
   retrieving secrets; browser stores: validate store-location/metadata access, never
   extracting credentials; DPAPI: protect/unprotect synthetic test data with
   disposable test keys only; Kerberos: real SPN/service-account enumeration, never
   requesting or extracting tickets.
2. **Cloud branch maturity.** Rejected: skip it, or fake a tenant. **Approved:**
   code-complete, separate YAML, explicitly marked execution-unverified until a real
   test tenant exists — matching how this repo has already handled every other
   tenant-dependent initiative (Azure Real Discovery, Cloud Real Integration).
3. **Cloud branch architecture.** The builder check found this platform's agent only
   runs PowerShell on the Windows endpoint today; there's a read-only Azure-discovery
   connector but no path for an authenticated Graph *write* call, and an existing
   scenario (`entra-hybrid-identity-attack.yaml`) already documented that Cloud
   Account Discovery (T1087.004, one of the 5 stages here) has "zero real atomics
   upstream" and used a local condition check instead. Two options: (A) all 5 stages
   as local condition-check stand-ins, matching that existing precedent, cheap, weaker
   fit to "every step performs a real operation"; (B) build a real connector (extend
   `secretstore`/`msauth`) so 4 of the 5 stages make real Graph API write calls once a
   tenant exists, with Cloud Account Discovery alone staying a condition check since no
   real atomic exists for it regardless of architecture. **Decided: B.**
4. **Dual outcome recording.** Considered building a new result schema.
   **Finding, not a new build:** `models.SimulationResult` already carries execution
   outcome, detection outcome, and cleanup outcome as three independent fields, and a
   `detection_profiles` schema already exists and is referenced by the current 5
   stages. The work here is authoring new steps against that existing model, not
   inventing one. `detection_profiles` entries live as signature-verified data files
   under `scenarios/detection-profiles/*.yaml`, not in a `.go` loader.

## Decided (my calls, stated as such)

- **File layout:** extend `scenarios/apt29-kill-chain.yaml` to Stages 1–30 in place
  (keep the five, append the 25); add a new `scenarios/apt29-cloud-identity.yaml` for
  the 5 cloud stages. Matches the literal request to keep the five and add to "the"
  scenario, with cloud split out as its own branch as asked.
- **Grouping:** the 30 Windows stages are grouped under MITRE tactic section headers
  (discovery, execution, defense evasion, persistence, credential access, lateral
  movement, collection, command-and-control, exfiltration) in the same order as the
  user's table, for readability — same comment-block convention the file already uses.
- **New `detection_profiles` entries:** one per new technique, added as signature-
  verified data files under `scenarios/detection-profiles/*.yaml` alongside the
  existing ones, `verification: automatic` for this phase (not `api` — see Non-goals).
- **Lab-validation writeup:** a new `docs/apt29-phase7-lab-validation-runbook.md` and a
  QA-log entry, written once the 30 stages are code-complete, following the exact
  pattern already proven for the ADCS audit.

## What's left to the builder

- The exact PowerShell/WinAPI call for each of the 25 Windows stages and 5 cloud
  stages, matched one-to-one to the user's ATT&CK table, each with
  `blast_radius`/`telemetry`/`detection`/`command`/`cleanup` fields in the file's
  existing style.
- The exact new `detection_profiles` keys, one per new technique, under
  `scenarios/detection-profiles/*.yaml`, following existing naming conventions.
- The exact shape of the new `secretstore`/`msauth` write-connector (option B, cloud
  branch): which Graph API calls it wraps for each of the 4 real-mutation stages, how
  app-registration credentials are supplied/stored, and how a `Step` invokes it instead
  of running local PowerShell.
- Step-contract ledger/baseline diff mechanics and signer re-run, using the existing
  gen/sign/verify loop.
