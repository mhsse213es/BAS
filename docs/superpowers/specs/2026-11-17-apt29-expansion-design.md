# APT29 kill chain expansion: design

Status: approved by the user on 2026-11-17 ("approved, go ahead"). Approach: fix the existing scenario in place, add five new scenarios, defer the cloud branch.

## Intent
`apt29-kill-chain` has five stages and exercises 4 of the 110 techniques on MITRE's G0016 page (ATT&CK v20 numbering). Two built-in adversary templates (`apt29-quick`, `apt29-full`) reference it by id. The goal is meaningful APT29 coverage built on documented behaviours, with independently verifiable evidence per step and an honest verdict model, not a longer linear chain.

## Goals
- Each step has an APT29 attribution basis (a technique on MITRE's G0016 table), one distinct defensive objective, and evidence that can be checked independently of the verdict.
- A prevention verdict (PASS) requires a block event naming the run; a failed or absent run without such an event is inconclusive (SKIP), never a pass.
- Detection/telemetry visibility is reported separately from prevention and never changes it.
- Every artifact is created under a run-unique name and removed; removal is verified and reported.

## Non-goals / anti-goals
- No invented linear attack chain. No padding with variations of the same behaviour.
- No real credentials, tickets or secrets; synthetic data only. No real C2, no external egress. Exfiltration to a sink stays with the DLP scenarios.
- Not claiming vendor-EDR coverage: only Microsoft Defender and AppLocker are queried for block evidence.
- Cloud identity / Microsoft 365 (T1098.x, T1606.002, T1114.002, T1087.004 ...) is a separate later pack; it needs a configured tenant and real-tenant verification is blocked.

## Constraints
- Agent runs Windows PowerShell 5.1; generated YAML must be ASCII; scenario files are signed (`signer.go sign`, `verify-all`).
- Existing id `apt29-kill-chain` and the order/meaning of its stages stay (templates and API tests reference it). Stage 2 becomes two stages (download, execute), so it grows from 5 to 6 stages.
- ATT&CK dataset in the repo is v16.1: steps carry repo-known IDs (T1562.002) and mention the v20 ID (T1685.001) in text.
- Attribution rule: only techniques on MITRE's G0016 table. Nine items in the request are not on it (T1003.001, T1041, T1518.001, T1543.003, T1546.015, T1555.004, T1567.002, T1569.002, T1615) and are not built into this pack; existing generic scenarios cover several.

## Approaches considered
1. One 40-step linear scenario: rejected (invented chain, one pass/fail blob).
2. Fix in place + new scenarios per tactic from a shared library: chosen (same pattern as Akira; templates keep working).
3. Wrap existing generic scenarios only: rejected; they have no APT29 attribution or sequencing and leave the 21 uncovered techniques untested.

## Design
Shared library `scenarios-src/apt29-common/lib.ps1`, minified into each step by the existing generator `orchestrator/scripts/appctlgen` (it takes any common dir). Functions: run id and work dir; `Get-A29Control` (Defender real-time/ASR state, AppLocker); `Get-A29Blocks` (Defender 1116/1117/1121, AppLocker 8004/8007, counted by run-id needle); `Resolve-A29Outcome` (decision table above); `Get-A29Telemetry` (Sysmon / 4104 / Security visibility per step, never affects the verdict); `Invoke-A29Test` (runs the attempt, resolves, cleans, emits `APT29_FAMILY / APT29_EVIDENCE / APT29_TELEMETRY / APT29_OUTCOME` and PASS/FAIL/SKIP). A direct mode lets telemetry-validation and posture steps give their own verdict with a reason.

Scenarios (29 steps): `apt29-kill-chain` (6, fixed in place), `apt29-execution-evasion` (9), `apt29-persistence` (4), `apt29-credential-access` (3), `apt29-command-control` (4), `apt29-collection-staging` (3). Anything that registers or changes host state beyond the user's temp area (WMI subscription, portproxy, remote staging share, test event log clear) is behind an exact-match lab flag, administrator only, and verified-removed.

## Verification limits (stated up front)
Steps are executed for real on the build host, which has no EDR/SIEM; block and telemetry paths are verified against stubbed fixtures only. Gated paths are run only where they are low risk and fully reversible.
