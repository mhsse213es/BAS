# Application Control Efficacy — Test Contracts

Each behavioral family in `scenarios/appcontrol-efficacy.yaml` has a contract. A contract states what the test claims, what it needs, what counts as evidence, and where it cannot say anything. A result that falls outside its contract is not a pass.

Every contract has the same fields: family, control under test, prerequisites, expected-result source, expected outcome, evidence requirements, attribution rule, cleanup, unsupported conditions, and known blind spots.

`TestAppControlContracts_EveryFamilyHasContract` in `orchestrator/internal/scenario/appcontrol_contract_test.go` fails if a family in the scenario has no section here, or if a section is missing a field.

## Shared rules (all families)

- **Expected-result source.** The effective policy is captured with `Get-AppLockerPolicy -Effective` immediately before the attempt. The expected result comes from the test contract, not from what the policy is assumed to say.
- **Outcome rule.** `blocked_as_expected` requires all of: the marker is absent, exactly one control block event names the attempted binary, file, or parent, and the controlling collection is `Enabled`. Anything else is `inconclusive`, `not_enforced`, `allowed_unexpectedly`, or `not_applicable`, as the decision function defines. A process failure alone is never a pass.
- **Unreadable log.** An unreadable event log is `inconclusive`.
- **Control unavailable.** When the mechanism or its control is absent (service stopped, policy unreadable, component not installed), the result is `not_applicable`. It is never a pass.
- **Visibility.** `APPCTL_DETECTION` records whether Sysmon process-creation telemetry saw the attempt. It is recorded separately from the outcome and never sets a prevention verdict.
- **Cleanup.** Every temporary file or copy is deleted in the step's own cleanup, and in the step's own run.

## indirect_execution

- **Control under test.** AppLocker Exe rules applied to `powershell.exe` launched through a `cmd.exe` parent.
- **Technique.** T1202.
- **Prerequisites.** Windows with AppLocker available; AppIDSvc running; Exe collection readable.
- **Expected-result source.** Effective Exe collection mode captured immediately before the attempt.
- **Expected outcome.** `blocked_as_expected` when Exe is `Enabled` and the policy covers `powershell.exe`.
- **Evidence requirements.** `APPCTL_EVIDENCE` with test ID, `ran`, `exit`, `attributed`, `log_readable`, and capture time. Attribution: exactly one `Microsoft-Windows-AppLocker/EXE and DLL` event 8004 in this test's window naming `powershell.exe`.
- **Cleanup.** Removes the temp output file.
- **Unsupported conditions.** AppLocker unavailable (edition); AppIDSvc not running; event log unreadable.
- **Known blind spots.** A parent-process path only. It does not test PowerShell launched directly, or through any other interpreter.

## alternate_binary

- **Control under test.** AppLocker Exe rules applied to a renamed copy of `powershell.exe`.
- **Technique.** T1036.
- **Prerequisites.** As indirect_execution. Write access to `%TEMP%`.
- **Expected-result source.** As indirect_execution.
- **Expected outcome.** `blocked_as_expected` when the rule is path-, hash-, or publisher-based and covers the renamed copy. A path-only allow rule that does not cover the copy is a real gap, and the result reports it.
- **Evidence requirements.** As indirect_execution, attributed to the unique copy name.
- **Cleanup.** Removes the copy and the temp output file.
- **Unsupported conditions.** As indirect_execution.
- **Known blind spots.** Covers the renamed copy of one Microsoft binary. It does not cover other renamed binaries or unsigned binaries.

## script_host_proxy

- **Control under test.** AppLocker Script rules applied to `.vbs` run through `cscript.exe`.
- **Technique.** T1059.005.
- **Prerequisites.** AppLocker available; Script collection readable; `cscript.exe` present.
- **Expected-result source.** Effective Script collection mode captured immediately before the attempt.
- **Expected outcome.** `blocked_as_expected` when Script is `Enabled` and the policy covers the file.
- **Evidence requirements.** `APPCTL_EVIDENCE`. Attribution: exactly one `Microsoft-Windows-AppLocker/MSI and Script` event 8006 naming the unique `.vbs` file.
- **Cleanup.** Removes the `.vbs` and the temp output file.
- **Unsupported conditions.** AppLocker unavailable; event log unreadable.
- **Known blind spots.** Covers `cscript` with `.vbs` only. Not `wscript`, `.js`, `.ps1`, or other script hosts.

## alternate_ps_host

- **Control under test.** AppLocker Exe rules applied to PowerShell 7 (`pwsh.exe`), which Desktop-edition rules may not cover.
- **Technique.** T1059.001.
- **Prerequisites.** `pwsh.exe` installed; AppLocker available.
- **Expected-result source.** As indirect_execution.
- **Expected outcome.** `blocked_as_expected` when the Exe rules cover `pwsh.exe`. `not_applicable` when `pwsh.exe` is not installed.
- **Evidence requirements.** As indirect_execution, with `pwsh_present` recorded. Attribution: exactly one event 8004 naming `pwsh.exe`.
- **Cleanup.** Removes the temp output file.
- **Unsupported conditions.** `pwsh.exe` absent (reported `not_applicable`, never a pass); AppLocker unavailable.
- **Known blind spots.** Only the PowerShell 7 host, and only where it is installed. Does not test in-process hosting.

## parent_child_asr

- **Control under test.** The Attack Surface Reduction rule that blocks Office applications from creating child processes (`D4F940AB-401B-4EFC-AADC-AD5F3C50688A`).
- **Technique.** T1204.002.
- **Prerequisites.** Microsoft Defender preferences readable; `Set-MpPreference` ASR state present; administrative rights to create the test copy.
- **Expected-result source.** The ASR rule's action (Block, Audit, or not configured) read from Defender preferences immediately before the attempt.
- **Expected outcome.** `blocked_as_expected` when the rule is in Block mode and the child process is not launched. `not_applicable` when Defender preferences are unavailable.
- **Evidence requirements.** `APPCTL_EVIDENCE`. Attribution: exactly one `Microsoft-Windows-Windows Defender/Operational` event 1121 whose message contains this test's unique ID.
- **Cleanup.** Removes the copy directory and the temp output file.
- **Unsupported conditions.** Defender preferences unavailable; event log unreadable.
- **Known blind spots.** The parent is a copy of `cmd.exe` named `winword.exe`, not a real Office application. The test shows whether the rule matches on image name. It does not show whether a real Office child is blocked.

## Known blind spots shared by all families

- Every result holds only for the tested Windows build, policy version, and execution path.
- Live enforcement is verified only by a run on a host with the control configured and enforced. The fixture tests that check this code are stubs and are not evidence of enforcement.
- Vendor-specific correlation (Defender and SentinelOne detection verdicts) is not part of these contracts.
