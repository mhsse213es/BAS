# Endpoint Mastery 05 — Persistence Mechanism Validation: QA log

Scenario: `scenarios/endpoint-mastery/em-05-persistence-validation.yaml` (signed).
Source sha256: 262c795dba71515c8cfcc1a767323798d0ec4e192d798a17d6e14ce051bb5ff6
Steps: 51 across nine categories. 41 read-only checks; 10 write probes, gated.

## Scope and design

The two original steps are kept under their original names and improved:
- **Registry Run Key Modification attempt (HKCU)**: now writes a uniquely named synthetic value that runs `cmd.exe /c exit 0`, checks for a Sysmon EID 13 event, removes the value, and verifies removal. The old version reported PASS on a blocked write without checking detection.
- **User Startup Folder File Drop**: now writes a uniquely named .txt file (not executable), checks Sysmon EID 11, removes it, and verifies removal.

Verdict rules:
- PASS: the write was blocked, or it succeeded and was detected. For read-only checks, the configuration is in the expected state.
- FAIL: the write succeeded and was not detected, or an unsafe configuration was found. Where Sysmon is absent, a successful write is reported as FAIL with the reason stated.
- SKIP: not applicable or not assessable here, with a reason. Not scored. Write probes SKIP unless the gate is set.
- ERROR: the check could not complete, or cleanup failed (the verdict line names the item to remove manually).

Write probes (10):
- HKCU and HKLM Run; HKCU and HKLM RunOnce; user and all-users Startup file drops; a demand-start service with a missing binary (never runs); a one-time task scheduled for 2099 with a no-op action; a permanent WMI subscription whose filter never fires (event-log consumer only, no command-line or script consumer); an IFEO Debugger for a synthetic image name that never runs.
- All are gated by `BAS_EM05_ALLOW_WRITE_PROBES=1`. They are not run on the production client. They must run only on an isolated lab host.

## Client run (DESKTOP-5TVEBSI), write gate off

- Run 3 (final read-only run): **29 PASS, 9 FAIL, 13 SKIP, 0 ERROR, 0 NO_VERDICT.** The 10 write probes SKIP as designed.
- Findings on this client:
  - Three HKCU Run entries point at user-writable folders (AppData): user-installed applications. Owner should confirm they are expected.
  - HKLM Run has no success audit rule.
  - An unquoted service path (CoworkVMService).
  - NoDriveTypeAutoRun is absent (autorun is not disabled).
  - The task store (System32\Tasks) grants **explicit** Write to NT AUTHORITY\Authenticated Users (not inherited). Check whether this is a deliberate change.
  - Task creation is not audited for success (EID 4698 not recorded).
  - Registry auditing and process-creation auditing with command lines are off; Security log maximum is 20 MB.
  - Sysmon is not deployed, so the Sysmon-based detection checks SKIP.

## Corrections made during testing (before the final run)

- Defender services and tasks were flagged because `ProgramData` was treated as user-writable. Removed from the user-writable patterns; Defender now passes.
- The built-in SCM Event Log WMI filter, consumer and binding were flagged as unexpected. Excluded by name.
- The WMI orphan-binding check compared against a base-class filter that returned nothing. Changed to enumerate names.
- The Winlogon ACL step used a `Registry::` path that Get-Acl did not resolve. Fixed; now PASS.
- Get-Acl -LiteralPath on HKLM paths replaced with -Path.

## Not yet verified

- **The 10 write probes have not been executed on any host.** All 51 steps parse as PowerShell (checked with the PowerShell parser without running them). Their behaviour, detection and cleanup need a lab run with the gate on.
- Sysmon-based detection has not been exercised: Sysmon is not on the client or the server.
- The step 21 Authenticated Users write grant on the task store: needs owner review.

## Server run

Pending. Run on the lab server (WIN-2IP8FNO4MAD) with `BAS_EM05_ALLOW_WRITE_PROBES=1`. Results to be recorded here.

## Changes in this branch

- `scenarios/endpoint-mastery/em-05-persistence-validation.yaml` and `.sig` (51 steps; signed).
- `orchestrator/internal/scenario/testdata/step_contract_ledger.json` (EM-05 rows only). `TestStepContract` passes; full scenario package passes.
- `docs/endpoint-mastery-05-qa-log.md` (this log).

## Lab server run (out9) — WIN-2IP8FNO4MAD, 2026-11-21 00:17 -08:00, write gate on

- Source sha256 63179fb2416295b70c517ed558922ac9fd806fb1d8f7147562fea319b4f2e1ca (matches HEAD ded1ce8e).
- Counts: **PASS 35, FAIL 17, SKIP 0, ERROR 0, NO_VERDICT 0.** First clean run of the full set.
- All 10 write probes ran; cleanup verified for each.

Established and not detected (FAIL):
- Run / RunOnce (HKCU and HKLM): writes succeeded, no Sysmon EID 13 recorded. The Sysmon configuration does not cover CurrentVersion\Run (step 47).
- User and all-users Startup file drops: succeeded, no EID 11 recorded.
- IFEO Debugger for a synthetic image name: succeeded, no EID 13 recorded.
- Task creation: succeeded, no EID 4698 recorded (task-creation audit off, step 25).
- Service creation: PASS. The install was recorded (EID 7045) under the display name. Detection matched on the display name after the fix.
- WMI subscription: PASS. Created, EID 5861 recorded, removed.

Configuration findings (FAIL):
- User Startup folder is redirected to C:\Users\Administrator\AppData\Local\Temp\atomictest\ (step 51). That folder contains calc.exe (step 12), an executable that runs at logon. Probably left by an Atomic Red Team test. Not removed; restoration needs owner approval.
- Task store (System32\Tasks) grants explicit Write to NT AUTHORITY\Authenticated Users (step 21). Confirmed on server and client.
- BootExecute is 'autocheck autochk /q /v *' rather than the default (step 40). Owner to decide.
- Autorun not disabled for all drives (step 42); registry auditing off (step 48); Run key SACL absent (step 7).

## Defects found and fixed during lab runs

- Blocked-write PASS accepted any failure; now only an access-denied reason passes, other failures are ERROR.
- Service detection searched the internal name; the event reports the display name. Display name now carries the suffix.
- WMI subscription: NTEventLogEventConsumer rejected by the server (null value at the consumer stage); LogFileEventConsumer used instead. Binding reference type mismatch fixed by using WMI object paths.
- **WMI cleanup removed only NTEventLogEventConsumer objects and verified the same wrong class.** A failed run (out7) left a filter and a log-file consumer on the server while reporting cleanup verified. Those objects were removed by hand (only AudspectEM05* names), and the cleanup now covers both consumer classes and verifies the same objects.

## Runner notes

- NO_VERDICT ("An error occurred while creating the pipeline") appeared on single steps across several runs (05, 07, 11, 17, 28, 36, 44, 47). Each cleared on re-run. Not reproduced locally.

## Open

- Startup redirect and calc.exe: awaiting owner approval to restore the standard Startup location and remove the file.
- PR #23 open; not merged. Merge after owner review of the findings above.
