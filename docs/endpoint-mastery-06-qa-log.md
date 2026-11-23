# Endpoint Mastery 06 — Defense Evasion & LOLBin Execution: QA log

Scenario: `scenarios/endpoint-mastery/em-06-defense-evasion.yaml` (signed).
Source sha256: 0fd5de86a58e30a96c8e550e78bc25cb22590faa1947ecf38ef008502912f732
Steps: 16 (EM-06-01 to EM-06-16), per the approved plan (docs/endpoint-mastery-06-implementation-plan.md).

## Approved decisions applied

1. Test 09 kept as a distinct local-path regsvr32 case.
2. Test 05 (InstallUtil) compiles a no-op installer assembly in a temp folder. Gated.
3. Test 10 (certutil) decodes only. The certificate-store part (T1553.004) is removed.
4. Test 08 (CMSTP) is gated and off by default.
5. Test 14 (masquerading) copies where.exe into a temp folder under a new name. Gated.
6. Test 16 is read-only. T1562.001 is removed from its mapping; no defence is changed.

Gated probes (05, 08, 10, 13, 14) run only with BAS_EM06_ALLOW_EXEC_PROBES=1.

## Verdict model

Each step reports three separate facts: EXECUTED, DETECTED and BLOCKED. COLLECTED is reported as NOT_ASSESSED, because it needs an Audspect query that the endpoint probe cannot make.

- PASS: blocked by policy, or endpoint security detected or blocked the behaviour (Defender 1116/1117/1121/1122, AppLocker 8003/8004, WDAC/CodeIntegrity 3076/3077, matched by image name in the step window).
- TELEMETRY (Sysmon EID 1 or Security 4688 with the marker) is recorded as a separate field and does not affect the verdict.
- FAIL: executed, and no endpoint security detection or block was recorded (or, for test 02, certutil wrote a file).
- SKIP: no process telemetry source (Sysmon not running and process auditing off). Not scored.
- ERROR: the process could not start, or cleanup failed.

Blocking is recognised only from policy-type errors (blocked, policy, access denied). A non-zero exit is not a block.

## Verdict change (approved recommendation)

The first server run gave 16 PASS. Every step passed on process telemetry alone: the behaviour executed and Security 4688 or Sysmon recorded it. Defender logged no detection or block for any step (only event 1151 in the last hour, which is not a detection event). Process telemetry is present on any host with command-line auditing, so it cannot show that endpoint security responded. The verdict now requires an endpoint-security detection or block. Telemetry is reported separately.

## Client run (DESKTOP-5TVEBSI), gate off

- Counts: **SKIP 16** (no process telemetry source on this client). The 11 default probes ran and recorded EXECUTED=yes. The 5 gated probes were skipped by design.
- Detection and blocking are not assessed on this client, because Sysmon is not installed and process auditing is off. This exercises the SKIP path only.

## Lab server run

Pending. Run on WIN-2IP8FNO4MAD with BAS_EM06_ALLOW_EXEC_PROBES=1. The server has Sysmon and command-line auditing, so DETECTED and BLOCKED are assessable there. Results go in this log.

## Notes

- The earlier EM-06 steps (regsvr32 and certutil) reported PASS on any non-zero exit, and certutil wrote a file to the working folder without cleanup. Both are replaced.
- Test 12 encodes the download cradle. The encoded command line is what process telemetry records, so the detection depends on the telemetry capturing the encoded form.
- Test 16 SKIPs where neither Sysmon nor process auditing is available.

## Lab server run (WIN-2IP8FNO4MAD, lab.local), gate on, scenario sha256 0fd5de86e1db824282118f7fdcbbeb0c09d2ec05a44936dc29ee49a8a9aec3a4

Run 3 (out3, 2026-11-21 01:52 -08:00). Clean: 16 verdicts, no NO_VERDICT.

- Steps 01-15: FAIL (15 steps). Each behaviour ran (EXECUTED=yes) and process telemetry recorded it (TELEMETRY=yes). No Defender 1116/1117/1121/1122, AppLocker 8003/8004 or CodeIntegrity 3076/3077 event was logged for the step's image. As far as the Windows logs show, endpoint security did not detect or block these behaviours.
- Step 16: PASS. This is a telemetry-coverage check (a read-only query of the WinDefend state is recorded by process telemetry). It does not show that a security control responded.
- Earlier run (out2, 01:33) reproduced the same 15 FAIL results; the 01:33 run also gave a NO_VERDICT for step 09, which did not recur in out3.
- Trellix (ePO) alerts are not in the Windows logs this scenario reads. An ePO check for the 01:52-01:53 window is still required before concluding that Trellix did not respond.

Temp-folder cleanup: one folder, `C:\Users\Administrator\AppData\Local\Temp\2\AudspectEM06_785b9105ec` (timestamp 1:49 AM), was left after the runs. It was empty when checked. It was removed manually and a re-check printed nothing. Its creation time falls between the out2 (01:33) and out3 (01:52) runs, and no recorded run explains it. Cause not identified; it did not recur in out3's check. Not a Windows or user-environment change; no data was lost.

Not run: the Trellix ePO check, and the Audspect COLLECTED check (requires the Audspect query API).

## Orchestrator run (run 18ea92e7d91b1477, staging orchestrator 192.168.10.78:9543): not a result for this scenario

- The run executed the old 2-step EM-06 on main (Regsvr32 Squiblydoo mock and Certutil URL pattern), not the 16-step scenario in this branch. Events show stepsTotal 2. The new scenario was not imported to that orchestrator.
- The old steps reported pass on exit code 0, so the run's "prevented" kill-chain labels come from exit codes, not from a control. That is the defect the new verdict model replaces. Not used as evidence.
- Report flags cleanup failure from a user-level registry key already present before the run: HKCU\Software\Classes\ms-settings\shell\open. The agent lists it as pre-existing. Not changed; owner to review.
- COLLECTED: NOT ASSESSED for the 16-step scenario. Decision: moved on to the next scenario with this left open.
- Still open: Trellix ePO alert check for the 01:52-01:53 lab window (2026-11-21); the 16-step scenario has not been run through the orchestrator.
- PR for EM-06 not opened.
