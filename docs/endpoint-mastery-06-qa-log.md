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
