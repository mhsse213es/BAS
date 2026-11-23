# Endpoint Mastery 08 — Exploit Mitigation & Posture Check: QA log

Scenario: scenarios/endpoint-mastery/em-08-exploit-mitigation.yaml (signed, 50 steps, EM-08-01..50).
Source sha256: b83856e51083d6c950f00c5d624844c50d148be6a5c15b87be7fcd9248d9ad18
Plan: docs/endpoint-mastery-08-implementation-plan.md. Decisions 8.1–8.7 approved.

## Approved decisions applied
1. Verdict word SKIP (not SKIPPED).
2. OptIn DEP: FAIL unless per-process DEP is confirmed (tests 04–06, 21, 44–45 check per-process DEP/CFG/ACG).
3. Targets: explorer.exe, powershell.exe, svchost.exe, plus application list entries from BAS_EM08_APPS.
4. Application list: none supplied, so tests 47–50 SKIP.
5. 50 tests.
6. ATT&CK T1203 (Exploitation for Client Execution) on all mitigation tests.
7. Both original steps replaced.

## Corrections to the existing scenario
- DEP mapping was wrong. DataExecutionPrevention_SupportPolicy 2 was read as AlwaysOn. On this host the value is 2 and bcdedit reports nx OptIn. The new mapping is 0 AlwaysOff, 1 AlwaysOn, 2 OptIn, 3 OptOut, verified only by agreement with bcdedit on this host.
- ASLR check passed on registry existence. Replaced by effective policy reads.

## Field semantics (verified on the build host)
- Get-ProcessMitigation -System returns policy objects per area (Dep, Aslr, Cfg, BinarySignature, DynamicCode, SEHOP, Heap, ExtensionPoint, ChildProcess, ImageLoad, StrictHandle, UserShadowStack); Source is 'System Defaults' when no custom policy is set.
- NOTSET means the setting is not configured and inherits the OS default. The effective per-process value is the override if set (ON/OFF), otherwise the system value.
- Get-ProcessMitigation -Name <image> returns nothing when the image has no override. That is treated as no override, not as unreadable.

## Build-host run (WIN-2IP8FNO4MAD was not used; this is the Windows 10 build workstation), read-only, run2
- Counts: PASS 6, FAIL 39, SKIP 5, ERROR 0, NO_VERDICT 0.
- Interpretation: default Windows policy. Most mitigations are NOTSET. FAIL here means "not configured or not effective", as the plan requires. Not a defect in the host.
- SKIP 5: test 43 is not SKIP (it PASSes: no override). SKIPs are test 42 (Defender Exploit Protection, not verifiable), and tests 46–49 (no application list).

## Open question for approval (not changed)
- Tests 04–06 (per-process DEP) FAIL on all three 64-bit targets: override NOTSET, system NOTSET, arch x64. The approved rule ("FAIL unless per-process DEP is confirmed") applied literally. Whether 64-bit processes get NX enforcement regardless of the OptIn setting has not been verified in this run. Decide whether to keep the literal rule or treat 64-bit targets differently.

## Not run yet
- Client read-only run (DESKTOP-5TVEBSI).
- Lab server run (WIN-2IP8FNO4MAD, Server 2019). Expected to show different SKIP patterns, since some mitigations are not exposed on Server 2019.
- Application list run with BAS_EM08_APPS set.
- Field names for Defender Exploit Protection not verified (test 43 SKIPs).
- Trellix ePO correlation: not applicable here (read-only policy queries).
