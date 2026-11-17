# Akira Windows Completeness (stages 17-25): design (approved by standing instruction 2026-11-17)

Sub-project 4. Extends `akira-kill-chain` (v2.1.0 -> v2.2.0) with nine steps. Parent: `2026-11-17-akira-expansion-part1-design.md`.

## Steps (ids `akira-s17` .. `akira-s25`; one technique tag per step, secondary techniques named in evidence)
17 valid-account posture T1078 (read-only); 18 external remote services exposure T1133 (read-only); 19 remote system and domain trust discovery T1482 (carries T1018; SKIP for the domain part off-domain); 20 process/system/file discovery T1082 (carries T1057, T1083); 21 PowerShell/WMI/service execution telemetry T1059.001 (carries T1047, T1569.002; service part gated `BAS_CONFIRM_SERVICE_EXEC`; verdict from event-log evidence, not from the command running); 22 Kerberoasting exposure T1558.003 (read-only LDAP; TGS request only with `BAS_CONFIRM_KERBEROAST_TGS=true` and `BAS_KERBEROAST_SPN`; never extracts or cracks); 23 account persistence exposure T1136.001 (capability posture; gated `BAS_CONFIRM_ACCOUNT_CREATE=true` creates a DISABLED random-password local account, verifies, deletes, verifies); 24 run-key persistence T1547.001 (inventory; gated `BAS_CONFIRM_RUNKEY_WRITE=true` writes and removes one HKCU Run value); 25 remote access tool exposure T1219 (presence only; allow-list `BAS_ALLOWED_REMOTE_TOOLS`).

## Decisions
- Insert order follows the kill chain (17,18 before s1; 19,20,21 after s2; 22 after s3b; 23,24 after s4; 25 before s5); the engine runs list order, `depends_on` is decorative.
- Step 23 tags T1136.001 (local), not the T1136.002 (domain) in the request, because the only simulation creates a local account; domain account creation is not simulated.
- Real detection profiles only where the step always performs the behavior: 19 `windows_ad_discovery`, 20 `windows_file_discovery`, 21 `windows_encoded_powershell`. Others carry none (a profile would expect detections for behavior the step does not perform).
- New technique mappings in `rwtaxonomy`: T1133, T1482, T1082, T1059.001, T1558.003, T1136.001, T1547.001, T1219.
- No new gate defaults; all gates exact lowercase `true`; every created artifact is removed and removal verified.

## Honest limits
Domain steps (19 domain part, 22) can only SKIP on the workgroup build host; step 22 logic is unexecuted against a real domain. Telemetry verdicts depend on logging being on; a host without audit policy reports a gap, which is the finding. Nothing runs through the real agent.
