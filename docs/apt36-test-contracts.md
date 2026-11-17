# APT36 Mastery - Test Contracts

Scope: `apt36-kill-chain` reworked (10 stages, one MITRE technique each) plus five new mastery scenarios (27 new steps, 37 in total). All Windows, all synthetic data. Source: public reporting on APT36 / Transparent Tribe / PROJECTM.

## Verdict model
Same model as the APT29 pack (`docs/apt29-test-contracts.md`): PASS only with a block event naming the run tag; executed with no block = FAIL; not executed with no block event = SKIP/inconclusive. Telemetry mode (DNS beacons) and Direct mode (capability probes, the Defender-exclusion check) are reported separately from prevention. Every step verifies its own cleanup.

## Safety rule added mid-build
No step may change live system/security-control state beyond its own run-tagged artifacts without an exact-match gate **and** without reporting the change back for independent verification, not trusting a command's exit code. Two steps were revised against this rule before being shipped:
- `apt36-k4` (WinRM lateral-movement check, T1021.006) was rewritten from "start the service, use it, stop it" to a pure read of current WinRM state. It never starts, stops or reconfigures WinRM.
- `apt36-pe5` (Defender exclusion, T1562.001) is gated behind `BAS_CONFIRM_APT36_DEFENDER_EXCLUSION` (exact, admin-only), refuses to run if its tagged path is already excluded, and verifies both the add and the removal against live `Get-MpPreference` state rather than the command's exit code. It was reviewed but never run live on the build host in this session.
- `apt36-k6` (T1053.005 remote) acts on remote hosts the same way `k5` does: gated by `BAS_CONFIRM_APT36_LATERAL_MOVEMENT`, admin-only, targets from `BAS_LATERAL_TARGETS` only. It creates a one-time task whose action writes a marker file, queries and deletes it, and verifies deletion on each target. The task is never triggered. Built, not run.
- `apt36-k5` (T1569.002) is the only step that acts on other hosts. It runs only against hosts named in `BAS_LATERAL_TARGETS`, under `BAS_CONFIRM_APT36_LATERAL_MOVEMENT=true` (exact), as administrator. It creates, starts, stops and deletes a run-tagged demand-start service per target, verifies the deletion with a separate query, and uses the current identity only. It is built but has not been run against any target.
- `apt36-i2` (execution from a mounted virtual disk image, a Mark-of-the-Web bypass route) was withheld entirely rather than shipped, after review.
- Keystroke collection (a real global keyboard hook) was not built. Installing a hook that captures keystrokes is keylogging, not a bounded simulation; `s3` stays a capability probe.
- A full macro-enabled document chain was not built. Shipping one would mean a working macro-execution payload on the host, so only the child-process and template-fetch pieces exist.
- The Android/mobile branch was not built. The product has no mobile agent.
- HTTPS exfiltration was not built here; exfiltration to a verified sink lives in the DLP scenarios.

## Steps
| Scenario | Steps |
|---|---|
| apt36-kill-chain | s1 T1204.002 renamed-binary parent; s2 T1221 remote template fetch; s3 T1056.001 keyboard-hook capability probe; s4 T1547.001 Run key; s5 T1071.004 DNS A beacon (telemetry); s6 T1053.005 task; s7 T1218.005 mshta; s8 T1218.010 regsvr32; s9 T1071.004 DNS TXT beacon (telemetry); s10 T1105 download cradle, hash-verified |
| apt36-initial-execution | i1 T1204.002 .lnk, i3 T1059.005 wscript, i4 T1059.001 encoded PowerShell, i5 T1047 WMI, i6 T1218.001 CHM |
| apt36-discovery | d1 T1057, d2 T1082, d3 T1083, d4 T1016, d5 T1135 - all read-only |
| apt36-collection-credential | cc1 T1003.001 query-only LSASS handle, cc2 T1555.004 Credential Manager list, cc3 T1555.003 stealer-style store copy, cc4 T1115 clipboard, cc5 T1113 screenshot |
| apt36-persistence-evasion | pe1 T1546.003 WMI subscription (gated), pe2 T1547.001 Startup script, pe3 T1543.003 service lifecycle (gated), pe4 T1546.015 COM CLSID override, pe5 T1562.001 Defender exclusion (gated) |
| apt36-command-control | k1 T1071.001 HTTP beacons, k2 T1560.001 tar archive, k3 T1021.002 admin-share staging (gated), k4 T1021.006 WinRM exposure check (read-only), k5 T1569.002 remote service execution over SCM (gated, lab targets only, built but not run), k6 T1053.005 remote scheduled task over RPC (gated, lab targets only, built but not run), k7 T1071.004 DNS tunneling volume pattern (telemetry only) |

## Corrections applied from the review
- Office child-process chain is now explicitly T1204.002/T1059.001, not T1566.001 (delivery is not tested here; it is a separate, unbuilt concern).
- Template injection (s2) builds a real OOXML relationship and fetches the template over the network; it is not a bare localhost connectivity check, though Office is never opened so macro execution itself is not tested.
- The keyboard-hook probe (s3) is explicitly scored as a capability probe (Direct mode, inconclusive), never credited as a keylogging test.
- T1550.003-style "it's just enumeration" labeling mistakes from the APT29 review were avoided here by naming cc1 as a T1003.001 *precondition* in its summary text.

## Deliberately excluded
Android/mobile branch (needs a mobile agent, out of scope here). LSASS memory read, DCSync and other credential-dumping techniques already covered by other scenarios are not duplicated. SMB/WinRM steps stop at "can this host reach itself," not real cross-host lateral movement, which needs a second host.
