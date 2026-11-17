# APT29 Mastery - Test Contracts

Scope: `apt29-kill-chain` (reworked, 6 stages) plus five new scenarios (22 steps). All Windows, all synthetic data. Sources: MITRE ATT&CK group G0016, CISA AA21-148A, public SolarWinds DFIR reporting. The repo ATT&CK dataset is v16.1; T1562.002 is tagged (v20 renumbers it T1685.001, noted in the step name).

## Verdict model
- Prevention (default): PASS only when a Microsoft Defender (1116/1121) or AppLocker (8004/8007) block event names the step's unique tag `bas_a29_<run>_<id>`. Executed with no block = FAIL (`not_enforced` or `allowed_unexpectedly`). Not executed and no block event = SKIP/inconclusive; absence is never a pass.
- Telemetry mode (`apt29-s5`, `apt29-k1`, `apt29-k2`, `apt29-x9`): the behavior must run and every required log spec must show an event naming the run; PASS means host telemetry recorded it. SIEM ingestion is not verified.
- Every step: behavior is attempted for real, artifacts are run-tagged, removal is verified (`cleanup_verified`), one `APT29_OUTCOME` line, one `PASS|FAIL|SKIP` verdict line.

## Steps
| Scenario | Steps |
|---|---|
| apt29-kill-chain | s1 T1482 discovery; s2a T1105 encoded download (loopback); s2b T1059.001 layered encoded exec; s3 T1547.001 Run key; s4 T1053.005 task; s5 T1071.004 DNS beacon (telemetry) |
| apt29-execution-evasion | x1 T1047, x2 T1218.011, x3 T1218.005, x4 T1027, x5 T1027.001, x6 T1036.005, x7 T1070.006, x8 T1553.005, x9 T1562.002 (gated) |
| apt29-persistence | p1 T1547.001 Startup script, p2 T1547.009 shortcut, p3 T1546.003 WMI subscription (gated), p4 T1053.005 task modify/restore |
| apt29-credential-access | c1 T1550.003 klist precondition (no ticket exported or replayed), c2 T1552.004 key search, c3 T1555.003 stealer-style store copy |
| apt29-command-control | k1 T1071.001 HTTP beacons (loopback, telemetry), k2 T1568 generated-name burst (telemetry), k3 T1090.001 portproxy (gated) |
| apt29-collection-staging | o1 T1005 collection, o2 T1074.002 remote staging via loopback C$ (gated), o3 T1560.001 tar archive |

## Gates (exact-match `true`, admin only)
`BAS_CONFIRM_APT29_TEST_LOG` (x9), `BAS_CONFIRM_APT29_WMI_SUBSCRIPTION` (p3), `BAS_CONFIRM_APT29_PORTPROXY` (k3), `BAS_CONFIRM_APT29_REMOTE_STAGING` (o2). `True`, `1`, `yes` and empty all skip.

## Deliberately excluded
Nine items from the analysis are not attributed to G0016 and were not built: T1003.001, T1041, T1518.001, T1543.003, T1546.015, T1555.004, T1567.002, T1569.002, T1615. Exfiltration to a sink stays with the DLP scenarios. Encrypted-channel/domain-fronting C2 not built (loopback TLS is invisible to sensors; fronting needs real egress). Cloud identity / Microsoft 365 pack is a separate later pack and needs a tenant.
