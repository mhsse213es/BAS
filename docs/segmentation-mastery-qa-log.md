# Segmentation Mastery (REQ-015 Phase 1) — QA Log

Scope: emulated BFSI lab on the staging host (`audspect-staging`, Docker, 12 containers, six zone networks 172.31.10–60.0/24) plus `internal/segprobe`. Phase 1 proves prohibited zone-to-zone connections are blocked **with firewall evidence**; customer-network probes are Phase 3.

## Verdict rules exercised
- PASS for a deny probe requires a blocked outcome AND a DROP/REJECT record for the tuple.
- A deny probe that connects is FAIL.
- An allow probe needs ACCEPT evidence; same-zone allow probes are reachability-only (no firewall crossing).
- Missing firewall evidence, or an unreadable log, is UNKNOWN, never PASS.
- Destination down is ERROR.

## Live gates (staging, `SEG_LAB=1`, Linux test binary)
| Gate | Test | Result |
|---|---|---|
| Rules reset between runs | TestLive_RulesResetBetweenRuns | PASS |
| G1 opened prohibited path → FAIL | TestLive_G1_OpenedProhibitedPath_IsFail | PASS |
| G2 firewall block → PASS | TestLive_G2_FirewallBlock_IsPass | PASS |
| G3 no evidence → UNKNOWN | TestLive_G3_NoEvidence_IsUnknown | PASS |
| G4 destination down → ERROR | TestLive_G4_DestinationDown_IsError | PASS |
| G5 authorized path → PASS | TestLive_G5_AuthorizedPath_IsPass | PASS |
| G6 log collector stopped → UNKNOWN | TestLive_G6_LogDisabled_IsUnknown | PASS |
| Three runs identical and all PASS, per pack | TestLive_ThreeRunsIdentical | PASS |

Final live run: `live-run4.log` on staging (commit 9b02d703), `exit=0`, 8/8 top-level tests PASS. Earlier runs: `live-run3.log` (before the review minors were closed).

## Repeated-run CLI output (final binary)
```
== swift-isolation (3 runs)            stable=true, 9/9 PASS
== cde-atm-isolation (3 runs)          stable=true, 12/12 PASS (app-to-cde = REJECT → refused, PASS)
== core-banking-tiering (3 runs)       stable=true, 12/12 PASS (app-to-db-authorized = ACCEPT evidence)
```

## Defects found and fixed during live runs
1. **Log flush race → false UNKNOWN (G5).** NFLOG reaches the log asynchronously; a read right after the probe could miss the record. Fix: `readEvidence` polls up to 3s while the log is readable and no matching record exists. Test: `TestRunScenario_LateFirewallRecordIsFound`.
2. **Probes too close together → possible cross-attribution.** The CLI ran probes back to back, so one probe's records could fall inside the next probe's ±2s window. Fix: `probeGap` (3s) between probes and between repeated runs, enforced in the executor. Test: `TestRunScenario_SpacesProbesByProbeGap`.
3. **Stable but wrong passed the determinism gate.** `cde-atm-isolation` returned the same UNKNOWN three times, and the gate only checked stability. Fix: the gate now also requires PASS for every probe.
4. **Same-zone positive control could never PASS.** Evaluate requires ACCEPT evidence that a same-zone probe cannot produce. Fix: `sameZoneOutcome` (connected = PASS, no firewall read). Test: `TestRunScenario_SameZoneConnected_IsPassWithoutFirewall`.

## Test-only firewall rules (never in normal runs)
- `fw/rules/test-open-corp-db.sh` (G1), `fw/rules/test-no-evidence.sh` (G3, with `NO_CATCHALL=1`).

## Not covered in Phase 1
- Customer-network probes (Phase 3).
- Windows `connection refused` mapping: the runner is Linux-only; refused is verified on Linux.
- Pack-level pass/fail rollup (Phase 2 reporting).

## Closure (commit 9b02d703 and the review fix before it)
- Review finding (Important): a deny probe whose target refused, while the firewall ACCEPTed, was UNKNOWN. Now FAIL. Test: `TestEvaluate_DeniedButFirewallAccepted_IsFail`.
- Review minors, all closed:
  - Verdict reasons name the deciding rule, e.g. `blocked with firewall evidence (SEG-DENY-DB-1)`. Test: `TestEvaluate_BlockReasonNamesRule`.
  - ICMP and other non-TCP/UDP log records are skipped, not fatal. Test: `TestParseFirewallLog_SkipsNonTransportRecords`.
  - Transient log read/parse errors are retried to the deadline; collector-down is still immediate UNKNOWN. Test: `TestRunScenario_TransientLogReadErrorIsRetried`.
  - A run cancelled during a probe returns an error. Test: `TestRunScenario_CancelledDuringLastProbeReturnsError`.
  - Listeners are persistent (`nc -lk -e /bin/true`), so a positive control cannot land in a restart gap. Verified 5/5 connects on staging.
- CLI after closure: swift 9/9 PASS, cde-atm 12/12 PASS, core-banking 12/12 PASS; all stable across 3 runs.
- The lab was shut down after the run (`docker compose down`, logs kept).
