# Score impact of telemetry-only probes now SKIPping

Commits `e021287f` and `6e3558c8` changed steps that only run a harmless command (share or file enumeration, command-line
probes) from PASS-on-exit-0 to `SKIP: telemetry-only probe; it records process telemetry and has no control outcome to
score. Not scored.` Both commits say "NOT VERIFIED on a lab host". This note is a static review of what that does to
scores. Nothing here was run against an agent.

## What a SKIP does, from the code

| Where | Effect of a skipped step |
| --- | --- |
| Prevention score (`models/score.go`) | Left out of numerator and denominator. A run with no executed step is `NotAssessed`, not 0. |
| Compliance mapping (`compliance/mapper.go`) | Ignored, so a control that relied on the step has no evidence and shows Untested. |
| Detection effectiveness, coverage analytics, campaign totals | Ignored. |
| SIEM correlation (`siem/correlator.go`) | Recorded as `not_executed`: the step is never checked against SIEM alerts. |
| Execution coverage % | Counts as scheduled but not covered, so the figure goes down. |

The skip carries no skip reason, so it lands in the "intentional" outcome bucket.

## Which scenarios, and how much weight

16 scenarios, 34 steps (steps whose command contains the telemetry-only SKIP line). "Weight" is the share of the
scenario's severity weight (Critical 4, High 3, Medium 2, other 1) that no longer scores.

| Scenario | Steps | Now SKIP | Weight | Techniques with no scored step left |
| --- | --- | --- | --- | --- |
| akira-kill-chain | 16 | 1 | 2% | none |
| apt36-kill-chain | 10 | 3 | 30% | T1071.001, T1071.004, T1221 |
| black-basta-kill-chain | 10 | 3 | 30% | T1083, T1562.001 |
| clop-kill-chain | 5 | 1 | 20% | T1083 |
| cscrf-mii-drill | 9 | 3 | 33% | T1069.001, T1082, T1110.001 |
| evasion-testing | 5 | 2 | 40% | T1027, T1027.013 |
| insider-threat-kill-chain | 3 | 1 | 33% | T1083 |
| linux-ransomware-drill | 4 | 1 | 25% | none |
| lolbin-execution-coverage | 21 | 3 | 14% | T1140, T1197 |
| lolbin-execution | 5 | 1 | 20% | T1218.010 |
| play-kill-chain | 8 | 1 | 12% | T1135 |
| ransomhub-kill-chain | 8 | 2 | 25% | T1135 |
| ransomware-drill | 9 | 2 | 22% | T1070.001, T1083 |
| ta505-kill-chain | 9 | 1 | 11% | T1490 |
| upi-fraud-killchain | 9 | 4 | 44% | T1048.003 |
| windows-discovery-validation | 3 | 3 | 100% | T1018, T1083, T1087.002 |

Score swing: these steps used to count as passes, so a scenario's old score was inflated by `(1 - pass rate of the
remaining steps) x weight share`. On a host that stops everything else the swing is 0; on a weak host it approaches the
weight column (for example up to about 30 points for apt36 and black-basta).

## Findings

1. `windows-discovery-validation` can no longer produce a score. All three steps skip, so every run is NotAssessed.
   Decide whether it stays (as an inventory scenario) or is retired.
2. Scores and trends are not comparable across this change. Historical runs include these steps as passes. Expect a
   visible step down in trend charts and re-run comparisons, mostly for scenarios above 25%.
3. The detection signal is lost. These probes exist so a SIEM or EDR can see the activity. As SKIP they are
   `not_executed` in SIEM correlation, so "did the SIEM see `net view`" is no longer measured. If telemetry is the
   point, grading them from the verification store (Detected / Not detected) is more honest than SKIP.
4. Technique coverage drops for the techniques listed above. Where another step covers the same technique in another
   scenario it is fine; where not, the technique now reads untested for that scenario.
5. Execution coverage % falls, because these steps are scheduled but never covered. That is accurate but may look like
   a regression to a reader.

## Decisions for the owner

- Keep SKIP (honest about no control outcome) or move these probes to detection grading (keeps the detection signal).
- Retire or relabel `windows-discovery-validation`.
- Add a release note about the trend break, and do not compare pre- and post-build scores directly.
- Run one affected scenario (for example apt36 or black-basta) on a lab host and confirm the figures above.
