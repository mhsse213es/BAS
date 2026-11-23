# Exfiltration Channel Variants Probe: expansion QA log

Plan: docs/collection-channel-variants-plan.md. Decisions 6.1–6.7 approved as recommended, with one exception recorded below.
Fix commit: b2cb4307 (connections and POSTs removed, resolver-only, SKIP).
Scenario: scenarios/collection-channel-variants-exfil.yaml (signed, 24 steps across six areas).
Tests: scripts/collection-channel-variants-exfil.Tests.ps1 (Pester 5).

## Coverage (24)
| Area | Steps |
|---|---|
| SFTP / SSH | 1.1 resolver; 1.2 default outbound action; 1.3 firewall/proxy correlation; 1.4 synthetic transfer detection |
| SMB outbound | 2.1 resolver; 2.2 TCP 445 outbound block rule; 2.3 firewall block correlation; 2.4 SMB client log availability |
| C2-style HTTPS | 3.1 resolver; 3.2 HTTPS egress and WinHTTP proxy; 3.3 proxy detection; 3.4 DLP correlation; 3.5 periodicity |
| Cloud storage | 4.1 local destination classification; 4.2 upload policy; 4.3 DLP policy; 4.4 proxy/firewall enforcement |
| Egress firewall and proxy | 5.1 default outbound action; 5.2 proxy configuration; 5.3 block evidence; 5.4 drift against baseline |
| DLP and telemetry | 6.1 synthetic pattern detection; 6.2 Sysmon log availability; 6.3 correlation and 15-minute freshness |

Correlation key: `bas-sim-<channel>-<runId>.invalid`, carried in every resolver name.

## Exception to the approved plan
Decision 6.2 moved the periodicity test to a Go unit test against recorded telemetry. The backend has no periodicity or beacon detector, so there is nothing for such a test to exercise. Step 3.5 reports NOT_CONFIGURED instead. Building a detector is a separate piece of work.

## Results
| Check | Result |
|---|---|
| Parse: 24 steps, unique names | pass |
| Live run of all 24 commands on the build host | 24 of 24 emit only SKIP-state verdicts. No PASS or FAIL. |
| Pester (10 tests): structure, safety, integrations, firewall reads | 10 / 10 pass |
| `go test -count=1 ./internal/scenario/` (full) | ok, after regenerating the step-contract ledger |
| Step-contract baseline | unchanged; the ledger gained 24 entries |
| Signature | verified with the scenario key's public half |

Pester checks include: no connection, POST, upload or socket code anywhere; resolver use only in steps 1.1, 2.1 and 3.1; no PASS or FAIL in any step; an unconfigured adapter reports NOT_CONFIGURED and a configured one reports UNVERIFIED.

## Notes
- The firewall reads report NOT_CONFIGURED when Windows reports no default outbound action on any profile. On this host that is the case, so steps 1.2, 3.2 and 5.1 report NOT_CONFIGURED for firewall configuration.
- Read-only firewall and proxy queries were run live on this host. No rule or proxy setting was changed.

## Not done
- No operational probe for any integration. Each adapter needs its own query and a recorded-response test before it can PASS.
- No periodicity or beacon detector (see exception above).
- No end-to-end agent run.
