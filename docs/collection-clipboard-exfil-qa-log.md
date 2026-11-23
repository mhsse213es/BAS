# Clipboard Collection Probe: expansion QA log

Plan: docs/collection-clipboard-exfil-plan.md. Decisions 1–5 approved as written (one scenario, about 30 tests in sections; registry value = CONFIGURED; resolution-only exfiltration probe; modular integration adapters; compare-before-clear clear).
Scenario: scenarios/collection-clipboard-exfil.yaml (signed, 32 steps, 7 sections).
Tests: scripts/collection-clipboard-exfil.Tests.ps1 (Pester 5).

## What the scenario does now
- Clipboard collection and access (1.1–1.6): API availability, presence check without reading, history and cross-device policy values, no supported access policy, monitoring adapter.
- Monitoring and protection (2.1–2.5): Defender, Purview and Trellix adapters, egress adapter, monitoring for the synthetic write.
- Synthetic capture (3.1–3.5): capture runs only when the clipboard is empty. It writes one marker, reads back only that marker, and clears only if the clipboard sequence number has not changed (GetClipboardSequenceNumber), so later user changes are never cleared and content is not read to compare.
- History and sync (4.1–4.4): effective enforcement from HKCU against policy. PASS only when policy and effective setting agree; FAIL when the effective setting contradicts policy; CANNOT_VERIFY when the effective value is unreadable.
- Remote Desktop (5.1–5.4): policy value (CONFIGURED); effective redirection is CANNOT_VERIFY because no session is opened; service state only.
- DLP enforcement (6.1–6.4): synthetic pattern BAS-TEST-PATTERN-0000 through the Purview and Trellix adapters.
- Exfiltration prevention (7.1–7.4): resolver-only probe of a random .invalid name, with no connection and no data sent; egress and network evidence through adapters; failed versus blocked is CANNOT_VERIFY.

## Integrations
An adapter reports NOT_CONFIGURED unless its environment flag is set. A configured adapter reports UNVERIFIED, because no operational probe is implemented in this release. No adapter can return PASS yet.

## Results

| Check | Result |
|---|---|
| Parse: 32 steps, unique names | pass |
| Live run of all 32 commands on the build host | 32 of 32 emit a verdict line in the agreed vocabulary, all SKIP (no integration configured, no enforcement verifiable). No PASS or FAIL. |
| Pester: structure and safety (5) | 5 / 5 pass |
| Pester: enforcement verdicts with stubbed policy values (8) | 8 / 8 pass |
| Pester: integrations never PASS (2) | 2 / 2 pass |
| Pester: synthetic capture (3) | 2 pass, 1 skipped: the empty-clipboard path needs an empty clipboard, which this host did not have. It is not exercised live. |
| `go test -count=1 ./internal/scenario/` | ok, after regenerating the step-contract ledger |
| Signature | verified with the scenario key's public half |

## Step-contract ledger
- The 32 new steps went into `testdata/step_contract_ledger.json` (the test requires one entry per step).
- `testdata/step_contract_baseline.json` changed for `endpoint-mastery/em-09-browser-attack.yaml` only: detection 2 → 0 and telemetry 1 → 0. That is an improvement from the EM-09 rewrite, which had not yet updated the baseline.

## Not done
- No operational probe for any integration. Each adapter needs its own query implementation and a test against a real or recorded product response before it can return PASS.
- Exfiltration verdicts need egress or DLP events from a real source. Until then, egress checks report NOT_CONFIGURED or UNVERIFIED.
- No end-to-end agent run. The live check covers the commands, not the scenario runner.
- The empty-clipboard capture path has no live test on this host.
