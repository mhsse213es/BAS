# Endpoint Mastery 09 — Browser Data-Access Exposure: QA log

Plan: docs/endpoint-mastery-09-implementation-plan.md (decisions 7.1–7.6 approved as recommended).
Scenario: scenarios/endpoint-mastery/em-09-browser-attack.yaml (signed, 2 steps, one line per profile file).
Tests: scripts/em09-browser-attack.Tests.ps1 (Pester 5).

## Results

| Suite | Result |
|---|---|
| Scenario YAML structure (techniques, no [cite]/BAS-SIM, no extraction verbs) | 3 / 3 pass |
| Fixture: Chrome discovery, ACCESS_ALLOWED, ACCESS_DENIED (ACL), LOCKED_BY_BROWSER, NOT_FOUND, WAL sidecar, no browser | 5 / 5 pass |
| Fixture: Edge Login Data ACCESS_ALLOWED and NOT_FOUND | 2 / 2 pass |
| Lab (BAS_EM09_LAB=1) on the build host, real Chrome and Edge profiles, read-only | 2 / 2 pass (output format only) |
| `go test ./internal/scenario/` (loads the scenario library, including the new EM-09 YAML) | ok |
| Signature re-check: `openssl dgst -sha256 -verify` against the key's public half | Verified OK |

Total: Pester 12 / 12 pass (lab gate on).

## Notes
- The first Pester run failed on a return-value bug in the profile list (`return ,$names` produced a nested array). Fixed by returning `$names`; both browser steps changed.
- Verdict aggregation follows the runner's fail-safe order (FAIL > ERROR > SKIP > PASS), so one ACCESS_ALLOWED profile makes the step FAIL.
- The lab test checks only that every line uses a known state. It does not record or print profile contents, and no cookie or credential value is read.
- Browser process state was not changed by these tests. A browser that held its file open produced LOCKED_BY_BROWSER, which is reported as SKIP.

## Not done
- No endpoint run through the agent. The scenario runner path has been covered by the scenario package tests, not by an end-to-end scenario execution.
- The signing key is the scenario key from the main checkout (not copied into this worktree).
