# Ransomware detection and response efficacy: design (user: "go with your recommendation")

## Intent
Answer, for one run: was it prevented, detected, contained, recoverable, and what is NOT proven. Never claim more than the evidence.

## Found in recon
`rwresponse.BuildEffectivenessReport` groups by technique only and `selectDimension` returns the FIRST row per capability, so several steps sharing a technique (e.g. three T1490 steps) let an early PASS hide a later FAIL. It also has no run-level verdict, and detection latency is never supplied (always nil). `rw_capability_results` already carries one row per (technique, action, capability).

## Approach (chosen: recommendation)
New pure package `internal/rwefficacy` (no DB, no HTTP), fed the existing `db.RWAttemptRow` list: (A) per-attempt rows keyed technique+action with worst-case verdict per dimension; (B) run-level per-dimension status: `gap` (any FAIL), `unproven` (no evidence, only skips, or only ERRORs), `partial` (some PASS, some unproven), `proven` (all applicable attempts PASS), `not_applicable`; (C) overall: `gaps_found` if any dimension gap, else `unproven` if detection, containment or recovery is not `proven`, else `evidenced`. not_applicable attempts are excluded from counts. Endpoint `GET /api/scenarios/runs/{runId}/ransomware-efficacy`, same auth group as the existing effectiveness route.
Rejected: patching rwresponse in place (changes an existing endpoint's meaning; flagged instead); wiring sink receipts/DLP/EDR as new evidence sources (they already feed rw_capability_results through rwevidence observers; a second path would double count).

## Non-goals / honest limits
Response latency stays not establishable (no causal link detection-to-containment exists). Detection latency stays absent. Nothing is live-verified; unit tests only plus Docker handler test.

## Built and verified (2026-11-18)
`internal/rwefficacy` (9 unit cases: later FAIL not masked, full status matrix, overall rules, ordering/counts), handler `GetRansomwareEfficacy`, route `GET /api/scenarios/runs/{runId}/ransomware-efficacy` (tierAny, same as the sibling route; RBAC drift test caught the missing matrix entry and it was added). Docker handler tests pass: empty run is `unproven`; rows from `EvaluateStep` with the fake observers never read as `evidenced`.
Not done: no UI consumer yet; not run against a real run with live observers; the existing `/detection-response-effectiveness` endpoint still returns the first row per capability per technique (masking issue left untouched, flagged).
