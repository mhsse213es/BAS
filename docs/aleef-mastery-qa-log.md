# Aleef Mastery QA Log

Initiative: Aleef Milestone 1 (logic-flaw discovery against a synthetic bank API).
Benchmark contract: `docs/aleef-benchmark-spec.md`.

## Status: NOT YET EVALUATED. No performance claims.

The held-out evaluation (Step 6) has not been run. Nothing in this log says how well Aleef finds flaws. The only numbers
below come from a rehearsal on the FIXED (flaw-free) bank, which can only show that the harness works and that Aleef does
not report a flaw where none exists.

## Scope (Milestone 1)

- Business-logic and authorization flaws in an API described by an OpenAPI document (ownership, role, authentication,
  maker-checker, idempotency, state-transition and race properties).
- Lab only. The target is a synthetic bank on a loopback listener. There is no UAT access and no production testing;
  production is refused by the engagement.
- No claim of real-bank readiness. A design-partner UAT run is required before any such statement.
- Wording: a finding is "new to Audspect" only after a human recorded `checked_none_found`. The product never says
  "zero-day".

## What the implementers knew

The implementers saw the property list in the visible spec (section 10) and never the trigger conditions of any seeded
defect. The sealed defect file (`orchestrator/internal/aleef/bank/sealed/sealed_defects.go`) and the ground-truth labels
(`labels.json`) are authored by the owner and are git-ignored; `TestOwnerOnlyFilesAreIgnoredAndUntracked` fails if either
becomes tracked. An import-graph test keeps the generator side from importing the benchmark side.

## Fixed-bank rehearsal (`go run ./cmd/aleef-bench -fixed-only`)

Last run on the final-fix head: 229 tests generated, 229 run; 221 clean; 2 rejected candidates; 6 unconfirmed; verified 0
(must be 0); cleanup PASS (no orphans, the bank holds no test objects).

- The 2 rejected candidates are P-OWN-2 on `POST /v2/payments/{id}/approve`. The attacker account is the approver role, whose
  approve call is legitimate for the control; the negative control ("a permitted request must succeed") failed, so the
  candidate was rejected, not verified.
- The 6 unconfirmed are P-OWN-3 on `POST /v2/beneficiaries`: the create returned 201 and the runner could not decide
  (status 201 is inconclusive evidence).
- The first rehearsal (252 run, 0 verified, 0 candidates) was INVALID: nothing could ever verify (the bank had no delete,
  so cleanup could not be assessed) and the fixtures were nominal (the lowest-id object of the owner was used for every
  operation). It was corrected by task 14a (resource-aware fixtures, typed existing objects, chained setup, created-object
  compensation). Do not cite 252/0.

## Evaluation (owner run)

To be filled by the owner after the held-out run. Nothing here is a result.

| Item | Value |
|---|---|
| Date / build | _pending_ |
| Vulnerable build: flaws verified (of 8) | _pending_ |
| Per-flaw result (property id, test id, verified / not) | _pending_ |
| Fixed build: verified findings (must be 0) | _pending_ |
| Controls (owner control, negative control) per verified finding | _pending_ |
| Three consecutive reproductions from fresh objects | _pending_ |
| Regression saved and replayable for each verified finding | _pending_ |
| Safety checks (no production, no unauthorised money movement, in-window, engaged origin) | _pending_ |
| Cleanup (orphans, bank object counts) | _pending_ |
| Reviewer note on prior knowledge ("new to Audspect" checks) | _pending_ |

6 of 8 is a prototype acceptance threshold, not proof of broad discovery capability.

## Known limitations

- P-OWN-2 approver-role refinement is not built: when the attacker is a role that may legitimately act on the object
  (the approver), the property cannot tell the legitimate call from the attack. Sole-attacker risk remains.
- Id aliasing: tests are generated on one fixture and verified on fresh ones, so server-assigned ids are translated.
  Only top-level string ids are translated; numeric ids and `\u`-escaped ids are not. A refusal feeds the guard's circuit
  breaker, so three in a row halt the campaign with a generic reason.
- Money and notifying operations: the simulated rail and the explicit operation id are enforced. Beneficiary and
  recipient VALUES in a request are not inspected in Milestone 1.
- The Guard matches hostnames, not resolved IP addresses. DNS rebinding is not addressed. Acceptable for the lab; it must
  be addressed before any UAT use.
- Run status is held in memory and persisted at the end; a run cut off by a restart or a shutdown timeout is marked
  `interrupted` and loses its final outcome and orphan list (objects it created may remain on the target).
- The console was verified only in a headless browser against a mocked API, not against a real licensed server.
- The full `internal/api` suite (about 32 minutes) was not rerun on the final head. On the base commit it has 3 failures
  not caused by this branch (two scenario/campaign signature failures in a worktree, one lingering-session TRUNCATE
  flake). Narrow Aleef, RBAC and licence tests pass.
- The race detector is unavailable on this host (`go test -race` needs cgo), so data-race checks were by design and test
  only.
- Existing engagements created before the engagement classes and token references were introduced classify nothing and
  allow no references; recreate them.

## Material deviations from the plan

- Licensing: Aleef is a separate add-on in the "special" category, granted only by the signed feature token
  `addon:aleef`; no tier includes it. A dev build with no licence refuses Aleef (fail closed).
- A third permission, `aleef:authorize` (admin only), creates engagements. The approver is the authenticated user, never a
  body value.
- The engagement carries the administrator's operation classes (the ceiling for a run) and the allowed token references.
  A run may keep or tighten a class, never loosen it; an unclassified operation never runs; setup and compensating
  operations are checked against the engagement's classification. The Guard also refuses any non-GET/HEAD/OPTIONS
  operation classed `read`. Added after the final review found that run-body classes could bypass the engagement.
- Id aliasing (campaign package) and a 14a fixture model (per-owner, per-resource-type objects, typed existing objects,
  chained setup) were added beyond the plan.
- The benchmark bank gained owner-only DELETE operations and an `ObjectCounts` accessor so cleanup can be assessed. They
  are bench-only and must never ship in a product build.
- Regressions are persisted as a Bundle at verification time (`aleef_regressions`); `export.Check` validates them; a
  verified finding without a regression is demoted and is never listed as verified.
- `MinReproductions = 3` is a floor.

## Post-hoc property additions

None so far. Any property added after seeing benchmark results must be recorded here as post-hoc.

## Owner steps for Step 6

1. Author `orchestrator/internal/aleef/bank/sealed/sealed_defects.go` (`//go:build aleefsealed`) and `labels.json`
   outside version control (both are git-ignored).
2. Build and run the held-out evaluation on the vulnerable and the fixed bank with the `aleefsealed` tag
   (see `cmd/aleef-bench` usage); keep the labels away from the generator.
3. Record the results in the Evaluation table above, with the per-flaw property and test ids.
4. Review each verified finding, record the prior-knowledge check (`checked_none_found`, `known_public`, `known_vendor`).
5. Decide the merge and the next milestone (UAT needs a design partner, DNS-rebinding hardening and a secret store).
