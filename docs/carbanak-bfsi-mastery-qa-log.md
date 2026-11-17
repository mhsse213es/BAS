# Carbanak BFSI pack: QA log

Status: **structural verification only. No lab run has been performed.** Every
result below comes from `go test` or `verify-all`. The lab tables at the end are
blank until a run on a lab host.

Spec: `docs/superpowers/specs/2026-11-17-carbanak-bfsi-expansion-design.md`.
Plan: `docs/superpowers/plans/2026-11-17-carbanak-bfsi-expansion.md`.
Mapping: `docs/carbanak-mapping-register.md`.
Runbook: `docs/carbanak-bfsi-lab-runbook.md`.

## What was built

| Area | Files |
|---|---|
| Chain (stages 1–7, 8a–8g, 10–18, 19–22, 29–32) | `scenarios/carbanak-kill-chain.yaml` |
| Item 9 (standalone) | `scenarios/carbanak-bfsi-app-discovery.yaml` |
| Items 23–28 (standalone, fresh state) | `scenarios/carbanak-bfsi-{beneficiary-creation,amount-manipulation,unauthorized-approval,session-misuse,off-hours-transfer,limit-modification}.yaml` |
| Ledger rules, audit log, API, command | `orchestrator/internal/carbanakledger/`, `orchestrator/cmd/carbanak-ledger-sim/` |
| Fraud verdict and marker | `orchestrator/internal/scenario/fraud_control.go`, `orchestrator/internal/models/fraud_verdict.go` |
| Scorer and compliance fold | `orchestrator/internal/models/score.go`, `orchestrator/internal/compliance/mapper.go` |

Scenario count: **159** (`product_line_test.go`), up from the branch base of 152
by the 7 new files. The count was re-read at Task 14 before it was set.

## Structural results

| Check | Result |
|---|---|
| `go build ./...` | OK |
| `go vet` on changed packages | OK |
| `signer.go verify-all ../scenarios` | ok=195 fail=0 (at Task 12; re-run at Task 14 close) |
| `TestCarbanak*`, `TestFraud*`, `TestInterpret*`, `TestFSThreat*`, `TestStepContract*` | pass |
| `internal/carbanakledger` | pass (rules, audit chain, tamper detection, restart, HTTP API, loopback refusal, port-in-use) |
| `internal/models`, `internal/compliance`, `internal/reporting` | pass |
| Full `internal/scenario/...` and `carbanakledger/...` | see Task 14 entry in the progress ledger |

Negative-path tests that matter most:
- A spoofed `host` field in a request body is ignored; the caller host comes from the connection.
- A tampered audit row is detected at the first bad index.
- A non-loopback bind is refused without the override and a lab hostname.
- An endpoint PASS with a fraud FAIL scores as failed, not as resisted.
- A fraud SKIPPED never counts as tested.

## Rulings made during the build

These are also in the progress ledger with their cost if wrong.

1. **Ledger config is JSON, not YAML.** Avoids adding a parser dependency to the lab tool.
2. **Sessions are created even when flagged.** Only a bad credential refuses one.
3. **Alerts list every non-approved decision.** Rejections and flags both count as control firings.
4. **Non-loopback binding needs two things:** the env override and a `lab_hostname` ending `.test`, `.invalid` or `.lab`.
5. **Fraud record lives on `SimulationResult.FraudControl`,** attached in `Interpret()`. The plan named `outcome.go`, which only classifies execution.
6. **Evidence-only steps (8a) are SKIPPED,** not scored as control tests.
7. **Item 17 (T1558.003, SPN enumeration) kept** at its validated-with-caveat status. You asked to continue without stopping; setspn is the documented precursor.
8. **Stage 18 uses T1552.001,** the register value, not the plan's T1552.
9. **Stage 32 exfil posts to the Stage 7 channel host `192.0.2.1`,** not the plan's `.invalid` domain. The register caveat requires reusing the existing C2 channel, and the non-routable host keeps the safety property.
10. **Gap steps are five, not two.** Chain steps 8b, 8f and 8g are `no_clean_attack_technique`. 8f and 8g are verification steps with no ATT&CK technique. Register rows were added for them.
11. **Item 26 (session misuse) is gated** on `BAS_CARBANAK_LEDGER_REPLAY_URL` and SKIPs otherwise. A host mismatch is only detectable from a second host.
12. **Items 24 and 27 use the ledger's own flag rules.** The scenario submits and reports; the ledger decides.
13. **Fraud verdict is stored in the result.** `Interpret` folds the fraud verdict into `Result`, so every reader sees it. Results stored before the fix are folded by `cmd/fraudverdictbackfill`.
14. **No detection-profile wiring rows.** No new stage names a detection profile, so the plan's wiring condition selects none.

## Open items

- **Lab validation.** No stage has run against a lab target or the ledger. Every EXEC path, SKIP path and fraud marker is unverified at runtime.
- **Staging backfill.** Run on staging, 2026-11-17. 268 `scenario_runs` rows, none with a fraud record: the Carbanak fraud steps have not run there yet, so the dry run and apply both changed 0 rows. Backup taken: `/tmp/scenario_runs-before-fraudverdict-20261117-120335.sql` on staging (11.6 MB).
- **Item 26 on a single-host lab** never runs.
- **Stages 19–22** need a target host. Without one they SKIP.
- **APT29 Phase 7 reconciliation** with the other session's APT29 files is still future work, by user decision.
- **Push** of the local commits to main is not authorized.

## Lab results

| Stage / item | Run date | Host | Endpoint | Fraud | Combined | Notes |
|---|---|---|---|---|---|---|
|  |  |  |  |  |  |  |
