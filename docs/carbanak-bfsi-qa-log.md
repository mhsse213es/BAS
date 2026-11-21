# Carbanak BFSI Expansion — QA Log

Plan: `docs/superpowers/plans/2026-11-17-carbanak-bfsi-expansion.md`. Spec: `docs/superpowers/specs/2026-11-17-carbanak-bfsi-expansion-design.md`.
Branch: `feat/carbanak-bfsi-expansion`. Date: 2026-11-21.

## Results by task

| Task | Scope | Result |
|---|---|---|
| 0 | Reconcile spec with repo; Stage 8 description; 24–27 ruling | Done. Test `TestCarbanakDescriptionHasNoDecoyWording` failed first, then passed. Kill chain re-signed. |
| 1 | Scenarios 10–15, 17, 18 | Done. `TestCarbanakBFSITask1Scenarios` failed first (files missing), then passed. |
| 2 | Scenarios 19–22 (second-host gate) | Done. `TestCarbanakBFSITask2Scenarios` failed first, then passed. |
| 3 | Scenarios 29–32 | Done. `TestCarbanakBFSITask3Scenarios` failed first, then passed. Scenario 32 remapped T1041 → T1567. |
| 4 | Acceptance criteria 8 and 9 | Done. Criterion 9 test failed on 8f → ruling recorded. Criterion 8 locks existing behaviour. |
| 5 | Ratchet, ledger, baseline, full suite | Done (this log). |
| 6 | Lab validation | **Not started. Needs the lab.** |

## Task 5 detail

- Ratchet (`TestStepContract_Ratchet`) run before regeneration: passed. New files must have zero cleanup, detection and telemetry gaps; the 16 new scenarios have none.
- `STEP_CONTRACT_WRITE=1` regeneration: baseline 219 files; ledger 1119 entries (was 1103; +16 new steps).
- Baseline diff: 311 lines added, 2 removed. The 2 removals are improvements already on main (`endpoint-mastery/em-04` and `em-05` detection gap 1 → 0). The ratchet allows falls.
- Full suite: `go test ./internal/scenario/...` — **ok** (335.9 s), exit 0.
- Signatures: `signer.go verify-all` reported `ok=290 fail=0` after Task 3; no scenario edits since.

## Rulings made during the build

1. **24–27 mapping status:** validated with caveat; no `mapping: proposed` marker (spec, Task 0).
2. **Scenario 32 technique:** T1041 → T1567. T1041 requires an existing C2 channel, which the scenario does not have.
3. **Scenario 8f exempt from shared run state:** `/audit/verify` checks the whole chain, not one run.
4. **Scenario 18 technique:** parent T1552. T1552.001 (Credentials In Files) is the likely refinement; not yet confirmed against its page.
5. **Scenario 21 caveat:** exercises service creation (T1569.002), not payload execution. The service is never started.

## Known gaps and open items

- Lab validation (Task 6) has not run. Scenarios 19–22 need `BAS_CARBANAK_TARGET_HOST`.
- Scenario 29 is validated with a caveat: it collects only its own synthetic files.
- Acceptance criteria 1–5, 6–7, 10 and 11a are covered by existing tests listed in the Task 4 commit (`ba489e35`).

## Not verified here

- No scenario has run on a Windows host. Every result above is static (tests, signatures, ratchet).
- The ledger service was not started against the new scenarios.
