# Segmentation Phase 2 — QA Log (API, database, console)

Plan: `docs/superpowers/plans/2026-11-11-segmentation-phase2-api-ui.md`. Scope approved 2026-11-11: API to start a pack and read results (admin runs, analyst reads), Postgres tables for runs and per-probe verdicts, and a console page with the per-probe verdict table.

## Verified on the build host (Windows)

| Area | Check | Result |
|---|---|---|
| Permissions | `TestSegmentationPermissionMatrix` (admin runs and reads; analyst reads only; viewer neither) | PASS |
| Schema | `TestEnsureSegmentationSchema_IdempotentAndCreatesTables` against a real Postgres, applied twice | PASS |
| Run store | `TestStore_RoundTripKeepsVerdictsAndOrder`, `TestStore_GetUnknownRunIsNotFound`, `TestStore_FailStaleClearsInterruptedRuns` against a real Postgres | PASS |
| Pack registry | `TestLookupPack_UnknownIDRejected`, `TestLookupPack_RegisteredPacksResolve` | PASS |
| Rules applier | `TestApplyRules_RejectsUnregisteredFileWithoutExecuting`, `TestApplyRules_RunsRegisteredFileInFirewallContainer` | PASS |
| Service | happy path (three passes stored, nine rows for a three-probe pack), busy refusal, rules failure (no results stored), unknown pack (no run row), row mapping | PASS |
| API handlers | packs listed for analyst with `can_run` false, analyst and viewer refused, admin run then analyst reads stored verdicts, unknown pack 400, busy 409, disabled 503, missing or malformed run ID 404 | PASS (real Postgres) |
| RBAC | `TestRBACMatrix_NoDrift`, `TestRBACMatrix_AuthorizationBoundary`, `TestRBACMatrix_MethodConfusion`, `TestPlatformAdminRoutes_Gating` with the four segmentation routes in the matrix | PASS |
| Server build | `go build ./cmd/server` and `go vet` on the changed packages | OK |
| Console | `node --check` on edited modules; `eslint src`: 0 errors (warnings are the project's `innerHTML` rule, same as every feature); `node --test tests/unit/*.test.mjs`: 777 pass, 0 fail | PASS |

## Design decisions recorded
- Pack IDs select fixed scenario and rules files from a registry. Client input is never a path. `ApplyRules` refuses any name outside the registry, and the test proves nothing executes for a refused name.
- One run at a time. Runs share the lab's firewall rules, so a second run is refused (409), not queued.
- A run is audited (`segmentation.run.request`) before anything starts. If that audit row cannot be written, the request fails with 500 and no traffic is sent.
- A probe graded ERROR is a stored verdict; the run still completes. Only infrastructure faults (rules, scenario, storage) mark a run `failed`.
- On server start, runs left `queued` or `running` by a previous process are marked failed, so a crash cannot leave the lab locked.
- The lab is disabled unless `SEGMENTATION_LAB_DIR` is set. The packs endpoint still answers, with `enabled: false`, so the console can explain why.
- `can_run` is computed server-side from the caller's permission. The server enforces the run route regardless.

## Process gaps (recorded, not hidden)
- The schema, run store, service, and API handler tests were written in the same step as their implementation, so the red run was not observed for them. Build failure was observed for the permission, pack registry, and rules applier tests.
- `go test -race` could not run on this host (cgo unavailable). The service's goroutine is not race-checked.

## Not verified yet
- Live on staging: the staging orchestrator has not been deployed with this code, so the API has not been exercised against the lab there. This needs a deploy to staging, which was not done without approval.
- Browser render of the new page. The console has only been checked by syntax, lint, and the unit suite.
- Full `internal/api` package run (about 22 minutes; see the entry below).

## Full package run
(see entry added after the run completes)
