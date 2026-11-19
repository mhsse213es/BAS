# Segmentation Phase 2: API, Database and Console

> Approved scope (user, 2026-11-11): build all three recommended parts. (a) API to start a scenario pack and read its results, (b) Postgres tables for runs and per-probe verdicts, (c) a console page with the per-probe verdict table. Running is admin-only. Analysts can read.

**Spec:** `docs/superpowers/specs/2026-11-11-bfsi-segmentation-lab-design.md` (Phase 1 doc; Phase 2 is named there as "API, database or UI integration").
**Phase 1 (done):** `internal/segprobe` verdict engine, executor, Docker provider, and the lab on staging. Gates G1–G6 pass live.

## Global constraints
- Only pack IDs from an allowlist can run: `swift-isolation`, `cde-atm-isolation`, `core-banking-tiering`. Client input never becomes a file path or a rules file name.
- One run at a time. The lab's firewall rules are shared state; a second run must be refused, not queued.
- The lab is disabled unless `SEGMENTATION_LAB_DIR` is set. When disabled, run endpoints return 503 and the console says so.
- Verdicts are stored exactly as produced. The API never recomputes or softens them.
- All output shown in the console is escaped.
- Phase 3 (customer networks) is out of scope.

## Tasks

### Task 1: Permissions
- `CanRunSegmentation` (`segmentation:runs:run`): Admin only.
- `CanViewSegmentation` (`segmentation:runs:view`): Analyst and Admin. Viewer has neither.
- Test: role matrix in `internal/auth`.

### Task 2: Schema
- `db.EnsureSegmentationSchema`: `segmentation_runs` (id, pack_id, requested_by, status, runs, stable, failure_reason, created_at, started_at, finished_at) and `segmentation_probe_results` (run_id, run_index, probe_id, src, dst, dst_port, proto, expect, verdict, reason, outcome, started_at, ended_at, rule_ids jsonb). Idempotent `CREATE TABLE IF NOT EXISTS`.
- Test: against `testutil.NewTestDB`, applying twice succeeds and the tables exist.

### Task 3: Run store
- `internal/segprobe/runstore`: `Create`, `SetRunning`, `SaveProbeResults` (one transaction per run index), `Finish(status, stable, failure)`, `List`, `Get`.
- Test: round trip against the real database, including `Get` returning results in order.

### Task 4: Rules applier and pack registry
- `DockerProvider.ApplyRules(ctx, file)` runs `apply.sh` in `seg-fw` with a fixed file name taken from the registry.
- `internal/segprobe/packs.go`: registry maps pack ID → scenario file, rules file, description. Unknown ID is an error.
- Test: unknown pack rejected; each registered pack's scenario loads with `LoadScenario`.

### Task 5: Service
- `internal/segprobe/service.go`: `Submit(ctx, packID, requestedBy)` validates the pack, refuses when a run is active (single-flight), creates the run row, and starts a background goroutine: apply rules, `RunRepeated(3)`, save results, finish. Failure at any step marks the run `failed` with the reason.
- The store is an interface so the service is unit-tested with a fake store and fake provider.
- Test: happy path persists 3 runs; second submit while active returns `ErrBusy`; an apply-rules failure yields `failed` and no results saved for that run.

### Task 6: API
- `GET /api/segmentation/packs` (view), `GET /api/segmentation/runs` (view), `GET /api/segmentation/runs/{id}` (view), `POST /api/segmentation/runs` (run; body `{"pack":"..."}`; 202 with the run; 409 when busy; 503 when disabled).
- Test: httptest for each status code and for the permission gate.

### Task 7: Wiring
- `routes.go` registration; `cmd/server/main.go` calls `EnsureSegmentationSchema` and builds the service only when `SEGMENTATION_LAB_DIR` is set.

### Task 8: Console
- `web/src/features/segmentation.js`: pack list, run button (admin only), run history, per-probe verdict table with reasons. Nav item, tab, `showTab` entry, title, and nav group in `index.html`, `shell.js`, `shell-ui.js`.
- Test: `node --check` and the existing web lint and unit tests pass.

### Task 9: Live verification and QA log
- Staging: run each pack through the API; confirm the stored results match the CLI tables from Phase 1.
- `docs/segmentation-phase2-qa-log.md` records the commands and outputs.

## Deferred
- Phase 3: customer-network probes.
- Rule-to-pack enforcement (Phase 1 ruling: rule name is shown in each verdict).
