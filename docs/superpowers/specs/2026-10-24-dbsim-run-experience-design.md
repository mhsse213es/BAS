# Database Security Simulation: run experience, history and reports (design)

Status: APPROVED by the owner on 2026-10-24 (the owner replied "approve" to the document including the recommendations in section 8, which are therefore the working decisions: run permission = `CanRunScenario` for lab runs and Admin only for client mode; 24-hour identity-check validity as a configurable default; TLS opt-outs forbidden for client targets; Analysts read-only; DPAPI helper documented, not built). The plan starts with the dispatch spike in section 6.8. Nothing in this document is implemented yet. `dbsim_runs` is unchanged. Nothing is pushed.

## 1. Intent

An engineer should be able to answer one question from the console: "If someone attempts an unauthorized database action, will our controls stop them, will our monitoring catch them, and can we prove it?" The simulation engine (DB-01..DB-11, PostgreSQL and MySQL) is built and verified live in the lab. What is missing is the product around it: nothing can start a run, nothing shows results, and the registry's identity check cannot run. This design covers that missing product layer only.

## 2. Decisions already made by the owner

- **Lab first.** All eleven scenarios run against a disposable lab/test database after an explicit lab-scope confirmation (synthetic fixtures, bounded execution, verified cleanup).
- **Read-only pilot.** Production-like databases may run only the six read-only scenarios, only after an Admin enables client mode and the target's read-only identity check has passed. Off by default; enforced in the engine (already built), never only in the console.
- **Alert source.** Elastic Security is "supported" (proven live). Splunk, Sentinel and QRadar connectors are "experimental until a live run". Native logs, cloud logging and dedicated DAM tools are out of scope. An unreachable or insufficient source is shown as unverifiable, never as a miss.
- **Credentials.** The console registers a target and a credential reference only. The secret is set on the agent host (`BAS_DBCRED_<NAME>` or the agent's protected store) and is never entered into, stored by, or returned from the console or server.
- **Results page** ("layout A"): a summary row plus one row per scenario with three independent badges (prevention, detection, response) and an overall PASS/FAIL/ERROR/SKIPPED. Separate denominators: Prevention = blocked / prevention-assessable; Detection = caught / detection-assessable; Response = "not tested"; plus a count of scenarios unable to be assessed. A missing least-privilege policy is a prerequisite state ("unable to assess"), never a pass or fail. Remediation guidance appears only for an established failure and is worded conditionally unless the evidence names the exact grant or setting. "Allowed" is judged against the scenario's declared expectation, not assumed to be a failure.
- **Score.** The database simulation does not enter the overall security score in the first release. It has its own summary.
- **Open owner position:** the owner has NOT approved a separate run API and reporting lifecycle; they asked for the integration options to be compared from evidence first. This document is that comparison.

## 3. Goals, non-goals, anti-goals

Goals: an operator can register a target, validate it, choose scenarios, start a run, watch progress, and read an evidence-backed result, from the console. Runs are listed, retrievable and printable. No change to any other product's behaviour or scores.

Non-goals (first release): DB-12 (cross-system trust), mobile, DB-08's global-disablement mode, DB-11's controlled export, a Windows DPAPI provisioning CLI, MariaDB, merging dbsim into the overall score, global search over dbsim, a unified Reports-hub entry, an audit pack that includes database results.

Anti-goals (would make this a failure even if it works): any false pass (ERROR, SKIPPED or unverifiable counted as a pass); a second competing source of truth for results; any weakening of the agent's destructive-action gate (B5) or of any lab/client gate; any secret reaching the server; any dbsim run affecting `FleetRisk` or other aggregates.

## 4. What exists today (verified in the code)

- Engine, probes, grading, correlation: built and live-verified (Tasks 1-15). `dbbuild.BuildSteps` already produces agent steps (executor `dbprobe`) from a signed scenario and a target resolver; `dbrun.Evaluate` already grades each agent result.
- Registry, settings and permissions (Task 16): `dbsim_targets`, `dbsim_settings`, `/api/dbsim-targets...`, `/api/dbsim/settings/client-mode`, read-only `/api/dbsim-runs` and `/api/dbsim-runs/{id}`, RBAC rows, licence gate (Advanced and Enterprise). The identity-check endpoint answers 501: no runner is installed.
- **No run can be created.** `SaveDBSimRun` has no production caller; nothing dispatches `dbbuild` output to an agent; the identity-check runner is nil.
- `dbsim_runs`: one immutable row per (run_id, scenario_id), result PASS/FAIL/ERROR/SKIPPED, `report` JSON = `StoredReport` (per-scenario dimensions with five states, the result record, evidence). It has no status column.
- The platform has no single run model. The core `scenario_runs` table serves ATT&CK-style scenarios; each other product line (API BAS, phishing, email gateway, cloud, Kubernetes, network, kill chain) has its own table, endpoints and page. There is no cross-product run listing anywhere. The Reports hub is hard-wired to three kinds (posture, audit, compliance), all scoped to `scenario_runs` and an agent. `scenario_runs` has no product-line column, and `FleetRisk`, the audit pack and the report engine average or read all scored `scenario_runs`.

## 5. Options for history and reports

| Option | What it is | Touches | Migration | Risk to other products | Size |
|---|---|---|---|---|---|
| A. Own page and list (baseline) | New console page reads `/api/dbsim-runs` (list + detail) | One feature module, page markup | none | none | small |
| B. A + per-run report endpoint | `GET /api/dbsim-runs/{id}/report`, printable HTML in the style of the phishing run report | `reporting/dbsim_report.go`, one handler, route, RBAC/gate row | none | none (no shared surface) | small-medium |
| C. B + client-side merged "all runs" view | Merge `/api/scenarios/runs` and `/api/dbsim-runs` in one console module | merge function, one existing page if placed there | none | low | medium |
| D. Backend UNION endpoint, Reports-hub kind, search doc type | Shared-surface integration | new handler, `report_log` type, hub selector, search builders | `report_log` handling | moderate (shared surfaces) | large |
| E. Write dbsim runs into `scenario_runs` | "First-class" in the core pipeline | schema decision, every consumer | yes | HIGH: pollutes `FleetRisk`; occupies the one-running-run-per-agent slot; reaper and pause/cancel treat it as a normal run; schema cannot hold per-dimension grades or evidence | large |

Findings that decide this:
1. The established pattern is a product-owned store, endpoints and page. A cross-product feed does not exist to plug into, so "integrate" means building a new feed, not joining an old one.
2. `dbsim_runs` is the single store. A dedicated page is a view of that store, so there is nothing to reconcile later. This satisfies the owner's rule that the page must not be a parallel store.
3. `scenario_runs` cannot represent the results faithfully and is read by about 35 files including the overall score. Option E is rejected.
4. `StoredReport` carries every dimension, reason and evidence item; a per-product report can render them without loss provided `not_expected`, `skipped` and `unverifiable` render as themselves (the phishing builder drops "not applicable" dimensions and must not be copied blindly).

**Recommendation: A, then B, in the first release. C when users ask for one chronological feed. D only on an explicit product requirement.** Option E is not recommended.

## 6. The run flow (needed under any option)

Precedents exist: the core pipeline dispatches a signed `command_scenario` message to an agent and the agent posts results to `POST /api/scenarios/result`; server-side executors (phishing, email gateway) use their own trigger, poller and recovery.

Recommended design (dbsim-owned, following the core path for dispatch because the agent is the executor):

1. **Trigger:** `POST /api/dbsim-runs` with target id, scenario ids, mode and (lab) the confirmation. Permission: a new Admin-or-operator permission (see section 8). The server resolves the target through the existing resolver, runs `Authorize` (lab/client gates, licence), builds steps with `dbbuild.BuildSteps`, and refuses if the target's check has not passed (client mode) or lab confirmation is missing (lab mode).
2. **Pending-run record:** a new table `dbsim_run_jobs` (run id, target id, agent id, mode, scenario ids, status `pending|running|completed|failed|partial|cancelled`, created/started/deadline, actor). `dbsim_runs` stays terminal-only and unchanged.
3. **Dispatch:** send `command_scenario` to the target's bound agent through the existing hub. **No `scenario_runs` row is created**, so the score, the reaper, the per-agent run limit and every aggregate are untouched.
4. **Ingest:** in `SubmitScenarioResult`, an unknown run id is today a deliberate no-op accept. Add a lookup of `dbsim_run_jobs` before that no-op; if the run id belongs to a dbsim job, hand the result to a dbsim ingest function (`dbrun.Evaluate`, then `SaveDBSimRun`, then job status update) and return. Existing behaviour for every other run id is unchanged. This hook sits on a shared hot path, so it needs explicit regression tests and is reviewed first.
5. **Lifecycle:** a dbsim reaper (same WHERE-guarded style as `ReapNeverStartedRuns` / `ReapAbandonedRuns`) moves jobs past their deadline to `failed` (never started) or `partial` (agent went offline). A cancel route sends `command_cancel`. Cleanup of fixtures remains the agent's verified-cleanup responsibility; an unverified cleanup is already graded ERROR as a safety incident.
6. **Identity check:** the same dispatch mechanism runs the existing `check_readonly_identity` probe for a target and records the result through the existing audited, version-bound store call. This installs the missing `CheckRunner` and ends the 501.
7. **Agent binding:** a target must name the agent that sits next to the database and resolves its credential reference (new field `agent_id` on the target; registration validates the agent exists).

### 6.8 Answers established after the builder check (verified in code unless marked as a call)

- **Signing (verified).** `hub.SendToAgent` signs every `command_scenario` message with a command envelope generically. dbsim dispatch needs no signing code of its own. The signed scenario `.sig` gate applies to the scenario file at load time and is unchanged.
- **Progress events (verified).** The agent posts step events to `POST /api/scenarios/events`; the handler inserts into `run_events` (primary key `(run_id, seq)`, no foreign key to `scenario_runs`), its `UPDATE scenario_runs` matches nothing for a dbsim run id, and events are relayed live to browsers. Live per-scenario progress is therefore feasible without a `scenario_runs` row.
- **Not yet proven (spike first).** Any agent-side or hub-side assumption that a `scenario_runs` row exists for a `command_scenario` run (agent run-limit bookkeeping, result-MAC and agent-id checks, `ExecutionAttempt` records). The first task of the plan is a thin spike: dispatch one lab scenario with no `scenario_runs` row and confirm on staging that the agent runs it, events flow and the result reaches the ingest hook. If the spike fails, the fallback is a dedicated dbsim command type and result route (more agent code), and the plan is revised before anything else is built.
- **What the agent receives (call).** The command carries the resolved target description (engine, host, port, database name, TLS setting, credential reference, expected identity) inside the signed steps, as `dbbuild.BuildSteps` already produces. Only the secret stays on the agent host.
- **Agent binding (call).** `agent_id` is required on a target and validated at registration. Changing the agent, host, port, database, TLS setting, credential reference or expected identity invalidates the passed identity check (extending the existing record-version binding).
- **Mode comes from the target, not the run (call; corrects section 6.1).** A target is registered as `lab` or `client`. A run uses the target's mode, so a lab-mode run can never be started against a client target and the reverse. The lab confirmation is a typed target name plus actor and time, stored on the job.
- **Grain (call).** One command per run carries all selected scenarios; the agent returns results for the run; ingest grades each scenario and writes one `dbsim_runs` row per scenario. The job is `completed` when every selected scenario has a row, `partial` if the agent reported partial or the deadline passed with some rows, `failed` if none. A duplicate result is ignored (the existing unique key and `ErrDBSimRunDuplicate` make this safe).
- **Concurrency (call).** At most one active dbsim job per target and per agent (409 otherwise). Overlap with a normal scenario run on the same agent is governed by the agent's own run handling; the spike confirms the behaviour.
- **Permissions (call).** Cancel uses the same permission as starting a run. The identity check is Admin-only. The report endpoint and report page use the same licence gate and read permission as the run list.
- **Deadlines (call).** Job deadline = 90 seconds per selected scenario + 120 seconds, configurable (staging lab scenarios took about 25 seconds each including the detection window).

## 7. Console

One feature module (pure view/describe functions that are unit-tested in Node, like the phishing run view), one page section and nav entry, ACTIONS entries, and test baselines (smoke, visual, integrity manifest). Screens: landing/explainer, targets (register with credential-reference field only, validate, status with last check time and result), test selection (safe-for-environment vs lab-only vs unsupported, clearly marked), run progress (per-scenario states: queued, running, collecting evidence, correlating, done; alert-source-unavailable and inconclusive shown distinctly), results (layout A with the denominators in section 2), scenario detail (what was simulated, what the database did, what monitoring saw with timestamps, which dimension failed, conditional remediation), report link (option B). The console cannot be built or visually checked on the current host (the build uses Node in Docker), so UI correctness must be verified on a Docker-capable host before any claim.

## 8. Decisions that are the owner's (carried from the review of Task 16)

1. Which permission starts a run (Admin only, or a new operator permission)? Recommendation: reuse the existing run permission used by phishing and email-gateway triggers (`CanRunScenario`) for lab runs; keep client-mode runs Admin-only.
2. Identity-check validity period (placeholder 24 hours).
3. TLS opt-outs for client-mode targets (recommendation: forbid).
4. Whether Analysts may read targets and results (currently yes, read-only; credential references are names, not secrets).
5. Agent binding per target (section 6.7): confirm.
6. Windows DPAPI provisioning helper: build now or document manual steps (recommendation: document for the first release).

## 9. Constraints

Engine gates, B5, client-mode layers and the import-cycle rules are unchanged. The Elastic alert-source option stays opt-in. Reads are licence-gated by the existing `/api/dbsim*` prefixes. No secret reaches the server. The new ingest hook must not change behaviour for any run id that is not a dbsim job.

## 10. Verification and honesty

Pure Go builders, mappers, the ingest function (with a fake store) and the reaper decision logic get unit tests runnable on any host. Handler, store and RBAC-matrix tests need a Docker-capable host and must be listed with exact commands in every report. A staging E2E run of one lab scenario through the new trigger-to-result path on PostgreSQL and MySQL is required before the feature is described as working; the console needs a browser check. Until then the documentation says exactly what was and was not run, as the QA log already does.

## 11. Left to the builder

File layout inside the existing packages; the exact status/deadline defaults for `dbsim_run_jobs`; HTML/CSS of the report within the phishing report style; progress polling interval; copy for the guided first run and the fixed remediation text per scenario (each must be reviewed by the owner before release).
