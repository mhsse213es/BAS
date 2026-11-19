# dbsim run dispatch spike: findings

Runbook: `docs/dbsim-run-spike-runbook.md`. Spike code: build tag `dbsim_spike`, lab only, Admin only.
Staging orchestrator ran the tagged image `bas-orchestrator:dbsim-spike` (id `27e4fc1399f0`) with `1.9.9.4` tag. The live image `1.9.9.4-live` (id `ed54bc7218d4`) is kept for rollback.

## Results

| # | Check | Result | Evidence |
|---|-------|--------|----------|
| 1 | Steps run with no `scenario_runs` row | PASS | 0 rows for every spike run id, PostgreSQL and MySQL |
| 2 | Probe result present on every step | PASS | `dbProbePresent=true` on all steps |
| 3 | Step events reached `run_events` | PASS | run_started, queued, started, completed, run_completed (5 events for 1 step, 8 for 2 steps) |
| 4 | Events reached the browser relay | PASS | A browser websocket listener on `/ws/browser` received `run_event` frames for spike run `spike-c1700f4db873415d` (run_started, queued) |
| 5 | Result MAC check passed | PASS | 0 `result MAC verification FAILED` lines |
| 6 | Agent-id check | PASS | `agentCheck=match` on every run |
| 7 | Agent run-limit and bookkeeping | PASS (agent side) | No run-limit or attempt errors in the agent journal. No `execution_attempts` rows are written for spike runs (see gaps) |
| 8 | Agent posts to detections and host-events do not break the run | Not checked | |
| 9 | Concurrency on the same agent | ANSWERED FOR NORMAL RUNS; spike path NOT TESTED | Two normal posture runs were sent together: the second was refused by the orchestrator with `agent busy`, so the agent never cancelled anything. The spike path skips that check and was never run against a busy agent. The production dbsim path is guarded by the busy check (`TestStartRefusesWhenAgentRunsANormalScenarioFailClosed`). Information only per runbook |
| 10 | DB-01 and DB-05 on PostgreSQL | PASS | Both steps exit 0, rows read, audit `found` |
| 11 | DB-01 and DB-05 on MySQL | PASS | DB-01 clean after the lab table repair (audit `found`). DB-05 ran before the repair with audit `error` |
| 12 | Elapsed time | PASS | 132 ms to 1.2 s per run |
| 13 | Unexpected errors | PASS after repair | Before repair: `Table 'general_log' is marked as crashed` on MySQL audit. Repaired on the lab MySQL (`REPAIR TABLE mysql.general_log`, status OK, one warning for a row with an empty timestamp at row 103160, kept) |

## Gaps for the production design

- **No `execution_attempts` rows** are written for spike runs. The real run path must create and settle them.
- **No `scenario_runs` rows.** That is intended for the spike. The production path will write them through the real run record.
- **MySQL audit depends on the `general_log` table**, which can be marked crashed. The production audit collector should report this as a finding, not swallow it.
- **Concurrency:** the orchestrator refuses a second normal run on a busy agent. The spike path bypasses that check, so spike-plus-normal-run behaviour on the agent is still unverified. The production path must keep the busy check.

## Open issues

- `tamper_detected` on `cis-ubuntu-l1`: the orchestrator refused a normal run on the agent. The agent was re-trusted (state `active`, `binaryTrusted: true`), but its version now reads `None`. The cause is not yet established, and it needs to be understood before a normal run can be tested on this agent.
- The agent config file was rewritten by the agent at 06:06:35, which removed the DB credential lines. Credentials now load from `/etc/bas-agent/dbsim.env` through a systemd drop-in.
- The agent is labelled `Production` but is the lab host.

## Decision

Rows 1 to 7, 10 to 13 pass. Row 9 is information only, per the runbook: answered for normal runs, spike path not tested. Recorded as **PROCEED**. Carried forward: the spike-plus-normal-run agent behaviour, and the `tamper_detected` cause (resolved by restoring the live image, not root-caused).

Done: spike endpoint and stub removed from the worktree (build and DBSim API tests pass); staging console restored to the live image `1.9.9.4` (`ed54bc7218d4`). The spike image `dbsim-spike` stays on staging for rollback reference. Not committed: this doc and the spike removal, pending approval.

## Re-verification required through the product path

The spike bypassed the real run path. Every item below must be re-proven on staging through the product run API (Task 6 onward), not the spike endpoint. Until then the spike results are evidence for the dispatch design only, not for the feature.

| Spike shortcut | What the product path must show |
|----------------|---------------------------------|
| Dispatch with no `scenario_runs` row | A real run creates its `scenario_runs` row, and the dbsim job links to it |
| No `execution_attempts` rows | Every dbsim step creates and settles an `execution_attempts` row (completed, failed or timed out) |
| No busy check (`agent busy` refusal skipped) | A dbsim start is refused with 409 when the agent or target is busy, and the refusal is audited |
| Results not graded | Results are graded by `dbjobs` Ingest from the stored plan, and a verdict row is written per scenario |
| Relay shown only with the spike id | Live run events reach the console panel for the real run id |
| MySQL audit checked by hand | The audit status is recorded in the report, and `general_log` errors appear as findings, not silent gaps |
| Lab repair done by hand | Any lab-side repair is a documented runbook step, not an undocumented fix |
| Credentials in a systemd drop-in | The product path must read credentials only from the agent's own environment, never from the orchestrator |

Acceptance: each row above is shown with a real run id on staging, with the evidence (DB rows, events, log lines) recorded in this doc.
