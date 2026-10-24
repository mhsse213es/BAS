# dbsim dispatch spike: staging runbook (TEMPORARY)

Purpose: prove that a `command_scenario` can be dispatched to an agent with NO
`scenario_runs` row, that step events arrive, and that the result reaches a hook
after the result-MAC check. The decision (PROCEED or FALLBACK) is recorded in
`docs/dbsim-run-spike-findings.md`. The spike code is build-tagged
`dbsim_spike`, lab only, Admin only, and is deleted afterwards. It must never be
merged or released.

Spike files (branch `worktree-dbsim`, one commit "spike(dbsim): TEMPORARY ..."):
`orchestrator/internal/api/dbsim_spike.go` (tagged), `dbsim_spike_stub.go`
(untagged no-op stubs), plus one call line each in `routes.go` and
`handlers.go` (`SubmitScenarioResult`).

## 0. Preconditions

* Staging lab is up (PostgreSQL on 55432 and MySQL on 53306 per `lab/dbsim/E2E.md`).
* A BAS agent is enrolled and online on a host that can reach the lab database,
  with the credential env vars set for that agent service
  (`BAS_DBCRED_LAB_PG_LAB`, `BAS_DBCRED_LAB_PG_RO`, `BAS_DBCRED_LAB_MY_LAB`,
  `BAS_DBCRED_LAB_MY_RO`; each value `{"user":"...","password":"..."}`).
* For DB-05 (fixture scenario) the agent service also needs
  `BAS_DBPROBE_LAB_MUTATION_ALLOWED=true`. DB-01 needs nothing extra.
* The route `/api/dbsim-spike/run` is NOT licence-gated (`productForPath` in
  `product_gate.go` matches only `/api/dbsim` or `/api/dbsim/...`, not
  `/api/dbsim-spike`). It is protected by Admin-only permission and exists only
  in a binary built with `-tags dbsim_spike`.
* You can log in as an Admin.

## 1. Build the orchestrator with the tag

Quick compile check anywhere (no Docker needed):

```
cd orchestrator
go build -tags dbsim_spike ./...
```

For the staging image, on the staging checkout ONLY (do not commit this edit),
add the tag to the `garble -literals build` command in `orchestrator/Dockerfile`
(CONFIRM its location with `grep -n "garble -literals build" orchestrator/Dockerfile`
before editing; do not rely on a line number):

```
garble -literals -tags dbsim_spike build \
```

then rebuild and redeploy through the normal installer path (never raw
`docker compose`; use `install.sh`). To revert afterwards: `git checkout --
orchestrator/Dockerfile` (that single file) and redeploy.

Confirm the tagged build is running: the dispatch log line below only appears
with the tag; without it `POST /api/dbsim-spike/run` returns 404.

## 2. Log in and get an Admin token

```
BASE=https://192.168.10.78:9443        # staging
TOKEN=$(curl -sk -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' \
  -d '{"username":"<admin user>","password":"<admin password>"}' | jq -r '.token')
```

If the login response has no `token` field, log in once in the browser and use
`-b 'bas_session=...'`/the cookie instead; the API accepts either the HttpOnly
cookie or `Authorization: Bearer <token>`.

## 3. Find the agent id

```
curl -sk "$BASE/api/agents" -H "Authorization: Bearer $TOKEN" | jq '.[] | {agentId, hostname, status}'
```

Use the `agentId` of the agent that sits next to the lab database
(`AGENT=<id>`). Field names may differ slightly; use the id the console shows.

## 4. Trigger the spike

No target registry rows are needed: the target is given inline in the body.
`mode` must be `"lab"` (anything else is refused). The scenario file names its
target `lab-db`; the spike answers whatever id the scenario asks for with this
one inline target.

**WARNING: `target.host` MUST be the lab database.** The agent will present the
agent-held credential to whatever host you name; a mistyped host sends a lab
credential to a non-lab machine. The spike refuses (400) a `credentialRef` that
does not start with `dbcred:lab-` (the lab refs are `dbcred:lab-pg-lab`,
`dbcred:lab-pg-ro`, `dbcred:lab-my-lab`, `dbcred:lab-my-ro`, per
`lab/dbsim/E2E.md`) and a blank `expectedIdentity`. Double-check host and port
before sending.

PostgreSQL, DB-01 (read-only; run this first):

```
curl -sk -X POST "$BASE/api/dbsim-spike/run" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
    "agentId": "'"$AGENT"'",
    "scenarioId": "dbsim-db01-auth-policy",
    "target": {
      "engine": "postgresql", "host": "<lab db host as the agent sees it>", "port": 55432,
      "database": "dbsim", "tlsMode": "disable",
      "credentialRef": "dbcred:lab-pg-lab",
      "expectedIdentity": "<SELECT system_identifier FROM pg_control_system()>",
      "mode": "lab"
    }
  }'
```

Expected response: `{"runId":"spike-<16 hex>","scenarioId":"...","agentId":"...","steps":N}`.
Save the run id: `RUN=spike-...`.

Repeat with:
* `dbsim-db05-suspicious-read` on PostgreSQL (fixture scenario; agent needs the mutation allowance).
* MySQL: `"engine":"mysql"`, `"port":53306`, `"credentialRef":"dbcred:lab-my-lab"`,
  `"expectedIdentity":"<SELECT @@server_uuid>"`, for DB-01 and DB-05.

Error responses: 400 with a redacted builder message (target or scenario
invalid), 403 not Admin, 404 scenario unknown, 409 agent offline.

## 5. What to look at

### 5.1 Orchestrator log

```
docker logs <orchestrator container> 2>&1 | grep -E 'dbsim-spike|\[events\]|\[perf\]|result MAC|agent mismatch'
```

Expected lines:

* `[dbsim-spike] dispatched run=spike-... scenario=... agent=... steps=N (no scenario_runs row)`
* `[dbsim-spike] RESULT run=spike-... ... agentCheck=match results=N expectedSteps=N partial=false elapsed=...`
* `[dbsim-spike]   step i task=... exit=... dbProbePresent=true denied=... rowsRead=... errorClass="" auditStatus="..."` per step (a failing step also logs `stderr(first 200, redacted)`)
* NO `result MAC verification FAILED`, NO `[events] ingest run ...` errors, NO `agent mismatch`.

### 5.2 Database

```
SELECT type, seq FROM run_events WHERE run_id = '<runId>' ORDER BY seq;
SELECT count(*) FROM scenario_runs WHERE id = '<runId>';      -- must be 0
SELECT count(*) FROM execution_attempts WHERE run_id = '<runId>';  -- note the result either way
```

(`execution_attempts` column name may differ; use the table that
`markExecutionAttemptCompleted` updates.) Expected events: `run_started`, then
`started`/`completed` per step, then a run-completed event.

### 5.3 Browser relay

Open the console, then DevTools, Network, WS, the dashboard websocket. During
the run look for frames of type `run_event` whose `data.runId` is the spike id.
(Alternative: `read_network_requests` style capture; any frame with the spike
run id is a pass.)

### 5.4 Concurrency check

Start a normal (non-dbsim) scenario run on the same agent from the console,
then immediately trigger the spike on that agent (and the reverse order). Note:
the agent cancels any in-flight scenario when a new `command_scenario` arrives
(`agent/agent.go:1572-1578`), so expect the normal run to be cancelled or the
spike run to be cancelled. Record exactly which one and how it ended.

## 6. Findings checklist (copy into `docs/dbsim-run-spike-findings.md`)

| # | Question | Where to look | Result (PASS/FAIL + note) |
|---|----------|---------------|---------------------------|
| 1 | Agent executed the steps with no `scenario_runs` row | 5.1 RESULT line, 5.2 count = 0 | |
| 2 | Result carried `dbProbe` for every step (`dbProbePresent=true`) | 5.1 step lines | |
| 3 | `POST /api/scenarios/events` calls arrived: rows in `run_events` | 5.2 | |
| 4 | Events reached the browser relay (`run_event` frames) | 5.3 | |
| 5 | Result MAC check passed (no MAC FAILED line) | 5.1 | |
| 6 | Agent-id check did not object (`agentCheck=match`; `EMPTY(not checked)` means the agent sent no id and is NOT a pass; `MISMATCH` is a fail) | 5.1 | |
| 7 | Agent run-limit / `ExecutionAttempt` bookkeeping did not object (no agent-side error, no stuck state) | agent log, 5.2 | |
| 8 | Agent-side posts to `/api/scenarios/runs/{id}/detections` and `/host-events` did not break the run (they target a missing row) | agent log, orchestrator log | |
| 9 | Normal run active on same agent: behaviour (cancelled which run?) | 5.4 | |
| 10 | DB-01 and DB-05 on PostgreSQL | all of the above | |
| 11 | DB-01 and DB-05 on MySQL | all of the above | |
| 12 | Elapsed per scenario (from RESULT line) | 5.1 | |
| 13 | Any unexpected orchestrator or agent error line | both logs | |

Decision: every row PASS (row 9 is information, not a pass/fail) means PROCEED;
any FAIL means FALLBACK (dedicated command type and result route) and the
controller returns to the owner before Task 2.

## 7. Cleanup

Revert the Dockerfile edit and redeploy a normal image. The spike stores only an
in-memory map (lost on restart) and writes `run_events` rows keyed by the spike
run ids; those rows are harmless and can be deleted with
`DELETE FROM run_events WHERE run_id LIKE 'spike-%';`.
