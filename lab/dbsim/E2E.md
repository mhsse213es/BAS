# dbsim end-to-end run on staging (Task 13 milestone)

> **NOT YET RUN.** The harness (`orchestrator/internal/dbsim/dbrun/e2e_test.go`,
> build tag `dbsim_e2e`) was written on a host with no Docker and no MySQL. Until
> someone runs it on the staging lab and sends the output back, the claim
> "signed scenario -> agent -> audit event -> alert -> graded Record works on
> PostgreSQL and MySQL" is **not demonstrated**. Failures below are expected to
> teach us things; do not "fix" the test to make it green.

Companion to `lab/dbsim/README.md` (ports 55432 PostgreSQL, 53306 MySQL, 59200
Elasticsearch, 55601 Kibana; compose project `dbsim-lab`). Do README steps 1-2
(bring-up, `setup.sh kibana`, `./smoke.sh` PASS) first. If `smoke.sh` is not
green, the E2E cannot be.

## What the harness does (and does not)

Real: shipped scenario YAML + `.sig` verified by `scenario.Engine.Load`;
`dbbuild.BuildSteps`; a `CommandEnvelope` signed with `internal/cmdsigning` and
verified by the agent's own `verifyCommandEnvelope`; the agent's `gateStep` /
`execStep` -> `executeDBProbe`, real adapters and drivers against the lab DB;
the real `detectverify` Elastic connector; `dbcorrelate.Correlate`;
`dbsim.BuildReport`; `Record.Validate()`.

Not real: the production agent has no one-shot mode (it only takes work over its
enrolled WebSocket from a running orchestrator), so the agent runs as a
`go test -c -tags dbsim_e2e` binary. WebSocket transport, enrollment, run events,
result upload and the `dbsim_runs` store are **not exercised**. The signing key
is a throwaway.

## 1. Prerequisites

* Lab up and smoke-tested (README). Elasticsearch has produced at least one alert.
* Go (version in `orchestrator/go.mod`) on the host that runs the test.
* The orchestrator test build must carry the vendor scenario public key (the
  default repo build does); the test fails if signature verification is off.

## 2. Build the agent test binary

On the staging Linux host (or cross-build from the dev box):

```sh
cd agent
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -tags dbsim_e2e \
  -o ../lab/dbsim/agent-bin/agent-e2e.test .
```

`lab/dbsim/agent-bin/` is the same directory the compose `agent` container
mounts; do not commit its contents. Run the harness on a host that can execute
this binary and reach the published lab ports.

## 3. Credentials for the lab accounts

The agent resolves `credentialRef: dbcred:<name>` from env `BAS_DBCRED_<NAME>`
(upper-case, `-` -> `_`). Export all four in the shell that runs `go test`
(values from `.env`; never paste them into logs or tickets):

| Reference (set by the harness) | Env var to export | Account |
|---|---|---|
| `dbcred:lab-pg-lab` | `BAS_DBCRED_LAB_PG_LAB` | PG `dbsim_lab` |
| `dbcred:lab-pg-ro`  | `BAS_DBCRED_LAB_PG_RO`  | PG `dbsim_test` (DB-03 must be denied) |
| `dbcred:lab-my-lab` | `BAS_DBCRED_LAB_MY_LAB` | MySQL `dbsim_lab` |
| `dbcred:lab-my-ro`  | `BAS_DBCRED_LAB_MY_RO`  | MySQL `dbsim_test` |

Each value is `{"user":"...","password":"..."}` (see README, "Agent connection").
Targets are registered in memory by the harness (`lab-db`, mode `lab`,
`LabConfirmed`, TLS `disable`); there is no registry endpoint yet (Task 16).

## 4. Environment variables (names only)

Common: `DBSIM_E2E_AGENT_BIN` (the file from step 2), `DBSIM_E2E_ES_URL`
(`http://<staging>:59200`), `DBSIM_E2E_ES_USER` (`dbsim_alerts_reader`),
`DBSIM_E2E_ES_PASSWORD`, `DBSIM_E2E_AGENT_IP` (the agent host's IP as the SIEM
would see it; any valid IP that is not the DB's), optional `DBSIM_E2E_WINDOW`
(default `3m`), `DBSIM_E2E_ALERT_WAIT` (default `150s`).

PostgreSQL (`DBSIM_E2E_PG_*`) and MySQL (`DBSIM_E2E_MYSQL_*`), same suffixes:
`HOST`, `PORT` (`55432` / `53306`), `DB` (`dbsim`), `IDENTITY`
(PG: `SELECT system_identifier FROM pg_control_system()`; MySQL: `SELECT
@@server_uuid`), `DBHOSTNAME` (`dbsim-pg` / `dbsim-mysql`, the `host.name` in
alerts), `DBIP` (`172.28.50.10` / `172.28.50.11`, the `host.ip` in alerts),
`CRED_LAB` (`lab-pg-lab` / `lab-my-lab`), `CRED_RO` (`lab-pg-ro` / `lab-my-ro`).

A completely unset engine is skipped. A **partially** set configuration fails
the test on purpose.

## 5. Run

Plumbing check first (no database or SIEM needed; proves signed envelope ->
agent verifier -> executor, and that a tampered envelope is rejected):

```sh
cd orchestrator
DBSIM_E2E_AGENT_BIN=../lab/dbsim/agent-bin/agent-e2e.test \
  go test -tags dbsim_e2e -count=1 -run TestE2EPlumbing -v ./internal/dbsim/dbrun/
```

(Always use `-run`: with only a common `DBSIM_E2E_*` variable set and no engine
configured, the `TestE2E_*` tests fail on purpose as a typo guard.)

Then each engine (the timeout matters: up to 150 s of alert polling per
detection step):

```sh
go test -tags dbsim_e2e -count=1 -timeout 60m -v \
  -run TestE2E_PostgreSQL_SignedScenarioToCorrelatedRecord ./internal/dbsim/dbrun/
go test -tags dbsim_e2e -count=1 -timeout 60m -v \
  -run TestE2E_MySQL_SignedScenarioToCorrelatedRecord ./internal/dbsim/dbrun/
```

Sub-tests: DB-01, DB-02, DB-03, DB-04, DB-05, DB-09, DB-06, DB-07 (each
scenario's steps are graded one step at a time; combining steps into one
scenario Record is Task 16).

DB-06 and DB-07 (Task 14) are UNVERIFIED until a staging run. Before running
them: re-run `elastic/setup.sh kibana` (and the `es` phase, so the index template
maps `dbsim.touches_classified`) and restart Filebeat with the updated
`filebeat.yml`, so the second rule `rule-classified.json` exists; confirm
`dbsim_lab` may create roles/users (README checklist 18). The agent test binary
must be rebuilt from this commit (it carries the new probes).

## 6. Expected end state (per step, both engines)

Mapping of the plan's wording to the real enums: `Telemetry=Present` is
`dlpreport.TelemetryPresent`; `Response=Alerted` is `dlpreport.ResponseAlerted`
(set only when a marker-correlated alert exists; no case/escalation/remediation
is assessed); non-zero latency is `Outcome.Corr.Latency > 0` (alert timestamp
minus the database-reported probe time); match grade `exact_marker`;
`Record.Validate() == nil`; result `PASS` (except DB-02 `read_grants`, below).

| Scenario step | Expected |
|---|---|
| DB-01 `auth_check`, `read_roles` | PASS, Telemetry Present, Response Alerted |
| DB-02 `read_roles` | PASS, Present/Alerted |
| DB-02 `read_grants` (as `dbsim_lab`) | **ERROR (Unverifiable) today, by design (ruling R-AJ):** grants observed, policy diff not wired. The Record carries "policy diff not performed; grants were observable (N) but not compared to a stated policy". The harness asserts this ERROR; a PASS here would be a bug. DB-02's excessive-grant detection is NOT produced end to end. Zero grants (README checklist 14 failing) is also ERROR, with "no grants observed: account may lack catalog visibility". Telemetry stays Present/Alerted |
| DB-03 `read_restricted_table` (as `dbsim_test`) | Enforcement Blocked, PASS, Present/Alerted |
| DB-04 `read_audit_config` | PASS if `audit_config: covered`; no SIEM query (the lab rule never alerts on it) |
| DB-04 `read_roles` (tagged) | PASS needs audit status `found` AND the alert. `unsupported` => SKIPPED, `absent` => FAIL, `incomplete`/`error` => ERROR (the harness reports any non-PASS as a failed assertion; the Record explains why) |
| DB-05, DB-09 | PASS, Present/Alerted, `CleanupStatus ok` (fixture schema `dbsim_*` gone) |
| DB-06 `auth_after_revoke` (class `bounded_synthetic`, ruling R-AO; signed `potentially_destructive`, passes the agent B5 gate) | PostgreSQL: **PASSED live** (run 2). MySQL: **UNVERIFIED** (run 1 vetoed by B5 as class `mutation`, fixed in round 3; run 2 failed the baseline with 1044 on the default schema, fixed in round 4 by dialling the throwaway account with no default database; not yet re-run). PASS needs the step note `revoke_steps=create=ok,baseline=ok,revoke=ok,reconnect=denied` (baseline login worked, revoke issued, NEW login refused with PG 28000/28P01 or MySQL 1045/3118), Enforcement Blocked, `CleanupStatus ok`. **Telemetry stays Unverifiable and Response NotTested BY DESIGN** (a failed login has no statement to carry the marker; the harness asserts they are NOT Present/Alerted and never queries the SIEM for this step). Honest non-PASS outcomes: `baseline_failed` / `revoke_failed` / `reconnect_error` / `account_create_failed` => ERROR (look at the `revoke_steps` note and the `revoke_detail:` lines; typical causes are `pg_hba.conf`, TLS mode, auth plugin, a missing CREATEROLE/CREATE USER privilege); the account still logs in after the revoke => FAIL (a real finding); a leftover `dbsim_<id>_acct` => ERROR (safety incident, clean by hand) |
| DB-07 `read_classified_fixture` | **UNVERIFIED.** Needs `rule-classified.json` installed. PASS needs Classification **Correct** (an exact-marker alert whose rule name equals `BAS dbsim classified-fixture read`), Present/Alerted, `CleanupStatus ok`. Only the generic rule alerting => Classification **Incorrect** => FAIL (rule missing or not firing: README checklist 16-17). Telemetry unverifiable (for example the MySQL marker comment not surviving) => Classification **Unknown** => ERROR, never Incorrect. No rule name configured => NotEvaluated => ERROR (the harness always configures it) |
| DB-08 `try_disable_audit` (class `bounded_synthetic`; session-scoped statement only) | **UNVERIFIED (Task 15, never run live).** A throwaway no-privilege account logs in (baseline) and attempts ONE fixed session-scoped statement (PG `SET log_statement = 'none'`, MySQL `SET SESSION sql_log_off = 1`). PASS needs the step note `audit_tamper_steps=create=ok,baseline=ok,attempt=denied` (refusal recognised ONLY by PG SQLSTATE 42501 / MySQL 1227), Enforcement Blocked, `CleanupStatus ok` AND a marker-correlated alert (Present/Alerted). Only the ONE attempt `SET` carries the per-dispatch marker; the baseline statement carries the non-correlated meta tag, so a logged baseline can never be credited as detection. That the denied `SET` is audit-logged with the marker is an EXPECTATION to be confirmed on staging, not an observed fact. `attempt=allowed` => FAIL (the account can suppress its own session's audit: a real finding). `attempt=error` (unknown parameter, timeout, ...) / `baseline_failed` / `account_create_failed` => ERROR, never Blocked. NO global or persistent audit change is ever attempted; actual audit disablement is not built |
| DB-10 `try_write_fixture` (class `bounded_synthetic`) | **UNVERIFIED (Task 15, never run live).** A throwaway SELECT-only account (PG: USAGE on the fixture schema + SELECT on `accounts`; MySQL: `GRANT SELECT ON <fixture schema>.*`, dialled with no default database) attempts one INSERT, UPDATE, DELETE on the fixture `accounts` table. PASS needs `write_attempt_steps=insert=denied,update=denied,delete=denied,fingerprint=unchanged` (denials recognised ONLY by PG 42501 / MySQL 1142, 1143, 1044), Enforcement Blocked, `CleanupStatus ok`, and the marker-correlated alert (only the INSERT, UPDATE and DELETE carry the marker; baseline read and both fingerprints carry the meta tag; audit-log recording of the denied statements is an expectation to confirm on staging). A permitted statement => FAIL with `fixture_changed=true`; all denied but `fingerprint=changed`/`error` => ERROR (`fixture_state_inconsistent` / `fingerprint_failed`), never PASS; any other error code => ERROR. `dbsim_lab` must be able to GRANT SELECT on the fixture schema (MySQL needs the global GRANT OPTION it already has) |
| DB-11 `check_export_privileges` (class `read_only`, lab-only; run as the restricted `dbsim_test`) | **UNVERIFIED (Task 15, never run live).** Fixed read-only catalog reads. PASS needs `export_checks` with `file_write=no`, `program_exec=no|na`, `file_read=no`, every check observed (no `unknown`), Enforcement Blocked. PASS means no server-file-write, program-execution or server-file-read privilege is held; it does NOT mean the account cannot dump or back up data (replication, pg_read_all_data, RELOAD, LOCK TABLES, broad SELECT are reported as informational only). No telemetry is claimed (Unverifiable / NotTested, no SIEM lookup). A held file-write/program/file-read privilege => FAIL; an unobservable check (denied catalog read, privileges via an active MySQL role, unmatched account) => ERROR. Pointing it at the privileged `dbsim_lab` account would legitimately FAIL. The "controlled operation if authorized" mode is NOT built |

## 7. If the MySQL marker comment does not survive

This is the documented central risk (README "Known risk"). Signs: MySQL steps
show Telemetry `Unverifiable` or `Absent`, match `ambiguous`/`none`, and DB-04
audit `absent`/`incomplete`. The test will FAIL; that failure is the honest
result. Record it, do not mask it:

1. Look at what the general log actually holds for a tagged statement:
   `docker compose exec mysql mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -e "SELECT event_time, LEFT(argument,160) FROM mysql.general_log ORDER BY event_time DESC LIMIT 20"`
   (redact before sharing).
2. In `docs/dbsim-mastery-qa-log.md` add: engine=mysql, audit source tried
   (general_log TABLE/FILE, performance_schema), the observed redacted text of a
   tagged statement, conclusion `Unverifiable: audit path strips the marker
   comment`. The PostgreSQL half remains the proven path only if it passed.
3. Do not weaken `checkStep` or the correlator. A follow-up (Percona audit
   plugin, session attribute) is a separate decision.

## 8. Verify cleanup independently

The agent reports `CleanupStatus` itself. Check the databases directly after a
run (expect no rows):

```sh
docker compose exec postgres psql -U postgres -d dbsim -c "\dn dbsim_*" -c "\du dbsim_*"
docker compose exec mysql mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -e "SHOW DATABASES LIKE 'dbsim\\_%'"
```

(`dbsim_audit`, `dbsim_lab`, `dbsim_test` are the lab's own objects and are
expected. Fixture objects are named `dbsim_<fixture id>` (schema/database) and,
on PostgreSQL, `dbsim_<fixture id>_ro` (role); DB-06 also creates the throwaway
login `dbsim_<fixture id>_acct` (PostgreSQL role / MySQL user `'...'@'%'`),
which must be gone too (`SELECT rolname FROM pg_roles WHERE rolname LIKE
'dbsim\_%\_acct'`; `SELECT User FROM mysql.user WHERE User LIKE
'dbsim\_%\_acct'`). Anything else matching is a leftover. The exact fixture ids come from the agent's fixture catalog.)

## 9. What to send back

* Both full `go test ... -v` outputs (they contain `SUMMARY` lines and the
  redacted Record JSON per step; the harness never prints credentials).
* For any non-PASS: the `reason` and `limitations` text printed with it.
* Output of README checklist items 4, 5, 9, 9a, 10, 11, 12 (audit view,
  comment survival, rule firing, field extraction, alert content, measured
  latency, connector against the live lab) - these decide most failures.
* The Elasticsearch alert document for one DB-05 run (`.alerts-security.alerts-*`,
  fields `message`, `event.original`, `host.name`, `host.ip`, `@timestamp`).
* `docker compose ps` and, if a step reports `connect_error`, the agent
  subprocess tail the harness prints.
