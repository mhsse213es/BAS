# dbsim lab: Elastic detection path for the database security simulation

Test infrastructure (spec R2): PostgreSQL + pgaudit, MySQL 8.0, Elasticsearch,
Kibana, Filebeat and a separate `agent` container, wired so that a probe
statement carrying the `bas-dbsim:` marker produces an Elastic Security alert
that the `detectverify` Elastic connector can read.

> **NOTHING IN THIS DIRECTORY HAS BEEN EXECUTED.** It was written on a host
> with no Docker and checked only statically (YAML/JSON parse, `sh -n`,
> cross-reading against the Go code). Every runtime behaviour below is an
> assumption until the staging checklist is completed. See "Verified vs
> UNVERIFIED".

## Layout

| Path | Purpose |
|------|---------|
| `docker-compose.yml` | the stack (project name `dbsim-lab`, network `172.28.50.0/24`) |
| `postgres/Dockerfile`, `10-seed.sh`, `seed-postgres.sql` | `postgres:16.4-bookworm` + `postgresql-16-pgaudit`; seed |
| `mysql/Dockerfile`, `dbsim.cnf`, `10-seed.sh`, `seed-mysql.sql` (top level) | `mysql:8.0.40` with general log; seed |
| `elastic/filebeat.yml` | ships PG stderr log + MySQL general-log FILE to `dbsim-audit-<date>` |
| `elastic/rule.json` | detection rule (Kibana detection-engine API body) |
| `elastic/index-template.json` | mapping for `dbsim-audit-*` (`host.ip` as `ip`, etc.) |
| `elastic/kibana.yml` | Kibana config (secrets via `${ENV}`) |
| `elastic/setup.sh` | `es` phase (template, roles, users) and `kibana` phase (rule) |
| `agent-sim/Dockerfile` | the `agent` container: psql 16, mysql client, curl |
| `smoke.sh` | end-to-end marker check, both engines |
| `.env.example` | placeholders; copy to `.env` (gitignored) |

## Prerequisites and sizing

* Docker Engine with Compose v2, on the **staging host** (not the dev Windows
  box). Elasticsearch (1 GB heap, 2 GB limit) + Kibana (2 GB limit) + two
  databases: budget about **6 GB RAM free**, 10 GB disk.
* Linux host: `sysctl -w vm.max_map_count=262144` (Elasticsearch requirement).
* `mkdir agent-bin` (the `agent` container bind-mounts it read-only).
* `curl` on the host (for `setup.sh kibana`).
* Passwords are `[A-Za-z0-9]` only (interpolated into SQL, JSON and shell).

## Bring up / tear down

```sh
cd lab/dbsim
cp .env.example .env            # then replace EVERY CHANGE_ME value
mkdir -p agent-bin
docker compose up -d --build    # bootstrap one-shot runs "setup.sh es" first
# wait until kibana is healthy (docker compose ps), then:
set -a; . ./.env; set +a
./elastic/setup.sh kibana       # creates the detection rule
./smoke.sh                      # PASS/FAIL per engine
docker compose down -v          # tear down AND wipe all data (needed to re-run the seeds)
```

The seeds (`seed-*.sql`) run only on an **empty** data directory. After changing
a seed, `docker compose down -v`.

Expected result of `./smoke.sh` **before** the stack is up: `FAIL: the lab
'agent' container is not running`, exit 2. After `up` but **before**
`setup.sh kibana` (no rule yet): all three checks FAIL with "no alert within
90 s", exit 1. Only a full PASS means the path works.

## MySQL-family choice and its limits

Chosen: **official `mysql:8.0.40` with `general_log=ON`, `log_output=TABLE,FILE`**
plus `performance_schema` statement history.

Why: the agent adapter (`agent/dbprobe/mysql/audit.go`) reads evidence only via
SQL, from `mysql.general_log` (TABLE) or
`performance_schema.events_statements_history_long`. It never reads a plugin's
file. With general log the **same events** go to the TABLE the agent queries and
the FILE Filebeat ships, so the SIEM and the agent see one source of truth.
The adapter supports MySQL 8, not MariaDB (Identity needs `@@server_uuid`), which
rules MariaDB out.

Not chosen: **Percona Server for MySQL 8.0 `audit_log` plugin** (JSON/XML
file). It is a real audit plugin (filtering, no full-statement-logging
overhead) and is a reasonable follow-up, but the agent could not query it, so it
adds a second source that the agent's evidence would not match, and I could not
confirm from vendor docs here whether it preserves a leading `/* */` comment.
MySQL Community has no audit plugin.

Limits (all accepted for a lab): general log records every statement
(performance cost, unbounded growth of `mysql.general_log` and `general.log`;
truncate by `down -v`); it is not a compliance-grade audit trail; for prepared
statements the log has a `Prepare` line (original text) and an `Execute` line
(text with parameters substituted); statement text is cut at server limits.
Whether a leading `/* ... */` comment survives into the general log is
**UNVERIFIED** (see checklist). MySQL clients strip comments by default (`mysql`
needs `--comments`; smoke.sh passes it); the server-side behaviour is the open
question. Sources to consult, **not fetched or confirmed by the author**:
<https://dev.mysql.com/doc/refman/8.0/en/log-destinations.html>,
<https://dev.mysql.com/doc/refman/8.0/en/query-log.html>,
<https://docs.percona.com/percona-server/8.0/audit-log-plugin.html>.

## How the evidence flows

```
agent container --SQL--> postgres (pgaudit, log_statement=all, logging_collector)
                          |- /var/log/postgresql/dbsim-pg.log  --Filebeat--> dbsim-audit-*  --rule--> .alerts-security.alerts-default
                          '- /var/log/postgresql/dbsim-pg.csv  --file_fdw--> dbsim_audit.pg_log (the agent's own evidence view)
                 --SQL--> mysql (general_log TABLE,FILE)
                          |- /var/log/mysql/general.log --Filebeat--> dbsim-audit-*
                          '- mysql.general_log table (the agent's own evidence)
```

* PostgreSQL: `log_statement=all` writes `statement: <text>` /
  `execute <name>: <text>`; pgaudit adds `AUDIT:` rows (`pgaudit.log=read,write,ddl,role`).
  Expect **two events per statement** (log line + AUDIT row): two alerts per
  probe is normal. Both `log_destination` formats are on: `csvlog` for the
  file_fdw view, `stderr` text for Filebeat (csvlog rows are multi-line CSV and
  would need CSV decoding).
* The csvlog path is fixed: `log_filename=dbsim-pg.log`, rotation off, so the
  collector writes one `/var/log/postgresql/dbsim-pg.csv` (collector replaces
  `.log` with `.csv`); `seed-postgres.sql` points the foreign table at it. It
  only grows. The foreign table lists all 26 PG16 csvlog columns; another major
  version needs a different column list.
* **Detection rule** (`elastic/rule.json`): KQL
  `message : "bas-dbsim:" and not message : ("dbsim-meta" or "general_log" or "pg_log" or "dbsim_audit" or "events_statements_history_long")`
  over `dbsim-audit-*`, every 10 s, lookback 70 s. The exclusions matter: the
  agent's own audit lookup contains the probe marker in its `LIKE` argument
  (tagged `/* dbsim:dbsim-meta */`), and must not alert as if it were the probe.
  `message` is a `text` field, so the phrase `"bas-dbsim:"` matches the token
  sequence `bas dbsim`; it is a prefix filter only. **Task 12's post-filter must do
  an exact substring match on the original message**, not rely on the rule.
* **Alert document**: a Kibana custom query rule copies the source event's
  fields into the alert (`message`, `event.original`, `host.name`, `host.ip`,
  `user.name`, `dbsim.*`) -- UNVERIFIED. `host.name` is `dbsim-pg` /
  `dbsim-mysql` and `host.ip` the DB server's static IP (`172.28.50.10` /
  `.11`), set by Filebeat `add_fields`, **not** the Filebeat container's.
* **detectverify compatibility** (read from `orchestrator/internal/detectverify/elastic.go`):
  it POSTs `/.alerts-security.alerts-*/_search` with `allow_no_indices=false`,
  filters `@timestamp` or `kibana.alert.original_time` in the window, and
  `host.name` (case-insensitive term / `host.hostname` / `host.name` prefix `<name>.`)
  or `host.ip` (term) -- so alerts must live in `.alerts-security.alerts-*`
  (they do: that is where the detection engine writes) and `host.ip` must be a
  valid IP (the template maps it as `ip`). Configure the connector with
  `BaseURL=http://<staging>:59200`, basic auth `ClientID=dbsim_alerts_reader`,
  `ClientSecret=$ALERTS_READER_PASSWORD` (the role has read on the alerts
  indices only). **The connector currently selects a fixed `_source` list that
  omits `message`/`event.original`** and its `RawJSON` is a normalised subset, so
  the marker is not visible through it until Task 12 widens `_source`. No
  different index pattern is needed. Alert `@timestamp` is when the rule ran,
  not when the statement ran (`kibana.alert.original_time` is the event time).
  The alert carries no ATT&CK `threat` mapping, so `matchAlerts` returns
  Medium confidence; dbsim never uses that verdict.

## Accounts

| Account | Engine | Privileges | Used for |
|---------|--------|-----------|----------|
| `postgres` / root | PG / MySQL | superuser / root | seeds only; secrets `PG_SUPERUSER_PASSWORD`, `MYSQL_ROOT_PASSWORD` |
| `dbsim_test` | PG | LOGIN, `default_transaction_read_only=on`; USAGE+SELECT on `dbsim_audit.pg_log`; EXECUTE `pg_control_system()`; **no** access to `bas_dbsim` | client-mode agent account, DB-03 expects denial |
| `dbsim_test` | MySQL | SELECT on `dbsim.*`, `mysql.general_log`, `performance_schema.{events_statements_history_long,threads,global_status,setup_consumers}`, column SELECT on `mysql.user(User,Host,account_locked,Super_priv)`; **nothing** on `bas_dbsim` | client-mode agent account |
| `dbsim_lab` | PG | LOGIN, CREATEROLE, CREATE on db `dbsim`, view + EXECUTE as above | lab-mode (fixture Seed/Cleanup) |
| `dbsim_lab` | MySQL | `CREATE, DROP, SELECT, INSERT, CREATE USER ON *.* WITH GRANT OPTION` | lab-mode; GRANT OPTION is needed because MySQL gives a schema's creator no rights on it |
| `bas_dbsim_app` | PG role (NOLOGIN) / MySQL locked user | USAGE on schema + SELECT `bas_dbsim.app_data` | the role DB-02 reads grants for |
| `dbsim_filebeat`, `dbsim_alerts_reader`, `elastic`, `kibana_system` | ES | write `dbsim-audit-*` / read alerts / superuser / Kibana | see `setup.sh` |

Lab objects: schema/database `bas_dbsim` with `app_data` and `restricted`
(synthetic `BAS-SIM-*` rows only; no one but the owner can read `restricted`).
Known visibility limit: `information_schema.role_table_grants` (PG) and
`TABLE_PRIVILEGES` (MySQL) only show grants the connecting account may see, so
DB-02 as `dbsim_test` may see **no** `bas_dbsim_app` grants even though they
exist (UNVERIFIED). The orchestrator reports an empty grant set as such, not as
a pass. Use `dbsim_lab` (or add visibility) if the lab needs them listed.

## Agent connection (BAS_DBCRED / Target registry / tests)

The agent resolves `credential_ref: dbcred:<name>` from env
`BAS_DBCRED_<NAME>` (upper-case, `-` -> `_`) holding
`{"user":"...","password":"..."}` (`agent/dbcred.go`). Register targets in the
orchestrator registry with the fields of `dbsim.Target`:

| Field | PostgreSQL target | MySQL target |
|-------|------------------|--------------|
| `Engine` | `postgresql` | `mysql` |
| `Host`, `Port` | `<staging host or postgres container>`, `55432` (container-internal: `postgres:5432`) | `<host>`, `53306` (internal: `mysql:3306`) |
| `Database` | `dbsim` | `dbsim` |
| `TLSMode` | `disable` (lab; PG has no TLS configured) | `disable` |
| `CredentialRef` | `dbcred:lab-pg-ro` (client) / `dbcred:lab-pg-lab` (lab) | `dbcred:lab-my-ro` / `dbcred:lab-my-lab` |
| `ExpectedIdentity` | `SELECT system_identifier FROM pg_control_system()` (numeric) | `SELECT @@server_uuid` |
| `Mode`, `LabConfirmed` | `client` / `lab`, `true` for lab | same |

Run the agent on a **different host/container** from the databases: put the
cross-built Linux agent in `agent-bin/` and `docker compose exec agent /opt/agent/<bin>`,
or run it on another machine against `<staging>:55432/53306`. Example env on the
agent host (names only; values from `.env`):

```sh
export BAS_DBCRED_LAB_PG_RO='{"user":"dbsim_test","password":"<DBSIM_TEST_PASSWORD>"}'
export BAS_DBCRED_LAB_MY_RO='{"user":"dbsim_test","password":"<DBSIM_TEST_PASSWORD>"}'
```

### Running the `dbsim_integration` tests against the lab

```sh
# PostgreSQL (space-separated key=value; lab account because Seed/Cleanup create schemas and roles)
export DBSIM_PG_DSN="host=<staging> port=55432 dbname=dbsim user=dbsim_lab password=$DBSIM_LAB_PASSWORD tlsmode=disable"
# MySQL
export DBSIM_MYSQL_HOST=<staging> DBSIM_MYSQL_PORT=53306 DBSIM_MYSQL_DB=dbsim \
       DBSIM_MYSQL_USER=dbsim_lab DBSIM_MYSQL_PASSWORD=$DBSIM_LAB_PASSWORD DBSIM_MYSQL_TLSMODE=disable
cd agent && go test -tags dbsim_integration ./dbprobe/postgres/... ./dbprobe/mysql/...
```

The audit tests construct a client-mode adapter from the same variables;
`dbsim_lab` can read the audit sources too (PG view grant, MySQL `SELECT ON *.*`).
If client mode insists on a verified read-only identity, run those with
`dbsim_test` credentials instead. The integration tests cover what `smoke.sh`
cannot: the Go drivers' prepared-statement path.

## Verified vs UNVERIFIED

**Verified (by reading/parsing only):** `docker-compose.yml`, `filebeat.yml`,
`kibana.yml` parse as YAML; `rule.json` and `index-template.json` parse as JSON;
`sh -n` passes for `smoke.sh`, `setup.sh` and both init scripts; compose
service/volume/network/build-path references are internally consistent;
`dbsim_audit.pg_log` column names match `agent/dbprobe/postgres/audit.go`; MySQL
sources/grants match `agent/dbprobe/mysql/audit.go` and `grants.go`; the alert
index, host fields and auth modes match `detectverify/elastic.go`. Images and
pins were **not pulled or checked for existence**. `shellcheck` was not
available.

**Everything else is UNVERIFIED**, in particular the staging checklist below.

Image pins: `postgres:16.4-bookworm` (+ apt `postgresql-16-pgaudit`, version
unpinned), `mysql:8.0.40`, Elastic stack `8.15.3` (ES/Kibana/Filebeat),
`curlimages/curl:8.10.1`. No `latest`.

## Staging verification checklist (every unverified assumption)

Record each result in `docs/dbsim-mastery-qa-log.md` (or the initiative QA log).

1. Images and tags exist and pull; `postgresql-16-pgaudit` installs from the PGDG apt repo in the official image; `default-mysql-client` installs in `agent-sim`.
2. ES security bootstrap: single-node with security on and transport SSL off starts (no bootstrap-check failure); `ELASTIC_PASSWORD` works; `bootstrap` sets `kibana_system`; Kibana connects; `${ENV}` substitution in `kibana.yml` works; `xpack.alerting.rules.minimumScheduleInterval.{value,enforce}` accepted (10 s rule interval allowed).
3. Postgres init: `10-seed.sh` runs (non-executable `.sh` is sourced by the entrypoint; mark it executable in git); `SET pgaudit.log='none'` before the library is loaded does not fail; the seed password statements do not appear in logs; `file_fdw` extension available; `GRANT EXECUTE ON FUNCTION pg_control_system()` valid.
4. `dbsim_audit.pg_log` readable by `dbsim_test`: file exists at `/var/log/postgresql/dbsim-pg.csv` (collector `.log`->`.csv` rename), 26-column layout matches, `log_time` parses, the view reflects new rows immediately (no caching), and the file is created before the agent first connects. Agent `Capabilities().AuditSources` is non-empty.
5. **Leading-comment survival** for the marker `/* dbsim:bas-dbsim:... */` in each of: PostgreSQL `statement:` log line (simple protocol), `execute <name>:` line (extended protocol, pgx prepares by default), csvlog `message`, pgaudit `AUDIT:` row; MySQL `general_log` TABLE and FILE for `COM_QUERY` (text protocol) and for server-side prepared statements (go-sql-driver uses them when args are present: both the `Prepare` and `Execute` rows), and `performance_schema.events_statements_history_long.SQL_TEXT`. The agent identifies a statement only if its text BEGINS with the comment (`ownStatement`), so any stripping gives absent/incomplete.
6. MySQL: `general_log=ON`, `log_output=TABLE,FILE`, and the four statement consumers are on after start; `SELECT` grants on `mysql.general_log` and the performance_schema tables work; column grant on `mysql.user` suffices for `read_roles`; `NOW(6) - Uptime + TIMER_START` timing is close enough (history_long path); `mysql_native_password` accepted by the Go driver; `sql_log_off` keeps the seed out of the log.
7. File ownership: the named volumes `pg-log` / `mysql-log` inherit `postgres`/`mysql` ownership from the images; Filebeat (root) can read both files.
8. Filebeat: multiline patterns match the real `%m` / ISO line starts; `dissect` extracts `user.name` (ignore_failure on, so failures are silent); `host.name`/`host.ip` end up as `dbsim-pg`/`172.28.50.10` and `dbsim-mysql`/`172.28.50.11` (i.e. `add_fields` overrides the beat's own `host.name`); `copy_fields` fills `event.original`; documents land in `dbsim-audit-<date>` with the template applied (`host.ip` is type `ip`).
9. Rule: created through `POST /api/detection_engine/rules` (and the `/index` call or its absence is harmless); the KQL phrase match on `bas-dbsim:` fires and the exclusion list suppresses the agent's own `dbsim-meta` lookups; both log-line and AUDIT-row events produce alerts; rule status healthy (not "no indices").
10. Alert content: `.alerts-security.alerts-default` documents contain `message`, `event.original`, `host.name`, `host.ip` in `_source` (needed by Task 12). If not, the fix is on the rule/alert side, not a different index.
11. **Latency**: time from statement to alert document. The agent's 5 s wait covers only the PG csvlog sync, not the rule; with a 10 s rule interval and Filebeat/refresh delays expect up to about 20-30 s. Task 13's detection window and `smoke.sh`'s 90 s budget must be checked against the measured value.
12. detectverify against the live lab: `TestConnection` passes with `dbsim_alerts_reader`; `Verify` for `host.name=dbsim-pg` and for `host.ip=172.28.50.10` returns the alerts; hidden-index expansion and `allow_no_indices=false` behave (the alerts index must exist: run one smoke first); `.internal.alerts-*` privileges are sufficient.
13. `smoke.sh` end-to-end PASS for all three checks, including `psql \bind` (psql 16 extended protocol) and the mariadb client's `--comments` (client-side comment preservation) and `MYSQL_PWD`.
14. DB-02/DB-03 behaviour of `dbsim_test`: DB-03 is denied on `bas_dbsim.restricted`; DB-02 grant visibility (see Accounts).
15. Fixture lifecycle as `dbsim_lab` on both engines (CREATE SCHEMA/ROLE/USER, GRANT, verified teardown), and no collision between a fixture id and the lab's `dbsim_audit` schema.

## Known risk: marker comment may not survive (MySQL especially)

If no mechanism preserves the leading marker comment in the MySQL audit source
(general log, history_long, or a Percona plugin tried later), the **MySQL half
of the Task 13 E2E is "Unverifiable"**, not a pass and not a failure of the
product. Record it as: engine=mysql, audit source tried, observed log text for a
tagged statement (redacted), conclusion `Unverifiable: audit path strips the
marker comment`, in the QA log and in the result's `Telemetry=Unverifiable`
limitation text, and keep the PostgreSQL half as the proven path. The same rule
applies to PostgreSQL if `statement:`/`execute` lines or pgaudit rows are found
to lose the comment.

## Security notes

Lab only: no TLS between components, databases bound to `127.0.0.1` on the host,
`general_log` and `log_statement=all` capture every statement (including
literals) in clear text, and the audit CSV is readable by the test accounts.
Never point this stack at real data. `.env` is gitignored; commit only
`.env.example`.
