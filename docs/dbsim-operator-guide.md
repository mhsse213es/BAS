# Database Security Simulation (dbsim) - Operator Guide

Read with `docs/dbsim-mastery-qa-log.md`, which is the authority on what has and has
not been verified. This guide never claims more than that log does.

## 1. What it is, and its status

dbsim runs named, fixed, signed probes against PostgreSQL and MySQL targets from an
agent that is NOT on the database host, and grades the result: did the database
enforce its controls, did the audit log record the probe, did the SIEM alert on it.
It never scores itself from agent claims: the agent reports observations, the
orchestrator grades.

Status at the end of Task 16 (read before promising anything to a customer):

* Lab mode, scenarios DB-01..DB-11, was run end to end on staging against PostgreSQL
  16.4 and MySQL 8.0.40 (run 4, 2026-10-23): all PASS except DB-02 `read_grants`,
  which is ERROR by design (section 8).
* **Client mode (customer databases) has never been run against any real database.**
  Its gates are unit-tested only, and no operator can complete the read-only identity
  check from the product yet (section 4).
* There is **no product run API**: nothing in the product starts a dbsim run, builds
  steps from a registered target or stores a result. Runs today come from the test
  harness (`lab/dbsim/E2E.md`).

## 2. Supported-feature matrix

"Live" means run against a real engine in the lab and graded PASS (staging run 4).
"Unit" means tested with fakes only.

| ID | What it checks | Class | PostgreSQL | MySQL | Modes | Verified |
|----|----------------|-------|-----------|-------|-------|----------|
| DB-01 | Authentication policy (`read_roles`, `auth_check`) | read_only | yes | yes | lab, client | Live (lab) |
| DB-02 | Excessive grants (`read_grants`) | read_only | yes | yes | lab, client | **ERROR by design**: grants are observed but no policy diff is wired, so it never grades PASS (R-AJ/R-AK) |
| DB-03 | Unauthorised table access (`read_restricted_table`) | read_only | yes | yes | lab, client | Live (lab) |
| DB-04 | Audit coverage (`read_audit_config` + tagged probe) | read_only | yes | yes | lab, client | Live (lab) |
| DB-05 | Suspicious read (`suspicious_read`, seeded fixture) | bounded_synthetic | yes | yes | lab only | Live |
| DB-06 | Account revocation (`auth_after_revoke`, throwaway account) | bounded_synthetic | yes | yes | lab only | Live. Enforcement only; **no telemetry claim** |
| DB-07 | Sensitive-data classification (`read_classified_fixture`) | bounded_synthetic | yes | yes | lab only | Live. Needs a named classification rule, else ERROR |
| DB-08 | Audit tamper resistance (`try_disable_audit`) | bounded_synthetic | yes | yes | lab only | Live. Session-scoped statement only |
| DB-09 | Bounded bulk read (`bounded_synthetic_read`) | bounded_synthetic | yes | yes | lab only | Live |
| DB-10 | Write/delete prevention (`try_write_fixture`) | bounded_synthetic | yes | yes | lab only | Live |
| DB-11 | Backup/export privileges (`check_export_privileges`) | read_only, lab-only flag | yes | yes | lab only | Live. PASS = no server-file-write, program-exec or server-file-read privilege; it does NOT mean the account cannot dump data |
| DB-12 | Cross-system trust | - | not built | not built | - | - |

Also: `check_readonly_identity` (Task 16) is the probe behind the client-mode release
gate. It is Unit tested only.

MariaDB is unsupported by design (no `server_uuid`). Oracle/SQL Server: not supported.

## 3. Modes and gates

* **Lab mode**: a database you own for testing. Non-read-only probes need ALL of: the
  target registered with mode `lab` and `labConfirmed`, the scenario's mutation
  approval, and the agent-local allowance `BAS_DBPROBE_LAB_MUTATION_ALLOWED=1`.
  Probes only ever create and drop objects they created in the same run
  (`dbsim_<id>` schema, throwaway `dbsim_<id>_acct` account); no probe changes global or
  persistent server state.
* **Client mode**: a customer database. Only plain read-only probes run:
  `read_roles`, `read_grants`, `auth_check`, `read_audit_config`,
  `read_restricted_table`, `check_readonly_identity`. Everything else (fixtures,
  throwaway accounts, lab-only DB-11) is refused at every layer, including steps
  mislabelled as read-only. Every client probe also runs in a READ ONLY transaction.
* **Identity**: every target needs its PostgreSQL `system_identifier` or MySQL
  `server_uuid` supplied at registration; a mismatch refuses the run. There is no
  trust-on-first-use in either mode (lab discover-then-confirm is not implemented).

## 4. Client-mode release gate

Client mode is refused unless ALL are true:

1. An Admin switched on "DB client mode" (`PUT /api/dbsim/settings/client-mode`,
   default OFF, audited as `dbsim.client_mode_enabled` / `_disabled`). An unreadable
   or missing setting means OFF.
2. The target was registered with mode `client` and its expected identity.
3. The target's latest read-only identity check PASSED. The check passes only if the
   account positively cannot write data, change the schema, administer accounts or
   change audit settings; anything unknown fails. A later failed check withdraws an
   earlier pass. A pass also **expires**: it verifies the target only while it is
   younger than the maximum pass age (default 24 hours; exactly that age fails). It is
   recorded against the exact target registration it was run for, so deleting and
   re-registering the same id does not inherit it. **Open user decision: the validity
   period.** 24 hours is a placeholder default chosen to fail closed, not a policy.
4. The agent host has `BAS_DBPROBE_CLIENT_ENABLED=1` (agent-local, never taken from
   the server).

**Current gap**: step 3 cannot be completed in the product. The endpoint
`POST /api/dbsim-targets/{id}/identity-check` answers 501 because no dispatch path to an
agent exists (open item). Until then no target becomes client-eligible, so client mode
is unreachable. That is the safe failure.

What the identity check inspects (SQL has NOT been run against any live server; the
staging integration tests for the cases below are written and unexecuted):

* PostgreSQL, for the account and every role it is a MEMBER of (a NOINHERIT membership
  can still be entered with SET ROLE): superuser or `pg_write_all_data`; INSERT, UPDATE,
  DELETE, TRUNCATE (and column INSERT/UPDATE) on any non-system table, partitioned
  table, view or foreign table; CREATE on the database or any non-system schema;
  ownership of any non-system relation; superuser, CREATEROLE, CREATEDB, BYPASSRLS or
  REPLICATION; any predefined `pg_*` role not on the read-only allow-list
  (`pg_read_all_data`, `pg_read_all_settings`, `pg_read_all_stats`,
  `pg_stat_scan_tables`, `pg_monitor`, `pg_database_owner`), so roles added by future
  versions fail closed; and SET on audit parameters (PostgreSQL 15+).
* MySQL: global/schema/table/column privileges of the exact account, `*_ADMIN`, SUPER,
  FILE, and GRANT OPTION (seen as `IS_GRANTABLE=YES` on any row). Roles active in the
  session, or merely granted (`information_schema.APPLICABLE_ROLES`, activatable with
  SET ROLE), make the answers unknown. EXECUTE makes can_write unknown, because a
  SECURITY DEFINER routine can write.

**Not inspected (remaining gaps)**: PostgreSQL sequences, functions and procedures
(including SECURITY DEFINER), large objects, foreign data wrappers/servers, event
triggers, row-level security effects, default privileges; MySQL PROXY grants
(`mysql.proxies_priv`), PROCESS, and routine bodies. A pass is therefore strong
evidence, not proof, of a read-only account.

**Conservative false FAILs**: on PostgreSQL 14 and earlier the default `public` schema
lets everyone CREATE, and in MySQL schema names containing `_` or `%` are wildcards in
`SCHEMA_PRIVILEGES`; in both cases can_ddl/can_audit report yes and the check fails.

## 5. Targets, credentials, API

Register (Admin): `POST /api/dbsim-targets` with `id, displayName, engine, host, port,
dbServerHost, database, tlsMode, credentialRef, expectedIdentity, mode, labConfirmed`.
`dbServerHost` is the database server's own host/IP as the SIEM reports it (alerts are
queried for it and for the agent IP); it defaults to `host`. Unknown fields (for
example `password`) are rejected. Read (Analyst, Admin): `GET /api/dbsim-targets`,
`GET /api/dbsim-targets/{id}`, `GET /api/dbsim-runs[/{id}]`. Delete: Admin.

Finding the identity: PostgreSQL `SELECT system_identifier FROM pg_control_system()`;
MySQL `SELECT @@server_uuid`.

`tlsMode`: empty or `verify-full` verifies the server certificate (default, no private
CA option exists yet); `insecure-skip-verify` and `disable` are explicit opt-outs that
the agent reports. Whether client targets should be forbidden to use the opt-outs is an
open product decision.

### Credentials

A target holds a reference `dbcred:<name>` (lower case letters, digits, `-`), never a
secret. The agent resolves it locally, in order:

1. Environment `BAS_DBCRED_<NAME>` (name upper-cased, `-` becomes `_`) containing JSON
   `{"user":"...","password":"..."}`. A malformed variable is an error and does not fall
   through.
2. Agent-local protected store. Linux/macOS: root-owned regular file
   `/etc/bas-agent/dbcred/<name>.json`, mode no wider than 0600. Windows: DPAPI value
   `BAS_DBCRED_<NAME>_ENC` (hex) under `HKLM\SYSTEM\CurrentControlSet\Services\Audspect
   Agent\Parameters`.

An unresolvable reference is a refusal (SKIPPED), never a default account. The values
are stripped from child process environments and redacted from logs and reports.

**Windows DPAPI: known gap.** There is no command-line tool to provision the value
(`StoreDBCredential` exists in the agent but is not wired to any flag). The value uses
machine-scope DPAPI with no extra entropy, so **any local principal that can read the
registry value can decrypt it**, not only SYSTEM or Administrators. The only protection
is the registry key's ACL, which the agent neither checks nor sets: restrict the
Parameters key to SYSTEM and Administrators yourself. A manual route (unverified here):
encrypt the credential JSON with `System.Security.Cryptography.ProtectedData` using
`LocalMachine` scope, hex-encode the bytes and write them as a string value named as
above. The environment variable is the simpler supported route on Windows.

Create a dedicated account per target. For client mode it should hold only SELECT (and
catalog visibility) on what you want assessed.

## 6. Licence

dbsim is in the Advanced and Enterprise tiers, not Core (`license/tier.go`,
`tierProductLines`). The `/api/dbsim`, `/api/dbsim-targets` and `/api/dbsim-runs`
routes are refused without it.

## 7. Audit configuration per engine

dbsim reads audit evidence over SQL through the test account, because the agent is on
another host. If no readable source exists the audit dimension is SKIPPED, never a pass.

* **PostgreSQL.** The lab runs `log_statement=all`, `pgaudit.log=read,write,ddl,role`,
  `logging_collector=on` with csvlog, and exposes the csvlog through `file_fdw` as
  `dbsim_audit.pg_log(log_time, user_name, database_name, command_tag, message)`, readable
  by the test account. A customer must provide an equivalent queryable view; the log
  file itself is not read.
* **MySQL.** The lab runs `general_log=ON`, `log_output=TABLE,FILE` and the
  performance_schema statement history consumers; the agent reads `mysql.general_log` and
  `performance_schema.events_statements_history_long`. MySQL Community has no audit
  plugin; whether a customer's audit plugin preserves the marker comment is unverified.
* **Marker.** Each probe statement begins with `/* dbsim:<marker> */`. Detection grading
  requires that comment to survive into the audit log and SIEM. Verified in the lab for
  the PostgreSQL log, pgaudit, and the MySQL general log; an engine or plugin that strips
  comments gives `Unverifiable`, which is honest, not a product fault.
* **SIEM.** Only the Elastic connector can match markers (lab: Filebeat + a detection
  rule). Other connectors are Unverifiable for marker matching.

Lab files and the verification checklist: `lab/dbsim/README.md`, `lab/dbsim/E2E.md`.
What a customer must supply: audit logging with statement text, a queryable audit view or
table for the test account, and a SIEM rule that alerts on the marker.

## 8. Limitations (not built or not provable)

* No run API, no scenario-level aggregation, no per-target policy for DB-02. DB-02 is
  ERROR until a policy diff is wired and grants are on the agent wire.
* DB-12 not built. DB-08 global disablement mode not built (only a session-scoped
  statement is attempted). DB-11 controlled export not built. No mobile.
* DB-06 and DB-11 have no telemetry claim (a failed login has no statement to carry a
  marker; DB-11 is catalog reads only), so Telemetry is Unverifiable by design.
* DB-11 PASS says nothing about replication, `pg_read_all_data`, RELOAD, LOCK TABLES or
  broad SELECT.
* Live-verified on one PostgreSQL and one MySQL version in a lab, with the agent running
  as a Windows test binary against a tunnel. Not verified: a Linux agent next to the DB,
  the WebSocket production path, client mode, customer audit plugins.
* B5 (the agent's destructive-step veto): the B5 logic is unchanged. It is invoked
  via `gateStep` after the dbsim shape pre-gate, so its call site moved, and the veto
  result gained fields. Every dbsim probe is read_only or bounded_synthetic, so B5
  never has a mutation step to veto from dbsim.

## 9. Troubleshooting (real findings)

| Symptom | Cause | Action |
|---------|-------|--------|
| SKIPPED, `credential_unresolved` | No `BAS_DBCRED_<NAME>` or store entry on the agent host | Provision per section 5 |
| SKIPPED, "agent veto (catalog)" | A step was signed `destructive`; B5 vetoes all of those | Probes must be read_only or bounded_synthetic; do not sign DB probes as mutation |
| Run refused before connect, lab probe | `BAS_DBPROBE_LAB_MUTATION_ALLOWED` unset, target not `labConfirmed`, or no scenario approval | Set all three deliberately |
| Run refused, client | Setting off, check not passed, `BAS_DBPROBE_CLIENT_ENABLED` unset, or a non-read-only probe | Section 4 |
| Identity mismatch refusal | Wrong `expectedIdentity`, or you reached a different server | Re-read the identity; never copy it from the first connection |
| MySQL error 1044 on DB-06 | Throwaway account dialled with a default database it cannot use | Fixed (account now dials with none); 1044 is ERROR, never a pass |
| DB-06 ERROR `baseline_failed` | The throwaway account could not log in (pg_hba, auth plugin, TLS) | Allow the agent host to reach the account |
| DB-02 ERROR | By design (section 8); also "no grants observed" if the account cannot see grants | Use an account with catalog visibility |
| DB-07 ERROR | No classification rule name configured | Configure the rule name; generic marker rule never counts |
| Audit `unsupported` -> SKIPPED | No readable audit view/table | Section 7 |
| Alerts not credited | Marker missing, quoted mid-statement, or another run's marker | Correct by design |
| Identity check endpoint 501 | No dispatch installed | Open item |
| Lab: `sudo` drops env, old Go toolchain, PowerShell `Tee-Object` UTF-16 | Runbook gaps | See QA log |

## 10. Cleanup and safety incidents

Every fixture run ends with a verified teardown. A residual or failed cleanup is a
**safety incident**: the run grades ERROR, never PASS, and no SIEM correlation is made.
Manual removal: PostgreSQL `DROP SCHEMA IF EXISTS "dbsim_<id>" CASCADE; DROP ROLE IF
EXISTS dbsim_<id>_acct;` MySQL `DROP DATABASE IF EXISTS dbsim_<id>; DROP USER IF EXISTS
'dbsim_<id>_acct'@'%';` (add the fixture id from the report). A timeout or cancel
during account creation or revocation can leave the throwaway account (agent cannot
redial as it). After incidents, run the independent check in `lab/dbsim/E2E.md` section
8. The throwaway password is a one-run random value; on PostgreSQL it can appear in the
statement log.
