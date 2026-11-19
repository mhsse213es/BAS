# DB-04: Database Audit and Monitoring Validation — Design

Status: APPROVED for implementation (2026-11-19). Decisions in section 11 are binding. Test IDs and priorities come from the
requirement pasted by the product owner; the engine-specific detail, evidence rules and
mapping proposals are this document's.

## 1. Intent

Show whether a database's audit trail would actually answer the question "what happened,
who did it, and would we know if the trail itself was damaged?" The simulation must not
stop at reading an audit setting. Every test separates three claims:

1. **Configuration.** Is auditing set up as the policy says?
2. **Generation.** When a known action runs, does the database write the expected audit event?
3. **Retention and delivery.** Are those events kept intact, protected from tampering, and
   delivered to the monitoring system?

A configured policy does not prove generation. A generated event does not prove delivery.
Each test reports these as separate outcomes, and a pass on one never implies another.

## 2. Goals and non-goals

Goals
- Cover DB-04-01 to DB-04-18 as listed in the requirement, in priority order P0, P1, P2.
- Give each test an engine-specific implementation for PostgreSQL and MySQL. Other engines
  are out of scope until a lab exists for them.
- Record evidence that a reviewer can re-check: the exact query or file read, the value seen,
  the time, and the run id.
- Keep every mutation inside the lab, behind the existing lab confirmation.

Non-goals
- Testing a customer's production audit trail. Read-only inspection of a client target is a
  separate decision and is not proposed here.
- Proving that an alert fired. Detection rule quality is a different question from whether
  events exist and arrive; DB-04 stops at delivery.
- Forwarding real data to a SIEM. Delivery tests use the lab's configured connector only.

## 3. Constraints (from the existing dbsim platform)

- Probes are read-only unless a scenario is lab mode with `LabConfirmed` set. The lab
  mutation boundary in section 7 follows that rule; it does not add a new one.
- A test's expectations are declared in `expectations.go` per scenario and probe, and each
  scenario is signed (`.sig`). Any scenario edit needs a re-sign.
- Every step needs telemetry and detection fields (the step-contract ratchet). DB-04 steps
  declare what the SIEM should see, so the ratchet stays green.
- Results are graded PASS / FAIL / ERROR / SKIPPED. A missing capability (for example
  pgaudit not installed) is SKIPPED with a reason, never PASS and never FAIL.

## 4. Approaches

**A. Read-only inspection plus a lab-only generated action per test (recommended).**
Each test reads configuration with a read-only probe, then performs one known, harmless
action in the lab (a login, a failed login, a grant change, a DDL statement on a synthetic
table) and reads back the audit trail. Mutation happens only in the lab, only for the
generation tests, and each action is reverted at the end of the run.

Trade-off: needs a read path to the audit trail (log file, audit table, or pgaudit output)
on the agent, which does not exist yet. It answers all three claims separately.

**B. Configuration and retention only (read-only everywhere).**
Inspect settings, log file permissions, retention values and delivery configuration. Never
generate an event.

Trade-off: no mutation at all, so safe anywhere. But it cannot prove generation, which is
the claim the requirement says a configured policy does not establish. It fails the
"configuration is not proof" rule by design.

**C. Full generation in every engine, including tamper and interruption tests on a copy of
the lab database.**

Trade-off: strongest evidence, but it needs a second lab database per engine and a way to
stop and restart audit services. Too heavy for P0.

**Recommendation: A.** P0 (tests 01–08) uses A without tamper or interruption. P1 adds
retention and integrity reads. P2 (tests 13–14) is the only place that changes audit
configuration, and it is lab-only (section 7). Option B is what the spec's "configuration
is not proof" rule forbids as a complete answer, so it is kept only as the read-only
baseline inside A. Option C is deferred.

## 5. Test catalogue

Claim column: C = configuration, G = generation, D = retention/delivery.

| ID | Test | Claim | Priority | PostgreSQL implementation (proposed) | MySQL implementation (proposed) |
|---|---|---|---|---|---|
| 01 | Audit configuration inspection | C | P0 | `pg_settings` for `log_connections`, `log_disconnections`, `log_statement`, `logging_collector`; presence of `pgaudit` in `pg_extension` | `performance_schema` / audit plugin status; `general_log`, `slow_query_log` settings |
| 02 | Audit policy enabled/disabled verification | C | P0 | Read the pgaudit settings (`pgaudit.log`, `pgaudit.log_relation`) and compare to the stated policy | Compare audit plugin options with the stated policy |
| 03 | Authentication event audit coverage | G | P0 | Generate one successful login as the lab user; read the log for the connection line | Same, through the general or audit log |
| 04 | Failed login audit coverage | G | P0 | One deliberate wrong password against a lab account; read the `FATAL` authentication line | Same, through the audit log |
| 05 | Privileged account activity auditing | G | P0 | Run one statement as the lab superuser-like role; confirm it appears in the trail with the role name | Same with the lab admin account |
| 06 | Role and permission modification auditing | G | P0 | `GRANT` then `REVOKE` on a synthetic table; confirm both statements are logged | Same |
| 07 | Sensitive table access auditing | G | P0 | `SELECT` on the synthetic PII table; confirm the object name is in the trail | Same |
| 08 | DDL operation auditing | G | P0 | `CREATE`/`DROP` of a temporary synthetic table; confirm both appear | Same |
| 09 | Stored procedure execution auditing | G | P1 | Create and call a no-op function; confirm the call is logged | Create and call a no-op procedure |
| 10 | Database administrative activity auditing | G | P1 | Run one administrative command (for example `ALTER SYSTEM` read-back, or `SET` of a session parameter); confirm it is logged | Run `SHOW GRANTS` and a `SET GLOBAL` read-back |
| 11 | Audit log retention configuration | C | P1 | Read log rotation and retention settings (`log_rotation_age`, `log_truncate_on_rotation`) | Read `expire_logs_days` and the audit file rotation settings |
| 12 | Audit log integrity verification | D | P1 | Check log file owner and mode, and whether it is writable by the database service account only | Same for the audit file |
| 13 | Audit configuration tampering detection | D | P2 | Lab only: change one audit setting, confirm the change is itself recorded or detected | Same |
| 14 | Audit logging interruption detection | D | P2 | Lab only: stop the log writer briefly, confirm a gap or a service event is recorded | Same |
| 15 | Audit event delivery to SIEM | D | P2 | Read back from the enabled detection connector (`detectverify`) that the generated events from 03–08 arrived | Same |
| 16 | Audit event completeness and timestamp consistency | D | P2 | Compare the event count from 03–08 with the actions performed; check timestamps are monotonic and within a tolerance of the agent clock | Same |
| 17 | Audit coverage for application service accounts | G | P2 | Run one statement as the lab application role; confirm it is logged under that role | Same |
| 18 | Audit coverage for database exports and backups | G | P2 | Run a lab-only dump of the synthetic table; confirm the dump is logged | Same with the lab dump tool |

Notes on the catalogue
- Tests 03–08 generate events. They run in lab mode only. They are the only P0 tests that
  mutate anything, and each action is reverted at the end of the run.
- Test 15 depends on a connector being enabled. Without one the result is SKIPPED with reason
  "no enabled detection connector", not PASS.
- Test 13 and test 14 are the only tests that change audit configuration. They are lab-only
  and are the first ones dropped if the lab cannot support them.

## 6. Evidence requirements

Every test result stores:
- the probe or statement run, with the exact query text (no credentials);
- the value or log line read back;
- the run id, target id, engine and engine version;
- the agent clock time at the read and the database clock time, so timestamp checks (16)
  have both;
- the expectation that was applied, from `expectations.go`.

A PASS needs the read-back value, not a claim. A generation test (03–08, 17, 18) passes
only if the generated event is found in the trail. A test that generated nothing and found
nothing is FAIL, not SKIPPED, unless the capability is absent.

## 7. Lab-only mutation boundary

Mutation is allowed only when all of these hold:
- the target is a lab target (`mode = lab`) with a typed confirmation, as DB-01 to DB-03
  require;
- the action is one of the listed statements on a synthetic table or role;
- the action is reverted by the run's cleanup, and the cleanup result is recorded;
- tests 13 and 14 are additionally gated by an explicit scenario flag, so they cannot run by
  accident in a normal lab sweep.

Production and client targets get read-only tests only (01, 02, 11, 12). Generation tests
are refused for non-lab targets by the existing mode check, not by new code.

## 8. ATT&CK mapping (proposed; verify each ID against the current ATT&CK release before build)

| Test group | Technique | Note |
|---|---|---|
| 03, 04 | T1078 Valid Accounts; T1110 Brute Force | Failed-login generation (04) relates to brute force |
| 05, 17 | T1078 Valid Accounts | Privileged and service account use |
| 06 | T1098 Account Manipulation | Grant and revoke |
| 07 | T1213 Data from Information Repositories | Sensitive table access |
| 08 | T1485 Data Destruction (for DROP only) | DDL, mapped conservatively; review |
| 10 | T1562 Impair Defenses | Administrative change that could weaken logging |
| 13 | T1562 Impair Defenses | Audit configuration tampering |
| 14 | T1562 Impair Defenses | Interruption of logging |
| 12, 16 | T1070 Indicator Removal | Log integrity and completeness |
| 18 | T1567 Exfiltration Over Web Service / T1537 (dump) | Backup and export coverage; the sub-technique must be checked |

Sub-technique IDs are not listed because they have to be checked against the current
release. The DB-02 note on T1686 also applies: a mapping correction must be validated
before it is used in a report.

## 9. Open questions (product owner)

1. Do we need PostgreSQL `pgaudit` installed in the lab? Without it, tests 02, 03–08 on
   PostgreSQL can only read the basic log lines. Installing it is a lab change and needs
   approval.
2. Which audit path is authoritative for MySQL in the lab: the audit plugin or the general
   log? They record different things.
3. What is the agreed timestamp tolerance for test 16 (the spec does not give one)?
4. Is a read path from agent to audit file needed on staging, or is the database's own audit
   table enough? This decides whether the agent needs new file-read permissions.
5. Should tests 13 and 14 exist at all in the lab, given they change audit configuration?

## 11. Decisions (product owner, 2026-11-19)

1. **PostgreSQL pgaudit: approved** for the dedicated lab instance only. Installation,
   configuration and rollback are documented. Not a mandatory production dependency.
2. **MySQL authoritative audit path: the Enterprise Audit plugin** (or an explicitly
   supported equivalent). The general log is supplementary evidence only and never
   counts as security audit evidence.
3. **Test 16 timestamp tolerance: ±5 seconds** between the generated event and the
   observed audit timestamp. Timezone normalisation and clock sync are accounted for.
   Larger deviations are FAIL.
4. **No new agent read path for audit files.** Use database audit tables or supported
   database interfaces. Where an engine only exposes evidence through files, that limit is
   documented and file collection is a separate, separately approved capability. No broad
   filesystem permissions.
5. **Tests 13 and 14 kept, lab-only.** Controlled, reversible configuration changes on
   isolated lab instances; verify detection and restoration. Never run against production.

Build constraints: keep the per-run fixture lifecycle, synthetic data, verified cleanup and
explicit PASS / FAIL / ERROR / SKIPPED outcomes. Do not merge until the full validation
suite passes.

## 10. Build order (after approval)

1. P0 read-only tests 01, 02 (both engines), with expectations and signed scenarios.
2. P0 generation tests 03–08 on PostgreSQL, then MySQL, each with cleanup and evidence.
3. P1 tests 09–12.
4. P2 tests 13–18, starting with 15 and 16, which need only reads and the existing connector.
5. Lab run on staging, then the findings doc, as for the dbsim run spike.

Each step gets its own failing test first, as the existing dbsim work did.

## 12. Existing work this design must build on (added after review, 2026-11-19)

The design above was written without checking the repository. These already exist on main:

- **Scenario `dbsim-db04-audit-coverage`** (commit 5b289ba9, signed): a read-only check
  that reads audit settings with `read_audit_config`, runs one marker-tagged `read_roles`,
  and reads the marker back from the audit source. It covers part of test 03 and the
  general shape of 01 and 02. It is the baseline for DB-04-01 onward, not something to
  duplicate.
- **Probe `read_audit_config`** for PostgreSQL and MySQL (`agent/dbprobe/*/audit.go`).
  PostgreSQL reads `log_destination`, `log_statement`, `logging_collector`, `pgaudit.log`,
  `shared_preload_libraries`, and whether `dbsim_audit.pg_log` is readable. So pgaudit
  coverage is already a probe output; test 02 mostly needs grading on it.
- **Probe `try_disable_audit`** (DB-08 tamper resistance, `task15.go`): already a
  lab-bounded tamper probe with an allowlisted statement set. Tests 13 and 14 must reuse or
  extend it rather than add a second tamper path.
- **Scenario `dbsim-db08-audit-tamper-resistance`**: the existing tamper scenario.

**PostgreSQL audit source.** The lab exposes the csvlog through `file_fdw` as the view
`dbsim_audit.pg_log` (operator guide section 7). The database reads its own log file; the
agent gets no file access. This matches decision 4: it is a documented, database-provided
interface, and the limitation (file-backed, provisioned by the operator) is recorded here.

**MySQL audit source: conflict with decision 2.** The current MySQL implementation reads
`mysql.general_log` and `performance_schema` statement history as the audit source. Decision
2 says the general log is supplementary only and the authoritative source is the Enterprise
Audit plugin or an explicitly supported equivalent. The lab's MySQL is Community, which has
no Enterprise Audit plugin. This needs a product decision before MySQL audit tests (03–08
on MySQL) are built. Options to consider: the Percona Audit Log Plugin (a supported
equivalent for MySQL-compatible servers, needs a Percona server build in the lab), or
restricting MySQL audit tests to SKIPPED until an audit plugin is provisioned.

**Consequence for the build order.** Section 10 is revised by this section: slice 1 is
largely present (read_audit_config and the baseline scenario). The new work is the
remaining catalogue tests on PostgreSQL, the grading expectations for each, and the MySQL
decision above.

## 13. Lab baseline change (recorded 2026-11-19, run by the product owner on staging)

Container `dbsim-lab-postgres-1`, database `dbsim`:

| Setting | Before | After |
|---|---|---|
| log_connections | off | on |
| log_disconnections | off | on |

Changed with `ALTER SYSTEM`, then the container was restarted. Revert: `ALTER SYSTEM RESET
log_connections; ALTER SYSTEM RESET log_disconnections;` and restart. The `read_audit_config`
probe now reports both settings, so the baseline shows them.
