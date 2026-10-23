# Database Security Simulation (dbsim) — Mastery QA Log

Single place to check before claiming anything about the dbsim initiative
(`docs/superpowers/specs/2026-10-22-dbsim-database-security-simulation-design.md`,
plan `docs/superpowers/plans/2026-10-22-dbsim-database-security-simulation.md`,
facts in `docs/dbsim-discovery.md`). Same role as `docs/dlp-mastery-qa-log.md`:
every verification gap stays here until it is resolved by updating its own entry
with the result and date, never by deleting it.

Branch `worktree-dbsim`, nothing pushed. Written 2026-10-23 on a Windows dev host
with **no Docker, no MySQL and no reachable PostgreSQL credential**.

## Milestone entry: Tasks 1-13 (Phase 4 gate)

### Staging results 2026-10-23 (supersedes the "Bottom line" below where they differ)

Run by the user on staging against the lab stack (`docker compose -p dbsim-lab`:
PostgreSQL 16.4 + pgaudit, MySQL 8.0.40 general_log TABLE+FILE, Elasticsearch/
Kibana/Filebeat 8.15.3), commit `04078f86` (branch `dbsim-lab-staging`), harness
run from a Windows dev host through an SSH tunnel with a Windows-built agent test
binary (`go test -c -tags dbsim_e2e`), not a Linux agent near the database.

* **Marker survival: VERIFIED on both engines.** `smoke.sh` PASS for postgresql
  (simple), postgresql-extended (psql `\bind`) and mysql: the leading
  `/* dbsim:<marker> */` reached the audit log, Filebeat extracted it, the rule
  fired and the alert's raw data carried it. The Go drivers' prepared path is
  covered by the `dbsim_integration` tests, which PASSED (postgres 86.7 s,
  mysql 130.1 s) incl. live audit-source reads, fixture lifecycle, DB-05/DB-09
  read probes at caps 1/5/1000, and edge data (counts 5/4/4096).
* **End-to-end: PASSED on PostgreSQL (126.9 s) and MySQL (115.2 s)** via
  `TestE2E_*_SignedScenarioToCorrelatedRecord`: DB-01, DB-02 `read_roles`,
  DB-03 (Enforcement Blocked), DB-04 (`read_audit_config`; tagged `read_roles`
  with audit `found` + alert), DB-05 and DB-09 all PASS with Telemetry Present,
  Response Alerted, match `exact_marker`. Alerts carrying other runs' markers
  were correctly NOT credited (records say so). DB-02 `read_grants` is ERROR by
  design (R-AJ, no policy diff): DB-02 excessive-grant detection is still NOT
  produced end to end.
* **Independent cleanup check: VERIFIED 2026-10-23** (`E2E.md` §8, run by the
  user on staging after both E2E runs). PostgreSQL: only `dbsim_audit` schema
  and roles `dbsim_lab`, `dbsim_test`. MySQL: databases `bas_dbsim`, `dbsim`
  plus system databases; accounts `dbsim_lab`, `dbsim_test` only. No fixture
  schema/database/role/account left on either engine, matching the agent's own
  `CleanupStatus ok`. (End state after normal runs only; failure-mid-fixture
  cleanup is covered by unit tests and the DB-06 limitation F3 below.)
* **Still unverified:** negative case (marker quoted mid-statement must not alert; unit-tested only);
  Linux agent next to the DB; WebSocket/enrollment/run API/`dbsim_runs` store
  (Task 16); PostgreSQL `dbsim_audit.pg_log` layout was exercised by the passing
  live audit tests but README checklist items 4, 9a, 10-12 outputs were not
  collected item by item.
* Setup problems hit (runbook gaps, not product defects): `sudo` drops exported
  env (run `setup.sh` without sudo); staging Go toolchain too old for the agent
  module (build elsewhere); placeholder `<...>` values pasted literally; PowerShell
  5.1 `Tee-Object` writes UTF-16 output files.

### Bottom line (written before the staging run; read with the results above)

**The end-to-end proof is NOT DEMONSTRATED on PostgreSQL and NOT DEMONSTRATED
on MySQL (including DB-05 and DB-09).** No signed scenario has ever been run
against a real database, no audit event has been read from a real audit source,
no real Elastic alert has been fetched through the connector, and no
`Record` has been produced from real evidence. What exists is code that is
unit-tested against fakes, a lab stack that is only statically checked, and an
E2E harness plus runbook (`lab/dbsim/E2E.md`) that has not been run against the
lab. Spec §9 makes this proof the Phase 4 exit; per the plan, Tasks 14+ and any
catalog expansion or client pilot wait for the user's review.

The central technical risk is untested: **whether the leading
`/* dbsim:<marker> */` comment survives into each audit source** (PostgreSQL
`statement:` / `execute <name>:` / csvlog / pgaudit rows; MySQL general log TABLE
and FILE for text and prepared statements, performance_schema SQL_TEXT) when
the Go drivers use extended/prepared protocols. If it does not, that engine's
result is `Unverifiable`, which is a legitimate outcome, not a product failure.

### What was built (Tasks 1-13)

| Task | Built |
|---|---|
| 1 | Discovery (`docs/dbsim-discovery.md`) and contract pins; spec amended A1-A10 |
| 2 | Wire types (agent `protocol` + orchestrator mirror), probe catalog, golden vectors |
| 3 | Safety gates: `CheckSpec`, `Authorize`, row budget, deadline (fail closed) |
| 4 | PostgreSQL adapter (pgx, READ ONLY txn, marker comment, redaction) |
| 5 | MySQL adapter (go-sql-driver, READ ONLY txn, TLS/env isolation); MariaDB deliberately unsupported |
| 6 | Agent `dbprobe` executor, credential-ref resolver (`BAS_DBCRED_*`), step-shape pre-gate before B5, child-env stripping |
| 7 | `dbsim` product line (license), gate prefixes, scenario step shape, execclass entries, `dbbuild.BuildSteps`, signed DB-01/02/03 |
| 8 | Result rendering: `dlpreport.Record` + PASS/FAIL/ERROR/SKIPPED grading with separated dimensions, `dbsim_runs` store |
| 9 | Audit collectors (PG `dbsim_audit.pg_log`, MySQL general_log / history_long), `read_audit_config`, signed DB-04 |
| 10 | Synthetic fixtures with verified cleanup, safety-incident fields |
| 11 | Lab stack (compose, pgaudit, MySQL general log, Filebeat, marker rule, seeds, smoke) — **static only** |
| 12 | Marker correlator over `detectverify` (`dbsim/dbcorrelate`), additive Elastic `source` key (A1), R-U |
| 13a | `suspicious_read` (DB-05) and `bounded_synthetic_read` (DB-09), fixture-table resolution, signed scenarios |
| 13b | `dbsim/dbrun` pipeline (agent result + correlator + audit -> Outcome/Record/report), notes parser, audit grading, DB-02 empty-observation guard, minimised alert refs, E2E harness (`dbsim_e2e`) with an agent runner, fake pipeline tests, this log, `lab/dbsim/E2E.md` |

### Verification status

**VERIFIED (run on this host, 2026-10-23):**
`go test -count=1 -p 1` over `orchestrator/internal/dbsim/...`, `detectverify`,
`dlpreport`, `license`; `internal/scenario` filtered to DB/signature/tamper
tests; agent `dbprobe/...` and `protocol` (Task 13a run); `go vet` for dbsim,
detectverify, `internal/verification` (proves no import cycle; R-AG), with
`-tags dbsim_e2e`, and with `-tags dbsim_integration`; `go build ./...` in both
modules; agent cross-vet for linux/darwin; the import-guard test. In addition
(13b): the no-database E2E *plumbing* test `TestE2EPlumbing_SignedEnvelopeReachesAgentExecutor`
ran against a Windows build of the agent test binary: a signed scenario was
compiled by `dbbuild`, wrapped in an envelope signed with `internal/cmdsigning`,
accepted by the agent's real `verifyCommandEnvelope`, gated and executed by the
real `execStep`/`executeDBProbe` (which refused with `credential_unresolved`
because no credential was provisioned), graded SKIPPED by `dbrun.Evaluate`, and
a tampered envelope was rejected by the agent verifier. This shows the harness
plumbing and the orchestrator/agent envelope compatibility; it touches no database.

**NOT VERIFIED (needs a live DB / Elastic / MySQL / Docker):** everything else,
in particular every SQL statement against a real engine, every audit-source
query, the lab stack, Filebeat extraction, the detection rule, the Elastic
connector against a real Elasticsearch (A1 `source` key), alert latency, the
`dbsim_runs` store against Postgres, and the API/RBAC/product-gate tests in
`orchestrator/internal/api` (TestMain starts Docker). The three
`TestE2E*`/`TestPipeline*` groups: `TestPipeline_FakeAgentFakeConnector_*` ran
(fakes only); `TestE2E_PostgreSQL_…` and `TestE2E_MySQL_…` were only compiled
and shown to skip without configuration and to fail on a partial configuration.

Per task: 1 contract pins ran against existing code (VERIFIED); 2, 3 unit +
golden (VERIFIED); 4 PG adapter: unit with fakes VERIFIED, live integration
tests written NOT executed; 5 MySQL: 35 unit tests VERIFIED, 4 live NOT
executed; 6 agent: unit VERIFIED, Windows DPAPI/HKLM read and POSIX file-mode
tests NOT exercised (compile-checked); 7 unit VERIFIED, api package tests NOT
run; 8 unit VERIFIED, store only compiled; 9 unit with fakes VERIFIED, all real
audit-source behaviour NOT; 10 unit VERIFIED, fixture integration tests NOT
executed; 11 static parse checks only; 12 unit VERIFIED, no real Elastic; 13a
unit VERIFIED, integration NOT executed; 13b fake pipeline VERIFIED, E2E NOT.

### Findings of Task 13b (code that changed existing behaviour)

1. **Correlator bug found and fixed (46879f3d).** The agent writes the marker as
   `/* dbsim:<marker> */`; the Task 12 token-boundary rule rejected a marker
   preceded by `dbsim:` (the colon is a token character), so a real alert would
   have graded `ambiguous`/`Unverifiable`. Task 12's tests used a bare marker.
   Fixed (only the exact `dbsim:` prefix word is tolerated) with a test using the
   real form. This is the kind of defect only the real statement shape exposes;
   expect more from the live run.
2. **`Response=Alerted` mapping (decision for review).** The correlator always
   returned `Response=NotTested`; the plan's milestone wants `Alerted`. `dbrun`
   sets `Alerted` only for a marker-correlated alert that is `Present` (never for
   Delayed/Ambiguous) and rewrites the limitation to say that no case,
   escalation or remediation was assessed. The correlator itself is unchanged.
3. **Audit grading (spec §7).** Added an `Audit` dimension and `DimSkipped`:
   `found` needs an event carrying this run's marker (the agent's claim alone is
   not believed); `unsupported` is SKIPPED (never a pass); `absent` is FAIL (the
   agent reports absent only when the source was healthy and caught up);
   `incomplete`/`error`/empty are Unverifiable. DB-04's config step grades from
   the `audit_config: covered|partial|none` note (`none` FAIL, `partial`
   Unverifiable). A `Present` alert whose audit slice does not back it becomes
   `Telemetry=Incomplete`. These are additive; existing report tests unchanged.
4. **DB-02 empty-observation guard.** `ScenarioMeta.RequireObservation` +
   `Outcome.Observed`: zero grants observed is ERROR with the limitation "no
   grants observed: account may lack catalog visibility", never PASS.
   **Gap:** the agent's wire result carries only `RowsRead`, not the grant rows,
   so the orchestrator cannot yet compute `dbsim.Report(policy, grants)`; the
   policy diff itself is not wired end to end (no non-test caller of `Report`).
   The guard works from the row count or an explicit `GrantsChecked`.
   **Ruling R-AJ (review fix round 1): DB-02 never grades PASS today.**
   `ScenarioMeta.RequirePolicyDiff` + `Outcome.Diff`: listable grants are not a
   comparison. Without a performed `DiffReport` the policy dimension is
   Unverifiable and the run is ERROR, with the limitation "policy diff not
   performed; grants were observable (N) but not compared to a stated policy".
   **Expected DB-02 outcome today: ERROR (Unverifiable): grants observed, policy
   diff not wired. DB-02's excessive-grant detection is NOT produced end to end.**
   A supplied `DiffReport` already decides (no deviations PASS, deviations FAIL);
   nothing fabricates one. This deliberately changed an earlier test that asserted
   PASS for 2 rows. The DB-02 scenario description was corrected to say the
   comparison is not wired and re-signed.
   Minor 7 (deliberate): an empty observation together with an absent alert
   grades ERROR (unobservable) before FAIL.
   Audit events additionally must BEGIN with the exact `/* dbsim:<marker> */`
   comment (after `statement: ` / `execute <name>: `) and not be a meta/lookup
   statement; a `found` status with zero such events is downgraded to
   Unverifiable.
5. **Minimised evidence.** `Correlation.AlertRefs` keeps id, time, rule, host and
   a redacted excerpt of at most 512 bytes (at most 5 alerts); raw alert JSON is
   never stored. Agent notes, audit events and error text are bounded and
   redacted again in `dbrun`.
6. One shared notes parser, `dbsim.ParseNotes` (`key=value` plus the
   `audit_config:` line), as the 13a review asked.

### Staging queue (everything unverified; run `lab/dbsim/E2E.md` first)

Record each result against its item, with date.

A. **Lab stack** (`lab/dbsim/README.md`, 15-item checklist plus 9a-9c): images
   exist and pull; ES security bootstrap; PG init scripts exec bit
   (`git ls-files -s lab/dbsim`); `file_fdw` view `dbsim_audit.pg_log` layout and
   freshness; **marker-comment survival** in every audit path (README item 5);
   MySQL general log TABLE+FILE, consumers, grants; Filebeat extraction of
   `dbsim.marker`/`is_meta`/`is_audit_lookup`; rule fires, forgery negative test
   (9b), exclusion set (9c); alert document contains `message`/`event.original`/
   `host.*`; latency vs the detection window; `detectverify` against the live lab.
B. **Task 4 PostgreSQL:** SQLSTATE 25006 on write in READ ONLY; `set_config`
   inside a READ ONLY txn; `pg_control_system()` executable; `role_table_grants`
   visibility; cancel/timeout behaviour; TLS verify-full with private CA (no
   private-CA option exists: lab uses `disable`); `$1` to `set_config` and
   parameterised `LIMIT $1` under `QueryExecModeExec`.
C. **Task 5 MySQL:** `START TRANSACTION READ ONLY` write error 1792; session
   `max_execution_time` in a READ ONLY txn; `LIMIT ?` as a prepared statement;
   error 3024; `caching_sha2_password`/`mysql_native_password` over the chosen
   TLS mode; `TABLE_PRIVILEGES` visibility; `mysql.user` columns on 5.7/8;
   `program_name` connection attribute.
D. **Task 6:** POSIX credential file-mode test (Linux), Windows HKLM
   `BAS_DBCRED_*_ENC` read and DPAPI provisioning, B5 loop wiring in `agent.go`.
E. **Task 8:** `dbsim_runs` DDL on real Postgres (`gen_random_uuid()` default,
   CHECK, UNIQUE, `$7::jsonb`, SQLSTATE 23505 handling, list filter).
F. **Task 9:** real `pg_log` refresh and csvlog contents under
   `log_statement=all`; pgx timestamptz encoding; MySQL
   `NOW(6)-Uptime+TIMER_START/1e12` conversion; `performance_schema.global_status`
   readability; `NO_BACKSLASH_ESCAPES` effect on LIKE; LIKE cost over a large
   csvlog (30 s bound); `performance_schema` privileges for the test account.
G. **Task 10:** MySQL `CREATE SCHEMA` needs global privileges; utf8mb4/LONGTEXT
   DDL; PG `CREATEROLE`; identifier length limits (63/64); whether
   `InspectFixture` sees objects the lab account created; real lifecycle of every
   catalog fixture.
H. **Task 12:** Elastic `_source` dotted-name filtering; `host.name`/`host.ip`
   query matches; alert `@timestamp` (rule run time) lag against the window; 16 KiB
   source cap sufficient; marker punctuation tolerance matches how the lab
   renders the comment.
I. **Task 13a:** `SELECT * FROM "dbsim_x"."t" LIMIT $1` (pgx) and
   `LIMIT ?` (MySQL prepared); lab account can SELECT its fresh fixture schema;
   byte accounting is a heuristic; DB-05/DB-09 need lab-mode registry entries
   with `LabConfirmed` and a credential that can create schemas.
J. **Task 13b:** the E2E itself on both engines (all six scenarios); the agent
   test-binary harness vs the production WebSocket path; whether
   `Response=Alerted` should stay; whether `absent` => FAIL is right for a
   comment-stripping audit path (the limitation says to check the source first).

### Spec amendments and rulings reviewers should know

Spec §10b **A1** additive Elastic `source` key (Task 12; other connectors
untouched and Unverifiable for marker matching); **A2** never use
`VerifyResult.Verdict`; **A3** mirrored wire types + golden vectors, agent code
in `agent/dbprobe`; **A4** the agent verifies the signed `CommandEnvelope`, not
the `.sig`; **A5** dedicated `dbsim_runs` store; **A6** exec-class mapping
(read_only -> non_destructive, bounded_synthetic -> potentially_destructive,
mutation -> destructive); **A7** credential references via `BAS_DBCRED_<NAME>`;
**A8** drivers build with `CGO_ENABLED=0`, real garble build on staging, legacy
go1.20 agent cannot run dbsim steps; **A9** the DLP-DB export scenario is
unrelated; **A10** license/gate/scenario plumbing.
Rulings: **R-U** a definite FAIL beats an unverifiable dimension; **R-Z**
fixture-aware probes take a bare table name, the adapter resolves the schema;
**R-AG** the correlator lives in `dbsim/dbcorrelate` (and the wiring in
`dbsim/dbrun`) so `internal/dbsim`, `internal/db` and `testutil` never reach
`detectverify` (guard test `importguard_test.go`); **R-AH** `strong_contextual`
needs principal AND run id (stricter than the brief); **R-AI** any step with a
fixture is gated as a mutation, so DB-05 (`suspicious_read`) was reclassified
`bounded_synthetic` and needs lab confirmation, scenario mutation approval and
the agent-local `BAS_DBPROBE_LAB_MUTATION_ALLOWED`.

### Known limitations

* Reconnect-for-teardown after a probe timeout: the fixture schema can leak and
  is reported `failed` (safety incident).
* MySQL lost-ack orphan: a non-context error after the server executed a `CREATE`
  is treated as not created, so an orphan schema is possible (PG is transactional).
* `strong_contextual` is stricter than the brief (principal AND run id).
* A truncated alert source with no visible marker is unattributable, even if a
  foreign marker is visible.
* A quoted literal `'dbsim:<marker>'` inside another user's statement also
  matches the correlator's marker form. Risk negligible: the marker has 24
  random hex characters, is issued per run and is not visible to other database
  users; attribution additionally rests on the exact post-filter.
* Ruling R-AK: the DB-02 policy requirement is default-safe. `dbrun.Evaluate`
  forces `RequirePolicyDiff` for `read_grants`, and the grading layer treats any
  Outcome whose `ProbeID` is `read_grants` the same way, so a caller that omits
  the flag still gets ERROR (Unverifiable) without a performed `DiffReport`. A
  denied `read_grants` is exempt (the denial is the observation).
* The lab detection rule is a hint (any DB user can start a statement with the
  marker comment); the orchestrator's exact post-filter is the authority.
* DB-05's 25-row cap is a code constant, not signed per scenario.
* Scenario-level aggregation (one Record per scenario from several step results)
  and the product run API/target registry are Tasks 14-16; `dbbuild.BuildSteps`
  has no production caller yet, and `dbrun.Evaluate` grades one step at a time.
* DB-02's policy diff is not wired (grant rows are not on the wire); only the
  empty-observation guard is.
* Expectations used by the harness (`support_test.go`) are lab-calibrated test
  data, not product policy.
* MariaDB is unsupported by design (no `server_uuid`/`max_execution_time`).

### Pre-existing repository issues NOT caused by dbsim

* 25 existing scenarios have invalid signatures at the branch base (origin/main
  `3b7fb02c`): `signer.go verify-all` shows them; `TestBuiltinScenarios_AllHaveValidProductLine`
  is red at base (loads fewer scenarios than the pinned count) and a dlpfixture
  drift test fails for the same cause. None are dbsim scenarios; their owners
  must re-sign them.
* `BAS_AGENT_SECRET` and `BAS_PROXY_*` are not stripped from child process
  environments by existing agent code (a scenario step that dumps its
  environment could exfiltrate the agent secret). dbsim added a `childEnvironment`
  helper for `BAS_DBCRED_*`/`BAS_DBPROBE_*`; applying it to those prefixes is a
  one-line change per site (ruling R-N also leaves the fixed built-in commands
  inheriting `BAS_DBCRED_*`).
* The orchestrator `internal/api` TestMain starts a Docker Postgres even with
  `-run`, so API-layer tests cannot run on a host without Docker.

### Decisions left to the user

* **Licensing tier:** dbsim is in Advanced and Enterprise, not Core (same as AD);
  changeable only in `orchestrator/internal/license/tier.go` (`tierProductLines`).
  The working tree also holds uncommitted edits to `license/tier*.go` and
  `api/product_gate*.go` that are not part of these commits.
* **Whether to push** the branch (nothing has been pushed).
* Whether `Response=Alerted` on a correlated alert is acceptable (item 2).
* Whether `absent` audit => FAIL is acceptable before the comment-survival
  question is answered.
* Whether a Percona `audit_log` follow-up is wanted if the MySQL general log
  strips the comment.

### Next step

E2E.md ran on staging 2026-10-23 (see "Staging results" above). Remaining before
Tasks 14-16 are accepted as built on solid ground: the independent cleanup check
(`E2E.md` §8). The user directed work to continue with Task 14 on 2026-10-23.

## Task 14: DB-06 account revocation, DB-07 sensitive-data classification

Built on commit `88e6e2e6` (staging E2E PASS base). Nothing in this section has
touched a live database or SIEM: every behaviour below is **unit/fake tested
only** unless it says VERIFIED, and the live tests are written, compile
(`go vet -tags dbsim_integration`, `-tags dbsim_e2e`) and have NOT been run.

### What was built

* **DB-06 `auth_after_revoke`** (class `bounded_synthetic` since fix round 3 / R-AO, originally `mutation`; fixture `empty`, both engines).
  The adapter creates a throwaway LOGIN account `dbsim_<fixture id>_acct` (PG
  `CREATE ROLE ... LOGIN PASSWORD`, MySQL `CREATE USER ... IDENTIFIED BY`; a random
  password generated in the agent process, hex only, added to the redaction set
  and never logged, returned, noted or put on the wire), opens a NEW connection
  as it and runs one marker-tagged statement (baseline), revokes it (PG `ALTER
  ROLE ... NOLOGIN`, MySQL `ALTER USER ... ACCOUNT LOCK`) and opens a NEW
  connection again. A refusal classified by SQLSTATE 28000/28P01 or the message
  "is not permitted to log in" (PG) or error 1045/3118 (MySQL) is `Denied`
  (`auth_failed`) => Enforcement Blocked; a connection that works is Allowed;
  anything else is `reconnect_error` => Unknown => ERROR, never Blocked. The
  account is registered in the adapter's created-objects tracking
  (`acctState.mayExist`, set before the CREATE, cleared when the server refuses
  the CREATE): `Cleanup` drops exactly that name and only then, and
  `InspectFixture` lists `role:`/`user:` `dbsim_<id>_acct` so `VerifyClean`
  reports a leftover as residual => `ErrSafetyIncident` (existing path). No
  configured, target or BAS account is ever created, altered or revoked (tests
  assert every account-addressing statement names only the throwaway account).
  A typed note `revoke_steps=create=<v>,baseline=<v>,revoke=<v>,reconnect=<v>` says
  which step produced which outcome; `dbsim.Notes.Revocation()` parses it
  strictly.
* **Grading** (`dbsim/report.go`): Enforcement is Blocked only if create,
  baseline and revoke are `ok` AND reconnect is `denied` AND the result agrees;
  contradictory or missing evidence => Unknown (ERROR). PASS therefore needs
  baseline OK + denial recognised + cleanup ok. Keyed on `Outcome.ProbeID`
  (default-safe, like R-AK). **Telemetry honesty:** DB-06 is never correlated
  (`dbrun.Evaluate` forces ExpectDetection/ExpectResponse off, no SIEM lookup),
  `ToRecord` pins Telemetry Unverifiable / Response NotTested whatever a caller
  supplies, and every record carries the limitation that a failed login has no
  SQL statement to carry the marker and the marker rides on the baseline
  statement only. The scenario description says so plainly.
* **DB-07 `read_classified_fixture`** (class `bounded_synthetic`, fixture
  `classified-pii`, both engines): the same bounded unfiltered SELECT as DB-05/09
  but fixed to `customers_pii` of the `classified-pii` fixture (no table param
  exists; a param can never override the fixed table), 25-row hard cap, READ ONLY
  transaction, counts only. Reuses `ActiveFixture` resolution (R-Z).
* **Rule-specific classification verdict** (`dbsim.ClassifyByRule`, wired in
  `dbrun.Evaluate`; policy data `StepInput.ClassificationRuleName`): Correct only
  when a marker-correlated (exact/strong) alert came from the named rule;
  Incorrect only when the read was allowed, on-time marker-correlated telemetry is
  Present and no alert came from that rule; Unknown for absent/delayed/ambiguous/
  unverifiable telemetry (never Incorrect from missing evidence); NotEvaluated
  when no rule is configured (default), the rule is the generic marker rule
  (`BAS dbsim marker in database audit event` never counts), or the read was
  denied/incomplete. `ExpectClassification` is forced on for the probe and any
  verdict other than Correct/Incorrect grades the dimension unverifiable, so
  DB-07 without a classification rule is ERROR, never a PASS.
* **Wire/catalog:** no new wire fields (the step note rides in the existing
  `Notes`). `ProbeDef`/`ProbeRegistryEntry` gained `RequiredFixture` and
  `FixedTable`; both catalog goldens regenerated (byte-identical across modules,
  no trailing newline); agent validation, gate, executor binding and orchestrator
  Authorize/builder (`checkFixture`) all enforce the one required fixture, lab
  only, no table param.
* **Scenarios:** `dbsim-db06-account-revocation` (T1078, risk high; originally described as a mutation class, see Fix round 3) and
  `dbsim-db07-sensitive-classification` (T1213, risk medium), both signed with
  `orchestrator/scripts/signer.go` (the private key is gitignored and not
  committed). Scenario-count pin 113 -> 115.
* **Lab (UNVERIFIED, ~45 lines):** `lab/dbsim/elastic/rule-classified.json`
  (second detection rule, name `BAS dbsim classified-fixture read`, KQL on the
  keyword/boolean field `dbsim.touches_classified`), the field extracted by both
  Filebeat `script` processors in the style of `dbsim.is_meta` (no reliance on text
  analysis), mapped boolean in the index template, `setup.sh kibana` creates both
  rules, README checklist items 16-19, E2E.md sections 5, 6 and 8.
* **Tests:** new tests: agent `dbprobe` 8, postgres 14, mysql 14, executor 4,
  fixtures 1; orchestrator `dbsim` 6, `dbbuild` 3, `dbrun` 10 (including
  `TestClassificationOutcomeCorrectWhenRuleFires`, `...IncorrectWhenRuleSilent`,
  `...NotEvaluatedWhenNoRuleConfigured`, `...UnknownWhenTelemetryUnverifiable`,
  `...GenericMarkerAlertDoesNotCountAsClassification`). Live tests written, NOT
  run: `postgres|mysql/revoke_integration_test.go` (tag `dbsim_integration`) and
  the DB-06/DB-07 steps in `dbrun/e2e_test.go` (tag `dbsim_e2e`).

### Verified here vs staging-unverified

Verified on this host (fakes only): all unit tests above; `go build ./...` and
`go vet` (orchestrator `dbsim`, `detectverify`, `verification`, tags `dbsim_e2e`,
`dbsim_integration`); agent cross-builds for windows/linux/darwin; the import-guard
test; both catalog goldens identical; `signer.go verify-all` lists exactly the same
25 pre-existing invalid signatures and none of ours (the scenario engine now loads
90, was 88: the known `TestBuiltinScenarios_AllHaveValidProductLine` red is
unchanged in cause: "loaded 90 want 115" instead of "loaded 88 want 113").

**UNVERIFIED (staging queue):** everything that needs a database or the SIEM:
CREATE ROLE/USER privileges for `dbsim_lab`; `pg_hba.conf`/TLS/auth plugin letting
the throwaway account connect from the agent host (a baseline failure is reported
`baseline_failed`, never a pass); the exact refusal SQLSTATE/number after
NOLOGIN/ACCOUNT LOCK; anonymous or host-specific MySQL accounts shadowing
`'name'@'%'`; whether `InspectFixture` sees the account (`pg_roles`, `mysql.user`);
the second Filebeat field and rule actually firing, and the alert's rule name
reaching `MatchedAlert.RuleName` unchanged (the DB-07 verdict is an exact name
comparison); MySQL comment survival for DB-07 (else Unknown/ERROR).

### Honest limits and risks

* DB-06 makes **no telemetry claim**. Failed logins are not expected in the audit
  sources; nothing proves the denial was detected. Only Enforcement is graded.
* On PostgreSQL the one-run random password appears in the server statement log if
  `log_statement` records DDL (`CREATE ROLE ... PASSWORD '<hex>'` cannot take a bound
  parameter). It belongs to an account dropped at the end of the same run, but it
  does reach the lab's audit/SIEM text (MySQL is documented to rewrite account
  passwords in its general log; not verified here). Pre-hashing a SCRAM verifier client-side would avoid this; not done.
* The agent's audit readback for DB-06 filters on the configured (admin)
  principal, so the baseline statement (run by the throwaway account) is not
  counted as audit evidence; DB-06 does not expect audit.
* `auth_after_revoke` runs create/baseline/revoke/reconnect under ONE spec
  deadline (`timeout_sec` 60); a timeout mid-run marks the adapter broken and the
  teardown then reports a safety incident rather than guessing (the existing known
  limitation of every fixture).
* DB-07's Incorrect needs a marker-correlated alert from SOME other rule as proof
  the pipeline saw the statement; with no alert at all the verdict is Unknown by
  design (a broken pipeline looks identical to a silent rule).
* A classification-rule alert is matched by rule NAME. If the connector reports
  another field, every run is Incorrect/Unknown, never a false Correct.

### Fix round 1 (independent review: approved with fixes)

* **F1** A fixture-gated probe (`auth_after_revoke`, any probe with a fixture
  param or required fixture) is never a PASS without a POSITIVE cleanup status:
  empty and `not_applicable` now grade ERROR "fixture cleanup unverified" (non-fixture
  probes unchanged; DB-05/09 with `ok` still PASS).
* **F2** `ClassifyByRule` returns Unknown, not Incorrect, when a correlated alert
  has an empty rule name, when a name matches the configured rule only after
  case-folding/trimming (misconfiguration), or when strong-contextual alerts were
  set aside behind exact-marker ones (`dbcorrelate.Result.StrongDropped`).
  Incorrect remains only for a clean case-exact miss with on-time Present,
  exact/strong telemetry. Correct is a rule-identity verdict and is ALSO granted
  when telemetry is Delayed (the rule did fire; latency is graded by detection).
* **F3 Known limitation:** a timeout/cancel during the DB-06 CREATE or REVOKE can
  leave the throwaway account on the lab database, because Cleanup cannot redial
  as that account (its password is blanked after Connect) and the adapter is
  marked broken. This is escalated as a safety incident (fail closed). Manual
  drop: `DROP ROLE IF EXISTS dbsim_<id>_acct;` (PostgreSQL) or
  `DROP USER IF EXISTS 'dbsim_<id>_acct'@'%';` (MySQL).
* **F4** Wording corrected: the throwaway account is created with no privileges
  granted beyond defaults (PUBLIC), not "no privileges beyond connect"
  (scenario re-signed).
* **F5** The throwaway password appears in server statement logs and, in the lab,
  the `dbsim-audit-*` index (`CREATE ROLE/USER ... PASSWORD` cannot bind it). It is
  a one-run random value for an account dropped in the same run; the statement
  carries no marker, so no rule fires on it. Nothing more is claimed.
* **F6** `ToRecord` states "Classification not evaluated: no classification rule
  configured/applicable" when a classification was expected but not evaluated and
  no "Classification not evaluated" sentence is already present, so a direct call
  outside `dbrun.Evaluate` still explains itself and the Evaluate path carries
  exactly one such sentence (fix round 2).

### Fix round 2

* **M1** `dbsim.CleanupUnverified` is now the single exported rule shared by
  `grade()` and the pipeline's `cleanupIncident`. A fixture-gated probe without a
  positive cleanup status is incident-equivalent in `Evaluate`: no SIEM correlation
  and no classification verdict (Classification stays NotEvaluated), next to the
  ERROR grade. Non-fixture probes (DB-01..04) are unchanged.
* **M2** The generic classification line is not duplicated when `Evaluate` already
  recorded one.

### Fix round 3 (first live staging run)

**What the live run showed.** DB-01..05 and DB-09 PASS on PostgreSQL and MySQL.
DB-06 was SKIPPED on both engines: "gate refusal (policy/scope decision): agent
veto (catalog): " with empty stderr, and the E2E harness then panicked (nil
`ex.DBProbe` in `checkStep`), so DB-07 never ran.

**Root cause (B5 finding).** `auth_after_revoke` was registered as class
`mutation`, which the orchestrator signs as ExecutionClass `destructive`. The
agent's pre-existing B5 gate (`evaluateB5Gate`, called by `gateStep`) vetoes every
signed `destructive` step unconditionally (source `catalog`) and has no approval
path, so no `mutation`-class dbprobe could ever run on a real agent. Our unit
tests called the executor directly and never pushed a mutation-class step through
`gateStep`. B5 was NOT weakened or bypassed.

**R-AO.** `auth_after_revoke` is `bounded_synthetic` in both registries (signed
`potentially_destructive`, action key `dbprobe_bounded_synthetic`): it only
creates, locks and drops its own throwaway account, like the fixture lifecycle
DB-05/09 already treat as bounded_synthetic. R-AI is independent of class and
still holds: agent `CheckSpec` gates on `class != read_only || FixtureID != ""`
and refuses fixture-aware probes outside lab mode; orchestrator `Authorize` gates
on `class != read_only || Fixture || fixtureAware` (LabConfirmed and
MutationApproved) and refuses client mode; `dbbuild.checkFixture` and the
executor's fixture binding key on `RequiredFixture`. No gate depended only on the
class being `mutation`. Tests prove it (agent `TestTask14StepsPassRealGateThenExecutor`
for both probes through the real `gateStep`, plus the existing gate tests).

**Regression guards.** Agent `TestEveryCatalogProbeIsRunnableThroughB5` fails for
any registered probe the real `gateStep` vetoes (a future true `mutation` probe
fails it with a message requiring a conscious B5/approval decision). Orchestrator
`TestNoRegisteredProbeSignsDestructiveWithoutAllowlist` (allowlist currently empty).

**Harness and reporting.** `checkStep` is nil-safe (agent veto reported as a normal
error, later sub-tests run). The pipeline's veto text now includes the signed
action key and ExecutionClass (`AgentExec` gained `VetoedActionKey` /
`VetoedExecutionClass`), so "agent veto (catalog): " can no longer be empty.
Scenario `dbsim-db06-account-revocation` reworded (no "mutation" class) and re-signed.

**OPEN DESIGN QUESTION for the user (not decided here).** Task 15's DB-08, DB-10
and DB-11 will hit the same B5 wall if they are true mutations (real state change
on the target, signed `destructive`): B5 vetoes them with no grant path. Options
include keeping them lab-fixture-scoped and bounded_synthetic like DB-06, adding
an explicit approval/grant design to B5 (a security-relevant change), or dropping
them. DB-06 itself has NOT been re-run live after this fix.

### Fix round 4 (second live staging run)

**What the second live run showed (code 3aabb921, lab unchanged).**

* PostgreSQL: all PASS, including DB-06 (Enforcement Blocked, Telemetry
  Unverifiable, Response NotTested) and DB-07 (Classification Correct, exact_marker,
  Present/Alerted). B5 fix (R-AO) confirmed live.
* MySQL: all PASS including DB-07 (Correct), EXCEPT DB-06 `auth_after_revoke` =
  ERROR (`baseline_failed`): `revoke_steps=create=ok,baseline=failed,revoke=skipped,
  reconnect=skipped`, detail `Error 1044 (42000): Access denied for user ... to
  database 'dbsim'`. The harness correctly reported ERROR, not a pass.

**Root cause and fix.** The throwaway account is created with no privileges (by
design, R-AL), but its baseline and post-lock connections named the target's
default database `dbsim`. MySQL refuses (1044) a connection that names a default
schema the account cannot use, whereas a USAGE-only account may connect with none;
PostgreSQL has no such rule. `Adapter.dialAs` now dials the throwaway account with
an empty `Database` (on a copy; `a.target` and the main connection keep theirs).
No privilege is granted, so "no privileges granted beyond defaults (PUBLIC)" stays
true. The baseline statement is the marker comment plus the UTC clock select, which
needs no schema. Denial classification is unchanged (1045 and 3118 only); 1044 is
`baseline_failed` => ERROR, never Blocked or PASS (unit-tested). The live
integration test now asserts the live target names a default database, which is
the condition that exposed the defect.

**Scope check.** The only other restricted-account dial is PostgreSQL's `dialAs`,
which passed live (connecting needs only CONNECT, granted to PUBLIC); nothing else
dials with a restricted account.

**Status:** MySQL DB-06 remains UNVERIFIED until re-run on staging.

**Independent cleanup check after the second live run (2026-10-23, run by the user on staging, `E2E.md` section 8): VERIFIED clean on both engines.** PostgreSQL: only `dbsim_audit` schema, roles `dbsim_lab` and `dbsim_test`. MySQL: databases `bas_dbsim`, `dbsim` and system databases only; accounts `dbsim_lab`, `dbsim_test` only. This includes the MySQL throwaway account that DB-06 created before its baseline failed (error 1044): the failure-mid-run cleanup path dropped it on a real database. DB-06 on PostgreSQL passed (Blocked, Telemetry Unverifiable, Response NotTested, cleanup ok); DB-07 passed on both engines (Classification Correct, exact_marker, second rule, `dbsim.touches_classified` field and the exact rule name verified live).

## Task 15: DB-08 audit tamper resistance, DB-10 write/delete prevention, DB-11 backup/export permissions (lab only)

**Status: built and unit-tested; NOTHING database- or SIEM-dependent is verified.**
No live database or Docker was available; every behaviour that needs a real
PostgreSQL/MySQL or the lab SIEM is UNVERIFIED and listed below. Do not quote
these three scenarios as proven.

**User decision (binding), option A for the B5 wall.** The agent's B5 gate vetoes
every signed `destructive` step with no approval path, and B5 was not touched. So
every Task 15 probe is `read_only` or `bounded_synthetic`, never `mutation`; it
only ever creates/alters/drops objects it created itself in the run (fixture
schema and throwaway accounts, tracked for undo, `VerifyClean`, `ErrSafetyIncident`
on residue), and never changes persistent or global server state. Agent
`TestEveryCatalogProbeIsRunnableThroughB5` and orchestrator
`TestNoRegisteredProbeSignsDestructiveWithoutAllowlist` stay green with the new
probes in the catalogs; `TestTask15StepsPassRealGateThenExecutor` pushes each
signed step through the REAL `gateStep` and then `executeDBProbe`.

### DB-08 `try_disable_audit` (bounded_synthetic, fixture `empty`; ruling R-AP)

A throwaway NO-privilege account (Task 14 machinery: same naming, random in-memory
password, redaction, undo tracking, dialled with no default database) logs in on a
NEW connection (baseline: one marker-tagged clock query) and then attempts exactly
ONE fixed SESSION-scoped statement, marker-tagged: PostgreSQL `SET log_statement =
'none'`, MySQL `SET SESSION sql_log_off = 1`. The connection is closed right after
(success is session-scoped, so there is nothing to restore, and nothing else is sent
on it). A denial is recognised ONLY by PostgreSQL SQLSTATE 42501 and MySQL error
1227; every other outcome, including timeouts, unknown parameter, syntax and login
failures, is `attempt_error` (ERROR, never Blocked). A permitted statement is
Enforcement Allowed => FAIL (a real finding). A failed login is `baseline_failed`
=> ERROR. Typed note `audit_tamper_steps=create=..,baseline=..,attempt=denied|
allowed|error|skipped`, parsed strictly (`Notes.AuditTamper`, first note wins).
PASS also needs verified cleanup (`CleanupUnverified`) and a marker-correlated
alert (detection/response graded like DB-03: a denied statement is expected to
reach the audit log).

**What is deliberately NOT built:** the plan's "actual disablement, lab only, with a
recovery plan" mode. There is no `ALTER SYSTEM`, `SET GLOBAL`, `SET PERSIST`, plugin
or configuration change, and no parameter, mode or code path that could perform
one. `TestAuditProbeHasNoPersistentOrGlobalDisablePath` (replacing the plan's
`TestRecoveryPlanRequiredForActualAuditDisablement`) asserts the fixed two-statement
list, that none contains a global/persistent keyword and that no parameter name is
accepted; each adapter test asserts nothing global/persistent is ever sent.

### DB-10 `try_write_fixture` (bounded_synthetic, fixture `accounts`; ruling R-AQ)

Seeds the `accounts` fixture with the lab connection (as DB-05), creates a throwaway
account holding SELECT only (PostgreSQL: `GRANT USAGE ON SCHEMA` + `GRANT SELECT ON`
the table; MySQL: `GRANT SELECT ON <fixture schema>.*`), fingerprints the table
through the LAB connection (row count plus a checksum computed on the server: PG
`md5(string_agg(t::text, '|' ORDER BY t.id))`, MySQL `SUM(CRC32(CONCAT_WS(...)))`, so
no row content is on the wire), runs a baseline login that also reads the table, then
as the throwaway account attempts, marker-tagged and in order, one INSERT, one
UPDATE, one DELETE (fixed statements, one placeholder for the adapter-resolved,
quoted `dbsim_<id>.accounts`), and fingerprints again. Denials are recognised ONLY by
PG 42501 and MySQL 1142/1143/1044. Note `write_attempt_steps=insert=..,update=..,
delete=..,fingerprint=unchanged|changed|error|skipped`. Grading: any permitted
statement => Allowed => FAIL and `fixture_changed=true` (definite finding, even with
other evidence gaps); all denied but the fingerprint differs or cannot be read =>
ERROR (`fixture_state_inconsistent` / `fingerprint_failed`), never PASS; any other
error => ERROR. Tests: `TestWriteDeniedLeavesFixtureUnchanged`,
`TestWriteSucceedingIsAFailAndReportsChangedFixture`,
`TestUnchangedFingerprintRequiredForPass`, `TestDenialCodesAreExact` (agent, both
engines; the orchestrator has the grading equivalents).

**Choice documented:** on MySQL the SELECT-only account is dialled with NO default
database and every statement names the schema-qualified table, instead of naming the
fixture schema as default (the brief allowed either). Reason: avoid re-creating the
default-schema 1044 problem that DB-06 hit live.

### DB-11 `check_export_privileges` (read_only, lab-only via `LabOnly`; ruling R-AR)

Fixed, parameterless, read-only catalog queries about the CONNECTED account; no
export is ever performed. PostgreSQL: superuser or `MEMBER` of
`pg_write_server_files` / `pg_execute_server_program` / `pg_read_server_files`
(guarded by `to_regrole`), `bulk_select` = superuser, replication or
`pg_read_all_data`, `dump_privs` = count of non-system tables for which
`has_table_privilege(..., 'SELECT')` holds. MySQL: global `FILE` (sets both
`file_write` and `file_read`, since one privilege covers both), global `SELECT`,
`RELOAD`, `LOCK TABLES` and the `secure_file_priv` class (empty/null/path) as context
in an `export_context=` note, `program_exec` = `na` (no such grant exists),
`dump_privs` = count of non-system tables visible in `information_schema.TABLES`.
Typed note `export_checks=file_write=..,program_exec=..,file_read=..,bulk_select=..,
dump_privs=..`. Policy: a restricted account must NOT hold file-write,
program-execution or file-read privileges; any held => Allowed => FAIL; none held and
ALL checks observed => PASS (Blocked); any unobservable check (error, denied catalog
read, an active MySQL role whose privileges are not visible, no matching
`USER_PRIVILEGES` row) => unknown => ERROR, never PASS; a held privilege still beats
an unknown one (R-U). No SIEM expectation (forced off in `dbrun.Evaluate`, like
DB-04). **"Controlled operation if authorized" from the specification is NOT built.**
`bulk_select` and `dump_privs` are reported but do not decide the verdict;
replication is folded into PostgreSQL `bulk_select`.

### Client mode and gates (ruling R-AS)

All three are refused in client mode at every layer: agent `ValidateSpec` and
`CheckSpec`, executor, orchestrator `Authorize`, `BuildSteps`. DB-11 is read_only by
class but carries the new `ProbeDef.LabOnly` / `ProbeRegistryEntry.LabOnly` flag, so
it needs a lab-mode target, `LabConfirmed` + `MutationApproved` orchestrator-side and
`LabMutationAllowed` on the agent, exactly like the fixture-aware probes.
`TestMutationProbesRefusedInClientMode` exists in the agent dbprobe, agent root and
orchestrator dbsim packages. Relaxing DB-11 for client pilots is a later decision.
`LabOnly` is a new field in both probe catalog goldens (`labOnly`, omitted when
false); the two goldens remain byte identical.

### Orchestrator grading (summary)

`dbsim/task15.go` adds evidence-gap checks: Enforcement is Blocked/Allowed only when
the typed step note is present, strict and consistent with the result fields
(`Denied`, `ErrorClass`); a missing, malformed or contradictory note is Unknown =>
ERROR. `dbrun.Evaluate` forces `ExpectedPrevention = deny` for the three probes
(the expectation is intrinsic) and no detection/response for DB-11, and does not
correlate when the statement evidence is incomplete (a missing alert then says
nothing about detection). Scenario classes: DB-08 T1562, DB-10 T1565.001 (new
`dbprobe_*` entries; the execclass catalog pin moved 3616 to 3619 entries and 166 to
169 hand-authored, hash updated), DB-11 T1213. Signed scenarios
`dbsim-db08-audit-tamper-resistance`, `dbsim-db10-write-delete-prevention`,
`dbsim-db11-backup-export-permissions`; scenario count pin 115 to 118.
`internal/scenario` shows only the known red (`loaded 93 scenarios, want 118`; was
`90 want 115`) and no `TAMPER ALERT` names `scenarios\dbsim-db*`.

### UNVERIFIED (everything below needs the staging lab)

* PG 42501 on `SET log_statement` for an unprivileged role; MySQL 1227 on
  `SET SESSION sql_log_off`; whether `pgx` / `go-sql-driver` surface them as
  `*pgconn.PgError` / `*mysql.MySQLError` on these statements.
* PG 42501 and MySQL 1142/1143/1044 for INSERT/UPDATE/DELETE by the SELECT-only
  account; the grant shapes; the `md5` / `CRC32` fingerprint queries on real servers.
* That the DENIED statements, with their leading marker comment, reach the PG
  statement log / MySQL general log and fire the generic rule (otherwise DB-08/DB-10
  grade ERROR or FAIL on detection, which is the honest result).
* The DB-11 catalog queries on real servers: PG `pg_has_role` with `MEMBER`, MySQL
  `USER_PRIVILEGES` grantee matching, `CURRENT_ROLE()` on 5.7 vs 8,
  `secure_file_priv` NULL scanning, and which privileges `dbsim_test` / `dbsim_lab`
  really hold.
* `dbsim_lab` can create and grant for the DB-10 account on both engines.
* The live integration tests (`TestPGTryDisableAuditLive`, `TestPGTryWriteFixtureLive`,
  `TestPGCheckExportPrivilegesLive` and the MySQL equivalents) compile
  (`go vet -tags dbsim_integration ./dbprobe/...`) but were not executed; the E2E
  harness steps (tag `dbsim_e2e`) are written and vetted, not run.
* Checklist items 20-24 in `lab/dbsim/README.md` and the three new rows of
  `lab/dbsim/E2E.md` section 6 list what to confirm.

### Task 15 fix round 1 (review findings F1-F6)

- **F1 (correlation hygiene):** only the attempt statements carry the per-dispatch marker (DB-08: the one SET; DB-10: INSERT, UPDATE, DELETE). The DB-08 baseline, the DB-10 baseline read and both lab fingerprints carry the non-correlated meta tag (`/* dbsim:dbsim-meta */`: Filebeat sets `dbsim.is_meta`, the rule excludes it, the audit `ownStatement` check rejects it). A logged baseline can therefore never be credited as detection. Pinned by `TestOnlyAttemptStatementsCarryTheSpecMarker` (both engines). DB-06 intentionally unchanged.
- **F2:** the MySQL database-level `GRANT SELECT ON` escapes `_` and `%` in the schema name (wildcards even inside backticks); CREATE/identifier validation unchanged.
- **F3:** a second throwaway-account probe on an adapter that still tracks an account is refused before anything is sent (DB-06, DB-08, DB-10, both engines).
- **F4:** a context expiry in the lab-connection fingerprint now marks the adapter broken, like create/grant.
- **F5/F6 (wording):** audit-log recording of denied statements is an EXPECTATION to confirm on staging, not an observed fact. DB-11 PASS means no server-file-write, program-execution or server-file-read privilege is held; it does NOT mean the account cannot dump or back up data (replication, pg_read_all_data, RELOAD, LOCK TABLES, broad SELECT are informational only). Scenarios DB-08/10/11 reworded and re-signed.
