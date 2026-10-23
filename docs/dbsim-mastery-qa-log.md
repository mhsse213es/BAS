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

### Bottom line

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

Run `lab/dbsim/E2E.md` on staging and send back the outputs it lists. Do not
start Tasks 14-16 until this entry is updated with real results.
