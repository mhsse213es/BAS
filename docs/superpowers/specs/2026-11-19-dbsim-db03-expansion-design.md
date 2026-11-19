# DB-03 Expansion: Unauthorized Access Tests (design)

Date: 2026-11-19. Status: APPROVED 2026-11-19, with the fixture model revised to the per-run catalog (see Fixtures). Four decisions recorded the same day are binding and are set out in "Decisions" below.

## Decisions (recorded 2026-11-19, binding)

1. **Fixture reads get their own classifier label.** Setup and verification reads of a per-run fixture carry the label `fixture_read`. They are kept separate from attacker-simulation reads, are never counted as simulated unauthorized access, and must not be able to produce a false-positive detection result. A step with this label is not graded as an attack.
2. **Test 11 ATT&CK mapping: T1087.** T1087 (Account Discovery) applies to the role and account enumeration in test 11. Object-name enumeration (table, schema and view names) remains unmapped, because ATT&CK has no technique for it.
3. **Test 01 and test 02 stay separate.** Test 02 specifically validates PII column permissions. It is not folded into test 01 as a column variant.
4. **Test 06 and DB-07 boundary.** DB-03 test 06 tests unauthorized view access and execution. DB-07 owns sensitive-view discovery and classification. Neither test does the other's job.

No new tests are added by these decisions, and the three DB-03 questions below are closed.

## Intent

DB-03 asks whether a database refuses access it should refuse. Today it runs one probe (`read_restricted_table`) against one restricted table. This expansion turns DB-03 into eleven graded tests covering the ways an unauthorized identity can reach data: direct tables, other schemas, sensitive data sets, views, stored procedures, inherited roles, a service account, and row-level security. A denial is the healthy outcome. A successful read is a finding.

Scope rule from the approval: remove redundancy, keep coverage. Test 12 (access after revocation) moves out of DB-03 into DB-06. Test 06 stays only as view execution (decision 4). Classification and discovery of sensitive views stay in DB-07.

## The tests

| # | Test | Objective | Engines | ATT&CK | Probe class |
|---|------|-----------|---------|--------|-------------|
| 01 | Restricted table read | Probe identity reads a table it has no grant on | PG, MySQL | T1213.006 | read_only (exists) |
| 02 | Unauthorized SELECT on sensitive columns | Probe selects named PII columns from a table it has no column grant on. Validates PII column permissions; kept separate from test 01 (decision 3) | PG, MySQL | T1213.006 | read_only |
| 03 | Access to another schema | Probe reads a table in a schema it has no USAGE on | PG, MySQL | T1213.006 | read_only |
| 04 | Customer records | Probe reads the synthetic `customers` table | PG, MySQL | T1213.006 | read_only |
| 05 | Financial / transaction records | Probe reads the synthetic `transactions` table | PG, MySQL | T1213.006 | read_only |
| 06 | Unauthorized view access | Probe queries a view over restricted data, without rights on the view | PG, MySQL | T1213.006 | read_only |
| 07 | Unauthorized stored procedure access | Probe calls a procedure that returns restricted rows, without EXECUTE on it | PG, MySQL | T1213.006 | bounded_synthetic (lab-only) |
| 08 | Access through inherited role permissions | Probe is a member of a role that holds grants it should not inherit | PG, MySQL | T1078 | read_only |
| 09 | Access through application service account | Probe runs as the app service account, which should be read-only on restricted data | PG, MySQL | T1078 | read_only |
| 10 | Row-level security bypass attempt | Probe reads tenant rows that RLS hides, through permitted execution contexts only | PG only | T1213.006 | read_only (lab-only) |
| 11 | Unauthorized metadata discovery | Probe lists role and account names it should not see, and object names it should not see | PG, MySQL | T1087 (role and account names); object names unmapped | read_only |

Each test runs one step in the scenario, the same shape as DB-03 today.

## ATT&CK mapping

- T1213.006 (Data from Information Repositories: Databases) is the mapping for every test where the step retrieves data from a relational database. Verified against attack.mitre.org. It is not yet in the repo's enrichment catalogue (`orchestrator/internal/reporting/attackdata/attack_enrichment.json`); that entry must be added so reports show its name.
- T1213 (the parent) and T1213.002 (SharePoint) are not used.
- T1078 (Valid Accounts) for tests 08 and 09, where the behaviour under test is account privilege, not the data read itself.
- Test 10 maps to T1213.006 because the behaviour is unauthorized data access. Not a privilege-escalation technique.
- Test 07 maps to T1213.006 because the procedure returns data from the database.
- Test 11 maps to T1087 (Account Discovery) for role and account enumeration. Object-name enumeration (tables, schemas, views) has no ATT&CK technique and is left unmapped. This is decision 2.

## Engines and what each test needs

PostgreSQL and MySQL both run tests 01 to 09 and 11. Test 10 is PostgreSQL only: MySQL has no row-level security, so on MySQL it is SKIPPED with reason "engine has no row-level security". Test 07 uses a stored procedure on both engines.

## Fixtures (per-run catalog, lab database only)

Revised 2026-11-19 (approved): DB-03 reuses the existing fixture system rather than a persistent schema. There are no persistent test roles, tables or procedures.

- Fixtures are catalog entries in `agent/dbprobe/fixtures/catalog.go`, the same way `classified-pii` is defined. Each run seeds its fixture into a fresh per-run `dbsim_<id>` schema, and cleanup drops that schema.
- The new catalog fixtures for DB-03 are:
  - `authz-restricted`: a `restricted` table (test 01) and its view `v_restricted_summary` (test 06).
  - `authz-pii`: a `customers` table with a `tenant_id` column and PII columns, used by tests 02, 04 and 10.
  - `authz-financial`: a `transactions` table (test 05).
  - `authz-cross-schema`: a second per-run schema holding one table (test 03).
  - `authz-procedure`: procedure `get_restricted_rows()` (test 07), PostgreSQL and MySQL. The body is a single SELECT, and a static test rejects any DML in it.
  - `authz-rls`: the `customers` table with a row-level security policy keyed on a session variable (test 10, PostgreSQL only).
- Roles are created per run by the same seeding path that creates the probe identity today, and dropped with the run. Test 08 uses a per-run role chain: the probe identity is a NOINHERIT member of a role that holds SELECT on `restricted`. Test 09 uses the application service account as a target credential, not a new probe.
- All fixture data is synthetic, marked with the existing `BAS-SIM-` marker.

Test 11 (metadata discovery) reads catalog and information_schema names only. It needs no fixture beyond the per-run schema, so it runs against the same fixture as test 01.

Fixture reads (decision 1): every read that sets up or verifies a per-run fixture carries the `fixture_read` label. The label is separate from attacker-simulation reads, and these reads are never counted as simulated unauthorized access. The label also prevents a fixture read from producing a detection result, so a fixture setup or check cannot register as a false positive.

## Cleanup and rollback

- Cleanup is the existing verified path: each fixture's drop runs after the probe, and the run records a cleanup status (ok, failed or not applicable).
- Cleanup failure is reported explicitly, never silently ignored. A run whose cleanup did not verify is graded ERROR with the cleanup reason, and the run's audit and probe evidence are still recorded.
- Setup is only ever run through the fixture lifecycle. There is no standalone setup or cleanup script, and nothing persists between runs.
- Rollback: if a run is interrupted, the existing orphan-fixture cleanup removes the `dbsim_<id>` schema. No manual step is needed.

## Evidence and grading

For each test the evidence is: the probe result (rows read, error class, denied flag), the database audit record found by the marker, and the cleanup status.

Grading per test, using the existing dbsim result model:

- **PASS:** the database denied the attempt (denied = true, 0 rows) and the audit record was found. Prevention and detection both pass.
- **FAIL:** the attempt read data it should not reach (rows > 0). This is a finding, not a test error. Detection still records what the audit showed.
- **SKIPPED:** the test cannot run on this engine or fixture is missing (for example test 10 on MySQL). The reason is recorded.
- **ERROR:** infrastructure failure: connection, gate refusal, cleanup failure. Never graded as PASS.

Test 07 and test 10 also check that the probe did not change state: a failed cleanup marks the run ERROR.

## Safety

- Lab database only, never a production database. The target registry must mark these targets as lab.
- Read-only transactions for tests 01 to 06, 08, 09, 10, 11. Test 07 is `bounded_synthetic` and reviewed: the procedure body is a read-only SELECT, the call runs in a READ ONLY transaction where the engine allows it, and the step runs lab-only.
- No attempt to obtain superuser, BYPASSRLS, or any privilege the probe identity does not already hold. Test 10 tries only permitted execution contexts: the probe as itself, through the view, and through the procedure.
- Row limit 10 per step, timeout 30 seconds, one connection.

## Implementation outline (after approval)

1. Probes: add probe ids for tests 02 to 11 to the agent catalogue and the orchestrator constants, both engines, with fixture-aware SQL and the gate classes above.
2. Expectations: add one entry per test to `expectations.go`, with the PASS/FAIL rules above.
3. Scenario: rewrite `dbsim-db03-unauthorized-access.yaml` with eleven steps; re-sign it.
4. Catalogue: add T1213.006 to the ATT&CK enrichment file.
5. Lab: run DB-03 through the product API on the lab target, record evidence and the cleanup status for each run.
6. Tests: unit tests for each probe and expectation, a static test on the procedure body, and a test that MySQL skips test 10.
7. Classifier: add the `fixture_read` label (decision 1) and a test that a step carrying it is never graded as simulated unauthorized access and never produces a detection result.

## Resolved questions

1. **Test 11 mapping:** resolved. T1087 for role and account names; object names unmapped (decision 2).
2. **Test 02 vs test 01:** resolved. Kept separate (decision 3).
3. **Test 06 scope:** resolved. Test 06 is unauthorized view access and execution; DB-07 owns sensitive-view discovery and classification (decision 4).

## Out of scope

- Test 12 (revocation): belongs in DB-06.
- Classification and discovery of sensitive views: DB-07.
- Any production database.
