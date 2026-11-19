# DB-03 Expansion: Unauthorized Access Tests (design)

Date: 2026-11-19. Status: DRAFT, awaiting approval. No code, lab changes or scenario edits until approved.

## Intent

DB-03 asks whether a database refuses access it should refuse. Today it runs one probe (`read_restricted_table`) against one restricted table. This expansion turns DB-03 into eleven graded tests covering the ways an unauthorized identity can reach data: direct tables, other schemas, sensitive data sets, views, stored procedures, inherited roles, a service account, and row-level security. A denial is the healthy outcome. A successful read is a finding.

Scope rule from the approval: remove redundancy, keep coverage. Test 12 (access after revocation) moves out of DB-03 into DB-06. Test 06 stays only as view execution. Classification and discovery of sensitive views stay in DB-07.

## The tests

| # | Test | Objective | Engines | ATT&CK | Probe class |
|---|------|-----------|---------|--------|-------------|
| 01 | Restricted table read | Probe identity reads a table it has no grant on | PG, MySQL | T1213.006 | read_only (exists) |
| 02 | Unauthorized SELECT on sensitive columns | Probe selects named PII columns from a table it has no column grant on | PG, MySQL | T1213.006 | read_only |
| 03 | Access to another schema | Probe reads a table in a schema it has no USAGE on | PG, MySQL | T1213.006 | read_only |
| 04 | Customer records | Probe reads the synthetic `customers` table | PG, MySQL | T1213.006 | read_only |
| 05 | Financial / transaction records | Probe reads the synthetic `transactions` table | PG, MySQL | T1213.006 | read_only |
| 06 | Unauthorized view access | Probe queries a view over restricted data, without rights on the view | PG, MySQL | T1213.006 | read_only |
| 07 | Unauthorized stored procedure access | Probe calls a procedure that returns restricted rows, without EXECUTE on it | PG, MySQL | T1213.006 | bounded_synthetic (lab-only) |
| 08 | Access through inherited role permissions | Probe is a member of a role that holds grants it should not inherit | PG, MySQL | T1078 | read_only |
| 09 | Access through application service account | Probe runs as the app service account, which should be read-only on restricted data | PG, MySQL | T1078 | read_only |
| 10 | Row-level security bypass attempt | Probe reads tenant rows that RLS hides, through permitted execution contexts only | PG only | T1213.006 | read_only (lab-only) |
| 11 | Unauthorized metadata discovery | Probe lists role and object names it should not see | PG, MySQL | see open question | read_only |

Each test runs one step in the scenario, the same shape as DB-03 today.

## ATT&CK mapping

- T1213.006 (Data from Information Repositories: Databases) is the mapping for every test where the step retrieves data from a relational database. Verified against attack.mitre.org. It is not yet in the repo's enrichment catalogue (`orchestrator/internal/reporting/attackdata/attack_enrichment.json`); that entry must be added so reports show its name.
- T1213 (the parent) and T1213.002 (SharePoint) are not used.
- T1078 (Valid Accounts) for tests 08 and 09, where the behaviour under test is account privilege, not the data read itself.
- Test 10 maps to T1213.006 because the behaviour is unauthorized data access. Not a privilege-escalation technique.
- Test 07 maps to T1213.006 because the procedure returns data from the database.
- Test 11 is open (see Open questions).

## Engines and what each test needs

PostgreSQL and MySQL both run tests 01 to 09 and 11. Test 10 is PostgreSQL only: MySQL has no row-level security, so on MySQL it is SKIPPED with reason "engine has no row-level security". Test 07 uses a stored procedure on both engines.

## Fixtures (lab database only)

All fixtures live in a dedicated schema `bas_dbsim` on the lab database. A second schema `bas_dbsim_other` supports test 03. Data is synthetic only.

- Tables: `restricted` (test 01), `customers` with a `tenant_id` column and PII columns (tests 02, 04, 10), `transactions` (test 05), another table in `bas_dbsim_other` (test 03).
- View `v_restricted_summary` over `restricted` (test 06).
- Procedure `get_restricted_rows()` (test 07). Body is a single SELECT, reviewed in the change; a static test rejects any DML in the body.
- RLS policy on `customers` keyed on a session variable (test 10, PostgreSQL).
- Roles: `bas_probe` (the probe identity, no grants on restricted objects), `bas_reader` (holds SELECT on `restricted`; `bas_probe` is not a member, so the denial is real), `bas_probe_inh` (a member of `bas_reader` with NOINHERIT, to test that inheritance is not silently taken), `bas_svc_app` (the application service account, read-only on non-restricted tables).
- MySQL: database `bas_dbsim`, the same tables and view, a stored procedure, and matching users with grants.

Every grant and membership is created by a reviewed setup script and removed by the cleanup script.

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

## Cleanup and rollback

- Setup script creates the schema, roles, tables, rows, view, procedure, policy and grants. Idempotent.
- Cleanup script drops everything it created, in order: procedure, view, policy, tables, schemas, grants, roles. It runs after each DB-03 run and is also a standalone script.
- The scripts are versioned with the scenario and reviewed like the scenario. Every change is logged in the QA doc for this initiative.
- Rollback: run the cleanup script. It is safe to run when fixtures are missing.

## Implementation outline (after approval)

1. Probes: add probe ids for tests 02 to 11 to the agent catalogue and the orchestrator constants, both engines, with fixture-aware SQL and the gate classes above.
2. Expectations: add one entry per test to `expectations.go`, with the PASS/FAIL rules above.
3. Scenario: rewrite `dbsim-db03-unauthorized-access.yaml` with eleven steps; re-sign it.
4. Catalogue: add T1213.006 to the ATT&CK enrichment file.
5. Lab: run the setup script on the lab database, run DB-03 through the product API, record evidence, run cleanup.
6. Tests: unit tests for each probe and expectation, a static test on the procedure body, and a test that MySQL skips test 10.

## Open questions

1. **Test 11 mapping.** ATT&CK has no technique for enumerating table or schema names in a database. Options: map to T1087 (Account Discovery) for role listing only and leave object-name listing unmapped; or drop the object-name part and keep only role enumeration. Which do you want?
2. **Test 02 vs test 01.** Both read a restricted object. Test 02 is about column-level grants on PII columns. Keep both, or fold 02 into 01 with a column variant?
3. **Test 06 scope.** Kept only as view execution, per your approval. Confirm that is the boundary with DB-07.

## Out of scope

- Test 12 (revocation): belongs in DB-06.
- Classification and discovery of sensitive views: DB-07.
- Any production database.
