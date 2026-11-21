# DB-04 MySQL P0 (tests 03-08): lab QA log

Lab: `dbsim-lab-mysql-1`, `percona/percona-server@sha256:a4ba7d1a…9ec2d` (8.0.46-37),
audit_log ACTIVE (JSON, policy ALL, SYNCHRONOUS). Audit file read by the harness on the host.
Branch: `feat/db04-mysql-readonly`. Not merged.

## Results (live, 2026-11-20/21)

| Test | Name | Live result | Evidence in the audit trail |
|------|------|-------------|------------------------------|
| 03 | Authentication event audit coverage | PASS | Connect and marked Query share one connection (181, 186) |
| 04 | Failed-login audit coverage | PASS | Refused Connect for `dbsim_nx_<run>` with status 1045 |
| 05 | Privileged account activity | PASS | Marked `FLUSH STATUS` by dbsim_fixture |
| 06 | Role and permission modification | PASS | GRANT SELECT and marked REVOKE on connection 216 |
| 07 | Sensitive table access | PASS | Marked SELECT on sensitive_synth |
| 08 | DDL operation | PASS | Marked CREATE TABLE and DROP TABLE; table absent after drop |

Runs: the first full set of 03/04 passed in two separate runs; 05-08 passed in one run after the
attribution fix (`e29859d0`). Repeat runs: not yet done.

## Findings during this run

- MySQL drops the marker comment from GRANT statements. The GRANT is still audited, with
  `command_class: grant`, status 0, on the same connection as a marked REVOKE. The verdict
  attributes unmarked statements through their marked connection, and a test covers the case
  where that connection is not marked.
- The first live run of 05-08 failed on test 06 for exactly this reason. Found by reading the
  audit file, not by changing the verdict to fit.
- The `mysql` client strips `/* */` comments unless `--comments` is passed. Harness code uses the
  driver directly, which keeps them; this was confirmed by the live results.

## Not yet verified live

- SKIPPED when audit_log is inactive. Implemented in each runner; not exercised on the lab,
  because turning the plugin off on the lab is a separate, approved step.
- Repeat runs for stability.
- Harness evidence (`Evidence`) feeding `HarnessEvidence` in the E2E step input: wired at the
  pipeline level, not yet connected to a live scenario run.

## Accounts used (lab only)

- `dbsim_harness`: no grants beyond login and SHOW PLUGINS.
- `dbsim_fixture`: DML/DDL and GRANT OPTION on `dbsim_audit_fixture` only; global RELOAD (test 05).
  Approved 2026-11-21.
Passwords live in `~/dbsim-lab-run/secrets/` (mode 600). Not in git, not in chat.
