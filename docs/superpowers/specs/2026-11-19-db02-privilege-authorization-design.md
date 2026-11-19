# DB-02 Privilege and Authorization Assessment: Design

Status: **APPROVED 2026-11-19.** Decisions below. Build order: Phase 0, then P0, P1, P2, P3.

## Intent

DB-02 today is one scenario, "grants conform to policy". Its grants dimension can never
PASS, because the pipeline does not yet feed real grants into the policy comparison (the
`read_grants` output is not wired to `dbsim.Report`; see `dbrun/pipeline.go` and the
R-AJ ruling in `dbrun/e2e_test.go`). This design makes DB-02 an assessment family that
measures authorization against policy, engine by engine.

## Three outcomes, reported separately

Every DB-02 result states which of these it establishes. None implies another.

1. **Discovery.** The account holds a permission. Read-only listing.
2. **Policy violation.** The permission exceeds the organisation's stated policy. Needs a policy source.
3. **Exploitability.** The permission can be used for an unauthorised action. Judged
   only by read-only capability checks, never by performing the action on real data.

A discovery result is never reported as a violation, and neither is reported as
exploitable.

## Scope and priority

| Priority | Scenarios | Outcome they establish |
|---|---|---|
| P0 | DB-02-03 to 08: excessive privilege, DBA-level access by service accounts, dangerous global grants, inheritance escalation, grant-option delegation, PUBLIC grants | Policy violation |
| P1 | DB-02-09 to 12: cross-schema access, sensitive tables, service account privilege, dormant privileged accounts | Policy violation and discovery |
| P2 | DB-02-13 to 14: privilege change and revocation validation | Active, see guardrails |
| P3 | Advanced chains (indirect escalation, ownership abuse, separation of duties) | Exploitability |

DB-02-01 (role enumeration) and DB-02-02 (application role grants) are discovery
prerequisites for P0 and are built first.

## Phase 0: wire the existing comparison (prerequisite, no new scenarios)

- The `read_grants` probe's output becomes the `[]dbsim.Grant` passed to
  `dbsim.Report`, with the policy source attached. Without this, nothing else is measurable.
- Acceptance: a clean lab account yields `DimPass` with `GrantsChecked > 0`; a
  deliberately over-granted lab account yields `DimFail` with the expected deviation.
  Both pinned by tests against the existing `Diff`.

## Gaps the proposal needs that `Diff` does not have

`dbsim.Grant` carries role, object and privilege only. P0 needs more:

- **Grant option flag** (`WITH GRANT OPTION`, `WITH ADMIN OPTION`), for DB-02-07.
- **Inheritance path** for each effective grant, for DB-02-06. `Diff` already resolves
  inheritance from the policy side; the probe must report the role chain it observed.
- **Privilege classes**, for DB-02-04 and DB-02-05: a named class such as
  `SUPERUSER`, `CREATEROLE`, `BYPASSRLS` (PostgreSQL), `sysadmin`, `CONTROL SERVER`
  (SQL Server), `DBA`, `SYSDBA` (Oracle), global `SUPER`, `FILE` (MySQL). The policy
  names classes; the probe maps engine privileges onto them.
- **PUBLIC as a pseudo-role** for DB-02-08 (Oracle and PostgreSQL), so grants to PUBLIC
  are compared like any role.

Each engine's mapping is written and tested per engine. No cross-engine guess.

## Guardrails (all phases)

- Discovery and capability checks are read-only. The probes call catalogue views only.
- Exploitability (P3) is judged from metadata. Nothing performs an unauthorised
  action on real data, including inside the lab.
- P2 changes privileges only on a synthetic lab role, and every change is reverted
  by a named undo step that is verified before the scenario reports.
- `Deviation` keeps the existing rule: no field carries a remediation or a runnable
  statement. The existing test `TestDiffNeverProducesRevokeAction` stays and extends to
  the new fields.
- Policy comes from a stated source (file, ticket or lab fixture), carried into every
  finding. A finding with no policy source is not a violation.

## Verdicts

- Each DB-02 sub-scenario reports three verdicts (discovery, violation, exploitability),
  each one of PASS, FAIL, SKIP or ERROR with a reason.
- An unverifiable dimension (no policy, no grants read) is SKIP, never PASS and never
  FAIL by omission. That rule already exists in `dbsim/audit.go` and is kept.

## Explicitly out of scope

- Remediation: no revoke or grant statements are generated or executed.
- Real production databases. Lab targets only, per the existing dbsim target rules.
- Cross-engine privilege equivalence. Each engine is judged by its own model.

## Decisions (approved)

1. **Lab engine: PostgreSQL first.** Other engines wait for their own lab targets.
2. **Privilege classes go into the policy now**, so DB-02-04 and DB-02-05 are built in P0.
3. **P2 privilege changes are allowed** on a synthetic lab role, with a verified undo step
   before the scenario reports.

## Acceptance for this design

Approved. Build order follows the phases above, Phase 0 first.
