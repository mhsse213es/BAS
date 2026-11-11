# REQ-021 release decisions, and REQ-018 Gap 2 and Gap 3 scoping

**Date:** 2026-11-11

## Part 1: REQ-021 release decisions (first build)

Decided by the owner (Tausif), following the recommended defaults.

| Item | Decision | Effect |
|---|---|---|
| Spring CVE-2022-22965 | (b) leave UNKNOWN | No rows added for spring-beans or spring-webmvc. `libspring-aop-java` stays rejected. |
| Redis CVE-2022-0543 | (b) keep excluded | Stays CONDITIONAL, not eligible, unless Ubuntu's redis build is shown to include the Lua sandbox file. |
| Kernel CVE-2025-39682 | (b) exclude from v1 | Kernel release strings are not compared. Not counted. |
| 25 Windows UNKNOWN rows | (b) leave UNKNOWN | No alias curation in this release. Windows coverage is 2 of 7 CVEs. |
| Matcher wiring | (c) first build, then (b) | First build: manual staging checks only, no customer-visible output. Next: expose EXPOSED, NOT_EXPOSED, UNKNOWN through the API once output is proven accurate on real hosts. |
| Release wording | Counts against the denominator | See below. |

**Release wording rules**
- Report counts against the 500 Critical KEV denominator, for example "18 Ubuntu rows and 3 Windows rows are covered."
- State the snapshot dates: KEV catalog 2026.11.09; NVD and Ubuntu OVAL snapshots as recorded in `req021-spike/results.json`.
- "Covered" means a reviewed mapping exists. It does not mean a host is exposed or not exposed.
- Do not report a percentage until the population grows.

## Part 2: REQ-018 Gap 2 and Gap 3 scoping

Source: `docs/superpowers/specs/2026-11-10-content-velocity-commitment-design.md`, sections 4 and 6.

### What the code already has (checked 2026-11-11)

- **Ledger:** `tcf_pipeline_events` is append-only. Its `event_type` CHECK lists 12 types, including `rejected`. Each event points at a source row (`source_table`, `source_pk`). The `bundle_packaged` migration shows the pattern for extending the CHECK idempotently.
- **Rejected events:** derived in `internal/tcv/reconcile.go` from `content_version_events` rows where `to_lifecycle = 'REJECTED'`. The event payload copies only `to_lifecycle`.
- **Reason field:** `content_version_events.reason` exists as free text, default `''`. It is not a machine-readable code from the spec's exclusion list.
- **Intake:** no advisory intake table was found under `internal/db` (searched for advisory, intake, and intel). The spec says "intake exists" for CERT-In and FS-ISAC. Where that intake is recorded needs to be confirmed before Gap 2 can be built.

### Gap 3: exclusion reason on rejection

**Build**
1. Add a `reason_code` column to `content_version_events`. Nullable, so existing rows stay as they are. A CHECK restricts it to the five codes in spec section 4: `relevance`, `insufficient_technical_detail`, `unsupported_platform`, `validation_environment_unavailable`, `third_party_dependency`.
2. Require `reason_code` when `to_lifecycle = 'REJECTED'` for new rows. Old rows without a code are counted as "unclassified," not dropped, per the spec.
3. Copy `reason_code` into the `rejected` ledger event payload.
4. Update the reconcile path to carry it.

**Tests:** constraint rejects an unknown code; new REJECTED without a code fails; a legacy row reconciles as unclassified; the exclusion count includes every rejected row.

**Risk:** `content_version_events` is an audit table. Any change must be additive and must not rewrite history. A reversal is a new event, per spec section 8.

### Gap 2: advisory intake and relevance events

**Build**
1. Confirm where CERT-In and FS-ISAC intake is recorded today. If there is no table, add `advisory_intake` with `source`, `external_id`, `received_at`, and a unique key on source and external_id.
2. Add a relevance decision: either a `relevance` column on the intake row or a separate table with `relevant` or `excluded`, plus a reason code from the same five-item list.
3. Add two ledger types, `advisory_received` and `advisory_classified`, to the CHECK. Each references the intake row.

**Tests:** duplicate advisories from the same source are deduplicated; every classified advisory has exactly one relevance decision; an excluded advisory carries a reason code; exclusions are counted in the denominator.

**Open question:** whether intake is already recorded somewhere not yet found. That changes the size of this item.

### Order and size

1. Confirm the intake location (short).
2. Gap 3 first: it is a single additive migration and touches only the reject path.
3. Gap 2 second: depends on step 1 and may need a new table.

Both need a migration applied to the staging database and a Postgres-backed test run. The Postgres 16 container used for the `bundle_packaged` migration is the verification path.

## Not decided here

- Whether the first build includes Gap 2 or Gap 3. Adoption of any REQ-018 target stays blocked until both are built.
