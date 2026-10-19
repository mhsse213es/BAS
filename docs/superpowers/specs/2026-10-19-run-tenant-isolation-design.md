# Run and Evidence Authorization — Design (Tier A)

Status: DECISIONS RECORDED; read-only audit complete. No code changed yet.
Date: 2026-10-19
Scope: current single-installation model (one customer, one database).
Tier B (shared-database multi-tenancy, 47-table ownership migration, RLS
activation) is deferred and out of scope here.
Blocks: Phishing BAS existing-run grading and new dispatch.

## 1. Decisions (settled)

**D1 — Viewer access.** Viewers may read reports. Raw evidence download and run
JSON export are allowed for runs the viewer can read, limited to documented run
data and evidence references. Secrets, credentials and internal-only data are
excluded from every export. Sensitivity and scope, not download-versus-display,
decide.

**D2 — Export permission. REVISED from the original decision.** The original
decision said to reuse `CanExport`. The audit found that premise does not hold:

- `CanExport` is defined as `verification:export` (`internal/auth/permissions.go:16`),
  is granted to `admin` and `analyst` only, and is referenced by **no handler**.
- The `viewer` role is granted **no permissions** (`RoleViewer: {}`).

So gating exports on `CanExport` would deny viewers export, which contradicts D1.
Recorded resolution: exports and raw-evidence downloads use **the same gate as
reading the parent run** (any authenticated role, `tierAny`, matching the current
route matrix). Authorization is the parent-run check, which inside one
installation means the caller is an authenticated member. No new permission is
added. A dedicated sensitive-artifact permission remains a later option if an
installation needs to restrict raw evidence to security administrators.

Decision needed to confirm: approve D2 as revised (no `CanExport` gate; parent-run
gate only), or instead restrict viewer export by introducing a permission.

## 2. Read-only audit

Source: `internal/api/routes.go` (route registration) and
`internal/api/rbac_matrix_test.go` (declared tiers). Every route below is inside
the JWT-authenticated group unless noted.

| Surface | Route | Declared tier | Mutation? | Sensitivity | Required negative test |
|---|---|---|---|---|---|
| Scenario runs | `GET /api/scenarios/runs` | any | no | run list | unauthenticated → 401 |
| Scenario runs | `/{runId}`, `/report`, `/report.json`, `/attackflow`, `/variant-coverage[/{tech}]`, `/pdf`, `/forensic.csv`, `/iocs`, `/rw-score`, `/double-extortion-correlation`, `/detection-response-effectiveness`, `/verifications[/...]`, `/events` | any | no | report / evidence | unauthenticated → 401 on each |
| Scenario runs | `GET /api/scenarios/runs/{runId}/export` | any | no | **raw run JSON** | secret-exclusion test (see §4) |
| Scenario runs | `POST /cancel`, `/pause`, `/resume` | permission `CanCancelScenarioRun` | **yes** | state change | viewer → 403 |
| EmailGW runs | `GET /api/emailgw-runs`, `/summary`, `/{id}`; `GET /api/emailgw/metrics` | any | no | run data | unauthenticated → 401 |
| EmailGW runs | `POST /api/emailgw-runs`, `/api/emailgw-campaigns*` | permission `CanRunScenario` | **yes** | dispatches email | viewer → 403 |
| Phishing runs | `GET /api/phishing-runs`, `/{id}`, `/{id}/report` | any | no | run data / report | unauthenticated → 401 |
| Phishing runs | `POST /api/phishing-runs` | permission `CanRunScenario` | **yes** | dispatch | viewer → 403 |
| Cloud runs | `GET /api/cloud-runs`, `/{id}` | any | no | run data | unauthenticated → 401 |
| Cloud runs | `POST /api/cloud-runs` | permission `CanRunScenario` | **yes** | dispatch | viewer → 403 |
| Exercises | `GET /api/exercises/executions`, `/{id}`, `/{id}/events`, `/{id}/evidence`, `/{id}/evidence/verify`, `/report.json|html|pdf|csv` | any | no | exercise evidence / report | unauthenticated → 401 |
| Exercises | `POST /launch`, `/abort`, `/steps/{id}/approve`, `/evidence` | permission per action | **yes** | state / evidence injection | viewer → 403 |
| Exercises | `POST /api/exercises/executions` (create) | any | **yes** | creates execution | **gap — see §3** |
| Evidence | `GET /api/evidence/{id}/download` | any | no | **raw evidence bytes** | parent-run check — **gap, see §3** |
| Evidence | `GET /api/verifications/{id}/evidence` | any | no | evidence list | unauthenticated → 401 |
| Evidence | `POST /api/verifications/{id}/evidence`, `DELETE /api/evidence/{id}` | permission `CanUploadEvidence` / `CanDeleteEvidence` | **yes** | state | viewer → 403 |
| Reports | `GET /api/report/full/{html,pdf,csv,json}`, `/audit-pack`, `/board`, `/navigator` | any | no | consolidated report | unauthenticated → 401 |
| Reports | `POST /api/report/verify` | any | no (verification only) | — | unauthenticated → 401 |
| Reports | `PUT /api/report/branding`; `/api/report/schedules*` | permission `CanUpdateConnectorConfig` | **yes** | config / scheduled output | viewer → 403 |
| Relationships | `GET /api/relationships/{id}/evidence` | any | no | threat-intel evidence | unauthenticated → 401 |
| Direct artifacts | No static file serving of run/evidence/report output found (`routes.go:46` is a doc comment; the only `FileServer` is the web UI) | — | — | — | confirm with the §3 gap test |

## 3. Gaps the audit found

1. **Evidence download has no parent-run check.** `DownloadEvidence`
   (`internal/api/verification_handlers.go:361`) looks up evidence by ID and streams
   it, with no permission and no check that the caller may read the
   verification's run. Inside one installation every authenticated role can read
   every run, so the current model does not produce a cross-user leak. The gap is
   that the rule is absent: a future permission change on runs would silently
   leave evidence open. Fix: resolve evidence → verification → run and apply the
   run's read gate, returning 404 on failure.
2. **Exercise-execution create is `tierAny`.** `POST /api/exercises/executions`
   creates an execution for any authenticated role, while launch and abort require
   permissions. This is a mutation without a permission gate. Whether creating a
   plan-run is meant to be viewer-level is unconfirmed. Recommendation: gate it on
   the existing exercise permission family, after confirming intent.
3. **Secret exclusion is not verified.** Handler bodies contain no secret-related
   fields, but stored `result` JSON and evidence payloads come from connectors and
   were not inspected. The export and report paths need a redaction review before
   D1's "no secrets in exports" promise can be stated as true.

## 4. Tests required (Tier A)

1. Unauthenticated requests to every route in §2 return 401 (route-matrix drift
   test already covers declared tiers; add behavioral checks for the new gates).
2. Viewer: allowed on rendered reports and permitted exports; denied (403) on each
   mutation listed in §2.
3. Child-to-parent: `GET /api/evidence/{id}/download` for evidence belonging to an
   unreadable run returns the same denial as the parent run (fails until gap 1 is
   fixed).
4. Export content: run JSON and report JSON contain no fields matching a secret
   allowlist (`secret`, `password`, `token`, `credential`, `api_key`), using a run
   seeded with connector credentials.
5. Regression: analyst and admin report access unchanged.

## 5. Open decisions

1. Approve D2 as revised: parent-run gate only, no `CanExport` (§1).
2. Gap 2: should creating exercise executions require an exercise permission?
3. Gap 3: should the redaction review be a blocking gate for the export change, or
   a follow-up with the export shipped on current data?

## 6. Tier B (deferred, not in this change)

- Shared-database multi-tenancy: `tenant_id` ownership across the run family,
  creation-time assignment, system-initiated run inheritance.
- RLS activation, which needs the `bas_user` NOSUPERUSER/NOBYPASSRLS hardening
  first (`internal/db/postgres.go:~1361`). RLS is not active anywhere, so no
  database-level defense is claimed.
- The `'default'` tenant columns (47 tables) stay as installation-scoped data and
  are not converted, reassigned or enforced in Tier A.

## 7. Sequencing

1. Confirm the open decisions in §5.
2. Implement gap 1 (evidence parent check) and gap 2 (if confirmed), each with
   negative tests.
3. Run the redaction review (gap 3) and fix any leaked field.
4. Verify with the RBAC drift test and the phishing-run suite.
5. Only then resume the phishing existing-run grader and new dispatch.

Phishing grading and dispatch stay unregistered until steps 1–4 pass. The eight
verified PH→EmailGW mappings remain groundwork.

## 8. Status — gaps 1 and 2 (2026-10-19)

- **Gap 1 (evidence download parent check): DONE.** `DownloadEvidence` now resolves
  the parent verification and returns 404 when it is missing. Tests:
  `TestDownloadEvidence_OrphanedEvidence_NotFound` (RED→GREEN),
  `TestDownloadEvidence_AuthorizedParent_Served`,
  `TestDownloadEvidence_Unauthenticated_401`.
- **Gap 2 (exercise-execution create gate): DONE.** `POST /api/exercises/executions`
  now requires `CanLaunchExerciseExecution`, the closest existing permission to
  creating an execution (held by admin and analyst, not viewer). Tests:
  `TestCreateExerciseExecution_ViewerForbidden_NoRowCreated` (RED→GREEN),
  `TestCreateExerciseExecution_AnalystPassesGate`, and the RBAC matrix suite.
- **Gap 3 (secret-exclusion review of stored payloads): OPEN**, not started.
- **D2 as revised:** exports and evidence use the parent-run gate; `CanExport` unchanged.

## 9. Status — gap 3 (secret exclusion), partial (2026-10-19)

- **Credential-access output withheld from exports and reports.** Steps whose
  persisted ATT&CK tactic is `credential-access` have `RawOutput` and `Details`
  replaced by `models.CredentialOutputWithheld` at every results load that feeds a
  response or artifact: run export JSON, run PDF, attack flow, compliance report,
  full-report PDF/JSON/CSV, forensic CSV, campaign/sweep/EM-sweep reports, and the
  audit pack. Tests: `TestRedactCredentialOutput_WithholdsCredentialAccessOutput`,
  `TestExportRunJSON_CredentialAccessOutputWithheld`.
- **Credential hashes not stored as run IOCs.** Hash-type indicators extracted from
  credential-access steps are dropped in `ioc.BuildRunIndicators`, so they are
  never served by `GET /api/scenarios/runs/{runId}/iocs`. Non-credential hashes
  are still extracted. Test: `TestBuildRunIndicators_CredentialAccessHashNotStored`.
- **Still open:**
  1. Closed: cross-run `GET /api/iocs` command-line rows from credential-access
     results have hash-shaped hex withheld before storage, and the same hex is
     withheld from the detection alert command line on exported results.
     Test: `TestExtractFromDetectionAlert_CredentialAccessCommandLineWithheld`,
     `TestRedactCredentialOutput_WithholdsAlertCommandLineHash`.
  2. Closed: results loaders that feed a response were classified. Run list (all
     three list endpoints), variant run detail, variant coverage and the finding
     variant breakdown now withhold credential-access output. Tests:
     `TestListScenarioRuns_CredentialAccessOutputWithheld`,
     `TestGetVariantRun_CredentialAccessDetailWithheld`,
     `TestVariantBreakdownForFinding_CredentialAccessDetailWithheld`,
     `TestGetVariantCoverage_CredentialAccessBypassDetailWithheld` (passes after
     the fix; not yet seen failing before it). Campaign child runs, RW-evidence
     dispatch and the detection-verification and posture loaders were checked and
     do not return raw output to a response.
  3. Partly done (pending verification): secret-shaped values (PEM private-key
     headers, bearer tokens, AWS access key IDs, password/token/API-key
     assignments) are withheld from every step's output on the export, report and
     list paths. Test: `TestWithholdSecrets_*`, `TestExportRunJSON_OrdinaryStepSecretWithheld`.
     Not yet verified: the full `internal/api` suite, which was stopped for memory
     on a clean export of b245fe97. Open decision: the `token` and `password`
     assignment rules may over-match ordinary lines; narrow or drop them if noisy.
