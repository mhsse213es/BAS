# API BAS: remaining work

Status as of 21 October 2026. Read this with `docs/api-bas-mastery-qa-log.md`, which holds the evidence for each completed item.

## 1. Where things stand

Completed and pushed to origin/main:

- Phases 1 to 6, including the source-backed regulatory registry, the reporting-workflow engine and its notification scenarios (Phase 6, `c439dda8`).
- Verified mappings for RBI IN-RBI-ITGRC-19A and UAE PDPL UAE-PDPL-A15-2, reviewed by Zain (`f842ed48`).
- Owner read-path erasure checks, DATA-012 and DATA-013 (`4612104f`).
- The NBFC sector pack: ten scenarios (AUTHZ-101 to 106, DATA-101 to 104), administrative access with audit, statement coverage, and detection wiring (`627a341f`). Verified from a fresh clone, with Windows cross-compiles passing.
- Catalogue size: 120 scenarios.

Written locally, not committed:

- The platform decisions for production, and the secret-store verification, appended to `docs/api-bas-mastery-qa-log.md`.
- This document.

Nothing is running in the background. The autonomous loop is stopped.

## 2. Decisions needed before implementation

These come from you. Implementation is blocked until they are answered.

| # | Decision | Current state | What is needed |
|---|---|---|---|
| D1 | External secret manager | The platform has no suitable store. Connector and SIEM credentials are plaintext `text` columns. `pgcrypto` is created but never used. | Confirm Vault, or name an external manager your organisation already approves. |
| D2 | Owner for the 250 ms timing ceiling | Not named. ABUSE-002 stays provisional. | A named product or security owner who approves the requirement and its rationale. |
| D3 | Staging load for timing qualification | `audspecterver` is the existing staging host (`zain@audspecterver`). | Confirm no other workload runs on it during qualification. Then record hardware, OS and build, Go version, CPU and memory, workload, and background load. |
| D4 | Plaintext platform credentials | Existing connector, SIEM, SSO and webhook secrets are plaintext at the column level. This is outside API BAS. | Decide whether to address this now or as separate work. |
| D5 | Credential rotation | Open. Nothing implements rotation. The earlier P0 rotation was declined. | Decide whether rotation is in scope for API BAS, and how. |
| D6 | PDPL wording reconfirmation | The DATA-011 coverage-gap text changed to point at DATA-012 and DATA-013. | Zain reconfirms the wording. The verification itself is unchanged. |

## 3. Implementation plan (starts after D1 to D3)

The order follows the platform decisions in the QA log. Each step needs its own tests and fresh-clone verification.

1. **Results store.** A Postgres migration for run metadata, scenario verdicts, exploitability results, detection outcomes, evidence references, hashes, timestamps, and target and build fingerprints. No raw HTTP bodies by default. Redact secrets and protected values. Retention defaults to 90 days and is configurable per installation.
2. **Access control.** A dedicated API BAS read permission for results and reports. Run-management permission must not grant result access. Admin access to results is explicit and audited.
3. **Run now.** A manual action on `internal/jobs`. Every run names a target, a scenario set and an environment. A general request may not supply an arbitrary target URL.
4. **Live-run approval.** Each live run needs explicit operator approval. A target-level approval flag alone is not enough.
5. **Safety.** Concurrency limits, timeouts, cancellation, and bounded retries. Never automatically retry a potentially state-changing live scenario. No production schedules enabled by default.
6. **Secret adapter.** Behind the existing `SecretResolver` interface, using the store chosen in D1. Credentials are referenced per target and granted to a run only when needed. Secrets never go into job records, result records or logs. Environment variables are for the lab and development only.
7. **Timing qualification.** Run only after D2 and D3 are answered. Until then, timing results are diagnostic only, or INCONCLUSIVE when qualification is missing.

## 4. Detection gaps

- **NBFC-007 (DATA-102)** stays `not_evaluated`. The loan read returns KYC identity evidence through a projection. REL-008 covers only foreign-owned projections, and the access event does not record which fields a response returned. A fix needs a field-level record in the event. That is an engineering decision, so it is not started.
- **Live SIEM validation has not been done.** Every detection result is `fixture_validated`.
- **Identity-forged blind spot (AUTHN-003, AUTHN-007).** Not started. The fix is to record the trusted identity from the authentication layer, not the claimed one.
- **False-positive measurement (DET-006).** Only partly covered by the healthy control. Full measurement is not done.

## 5. Timing

- ABUSE-002's 250 ms ceiling is provisional. It is evaluated but not validated.
- No new timing scenarios until D2 and D3 are answered.
- Until qualification is complete, timing is reported as diagnostic only, or INCONCLUSIVE.
- Policy: `docs/api-bas-timing-policy.md`.

## 6. Regulatory and reporting

- **RBI AUTHZ-001** is not extended to NBFC. A fresh applicability review is needed first.
- **NBFC scenarios** carry no regulatory mapping. Industry references in their YAML are descriptive only.
- **CBUAE clauses 6.1.2.6 and 6.1.7.2** have no provision-derived deadline. The CBUAE scenario never PASSes on timeliness until one is recorded and reviewed.
- **No live reporting channel.** A simulated PASS proves a workflow check only. It does not prove submission to CERT-In or the Central Bank.
- **DPDP section 12** stays unverified. The notification bringing it into force is not in the source set.
- **PDPL Executive Regulation** is not in the source set. It is a recorded gap.
- **Source URLs** in the registry came from search results and have not been fetched. The committed PDFs are the bytes the registry tests check.

## 7. Sector packs

- Manufacturing, healthcare, and retail/logistics/telecom are not started. You asked to hold them until the NBFC pack set a reusable pattern. That pattern now exists.
- Run a live NBFC deployment check. It has not been done.

## 8. Cleanup in the QA log

Some older "not done" lines are out of date and should be corrected:

- The Phase 5 list says DATA-011 is not checked against every read path. DATA-012 and DATA-013 cover that now.
- The Phase 5 list says no mapping has a reviewer. RBI and PDPL are now verified, and DPDP stays unverified.
- The Phase 6 list says the reporting scenarios are not built. They are built.

Also review the "still open" lines in the Blueprint Phase 3 section for the same problem.

## 9. Standing rules for the next session

- Commit and push after each phase. Stage only apibas files. Do not stage `.claude/settings.local.json`, `orchestrator/agents/BINARIES.sha256(.sig)`, `scenarios/*.sig`, or other unrelated modified files.
- Commit messages end with `Co-Authored-By: Claude Haiku 5.5 <noreply@anthropic.com>`.
- After each phase, verify a fresh clone: `go build`, `go test` on the affected packages, and `GOOS=windows go build ./cmd/server ./cmd/apibas-lab ./cmd/apibas-runner`.
- Any scenario edit requires re-signing its `.sig` file.
- Do not extend a regulatory mapping without a fresh applicability review and human approval.
- Record unverified results as unverified, and label simulated results as simulated.

## 10. Quick resume checklist

1. Answer D1 to D6.
2. Commit the QA-log platform-decisions entry and this document together.
3. Start step 1 of section 3 once D1 to D3 are answered.
