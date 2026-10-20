# API BAS Mastery — Step 0 Repository Audit

Source brief: `api.txt` (repo root). Audit date: 2026-10-20. Read-only: no code, scenario, or signature was changed.

Purpose: map what the repository already has for API security validation against the api.txt taxonomy (§1, categories 01–10), before any blueprint or build. Per api.txt §9, nothing here is counted as delivered coverage unless it is executable and evidence-backed.

## 1. What exists

| Area | Location | Count | Nature |
|---|---|---|---|
| API attack vectors | `orchestrator/internal/wafcatalog/catalog_api.go` | 6 (`API-001..003`, `AUTH-001..003`) | Declarative `AttackVector` records with request templates and CWE / OWASP API Top 10 mappings |
| API business-flow vectors | `orchestrator/internal/wafapiflow/catalog.go` | 5 (`APIFLOW-001..005`) | Declarative, with benign counterpart and standards mapping |
| Bot / automated-abuse vectors | `orchestrator/internal/wafbotabuse/catalog.go` | 4 (`BOTABUSE-001..004`) | Declarative |
| Shared web / network vectors | `wafcatalog` (`SQLI`, `XSS`, `PATHTRAV`, `SSRF`, `FILEUP`, `HTTPPARSE`, `RATE`, `CACHE`, `POLICY`) | 20 | Declarative; SSRF-001 is a webhook-callback SSRF |
| Attack-agnostic detection validation | `wafdetection` (completeness, alert correlation, response timing) | 3 shapes | Evaluation logic |
| Deployment-topology bypasses | `waforigin` (routing / direct-origin / fail-open, TLS and proxy forgery, cross-node consistency) | — | Evaluation logic |
| Shared evidence and verdict model | `wafval` (`CollectionResult`, `Observation`, `Verdict`) | — | Reusable core |
| Enterprise assessment scenarios | `wafassessment` + `/api/waf/scenarios/{slug}` (10 slugs, incl. `api-protection`) | 10 | Fixture-driven (see §3) |
| Industry profiles | `wafprofile` (BFSI, NBFC, manufacturing, healthcare, India, UAE) | 8 profiles | Unverified-only compliance references by design |
| Server-side ground-truth precedent | `internal/api/dlp_sink.go`, `webhooksink`, `cloudsink` | — | Sink-verified delivery via per-run token |
| Scenario YAML library | `scenarios/*.yaml` (188 files incl. signatures) | 1 API-named | `dlp-exfiltration-webhook.yaml` only |

## 2. Coverage against api.txt categories

Legend: **Partial** = some vectors exist but they are WAF-evaluation claims, not authorization or backend-outcome proofs. **Missing** = no vector or executor.

| # | api.txt category | Existing vectors | Status | Gap summary |
|---|---|---|---|---|
| 01 | Identity, authentication, session | AUTH-001 (credential-stuffing burst), AUTH-002 (enumeration), AUTH-003 (JWT `alg=none`), APIFLOW-002 (wrong-scope token), APIFLOW-003 (reset-token replay), BOTABUSE-003/004 (lockout) | Partial | No real token validation against an IdP. No OAuth/OIDC flow tests (PKCE, redirect URI, consent). No mTLS, service-account, session-binding, or step-up MFA tests. |
| 02 | Authorization / access-control bypass | API-001 (BOLA), API-002 (mass assignment), APIFLOW-002 (scope) | Partial, weakest of the partials | No multi-identity fixtures or ownership graph. No BFLA, parent-child, bulk, alternate-version, method-swap, or cache-leakage cases. |
| 03 | Gateway, WAF, perimeter | HTTPPARSE-001/002, POLICY-001/002, RATE-001/002, CACHE-001/002, PATHTRAV-002, APIFLOW-001 (schema), `waforigin` bypass pairs | Partial, strongest area | Shadow-route discovery, host-header and forwarded-header trust, and fail-open are only partly modelled. Gateway-node and region drift is not executable. |
| 04 | Input validation and injection | SQLI-001..003, XSS-001..003, PATHTRAV-001/002, SSRF-001/002, FILEUP-001/002 | Partial (web-centric) | No NoSQL, command or expression, SSTI, LDAP, XXE, JSON deserialization, prototype pollution, or GraphQL manipulation beyond depth. Note: these are WAF-block claims; api.txt requires proof of exploitation, not only blocking. |
| 05 | Business logic and sensitive workflows | APIFLOW-001 (negative quantity), APIFLOW-003 (reset-token replay) | **Missing** (essentially) | No payment, transfer, refund, maker-checker, race, idempotency-key, step-skipping, limit, beneficiary, or coupon scenarios. Only two vectors touch business logic. |
| 06 | Sensitive data exposure and privacy | API-003 (verbose-fields exposure), APIFLOW-005 (bulk-export limit), CACHE-002 | Partial | No cross-identity data-access ground truth, signed-URL or object-storage checks, log/error-leakage checks, export authorization, or retention-workflow checks. |
| 07 | Resource consumption and abuse | RATE-001/002, BOTABUSE-001..004, APIFLOW-004 (GraphQL depth), APIFLOW-005, FILEUP-002 (decompression) | Partial | No OTP/SMS cost-abuse path, queue-growth or retry-storm measurement, or controlled-environment recovery measurement. |
| 08 | Integrations, webhooks, backend trust | SSRF-001 (webhook callback), SSRF-002, `dlp-exfiltration-webhook` | **Missing** for API webhooks | `dlp-exfiltration-webhook` tests DLP egress via Slack/Teams-shaped POSTs, not webhook signature, timestamp or replay validation. No service-to-service, confused-deputy, partner-trust, or async-message integrity tests. |
| 09 | Discovery, lifecycle, configuration | POLICY-001/002 (indirect) | **Missing** | No OpenAPI import, shadow/orphaned API discovery, spec-vs-deployed drift, CORS, debug/admin endpoint discovery, or cross-environment auth comparison. |
| 10 | Detection, correlation, IR | `wafdetection` (completeness, alert correlation, response timing), `wafefficacy`, DLP sink token pattern | Partial, reusable | Detection shapes exist but are attack-agnostic and not wired to an API-event adapter. No SIEM case-routing test for API events, and no identity or transaction attribution check. |

Protocol coverage (api.txt §2): REST/JSON is the only protocol with executable-looking request templates. GraphQL has one depth vector. gRPC, SOAP/XML, WebSocket, async/queues, and mobile/device APIs have no vectors or adapters.

## 3. Findings that shape the blueprint

**F1. The WAF API catalogs are declarative and nothing executes them.**
No package under `wafcatalog`, `wafapiflow`, or `wafbotabuse` sends an HTTP request. A grep for `http.Client`, `.Do(`, and `http.NewRequest` across those packages returns nothing. The only consumers are `wafassessment` and `internal/api/waf_assessment_handlers.go`, which read the seed data. There is no executor, identity model, or backend probe for these vectors. *Implication:* the API BAS engine needs a real execution layer. Catalog entries alone do not satisfy api.txt.

**F2. The API-protection assessment is fixture-driven.**
`wafassessment/catalog_apiprotection.go` assigns `blocked()` or `missed()` per vector, and `/api/waf/scenarios/api-protection` serves the result. The report itself is labelled honestly: `reporting/waf_enterprise_scenario.go:123` says "every assertion above is fixture-validated, not a claim about a deployed WAF's live efficacy." That label should be kept. The memory note calling WAF "feature complete" is accurate only for the fixture layer. api.txt §9 would not count these as live-validated.

**F3. No vector has a backend ground-truth check.**
api.txt requires that a BOLA result depend on the backend's actual authorization outcome, not on a 200 response or a WAF verdict. None of the existing vectors defines a state-comparison step. Their verdict comes from `wafval` observations (enforcement, detection). A valid-looking request for another user's object ID is usually not a signature match, so a WAF will often allow it. A WAF-based BOLA verdict therefore measures the wrong thing. The strongest precedent for ground truth is the DLP sink: a per-run token must reach a server-side route, and the server verifies it.

**F4. No multi-identity or ownership model.**
Found no fixture type representing two synthetic customers with known objects. `API-001`'s benign template uses `{own_order_id}` and `{other_user_order_id}` as placeholders, but nothing resolves them.

**F5. Strong, reusable foundations.**
`wafval`'s separation of enforcement, detection and origin axes; its refusal to derive verdicts outside `EvaluateClaim`; `Coverage` as a first-class skepticism primitive; `wafdetection`'s separate verdict taxonomies; `wafprofile`'s unverified-only compliance stance; and the DLP sink's server-side token pattern. These match api.txt's rules closely. The blueprint should build on them rather than introduce new verdict strings.

**F6. API BAS stays separate from existing scenarios and vectors.**
`wafassessment` already imports `API-001..003` and `APIFLOW-001..005` by ID. The API BAS work must not reuse, rename, or extend those IDs, nor edit the `wafcatalog`, `wafapiflow`, `wafbotabuse` or `wafassessment` seed data, nor add files to the existing `scenarios/` YAML set. Separation rules, set by the user on 2026-10-20:

- Own ID namespace: `API-BAS-<CAT>-<NNN>` for scenarios, with the category codes from api.txt §1 (e.g. `API-BAS-AUTHZ-001`). Existing `API-00x`, `APIFLOW-00x`, `AUTH-00x` and `BOTABUSE-00x` IDs are never reused.
- Own package: a new `internal/apibas` tree. No changes to `wafval` semantics; if a shared type is needed, it is imported read-only.
- Own scenario directory: `scenarios/api-bas/`, so no existing `.yaml` or `.sig` file is touched and the signing gate applies only to the new files.
- Own assessment slug and report: distinct from `api-protection` in `/api/waf/scenarios/`. Its report never merges with WAF efficacy results.

## 4. Gap-to-phase mapping (input to the blueprint)

| Gap | Blueprint phase (api.txt §8) | Acceptance test |
|---|---|---|
| F1 no executor | Phase 1 Core engine | A BOLA scenario sends two real requests as two identities and records response plus state |
| F3 no ground truth | Phase 1 | A deliberately permissive fixture causes the scenario to FAIL on backend state even when the response looks blocked |
| F4 no identity matrix | Phase 1 | Negative test: same identity on both sides must not produce a finding |
| 05 business logic | Phase 3 | Replayed transfer on a sandbox ledger fixture changes balance twice; scenario FAILs on invariant break |
| 02 authorization depth | Phase 2 | BFLA, cross-tenant, parent-child and bulk cases each have a positive and a negative fixture |
| 08 webhook / backend trust | Phase 3 | Replayed signed webhook is accepted or rejected by a fixture receiver, verified server-side |
| 09 discovery | Phase 2 (partial), Phase 1 (import) | OpenAPI import diffed against a deployed fixture reports a documented-but-undeployed route |
| 10 detection | Phase 4 | Known attack produces a verified event at a fixture SIEM sink, not a simulated success flag |
| Protocols beyond REST | Phase 3, capability-gated | Unsupported protocols are reported as UNSUPPORTED, not covered |

## 5. Open items for the blueprint

1. **Lab target.** Deterministic fixtures need an API we own, with planted flaws and a fixed-correct variant. Nothing in the repo provides one. This is the main prerequisite and needs a decision.
2. **Execution origin.** Requests could come from the orchestrator, from an agent on the target network, or from a test runner with identity material. The DLP precedent runs agent-side. The API BAS identity and secret handling needs a decision before design.
3. **Regulatory versions.** `wafprofile` holds unverified references. api.txt §4 asks for versioned, sourced mappings. Sourcing must happen before any mapping is claimed.
4. **Scenario signing.** Any new `scenarios/*.yaml` requires re-signing the `.sig` (see the scenario signature gate note).

## 6. Summary

The repository has a credible verdict and evidence core and about 15 API-specific or bot-related vectors. However, none of them are executed, none check backend ground truth, and the API-protection assessment is fixture-driven, though it is labelled that way. Business logic, discovery, protocols beyond REST, and webhook/backend trust are effectively missing. The next step is the blueprint, which turns these findings into scenario contracts and phased acceptance tests, starting with the lab-target decision.
