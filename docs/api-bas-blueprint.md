# API BAS Mastery — Engineering Blueprint

Source brief: `api.txt` (repo root). Step 0 audit: `docs/api-bas-audit.md` (2026-10-20). Status: **Phases 1–19 merged to `main` (28 scenarios). Phase 20 tranche (environment fingerprint, tie-corrected separation, explicit requalification) on branch `feature/api-bas-phase20`.**

Goal (api.txt): the deepest defensible validation of whether an enterprise API's security controls work under realistic attack, with independent evidence for every result. Not the largest scenario catalog.

## 0. Separation rules (binding)

Set by the user on 2026-10-20. API BAS must stay separate from existing WAF and scenario work.

| Item | API BAS | Must not touch |
|---|---|---|
| Scenario/vector IDs | `API-BAS-<CAT>-<NNN>` (campaigns: `API-BAS-C-<NNN>`) | `API-00x`, `APIFLOW-00x`, `AUTH-00x`, `BOTABUSE-00x`, any `scenarios/*.yaml` ID |
| Go package | `orchestrator/internal/apibas/...` | `wafcatalog`, `wafapiflow`, `wafbotabuse`, `wafassessment`, `wafefficacy` seed data |
| Scenario YAML | `orchestrator/internal/apibas/catalog/*.yaml` (embedded) | Anything under `scenarios/`: the live engine walks that tree recursively and would load these as live scenarios |
| Report slugs | `api-bas-*` under a new route group | `/api/waf/scenarios/*` |
| Shared code | Read-only import of `wafval` verdict/coverage types; no semantic changes | Any change to `wafval` behaviour |
| Lab target | `orchestrator/internal/apibas/lab` + `orchestrator/cmd/apibas-lab` (not mounted by `cmd/server`) | Orchestrator routes |

## 1. Taxonomy

Every api.txt §1 bullet becomes one sub-technique ID. Category codes and counts match api.txt exactly (110 sub-techniques).

**Phase column** = the api.txt §8 phase that implements it. P2 = core security vectors; P3 = business logic and protocols; P4 = detection; P5 = sector packs; "P1-lab" = proven by the Phase 1 vertical slice where noted.

### AUTHN — 01 Identity, authentication and session (10)
| ID | Sub-technique | Phase |
|---|---|---|
| API-BAS-AUTHN-001 | Missing authentication on protected endpoints | P2 |
| API-BAS-AUTHN-002 | Expired, revoked, malformed and replayed tokens | P2 |
| API-BAS-AUTHN-003 | JWT algorithm, issuer, audience and signature validation | P2 |
| API-BAS-AUTHN-004 | OAuth 2.0 and OIDC flow weaknesses | P3 |
| API-BAS-AUTHN-005 | OAuth scope, consent, redirect URI and PKCE enforcement | P3 |
| API-BAS-AUTHN-006 | API keys, secrets, rotation and privilege scope | P2 |
| API-BAS-AUTHN-007 | mTLS identity and client-certificate validation | P3 |
| API-BAS-AUTHN-008 | Session binding, token substitution and identity confusion | P2 |
| API-BAS-AUTHN-009 | Service accounts, workload identities and M2M authentication | P3 |
| API-BAS-AUTHN-010 | MFA and step-up enforcement for sensitive actions | P3 |

### AUTHZ — 02 Authorization and access-control bypass (12)
| ID | Sub-technique | Phase |
|---|---|---|
| API-BAS-AUTHZ-001 | BOLA/IDOR: unauthorized access to another user's object | P1-lab |
| API-BAS-AUTHZ-002 | BFLA: unauthorized privileged functions | P2 |
| API-BAS-AUTHZ-003 | Property-level authorization and mass assignment | P2 |
| API-BAS-AUTHZ-004 | Horizontal and vertical privilege escalation | P2 |
| API-BAS-AUTHZ-005 | Cross-customer, cross-account and cross-branch access | P2 |
| API-BAS-AUTHZ-006 | Parent-child object authorization failures | P2 |
| API-BAS-AUTHZ-007 | Nested resource and bulk-operation authorization | P2 |
| API-BAS-AUTHZ-008 | Role, group, scope and entitlement inconsistencies | P2 |
| API-BAS-AUTHZ-009 | Read-vs-write-vs-delete permission differences | P2 |
| API-BAS-AUTHZ-010 | Bypass through alternate endpoints, methods or API versions | P2 |
| API-BAS-AUTHZ-011 | Cache-based authorization leakage | P2 |
| API-BAS-AUTHZ-012 | Asynchronous job, export and download authorization | P3 |

### GWAY — 03 Gateway, WAF and perimeter (12)
| ID | Sub-technique | Phase |
|---|---|---|
| API-BAS-GWAY-001 | Gateway bypass through direct backend access | P2 |
| API-BAS-GWAY-002 | Shadow APIs and undocumented routes | P2 |
| API-BAS-GWAY-003 | HTTP method and content-type policy gaps | P2 |
| API-BAS-GWAY-004 | Path normalization, encoding and routing inconsistencies | P2 |
| API-BAS-GWAY-005 | Duplicate headers, ambiguous parsing, request smuggling conditions | P2 |
| API-BAS-GWAY-006 | Host-header and forwarded-header trust failures | P2 |
| API-BAS-GWAY-007 | WAF evasion through encoding and structured payload variation | P2 |
| API-BAS-GWAY-008 | Missing schema enforcement and permissive policies | P2 |
| API-BAS-GWAY-009 | Rate-limit bypass through identity, key, IP or route variation | P2 |
| API-BAS-GWAY-010 | Inconsistent policy between gateway nodes and regions | P2 |
| API-BAS-GWAY-011 | Fail-open behaviour when security dependencies fail | P2 |
| API-BAS-GWAY-012 | TLS configuration, certificate validation, upstream trust | P3 |

### INJ — 04 Input validation and injection (12)
| ID | Sub-technique | Phase |
|---|---|---|
| API-BAS-INJ-001 | SQL and NoSQL injection | P2 |
| API-BAS-INJ-002 | Command and expression injection | P2 |
| API-BAS-INJ-003 | Server-side template injection | P2 |
| API-BAS-INJ-004 | LDAP and directory query injection | P2 |
| API-BAS-INJ-005 | XML external entity processing | P3 |
| API-BAS-INJ-006 | JSON parser and deserialization weaknesses | P2 |
| API-BAS-INJ-007 | GraphQL query manipulation | P3 |
| API-BAS-INJ-008 | Path traversal and unsafe file references | P2 |
| API-BAS-INJ-009 | Header injection and response splitting | P2 |
| API-BAS-INJ-010 | Server-side request forgery | P2 |
| API-BAS-INJ-011 | Prototype pollution and unsafe object merging | P2 |
| API-BAS-INJ-012 | Validation inconsistencies across JSON, XML, multipart, form | P2 |

### BIZ — 05 Business logic and sensitive workflows (12)
| ID | Sub-technique | Phase |
|---|---|---|
| API-BAS-BIZ-001 | Payment, refund and transfer authorization | P3 |
| API-BAS-BIZ-002 | Price, quantity, fee and discount manipulation | P3 |
| API-BAS-BIZ-003 | Transaction replay and duplicate processing | P3 |
| API-BAS-BIZ-004 | Idempotency-key misuse | P3 |
| API-BAS-BIZ-005 | Race conditions and concurrent state changes | P3 |
| API-BAS-BIZ-006 | Workflow step skipping and out-of-order transitions | P3 |
| API-BAS-BIZ-007 | Approval and maker-checker bypass | P3 |
| API-BAS-BIZ-008 | Limits, quotas and transaction-velocity controls | P3 |
| API-BAS-BIZ-009 | Account enrollment and beneficiary changes | P3 |
| API-BAS-BIZ-010 | Coupon, reward, credit and loyalty abuse | P3 |
| API-BAS-BIZ-011 | Reservation, inventory and resource allocation abuse | P3 |
| API-BAS-BIZ-012 | Fraud controls that fail to trigger or produce actionable alerts | P4 |

### DATA — 06 Sensitive data exposure and privacy (11)
| ID | Sub-technique | Phase |
|---|---|---|
| API-BAS-DATA-001 | Excessive response fields and hidden object properties | P2 |
| API-BAS-DATA-002 | PII, financial, health and confidential business-data leakage | P2 |
| API-BAS-DATA-003 | Sensitive data in error messages, logs, debug endpoints | P2 |
| API-BAS-DATA-004 | Bulk enumeration and pagination abuse | P2 |
| API-BAS-DATA-005 | Search, filter and aggregation side channels | P3 |
| API-BAS-DATA-006 | Cache poisoning and private-response caching | P2 |
| API-BAS-DATA-007 | Download, report and export data leakage | P3 |
| API-BAS-DATA-008 | Weak field-level masking and redaction | P2 |
| API-BAS-DATA-009 | Cross-environment data exposure | P3 |
| API-BAS-DATA-010 | Insecure object-storage references and signed-URL handling | P3 |
| API-BAS-DATA-011 | Data retention and deletion workflow inconsistencies | P5 |

### ABUSE — 07 Resource consumption and automated abuse (10)
| ID | Sub-technique | Phase |
|---|---|---|
| API-BAS-ABUSE-001 | Missing or inconsistent rate limits | P2 |
| API-BAS-ABUSE-002 | Expensive search, report and aggregation requests | P2 |
| API-BAS-ABUSE-003 | Excessive pagination and batch sizes | P2 |
| API-BAS-ABUSE-004 | GraphQL depth, breadth and complexity abuse | P3 |
| API-BAS-ABUSE-005 | Unbounded uploads and decompression | P2 |
| API-BAS-ABUSE-006 | Resource exhaustion via expensive validation or downstream calls | P3 |
| API-BAS-ABUSE-007 | SMS, OTP, email and paid-service consumption abuse | P3 |
| API-BAS-ABUSE-008 | Account creation and credential-validation automation | P2 |
| API-BAS-ABUSE-009 | Distributed low-rate abuse and per-identity throttling gaps | P2 |
| API-BAS-ABUSE-010 | Queue growth, retry storms, cascading failures | P3 |

### INTEG — 08 Integrations, webhooks and backend trust (11)
| ID | Sub-technique | Phase |
|---|---|---|
| API-BAS-INTEG-001 | Third-party API response trust and validation | P3 |
| API-BAS-INTEG-002 | Webhook signature, timestamp and replay validation | P3 |
| API-BAS-INTEG-003 | Outbound request destination restrictions | P2 |
| API-BAS-INTEG-004 | Unsafe redirects and DNS resolution changes | P2 |
| API-BAS-INTEG-005 | Internal service authentication gaps | P3 |
| API-BAS-INTEG-006 | Service-to-service authorization and confused-deputy failures | P3 |
| API-BAS-INTEG-007 | Dependency failure and fallback behaviour | P3 |
| API-BAS-INTEG-008 | Secret leakage in integration configuration | P2 |
| API-BAS-INTEG-009 | Excessive trust in partner identities | P3 |
| API-BAS-INTEG-010 | Event and message tampering | P3 |
| API-BAS-INTEG-011 | Insecure callback registration and subscription management | P3 |

### DISC — 09 API discovery, lifecycle and configuration (10)
| ID | Sub-technique | Phase |
|---|---|---|
| API-BAS-DISC-001 | Undocumented, shadow and orphaned APIs | P2 |
| API-BAS-DISC-002 | Deprecated and legacy API versions | P2 |
| API-BAS-DISC-003 | Debug, health, diagnostic and administrative endpoints | P2 |
| API-BAS-DISC-004 | OpenAPI specification vs deployed behaviour drift | P2 |
| API-BAS-DISC-005 | Missing security schemes or permissive CORS | P2 |
| API-BAS-DISC-006 | Environment-specific authentication differences | P3 |
| API-BAS-DISC-007 | Insecure defaults and exposed documentation | P2 |
| API-BAS-DISC-008 | Improper error handling and information disclosure | P2 |
| API-BAS-DISC-009 | Inconsistent controls across REST, GraphQL, gRPC, SOAP | P3 |
| API-BAS-DISC-010 | Configuration drift across clusters, regions, gateways | P3 |

### DET — 10 Detection, correlation and incident response (10)
| ID | Sub-technique | Phase |
|---|---|---|
| API-BAS-DET-001 | Gateway/API-security platform detects each simulated attack | P4 |
| API-BAS-DET-002 | Authentication and authorization failures are logged | P4 |
| API-BAS-DET-003 | High-risk business-flow violations alert | P4 |
| API-BAS-DET-004 | Distributed activity correlated across identities and endpoints | P4 |
| API-BAS-DET-005 | API attack alerts routed to the correct SIEM/SOC | P4 |
| API-BAS-DET-006 | Detections are actionable, not overwhelmed by false positives | P4 |
| API-BAS-DET-007 | Events attributed to the correct user, service and transaction | P4 |
| API-BAS-DET-008 | Responders can identify affected resources | P4 |
| API-BAS-DET-009 | Detection holds when telemetry is delayed or partly missing | P4 |
| API-BAS-DET-010 | Incident investigable from retained evidence | P4 |

Note (api.txt §10): a 403 does not prove detection. DET IDs are always separate assertions from the attack's own result.

## 2. Protocol capability matrix

Protocol support is capability-driven. A protocol without an executable adapter and fixture is `UNSUPPORTED`, never counted as covered.

| Surface | Adapter | Phase | Initial state |
|---|---|---|---|
| REST / JSON | HTTP adapter (method, path, headers, JSON/XML/multipart bodies) | P1 | Planned, first target |
| GraphQL | HTTP adapter + query builder (alias, batch, depth) | P3 | Planned |
| gRPC / Protobuf | Requires descriptor import and a gRPC client | P3 | `UNSUPPORTED` until adapter exists |
| SOAP / XML | HTTP adapter with WS-Security headers, XML entity fixtures | P3 | `UNSUPPORTED` until adapter exists |
| WebSockets | Handshake and frame adapter | P3 | `UNSUPPORTED` until adapter exists |
| Webhooks | Sink receiver in lab + signature/timestamp fixtures | P3 | Planned (reuses sink-token pattern) |
| Async / queues | Broker adapter | P3+ | `UNSUPPORTED` until adapter exists |
| OAuth / OIDC | Fixture IdP in lab | P3 | Planned |
| Mobile / device APIs | Out of scope for P1–P3 | — | `UNSUPPORTED` |
| API management planes | Out of scope for P1–P3 | — | `UNSUPPORTED` |

## 3. Engine architecture

Five stages, mirroring api.txt §5. Each stage writes to a separate record type so execution, control and response results never merge.

1. **Discover and inventory** (`internal/apibas/inventory`): OpenAPI import, approved endpoint list, protocol and version inventory. Output: `Inventory` with a source tag per endpoint (`documented` | `observed` | `approved`).
2. **Test context** (`internal/apibas/context`): identities, roles, object-ownership graph, policy expectations, synthetic fixtures. Identity material comes from a secret store reference, never inline in YAML.
3. **Execute** (`internal/apibas/runner`): baseline request, attack variant, then state snapshot before and after. Produces an `ExecutionRecord` per step.
4. **Verify** (`internal/apibas/verify`): ground-truth adapters read state independently of the HTTP response (see §4). Produces a `GroundTruth` record.
5. **Grade and report** (`internal/apibas/grade`, `internal/apibas/report`): combines the three independent axes in §5.

### 3.1 Scenario contract (api.txt §6)

Every scenario is YAML under `orchestrator/internal/apibas/catalog/`, embedded in the binary. Required fields:

```yaml
id: API-BAS-AUTHZ-001            # stable, unique, API-BAS namespace only
name: BOLA on an orders endpoint
category: AUTHZ
attack_objective: Customer A reads Customer B's order object
threat_model:
  attacker: authenticated customer
  identity: customer-a
  access_level: standard user
  objective: read another customer's order
preconditions:
  - identities: [customer-a, customer-b]
  - fixture: orders-two-tenant
  - endpoint: GET /api/orders/{id}
request_mutation: substitute customer-b's order id into customer-a's request
expected_control: order endpoint returns 403/404 and does not disclose the object
ground_truth:
  adapter: state
  check: order owner unchanged; response body contains no customer-b fields
detection_assertion:
  adapter: siem
  required_event: authz_denied for customer-a's token on the order id
evidence: [sanitized_request, sanitized_response, state_diff, event_ids]
result_vocabulary: [PASS, FAIL, ERROR, SKIPPED]
skip_reason_codes: [ADAPTER_UNAVAILABLE, PRECONDITION_MISSING, PERMISSION_MISSING, OUT_OF_SCOPE, UNSUPPORTED_PROTOCOL]
confidence: evidence-backed | inferred | inconclusive
cleanup: [delete-run-tagged-records]
industry_mapping: [banking: cross-customer statement access]
regulatory_mapping: []           # populated only with verified sources (§7)
side_effect_class: READ_ONLY
steps: [...]                     # campaign form; single-step scenarios use one step
negative_tests: [API-BAS-AUTHZ-001-N1]
```

Campaigns (api.txt, "Every scenario should be an attack campaign") add `steps` with `depends_on`, `branch_on`, and `failure_path`. A step that tests no hypothesis is rejected at load time.

## 4. Ground-truth adapters

A verdict must depend on the backend's real outcome. Each adapter declares its capability at startup; a scenario that needs an unavailable adapter becomes `SKIPPED` with `ADAPTER_UNAVAILABLE`, never `PASS`.

| Adapter | Source | Purpose | Phase |
|---|---|---|---|
| `state` | Lab state API, or read-only DB query with a scoped role | Ownership, balances, status, row counts before/after | P1 |
| `response` | Captured HTTP response | Field-level disclosure checks; **supporting only, never sufficient for PASS** | P1 |
| `gateway-log` | Gateway access log export | Routing, rate-limit and policy decisions | P2 |
| `siem` | SIEM query adapter (fixture SIEM in lab first) | Detection assertions | P4 |
| `sink` | Existing server-side token sink pattern | Delivery proof for webhooks and egress | P3 |

Rules, from api.txt §5 and §9:
- A 2xx response alone never produces a finding.
- A timeout, connection failure, empty body or unsupported adapter never produces PASS.
- Every state-changing step records a before and after snapshot with the test-run tag.

## 5. Grading model

Three independent axes per step. The reporting layer must never collapse them into one label.

| Axis | Values | Source |
|---|---|---|
| **Exploitability** — was the weakness exploitable? | `exploited`, `not_exploited`, `inconclusive` | Ground-truth adapter |
| **Control** — did the preventive control hold? | `enforced`, `failed`, `inconclusive` | Ground truth + expected control |
| **Detection** — was the attempt detected? | `detected`, `not_detected`, `inconclusive` | `siem`/`gateway-log` adapter (separate assertion) |

Scenario **Result** follows the existing outcome layer (`PASS`, `FAIL`, `ERROR`, `SKIPPED`) so reports stay consistent with the rest of Audspect. Rules:
- `PASS` requires `Control=enforced` **and** ground truth present. Detection failure is reported as its own finding and does not change the control result.
- `FAIL` requires `Exploitability=exploited` or `Control=failed` backed by ground truth.
- `ERROR` for infrastructure faults. `SKIPPED` for missing preconditions, with a machine-readable reason.
- `inconclusive` never grades as `PASS` or `FAIL`.

The existing `wafval` verdict strings (blocked, missed, and so on) are WAF-specific and are not reused here. Only `wafval`'s `Coverage` skepticism primitive is reused, read-only.

## 6. Safety and execution boundaries

| Side-effect class | Meaning | Default | Required to run |
|---|---|---|---|
| `READ_ONLY` | No state change | Allowed in lab and approved targets | Target allowlist |
| `STATE_CHANGE_SANDBOX` | Writes to synthetic records | Lab and sandbox only | Per-run authorization + tagged cleanup |
| `EXTERNAL_CONSEQUENTIAL` | Sends messages, triggers payments, consumes paid resources | Blocked by default | Explicit per-scenario authorization; not in P1–P3 |
| `RESOURCE_INTENSIVE` | Load, depth or size stress | Lab only, capped volumes | Lab flag; no production |

Hard rules:
- No production denial-of-service. Rate and resource scenarios run against lab fixtures with bounded volume and measure recovery, not outage.
- All synthetic data is fabricated and tagged; no real customer data.
- Every run records a run ID; cleanup deletes only run-tagged records and never audit evidence.
- Target scope is an explicit allowlist per run. The runner refuses hosts outside it.

## 7. Regulatory and sector mapping

Mapping records are data with provenance, not claims:

```
control_ref, framework, clause, version, effective_date,
applicability_conditions, mapped_scenarios, source_url, status: unverified | verified
```

- Default `status: unverified`. The `wafprofile` package follows the same unverified-by-default stance.
- India: RBI directions (applicability depends on regulated-entity type and payment activity), CERT-In directions, DPDP Act, NPCI scope. UAE: CBUAE, UAE PDPL and sectoral exceptions, DIFC/ADGM where applicable, healthcare authority requirements.
- A passing scenario demonstrates a control outcome. It does not certify compliance. Reports must carry that sentence.
- Sector packs (P5) validate business invariants, for example "customer A's statement endpoint never returns customer B's transactions" or "a beneficiary change requires the maker-checker approval."

## 8. Lab target — `internal/apibas/lab`

Required because no deterministic, owned API exists in the repo (audit §5 item 1).

- A small Go HTTP service with a seed loader for two tenants, customers, orders, accounts, and a loan-application object.
- **Two build modes from one codebase:** `vulnerable` (planted flaws, each tagged with the scenario ID it exercises) and `hardened` (the same routes with the control fixed). Every scenario has both: the vulnerable build must FAIL and the hardened build must PASS. This is the negative-test requirement from api.txt §9.
- A `state` endpoint, reachable only with a lab-admin token, that exposes ground truth for the verifier.
- A fixture IdP for OAuth/OIDC (P3), and a webhook receiver (P3).
- Runs locally or on the staging host only. Never shipped in the orchestrator binary and never reachable from production routes.

## 9. Coverage metrics (api.txt §9)

Reported separately, never summed:

| Level | Meaning |
|---|---|
| Catalogued | Sub-technique has an ID and a contract |
| Fixture-tested | Scenario runs against the lab with both vulnerable and hardened builds |
| Adapter-tested | Verified against real adapter output (e.g., a live SIEM query) |
| Live-validated | Run against an approved customer or staging target with authorization |

Baseline on day one: all 110 sub-techniques are Catalogued at most, with zero Fixture-tested. The report must say so.

## 10. Implementation phases and acceptance tests

Each phase closes only when its acceptance tests pass and the QA log is saved (`docs/api-bas-mastery-qa-log.md`).

### Phase 1 — Core engine and vertical slice
Scope: contract loader, identity and fixture model, REST HTTP adapter, `state` and `response` adapters, three-axis grading, lab with `vulnerable` and `hardened` builds, one scenario (`API-BAS-AUTHZ-001`, BOLA).

Acceptance tests:
- A1. BOLA against the vulnerable build: two identities, customer A requests customer B's order → Result `FAIL`, Exploitability `exploited`, state diff shows disclosure.
- A2. Same scenario against the hardened build → Result `PASS`, Control `enforced`, ground truth present.
- A3. Lab stopped (connection refused) → Result `ERROR`, never `PASS`.
- A4. Ground-truth adapter removed → Result `SKIPPED`, reason `ADAPTER_UNAVAILABLE`.
- A5. Same identity as both sides → no finding (negative control for the simulation itself).
- A6. Cleanup removes only run-tagged records; audit records remain.
- A7. A `200` response with no state change is not counted as exploited unless the `response` adapter shows disclosure of the protected fields.

### Phase 2 — Core security vectors
Scope: AUTHN-001/002/003/006/008; AUTHZ-002..011; GWAY-001..011; INJ (all P2 IDs); DATA P2 IDs; ABUSE-001/002/003/005/008/009; INTEG-003/004/008; DISC-001..008 (P2 IDs).

Acceptance: every scenario has a vulnerable and a hardened lab case; a scenario with no fixture is `SKIPPED`, never counted; each injection scenario distinguishes "payload blocked" from "exploit proven" using the `state` or `response` adapter.

### Phase 3 — Business logic and protocols
Scope: BIZ-001..011; INJ-005/007; AUTHN-004/005/007/009/010; GWAY-012; INTEG-001/002/005/006/007/009/010/011; GraphQL (ABUSE-004, DISC-009); webhooks; async and SOAP/gRPC/WebSocket only once their adapters pass their own tests.

Acceptance:
- Transfer or refund replay against the lab ledger: vulnerable build double-credits (`FAIL`, invariant broken), hardened build rejects the duplicate (`PASS`).
- Race scenario: the test runs N concurrent requests with a fixed seed and asserts the invariant; flakiness is measured and reported, not hidden.
- Webhook replay: the lab receiver accepts a replay on the vulnerable build and rejects it on the hardened build.
- Unsupported protocol → `UNSUPPORTED` in the report, not in the covered count.

### Phase 4 — Detection and response
Scope: DET-001..010, BIZ-012, the detection assertion on every P2/P3 scenario.

Acceptance:
- Attack executed, detection produced, verified against the `siem` adapter output (fixture SIEM in lab), not a flag.
- A 403 with no SIEM event → control `enforced`, detection `not_detected`, reported as separate findings.
- Delayed telemetry (lab injects a delay) → detection result `inconclusive` if outside the window, never `detected`.

### Phase 5 — Sector and regional packs
Scope: sector invariant scenarios for BFSI, NBFC, manufacturing, healthcare, retail/logistics/telecom; DATA-011; regulatory mappings per §7.

Acceptance: each sector scenario asserts a business invariant; every regulatory mapping has `status`, `source_url`, and `version`; no mapping is marked `verified` without a traceable source.

## 11. Decisions this blueprint makes (for your review)

These are my recommendations. Each is reversible before Phase 1 starts.

| # | Decision | Recommendation | Why |
|---|---|---|---|
| D1 | Lab target | **Confirmed 2026-10-20.** Audspect-owned vulnerable and fixed variants behind one contract, crAPI as a benchmark only | Only deterministic option; the negative test needs a fixed build |
| D2 | Execution origin | **Confirmed 2026-10-20.** Dedicated test runner (`cmd/apibas-runner`), orchestrated by Audspect; agent only where network placement requires it. Short-lived credentials, redacted evidence, per-run target allowlist | Separates scheduling and policy from request execution; agents are not mandatory |
| D3 | Verdict vocabulary | Three axes in §5, outcome layer PASS/FAIL/ERROR/SKIPPED | Keeps api.txt's separation of exploit, control and detection |
| D4 | Scenario location | **Revised 2026-10-20.** Embedded at `orchestrator/internal/apibas/catalog/`, not `scenarios/` | The live engine loads every YAML under `scenarios/` recursively, so API BAS files there would mix with live scenarios |
| D5 | Protocols in P1–P2 | REST only | Other surfaces need adapters first (api.txt §2) |

| D6 | Regulatory sources | **Confirmed 2026-10-20.** Official-source registry with versioning, applicability checks and reviewed mappings; progresses in parallel and stays `unverified` until reviewed | Mappings are not a Phase 1 dependency |

All decisions are now confirmed. Remaining open items are listed in the QA log.

## 12. Non-goals

- Replacing commercial API security or posture products. API BAS validates controls and detection; it does not inventory every API for a customer.
- Certifying regulatory compliance.
- Production load or denial-of-service testing.
- Real customer data, real payment rails, or live messaging of end users.
- Executing industrial or machine commands; api.txt §3 limits these to an explicitly approved test target, and they are not in scope here.

## 13. Dependencies

| Dependency | Needed by | Status |
|---|---|---|
| Lab target (`apibas-lab`) | Phase 1 | Built (Phase 1 slice, one flaw) |
| Secret-store reference for test identities | Phase 1 | Interface built; in-memory and env-var resolvers only, production secret store not built |
| Scenario signing for API BAS files | — | Not required: API BAS catalog is embedded, not loaded by the live engine |
| Fixture SIEM | Phase 4 | Not built |
| OAuth fixture IdP, webhook receiver | Phase 3 | Not built |
| Versioned regulatory sources | Phase 5 | Not started |
