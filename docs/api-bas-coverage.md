# API BAS coverage manifest

Refreshed 9 November 2026 from a measured run, not from earlier notes. The previous version of this file listed 28
scenarios and five unsupported protocols; both statements were out of date.

Reproduce the numbers with:

    cd orchestrator
    go test ./internal/apibas/runner/ -run 'TestPhase28_MeasuredCoverage$' -count=1 -v -timeout 25m

That test runs every catalogued scenario against the lab in both builds (vulnerable and fixed) and feeds the verdicts to
`internal/apibas/coverage`. Re-run it and update this file whenever the catalogue changes.

## 1. The four tiers

A number is only worth quoting with its tier. Nothing here is live-validated.

| Tier | Meaning | Count |
|---|---|---|
| Catalogued | Scenario file exists in `internal/apibas/catalog` | **145** |
| Executable | Has a working adapter (REST, or one of the protocol adapters) | **145 / 145** |
| Lab-validated | In both lab builds the vulnerable build FAILs as exploited and the fixed build PASSes with control enforced | **142 / 145** (97.9%) |
| Workflow-verified | Reporting-obligation scenario that PASSed with control enforced in both builds, graded by the reporting adapter. Simulated receiver; not part of evaluated or validated | **1** (REPORT-001) |
| Live-validated | Run against a real customer or staging API with real security telemetry | **0** |

Lab-validated is evidence that the scenario and the grader work against a deliberately flawed lab. It is not evidence about any
customer API.

### Not lab-validated (2) and one workflow-verified

| Scenario | State | Why |
|---|---|---|
| API-BAS-ABUSE-002 | provisional | Timing scenario. Verdicts are valid, but the 250 ms ceiling has no approved requirement owner or rationale (decision D2 in `api-bas-remaining-work.md`), so it is held out of validated. In the first measured run this scenario was classed plain `evaluated` rather than `provisional`; timing results can vary between runs, so treat its class as unstable until timing qualification (D3) is done. |
| API-BAS-REPORT-002 | unevaluated | `deadline_not_defined_by_provision`: no CBUAE provision-derived deadline is recorded, so it cannot PASS on timeliness. |
| API-BAS-REPORT-001 | **workflow-verified** | CERT-In six-hour obligation. PASS with control enforced in both builds, and its six fault cases (on time, exactly at the deadline, one second late, dispatch failed, receipt missing, misrouted) pass in both. It has no exploitability verdict and no vulnerable/fixed pair (the receiver is identical in both builds), and its PASS is simulated: a workflow check, never a genuine CERT-In receipt. So it has its own class and is counted in neither evaluated nor validated. |

AUTHN-007 and GWAY-012 were first reported as not validated (error and evaluated). That was a measurement fault, not a scenario
fault: both need TLS (a client certificate, an upstream certificate), and the measurement harness ran them on the plain-HTTP lab.
`TestPhase28_MeasuredCoverage` now runs them on the TLS environment their own acceptance test uses; both validate (vulnerable
FAIL/exploited, fixed PASS/enforced).

## 2. Catalogue by family (API.txt section 1)

| API.txt family | Scenario prefix | Scenarios |
|---|---|---|
| 01 Identity and authentication | AUTHN | 11 |
| 02 Authorization and access control | AUTHZ | 30 (12 general, 6 NBFC, 4 manufacturing, 5 healthcare, 3 retail/telecom) |
| 03 Gateway, WAF, perimeter | GWAY | 12 |
| 04 Input validation and injection | INJ | 12 |
| 05 Business logic | BIZ | 13 (12 general, 1 retail) |
| 06 Sensitive data exposure | DATA | 24 (13 general, 4 NBFC, 2 manufacturing, 3 healthcare, 2 telecom) |
| 07 Resource consumption and abuse | ABUSE | 10 |
| 08 Integrations, webhooks, backend trust | INTEG | 16 (11 general, 1 manufacturing, 1 healthcare, 3 retail/partner/logistics) |
| 09 Discovery, lifecycle, configuration | DISC | 10 |
| 10 Detection and response | DET | 5 |
| Reporting workflows (regulatory) | REPORT | 2 |

Known sub-technique gaps inside the families (from the audit against API.txt):

- Identity: issuer and audience validation, expired and malformed tokens, session binding and token substitution.
- Gateway: real request smuggling (only duplicate-header parsing is covered), broader WAF evasion.
- Injection: NoSQL, command injection, deserialization, XML and multipart parser inconsistencies.
- Business logic: loyalty and reward abuse.
- Abuse: distributed multi-identity low-rate abuse, decompression bombs, email consumption.
- Integrations: DNS-resolution changes.
- Discovery: OpenAPI import and the endpoint inventory step are not built. The lab serves a spec; nothing imports one.
- Detection: DET-001, 003, 006 and 008 are not in the catalogue. False-positive measurement (DET-006) is only partly covered.

## 3. Protocols (API.txt section 2)

Every protocol has an executable adapter and at least one lab-validated scenario. Depth is thin outside REST.

| Surface | Scenarios | Adapter limit |
|---|---|---|
| REST / JSON | most of the catalogue | none |
| GraphQL | ABUSE-004, INJ-007 | no introspection, batching or alias scenarios |
| gRPC | DISC-009 | JSON-transcoding form only; native HTTP/2 and protobuf descriptors are UNSUPPORTED |
| SOAP / XML | INJ-005 (XXE) | no WS-Security scenarios |
| WebSocket | AUTHN-011 | handshake only; frame and per-message behaviour UNSUPPORTED |
| Async | ABUSE-010, INTEG-010 | broker is a lab service |
| Webhooks | INTEG-002, 003, 010, 011 | covered |
| OAuth / OIDC | AUTHN-004, 005, 009 | partial |
| Internal and partner APIs | INTEG-005, 006, 009 | covered |
| Mobile and device APIs | none | **no scenarios** |
| API management planes | none | **no scenarios** |

## 4. Industry packs (API.txt section 3)

| Sector | State |
|---|---|
| BFSI | 84 scenarios tagged, most on the generic orders fixture; payment workflows are BIZ-003 to 009 |
| NBFC | 10 scenarios (AUTHZ-101 to 106, DATA-101 to 104). DATA-102 detection is `not_evaluated`. |
| Manufacturing | 7 scenarios (AUTHZ-201 to 204, DATA-201, 202, INTEG-201) on `manufacturing-two-plant`: cross-plant production-order read, operator releasing an order, supplier changing another supplier's purchase order, device commanding another device (simulated, lab only), BOM and CAD leakage, asset and telemetry listing, IT-side access to the OT management configuration. Detection: all seven graded by APIBAS-REL-004 (fixture-validated). No regulatory mapping: no applicable source in the registry. Not covered: ERP/MES inventory and bill-of-materials write paths, machine-command safety interlocks, OT protocol (Modbus, OPC UA) adapters. |
| Healthcare (FHIR, patient records) | 9 scenarios (AUTHZ-301 to 305, DATA-301 to 303, INTEG-301) on `healthcare-two-patient`: cross-patient record read, clinician without a treating relationship, prescription change, patient altering their own result, delegate beyond consent scope, medical image download, FHIR Observation read, records export, device posting to another patient's result. Detection: eight graded by APIBAS-REL-004, AUTHZ-304 by REL-021 (result changed by a non-device identity) and AUTHZ-305 by REL-022 (clinical data to a delegate beyond consent); all fixture-validated. REL-004 cannot tell a treating clinician from one without a relationship (AUTHZ-302). Eight carry an unverified DPDP section 8(5) mapping. Not covered: HL7 v2 and DICOM adapters, real FHIR server, break-glass access, consent revocation, audit-log integrity. |
| Retail, logistics, telecom | 9 scenarios on `commerce-telecom-two-tenant`: shipment tracking and redirect across shoppers (AUTHZ-401, 402), SIM swap on another subscriber's line (AUTHZ-403, simulated), usage listing and subscriber record exposure (DATA-401, 402), shopper setting their own order price (BIZ-401), partner reading another partner's API key (INTEG-401), partner escalating their own key scope (INTEG-402), shopper reporting delivery through the carrier callback (INTEG-403). Detection: six graded by APIBAS-REL-004 (fixture-validated); BIZ-401, INTEG-402 and INTEG-403 touch the caller's own object and stay `not_evaluated` until rules exist for non-staff price changes, key-scope changes and non-carrier delivery reports. No regulatory mapping. Refunds, coupons, stock reservation, partner quotes and webhook replay are covered by the general BIZ and INTEG scenarios. Not covered at all: number porting, billing disputes, real carrier or OSS/BSS integrations, SIM provisioning, inventory write paths. |

## 5. India and UAE (API.txt section 4)

Ten scenarios carry a regulatory mapping: AUTHZ-001, DATA-011 and eight healthcare scenarios. Registry: `internal/apibas/regulatory/registry.yaml` (seven entries, two verified, both DPDP entries unverified).

| Mapping | Scenario | Status |
|---|---|---|
| IN-RBI-ITGRC-19A | AUTHZ-001 | verified, reviewed |
| UAE-PDPL-A15-2 | DATA-011 | verified, reviewed |
| IN-DPDP-S12-3 | DATA-011 | **unverified**: the notification bringing it into force is not in the source set |
| IN-DPDP-S8-5 | AUTHZ-301, 302, 303, 305, DATA-301, 302, 303, INTEG-301 | **unverified**: same commencement gap, and no named reviewer has confirmed the mapping. Reasonable security safeguards (section 8(5)) is one access-control safeguard per scenario, not a compliance finding |

Healthcare AUTHZ-304 (a patient altering their own result) is not mapped: it is not a breach of another person's data. UAE healthcare data is not mapped to the PDPL because that law leaves health data to its own legislation, which is not in the source set. Manufacturing has no mapping: the registry holds no source document that applies (an OT or industrial security standard such as IEC 62443, or a sector regulation, would have to be obtained and reviewed first), and the DPDP Act does not fit production orders, bills of materials or device commands. Not mapped or not started: NPCI and UPI, an NBFC mapping (needs a fresh applicability review), CERT-In direction mapping
beyond REPORT-001 (unverified), CBUAE clauses 6.1.2.6 and 6.1.7.2 (no provision-derived deadline), DIFC and ADGM, UAE
healthcare rules, UAE information-assurance requirements, data residency, PDPL Executive Regulation (not in the source set).
There is no live reporting channel: a simulated REPORT PASS proves a workflow check only. A successful simulation never
certifies compliance.

## 6. Detection (API.txt section 1.10)

Detection is graded separately from exploitability. Every detection result is **fixture-validated**: the Elastic Security and
Microsoft Sentinel fixtures are local and deterministic. No live SIEM, Splunk, QRadar, or gateway or API-security-product
adapter exists.

| Build | detected | not_detected | inconclusive | error |
|---|---|---|---|---|
| vulnerable | 85 | 21 | 1 | 0 |
| fixed | 70 | 36 | 1 | 0 |

38 of 145 scenarios have no detection block and are `not_evaluated`, which is a distinct state from a miss. Per-scenario reasons
are in `docs/api-bas-det001-tracker.md`. The counts above are raw; a not_detected on the fixed build means the control denied
the request and the fixture raised no event, which is not automatically a gap. The per-scenario expectations decide that.

## 7. Orchestrated execution (not scenario coverage)

The orchestrator can run catalogued scenarios as jobs (child-process runner, registered targets with host and path scope,
write-only credentials, approvals with expiry, revocation and single use). Production execution is disabled behind three
guards. The staging end-to-end run has **not** been done: see `docs/api-bas-staging-e2e-runbook.md`.

## 8. Known gaps (printed with every coverage report)

- Native gRPC over HTTP/2 with protobuf descriptors: UNSUPPORTED. Only the JSON-transcoding form has an adapter.
- WebSocket frame behaviour: UNSUPPORTED. Only the handshake has an adapter.
- Certificate revocation (CRL/OCSP): not tested and not claimed. The lab has no revocation source.
- Live SIEM validation: every detection result is fixture-validated, not live-validated.
- Detection for the not_evaluated scenarios: reasons in `docs/api-bas-det001-tracker.md`.
- The timing threshold is frozen for the measured machine (i5-8250U, Windows 10, Go 1.26.8). Another machine fails closed with
  `ENVIRONMENT_MISMATCH` until recalibrated.
- The Windows build script (`build.ps1`) has not been run on recent tranches.
