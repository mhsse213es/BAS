# API BAS coverage manifest

This file is the honest coverage record for the API BAS suite. A sub-technique is
**implemented** only when its scenario file exists, its lab flaw and fixed control are
both in place, and its acceptance tests pass in both lab modes. Anything else is
listed below as **not implemented**, with the dependency that blocks it. Nothing here
is counted as covered.

## Implemented (28 scenarios)

| Scenario | Sub-technique | Evidence used |
|---|---|---|
| API-BAS-AUTHZ-001 | Cross-tenant object read (BOLA) | state, response |
| API-BAS-AUTHN-001 | Anonymous access | response |
| API-BAS-AUTHN-002 | Revoked token accepted | response, revocation check |
| API-BAS-AUTHZ-002 | Function-level authorization (BFLA) | state |
| API-BAS-AUTHZ-003 | Mass assignment | state |
| API-BAS-AUTHZ-010 | Retired-version authorization | response |
| API-BAS-DISC-003 | Debug route exposure | response |
| API-BAS-DATA-001 | Excessive data exposure via projection | response |
| API-BAS-AUTHN-003 | Unsigned token accepted (alg none) | response |
| API-BAS-DATA-004 | Unbounded list exposure | response |
| API-BAS-GWAY-003 | Method override | response |
| API-BAS-DISC-002 | Retired API version served | response |
| API-BAS-INTEG-003 | SSRF via webhook test | response |
| API-BAS-DATA-003 | Error-message disclosure | response |
| API-BAS-AUTHN-008 | Caller-supplied identity header | response |
| API-BAS-AUTHZ-007 | Bulk operation authorization | state |
| API-BAS-AUTHZ-004 | Vertical escalation (three-step chain) | state |
| API-BAS-AUTHZ-006 | Parent-child item authorization | response |
| API-BAS-INTEG-005 | Internal route without service credential | response |
| API-BAS-AUTHZ-012 | Export access by ID | response |
| API-BAS-BIZ-002 | Negative business quantity | state |
| API-BAS-INTEG-008 | Integration secret exposure | response |
| API-BAS-DISC-005 | Permissive CORS | forbidden response headers |
| API-BAS-ABUSE-001 | Missing rate limit on verification | counted attempts, detection |
| API-BAS-DATA-006 | Publicly cacheable authenticated response | forbidden response headers |
| API-BAS-ABUSE-003 | Excessive page size and item count | granted size, item count |
| API-BAS-ABUSE-005 | Unbounded upload | accepted bytes |
| API-BAS-ABUSE-002 | Expensive request without period limit | timing (frozen threshold), resource units |

## Detection coverage (fixture-validated, not live-SIEM-validated)

Only scenarios with a `detection:` block are graded on the detection axis. The Elastic
Security fixture is deterministic and local. Its results are labelled fixture-validated.

| Scenario | Expected rule | Vulnerable | Fixed |
|---|---|---|---|
| API-BAS-ABUSE-001 | APIBAS-REL-001 (repeated authentication failures, high) | detected | detected |
| API-BAS-AUTHZ-001 | APIBAS-REL-004 (access to an object owned by another identity, high) | detected | detected |

AUTHZ-001 was previously missed: a single cross-tenant request is invisible to a
threshold rule on repeated failures. The lab now records the owner of each order a
request touches, and APIBAS-REL-004 fires on any attempt by one identity against an
object owned by another, whether it was allowed or denied. The owner reading their own
order does not fire it.

## Explicitly not implemented

| Sub-technique | Blocked by |
|---|---|
| API-BAS-ABUSE-004 GraphQL depth, breadth and complexity | GraphQL adapter (protocol UNSUPPORTED) |
| API-BAS-ABUSE-006 Expensive validation or downstream calls | A second lab service to make the downstream call |
| API-BAS-ABUSE-007 SMS, OTP and paid-service consumption | A simulated paid provider in the lab |
| API-BAS-ABUSE-008 Account creation and credential-validation automation | Registration route and a multi-request flow in the scenario contract |
| API-BAS-ABUSE-009 Distributed low-rate abuse | Several source identities and per-identity throttling in the lab |
| API-BAS-ABUSE-010 Queue growth and retry storms | A queue service in the lab |
| API-BAS-ABUSE-004 and others above also need the detection fixture to carry their rules | Rule definitions per sub-technique |
| Pagination item count | Resolved: ABUSE-003 checks item count on `orders-paged` (151 owned orders, cap 100). The default fixture still has two orders and cannot test it. |

## Protocols reported UNSUPPORTED

A scenario that declares one of these protocols loads, and is reported
`SKIPPED / UNSUPPORTED_PROTOCOL` at run time. It is never counted as covered.

| Protocol | Adapter status |
|---|---|
| graphql | not built |
| grpc | not built |
| soap | not built |
| websocket | not built |
| async | not built |

## Other gaps

- Detection: one fixture (Elastic Security). Sentinel, Splunk and QRadar adapters are
  not built. The adapter interface is in place for them.
- Timing: the threshold is frozen for the measured machine (i5-8250U, Windows 10, Go 1.26.8).
  A timing scenario declares the baseline it was calibrated against. A run whose measured
  baseline falls outside a declared tolerance band is recorded as ERROR with
  `ENVIRONMENT_MISMATCH`. It is never graded as a timing pass or fail. Another machine
  therefore fails closed until it is recalibrated. Calibration checks the baseline only.
  It does not prove the attack-side ceiling holds on other hardware.
- Orchestrator scheduling and persistence, and the production secret store: not built.
- The Windows build (`build.ps1`) has not been run on these tranches.
