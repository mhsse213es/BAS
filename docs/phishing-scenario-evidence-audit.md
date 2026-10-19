# Phishing BAS: scenario-by-scenario evidence audit

Status: audit only. No behavior changed. The catalog has 44 scenarios. PH-BEC-003 and PH-BEC-007 are variants of PH-BEC-002, not separate scenarios, and they are not counted. Generated from the catalog and the
capability logic with the database-only environment that a running installation has.
The table is generated from that code, not typed by hand.

## Reading the table

- **Coverage** is the catalog's own tier: `catalog_only`, `fixture_tested`, or
  `adapter_tested`. **No entry is `live_validated`.** The only use of that tier is in a
  test.
- **Registered** means an executor is in the registry. An unregistered entry cannot
  run.
- **Capability** is the state the library and trigger report, given a database. It
  does not mean the scenario has been validated. `available` means the scenario may be
  triggered, not that its evidence is complete.

## Grader types

| Type | Scenarios | What the grade is based on |
|---|---|---|
| EmailGW read-back (existing run) | AUTH-002, 003, 004, 007, 008; BEC-001, 006; URL-001; ATT-001, 002, 003, 010; CHN-005 | An explicit completed EmailGW run ID. Refuses incomplete runs. Records provenance. Does not dispatch mail. |
| Two-leg relay path | EVA-002 | Two explicit completed EmailGW runs. Refuses incomplete legs. Records both runs. Verified this session. |
| EDR action request | IR-003 | The stored response-action row for a run ID. Vendor request shapes unconfirmed. |
| Ticketing (ITSM) | DET-002 | Ticket evidence in a window anchored to execution creation. No production connector. Missing connector is Inconclusive. |
| Exercise interaction | ID-001 | Recorded user behavior for an execution. Reported as behavior, not control efficacy. |
| Graph identity | ID-002, ID-003 | Gated (permission review). Unavailable. |
| Graph identity (heuristic) | ID-004 (experimental), ID-005 | Unavailable (identity connector not configured; ID-005 gated). |

## What is verified, and what is not

- **Verified by reading the code this session:** EVA-002, DET-002, ID-001, IR-003
  (request source only), and the registry and capability logic.
- **Not re-read this session:** the internal grading of each EmailGW read-back
  scenario (AUTH, BEC, URL, ATT, CHN-005). I have not checked each one's expectation
  or how it handles partial efficacy results. Those need the same audit before any
  claim is made about them.
- **Not validated against any live system.** Every registered scenario is
  fixture- or adapter-tested only.

## Scenario table

| ID | Coverage | Name | Registered | Capability (database-only) |
|---|---|---|---|---|
| PH-BEC-002 | adapter_tested | Supplier Payment-Change Validation | no | catalog_only/not_registered |
| PH-AUTH-001 | catalog_only | External domain spoofing | no | catalog_only/not_registered |
| PH-AUTH-002 | adapter_tested | SPF failure handling | yes | available/ |
| PH-AUTH-003 | adapter_tested | DKIM failure handling | yes | available/ |
| PH-AUTH-004 | adapter_tested | DMARC enforcement | yes | available/ |
| PH-AUTH-005 | catalog_only | Display-name impersonation | no | catalog_only/not_registered |
| PH-AUTH-006 | catalog_only | Lookalike-domain detection | no | catalog_only/not_registered |
| PH-AUTH-007 | adapter_tested | Internal sender spoofing | yes | available/ |
| PH-AUTH-008 | adapter_tested | Trusted-sender exception abuse | yes | available/ |
| PH-AUTH-009 | adapter_tested | Forwarding and mailing-list behavior | no | catalog_only/not_registered |
| PH-AUTH-010 | adapter_tested | Compromised legitimate sender | no | catalog_only/not_registered |
| PH-BEC-001 | adapter_tested | Executive impersonation | yes | available/ |
| PH-BEC-004 | catalog_only | Payroll and HR impersonation | no | catalog_only/not_registered |
| PH-BEC-005 | catalog_only | Procurement and purchase-order fraud | no | catalog_only/not_registered |
| PH-BEC-006 | adapter_tested | Reply-chain hijacking | yes | available/ |
| PH-BEC-008 | catalog_only | Customer or partner impersonation | no | catalog_only/not_registered |
| PH-URL-001 | adapter_tested | Known malicious URL | yes | available/ |
| PH-URL-005 | adapter_tested | Time-of-click protection | no | catalog_only/not_registered |
| PH-ID-001 | adapter_tested | Credential-harvesting simulation | yes | available/ |
| PH-ID-002 | adapter_tested | OAuth consent abuse | yes | unavailable/identity_connector_not_configured |
| PH-ID-003 | adapter_tested | Device-code phishing defense | yes | unavailable/identity_connector_not_configured |
| PH-ID-004 | adapter_tested | MFA fatigue defense | yes | unavailable/identity_connector_not_configured |
| PH-ID-005 | adapter_tested | Session-theft defense | yes | unavailable/identity_connector_not_configured |
| PH-EVA-001 | catalog_only | Allowlist policy bypass | no | catalog_only/not_registered |
| PH-EVA-002 | adapter_tested | Inbound relay-path bypass | yes | available/ |
| PH-EVA-005 | catalog_only | Delayed or modified destination | no | catalog_only/not_registered |
| PH-DET-001 | fixture_tested | SIEM ingestion and correlation | no | catalog_only/not_registered |
| PH-DET-002 | fixture_tested | User-reported phishing | yes | unavailable/itsm_connector_not_configured |
| PH-IR-001 | catalog_only | Retroactive mailbox search and purge | no | catalog_only/not_registered |
| PH-IR-002 | adapter_tested | Identity containment | no | catalog_only/not_registered |
| PH-IR-003 | adapter_tested | Endpoint follow-through | yes | available/ |
| PH-IR-004 | fixture_tested | Incident escalation | no | catalog_only/not_registered |
| PH-CHN-001 | adapter_tested | Teams collaboration lure | no | catalog_only/not_registered |
| PH-CHN-002 | adapter_tested | Malicious cloud-sharing invitation | no | catalog_only/not_registered |
| PH-CHN-003 | catalog_only | OAuth application invitation | no | catalog_only/not_registered |
| PH-CHN-004 | adapter_tested | Calendar invitation lure | no | catalog_only/not_registered |
| PH-CHN-005 | adapter_tested | Mobile QR-to-browser chain | yes | available/ |
| PH-CHN-006 | adapter_tested | SMS-to-email or email-to-SMS chain | no | catalog_only/not_registered |
| PH-CHN-007 | catalog_only | Voice callback fraud | no | catalog_only/not_registered |
| PH-CHN-008 | adapter_tested | Messaging-platform impersonation | no | catalog_only/not_registered |
| PH-ATT-001 | adapter_tested | HTML attachment | yes | available/ |
| PH-ATT-002 | adapter_tested | PDF with embedded link | yes | available/ |
| PH-ATT-003 | adapter_tested | Office document with external link | yes | available/ |
| PH-ATT-010 | adapter_tested | Post-delivery attachment verdict change | yes | available/ |

## Gaps that block the next maturity level

- **Unregistered (23 of 44 scenarios, 11 of them catalog-only):** each needs an executor, or a
  decision that they are out of scope. Not registered.
- **Side-effecting entries (CHN-001, 002, 004, 006, 008; IR-002):** unregistered until
  their reviews and guardrails are complete. See the guardrail design document.
- **EmailGW read-back (14 entries):** all are fixture-tested. None has live validation.
  Phishing-triggered dispatch does not exist, so each needs an existing run first.
- **DET-002:** no production ITSM connector. Completeness contract not yet built.
- **ID-001:** window not yet defined per scenario.
- **IR-003:** vendor request shapes unconfirmed against official references.
- **Identity (ID-002, 003, 005):** gated on permission review and live validation.
- **ID-004:** experimental; signal and evidence quality unvalidated.
