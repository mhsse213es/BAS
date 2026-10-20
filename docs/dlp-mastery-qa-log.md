# DLP BAS Mastery — Deferred QA Log

This document tracks every question, verification gap, or follow-up item for the DLP BAS Mastery initiative (`dlp.txt`) that cannot be resolved immediately — because it's blocked on external access, a licensing decision, a tenant/account permission, or something else outside this session's control. Each entry stays here until it's actually resolved; resolving one means updating its own entry with the resolution and date, not deleting it.

This is the single place to check before claiming either DLP vendor connector is "done" or making any external maturity claim about them — mirrors the role `docs/emailgw-mastery-qa-log.md`, `docs/av-mastery-qa-log.md`, `docs/waf-mastery-qa-log.md` and `docs/webgw-mastery-qa-log.md` play for their own initiatives.

## Open items

### 1. Microsoft Purview tenant provisioning/licensing + admin consent — open

**Status:** Open, blocked on account/licensing access, not an engineering gap.

**What's needed:** a Microsoft 365 tenant with Purview/compliance licensing (unified audit logging enabled), an app registration with admin-consented Application permissions `ActivityFeed.Read` and `ActivityFeed.ReadDlp` against `manage.office.com`.

**Tenant status:** unconfirmed. `project_azure_real_discovery_integration` (prior-session memory) names an existing Entra tenant (`ed059a30-...`) used for unrelated Azure resource-discovery work, itself blocked there on a missing Azure subscription and a missing admin role for Graph consent. That same missing-admin-role gap is the identical mechanism Purview's application-permission admin consent needs — very likely blocks this too, not independently verified.

**What this means for Priority 5:** `internal/vendors/purview`'s request-building/response-mapping (`EnsureSubscriptionStarted`, `QueryDLPEvents`) is built and proven against `httptest` now, exactly as `AnalyzedEmailEvidenceProvider` was before Defender-for-O365 tenant access existed (`docs/emailgw-mastery-qa-log.md` item 1b). Only the real-tenant integration stays deferred.

**What's still unverified once a tenant exists:**
- The exact `Office 365 Management Activity API` error code/text for "subscription already enabled" — `EnsureSubscriptionStarted` currently matches a case-insensitive substring ("already enabled") against the error message, which is Microsoft's documented wording but not guaranteed stable across tenants/API versions.
- Rate limits and pagination behavior on `activity/feed/subscriptions/content` for a high-volume tenant.
- Whether `ActivityFeed.ReadDlp` alone suffices for full `PolicyDetails`/`Actions` field detail, or whether a separate "Read DLP sensitive data" grant (documented by Microsoft as a distinct permission) is also required to see sensitive-data match detail, not just the policy/rule names this client currently surfaces.

**Resolution path:** provision a tenant (the existing Azure tenant, if it can be licensed for Purview, or a fresh Microsoft 365 Developer Program tenant) and admin-consent the app registration for both scopes above.

### 2. Trellix DLP license, API credentials, and the exact incident schema — open

**Status:** Open, blocked on vendor account/licensing access, not purely an engineering gap — the exact response schema is also genuinely unconfirmed by documentation research (see below).

**What's needed:** a Trellix account with DLP module licensing and an IAM client-credentials application with a DLP-incident-scoped grant.

**What's still unverified, independent of account access:**
- The exact JSON response envelope/field names for a DLP incident record from the Events API v2 `type=incidents` endpoint — research (2026-10-18) confirmed the endpoint's existence and general shape (regional hosts, `type=incidents` query param) but not an official, published field reference for DLP-specific incidents. `trellixdlp.Incident`'s fields (`ID`/`Timestamp`/`Severity`/`PolicyName`/`Action`/`Status`) are this package's best-effort mapping, not a confirmed schema.
- Which of Trellix's own conflicting documented token endpoints/domains is current: `https://iam.cloud.trellix.com/iam/v1.0/token` (used as this client's default) vs. the legacy `https://iam.mcafee-cloud.com/iam/v1.1/token`, and which regional Events API host (US/Singapore/Frankfurt/Sydney/India) applies to a given account.
- Whether the client-credentials grant genuinely uses HTTP Basic auth for the DLP-incidents scope specifically (confirmed for Trellix EDR/ePO integrations in the docs found; not confirmed DLP-specific).

**What this means for Priority 5:** `internal/vendors/trellixdlp`'s request-building/response-mapping (`QueryDLPIncidents`) is built and proven against `httptest` now, matching the same best-effort-but-explicit-about-the-gap posture as item 1 above. This package carries a stronger disclaimer than `purview`'s, since even the *response schema* (not just tenant access) is unconfirmed — see the package's own doc comment in `client.go`.

**Resolution path:** get Trellix DLP API documentation/sandbox access (the Trellix Developer Portal at developer.manage.trellix.com, or a support-provided DLP incident API reference) and a licensed test account; correct `Incident`'s field mapping and the token/events endpoint defaults against whatever the real account's IAM Client Credentials page and the real incident API reference show.

### 3. DLP-MOB (mobile DLP channel) — open, blocked on missing mobile agent, not a configuration or licensing gap

**Status:** Open, blocked on infrastructure Audspect does not have — a genuine engineering gap, not deferred for the same reason as items 1-2 above.

**What's needed:** `dlp.txt` §3B names `DLP-MOB` ("Supported mobile DLP controls, managed versus unmanaged applications, copy/paste restrictions and document sharing") as one of 10 exfiltration-channel scenario families. Audspect's agent runs on Windows/macOS/Linux endpoints only (confirmed by repo audit 2026-10-18: zero references to a mobile/Android/iOS agent anywhere in `internal/agent*` or `internal/models/schema.go`). Testing a real mobile DLP control (an MDM-enrolled device, a managed-app copy/paste restriction, a mobile DLP agent's own policy enforcement) requires a mobile execution surface — an actual Android/iOS agent, or at minimum an MDM/EMM API integration — that does not exist in this codebase at all.

**What this means:** per `dlp.txt`'s own non-negotiable engineering rule 1 ("Capability-aware execution: fail closed when required preconditions or authorization are absent; report NOT_TESTED rather than inventing a result") and §10's acceptance criterion ("Unsupported channels and unlicensed capabilities remain explicitly untested"), DLP-MOB is recorded here as an explicit, named, unsupported capability rather than a fabricated scenario that doesn't actually exercise a mobile environment. No `dlp-exfiltration-mobile.yaml` scenario exists, and none should be written until a real mobile execution surface exists to run it against — a scenario whose steps run on the existing Windows/macOS/Linux agent cannot genuinely test a mobile DLP control, regardless of how the payload is shaped.

**Resolution path:** build a mobile agent (Android/iOS) or an MDM/EMM API integration (e.g. Microsoft Intune, Google Workspace Endpoint Management) first — a separate, substantial engineering effort, not a follow-up to this initiative's existing scenario-authoring work. Until then, DLP-MOB stays at zero coverage, honestly.

### 4. Forcepoint DLP license, API credentials, and the exact incident schema — open

**Status:** Open, blocked on vendor account/licensing access, not purely an engineering gap — the exact incident response schema and token-cache lifetime are also genuinely unconfirmed by documentation research (see below).

**What's needed:** a Forcepoint DLP Manager account with a local **Application-type** administrator user (Network-type accounts cannot be used for API access) and DLP incident-query licensing/role.

**What's still unverified, independent of account access:**
- The exact JSON field names in an incident response record from `POST /dlp/rest/v1/incidents` — research (2026-10-18) confirmed the endpoint path, the filters-mode (vs. ID-list) request shape, the 10,000-row response cap, and the single-type-per-call (`INCIDENTS`/`DISCOVERY`) constraint, but the REST API Guide pages found (dated Dec 2021/Mar 2022, versioned for DLP 9.0/10) document endpoints and parameters, not a field-level incident schema. `forcepointdlp.Incident`'s fields (`ID`/`Timestamp`/`Policy`/`Department`/`RiskLevel`/`Severity`/`Action`/`Status`) are this package's best-effort mapping, not a confirmed schema.
- The access token's real cache lifetime — this client caches for a fixed 15 minutes as a conservative default; no documented token lifetime was found for the 2-step refresh-token/access-token exchange.
- The exact date-range filter parameter name inside the `filters` object — confirmed that `policy`/`department`/`riskLevel` are valid filter fields, but not confirmed whether `dateRange.start`/`dateRange.end` (this client's best-effort guess) matches the real parameter names.
- Pagination beyond the documented 10,000-row-per-response cap — `QueryDLPIncidents` does not page through results, so a real tenant with more than 10,000 incidents in the queried window would return a silently truncated (not erroring) result. Matches `purview`'s and `trellixdlp`'s own current non-paginating scope, not a new gap specific to this client.

**What this means for Priority 5:** `internal/vendors/forcepointdlp`'s request-building/response-mapping (`QueryDLPIncidents`) is built and proven against `httptest` now, matching the same best-effort-but-explicit-about-the-gap posture as items 1-2 above. See the package's own doc comment in `client.go`.

**Resolution path:** get a Forcepoint DLP Manager test account with an Application-type administrator user and DLP incident licensing, and the current (not 2021/2022-dated) REST API Guide for the installed version; correct `Incident`'s field mapping, the token cache lifetime, and the date-range filter parameter name against what the real account's API responses show.

### 5. Symantec (Broadcom) DLP license, API generation, and the exact incident schema — open

**Status:** Open, blocked on vendor account/licensing access, not purely an engineering gap — which of 2 documented API generations applies, and the exact incident response schema, are also genuinely unconfirmed by documentation research (see below).

**What's needed:** a Symantec/Broadcom DLP Enforce server account (a service account with DLP incident-query role) and confirmation of which API generation the license covers.

**What's still unverified, independent of account access:**
- Which of Symantec's two documented API generations a given license maps to: the 15.7+ REST API or the 16+ "Incident Reporting and Update API" web service — both exist in the documentation found, and this client's best-effort implementation cannot determine which a real account uses.
- The exact login endpoint path and incident-list endpoint path — research (2026-10-18) confirmed the auth *mechanism* (forms-based username/password, not OAuth — the Cortex XSOAR `symantec-data-loss-prevention-v2` integration's own config fields are exactly Enforce server URL + username + password) and the incident filter vocabulary (earliest time, status, severity, incident type, default page size 50), but not official endpoint paths. `LoginURL`'s/`IncidentsURL`'s defaults (`/ProtectManager/webservices/v2/authenticate` and `.../incidents`) are this package's best-effort guess, not confirmed paths.
- The post-login session mechanics — this client's best-effort guess is a `sessionToken` query parameter on the incidents request; no documented convention (cookie vs. header vs. query param) was found for what happens after a successful forms login.
- Pagination beyond the documented default page size of 50 — `QueryDLPIncidents` does not page through results, so a real tenant with more than one page of incidents in the queried window would return a silently truncated (not erroring) result. Matches `purview`'s and `trellixdlp`'s own current non-paginating scope, not a new gap specific to this client.
- The exact JSON field names in an incident response record — `symantecdlp.Incident`'s fields (`ID`/`DetectionDate`/`Status`/`Severity`/`IncidentType`) are this package's best-effort mapping aligned to the confirmed filter vocabulary, not a confirmed response schema.

**What this means for Priority 5:** `internal/vendors/symantecdlp`'s request-building/response-mapping (`QueryDLPIncidents`) is built and proven against `httptest` now. Its login step deliberately never retries a rejected attempt internally, since a documented account-lockout risk (default 6 failed attempts, 60-minute lockout) makes an automatic retry actively dangerous against a real account — this is a correctness decision, not a gap. See the package's own doc comment in `client.go`.

**Resolution path:** get a Symantec/Broadcom DLP Enforce test account, confirm which API generation (15.7+ REST vs. 16+ Incident Reporting) the license covers, and the current official API reference for that generation; correct the endpoint paths, session mechanics, and `Incident`'s field mapping against what the real account's API responses show.

### 6. `internal/dlpcorrelate` campaigns — "telemetry"/security-event correlation stays permanently out of scope, not a configuration gap

**Status:** Open by design, not blocked on access. **Corrected 2026-10-18** (originally written while building Campaign 02, revisited and found overbroad while scoping Campaign 05): this item previously claimed "no DLP-specific telemetry, security-event, or case-correlation evidence source exists anywhere in this repo today, for any campaign." That overclaimed the gap — `internal/siem` and `internal/ticketing` both exist as real, generic (non-DLP-specific) infrastructure. The real gap, corrected below, is narrower.

**What actually exists:** `internal/detectverify` has real per-vendor detection-verification clients (Splunk, Microsoft Sentinel, Defender XDR, CrowdStrike, Elastic, Trellix, QRadar) whose `Connector.Verify` returns `Detected`/`NotDetected` plus matched alerts for a technique, host and time window. This is the SIEM/EDR ingestion evidence Campaign 05 consumes. `internal/siem` (`Correlate`/`SIEMAlert`/`CorrelationReport`/`TechniqueCorrelation`) queries a SIEM for alerts and correlates them against BAS-executed MITRE ATT&CK techniques — but only QRadar has a working client; Splunk/Sentinel/Wazuh are rejected at config-creation time, never implemented here. `internal/ticketing` (`Connector`/`TicketRef`/`TicketFinding`, Jira/ServiceNow/webhook) creates and tracks ITSM tickets for BAS findings — analyst-gated, auto-create off by default. Neither package is DLP-specific, and no DLP scenario or `dlpcorrelate` campaign calls either today.

**What's still genuinely missing:** (1) no DLP scenario produces a `siem.SIEMAlert`/`TechniqueCorrelation` or `ticketing.TicketRef` today — wiring would be new work, not configuration; (2) `ticketing.TicketRef`/`Connector` has **no assignee field anywhere** — "incident creation and assignment" (Campaign 05's own wording) can be verified for creation only, never for assignment; (3) **no acknowledgment-timestamp or response-time concept exists at all** — `Connector.GetStatus` returns a raw provider status string with no semantic interpretation layer, so "measure acknowledgment and response" (Campaign 05) cannot be evaluated without building that interpretation layer first.

**What this means:** per the same capability-aware-honesty discipline already applied to DLP-MOB (item 3) and the vendor connectors (items 1-2, 4-5), Campaign 01's stage 4 ("security event and case evidence") and Campaign 02's telemetry half remain correctly gapped — nothing wires a real DLP scenario to `siem`/`ticketing` yet. Campaign 04's stage 3 ("correlate identity, data, channel and alerts") remains correctly gapped for the same reason. **Campaign 05 ("detection-to-response validation") is now built as a 6-stage chain** (`campaign05.go`). Stages 1-4 (enforcement, console event, SIEM ingestion via `detectverify`, incident creation) are real. Stages 5-6 (assignment, acknowledgment/response time) stay permanently NotTested. The paragraph below records why they were originally deferred.
**Previous deferral rationale (2026-10-18):** Campaign 05 ("detection-to-response validation") was evaluated and not built in that session — items (2) and (3) above are real new features inside `internal/ticketing`'s own scope (assignee tracking, ack/response-time measurement), not a `dlpcorrelate`-side translation task like Campaigns 01/03/04 were. Building them here would mean silently expanding `ticketing`'s scope mid-DLP-slice rather than naming the dependency.

**Resolution path:** (a) wire a DLP scenario to call `siem.Correlate`/`ticketing.Manager.PushFinding` for real, producing the already-computed verdicts a `dlpcorrelate` campaign would consume (same decoupled-consumption pattern as Campaigns 01/03/04); (b) add assignee tracking to `ticketing.TicketRef`/`Connector` and an ack/response-time measurement layer on top of `GetStatus` — a feature addition to `internal/ticketing` itself, sized like a vendor-adapter build, not a `dlpcorrelate` follow-up. Until both exist, Campaign 05 stays an explicit, named, unbuilt campaign — not a stub, not a mock.

### 7. Test-event start (B2) — end-to-end run on removable media not performed — open

**Status:** Open, needs hardware Audspect does not have here.

**What's needed:** a lab Windows host with a removable USB drive (or a virtual removable disk). Run `dlp-exfiltration-validation` USB step once with `BAS_TASK_ID` set by the agent.

**What this confirms:** the `DLP_EVENT_START` line is printed before the copy, `ParseDLPEventStart` reads it, and `dlp_evidence_records` gets `test_event_timestamp` and `test_event_source = payload-marker` for that step. Until this run, the marker path is verified only by unit and database tests.

**Resolution path:** one USB step run on a removable-media host, then read the row back with `GET /api/scenarios/runs/{runId}/dlp-records`.

### 8. Clock skew between test host and detection source — not measured; latency undefined — open

**Status:** Open. Latency cannot be reported until this is measured.

**Reading so far:** one host, `w32tm /query /status` on 2026-10-20: source `time.windows.com`, stratum 5, root dispersion 7.89 s. That is the host's own error estimate against its time source. It is not skew against the detection source, and it suggests a bound from this host would be seconds wide.

**What's needed:** measured offset between the test host and the detection-source clock (for example a time-sync source both can query), recorded with method, date and sample count, plus the milestone definition from the metrics spec §3.4.

**Resolution path:** measure, record the bound, then decide whether the host clock needs better sync.

### 9. Precision and recall for DLP — not computable from current evidence — open by design

**Status:** Open. Metrics are defined in `docs/superpowers/specs/2026-10-20-dlp-metrics-definitions-draft.md` and not computed.

**Why:** a block counts as TP or FP only from a correlated authoritative event. No adapter currently supplies one, and no adapter has been verified against a live tenant. Adapter conformance is labelled unverified.

**Resolution path:** verify a DLP or SIEM adapter against a live tenant (items 1, 2, 4, 5), then decide which block events it may contribute.

### 10. Start markers in other DLP scenarios — not run end to end — open

**Status:** Open. Markers were added to 12 scenarios and signed (`verify-all` 126/126), but none has run.

**Scenarios:** validation, multichannel, sftp, smtp, dns-tunnel, telnet, webhook, cloud-storage, coderepo, ai-prompt, db-export, sink-https.

**Deliberately excluded:** archive steps (local ZIP, no outbound attempt).

**Pooled-host caveat:** only observation-labelled PowerShell steps use the warm pool, and DLP transfer steps are not observation-labelled. So DLP steps take the per-process path, where `BAS_TASK_ID` is set. The pooled `BAS_TASK_ID` change is still correct, but it does not serve DLP steps.

**Resolution path:** run one step per channel on a lab host that supports it, and confirm each marker appears once per step. Multiple markers make the parser return `ambiguous`, which drops the start time.

### 11. Pre-existing `dlpfixture` drift failure (AI-prompt and DB-export) — resolved, see Resolved items

**Status:** Open. The drift test fails on unregistered fixture values in `dlp-exfiltration-ai-prompt` and `dlp-exfiltration-db-export`. It predates the start-marker work; the YAML diff there is additive.

**Decision needed:** register those payloads in the fixture catalog, or change the payloads.

### 12. Override handling in decision_class — not special-cased — open, decision needed

**Status:** Open. An operator override currently falls under the same B1 table rules. A step that was overridden and then delivered may be classed FN.

**Decision needed:** whether an override should yield Inconclusive, or a separate class, before any override-bearing run is used in a metric.

### 13. Operational impact — definition approved, no baseline or criteria — deferred

**Status:** Deferred by decision. No value is computed or published. Requires baseline runs and approved workflow success criteria.

### 14. Verdict store keyed on (run, expectation) — shared IDs can collide — open, decision needed

**Status:** Open. `dlp_evidence_records` is keyed by task ID, but the verdict store still keys on (run, expectation). A shared expectation ID across steps can collide in the verdict store.

**Decision needed:** whether to re-key the verdict store by task ID.

### 15. Late sink receipts not reflected in a record — open, decision needed

**Status:** Open. The record keeps the first evaluation, so a receipt arriving after evaluation is not reflected. This is disclosed in each record's limitations.

**Decision needed:** whether a later receipt should update the record, and how that interacts with the no-duplicate-record rule.


### 16. DLP-DEV developer-tooling scenario (dlp-exfiltration-devtools) — not run; scope limited — open

**Status:** Open. Added as three sink-verified HTTPS uploads (CI/CD artifact, package publish with a placeholder credential, internal design document). Signed and catalogued (commit 4c03d378). Not run end to end.

**Scope limit:** these imitate developer tooling over HTTPS. They do not drive git, npm, pip, docker or a CI runner, so they say nothing about any vendor's developer-tool control. Git-protocol repository pushes are not covered.

**Resolution path:** one run against the lab sink to confirm each step records a receipt. Then decide whether git-protocol pushes and developer package managers are worth a sink of their own.

### 17. Email recipient variants (dlp-exfiltration-email-recipients) — not run; attachments and encrypted mail not built — open

**Status:** Open. Two sink-verified steps: external business recipient and personal mail address (commit f0e87052). Signed and catalogued. Not run end to end.

**Limits, stated in the scenario:** the SMTP listener accepts one recipient and rejects multipart content, so attachment variants and multi-recipient variants cannot produce a receipt. Encrypted-mail and mail-exception cases need a policy to test against.

**Resolution path:** one run against the lab SMTP sink to confirm each step records a receipt. Attachments need a listener change that is a product decision, not a scenario change.

### 18. Archive transfer scenario (dlp-exfiltration-archive-transfer) — sink step not run; encrypted and OCR variants not built — open

**Status:** Open. Three sink-verified steps: plain ZIP, renamed-extension ZIP, nested ZIP (commit 90ece92d). Signed and catalogued. The packaging logic was run locally and works. The HTTPS sink step has not been run against the lab sink.

**Limits, stated in the scenario:** the sink never sees a filename. The renamed variant tests bytes plus a `filename=` line, not a real file-type inspection engine. Encrypted, password-protected and OCR variants are not built; they need an inspection engine and a policy to test against.

**Resolution path:** one run against the lab HTTPS sink to confirm each step records a receipt. Then decide whether the DLP product under test should be expected to unpack nested archives, which is a policy decision, not a scenario one.

### 19. Web upload and form scenario (dlp-exfiltration-web-upload) — not run; real browser form not tested — open

**Status:** Open. Two sink-verified steps: a browser-shaped file upload and a browser-shaped form submission (commit 9ecae9fd). Signed and catalogued. Not run end to end.

**Limits, stated in the scenario:** the scenario does not drive a browser. The HTTPS sink decodes JSON only, so a real multipart or urlencoded form cannot produce a receipt. The steps test the request shape and headers, not browser behaviour and not a web-form product control.

**Resolution path:** a true form test needs a sink endpoint that accepts multipart and urlencoded bodies. That is a listener change and a product decision. Until then, leave this item open and do not describe the steps as form tests.

### 20. Network share scenario (dlp-exfiltration-network-share) — not run; needs an operator-configured SMB share — open

**Status:** Open. Two steps, writable share and read-only share (commit 12764913). Signed and catalogued. The copy logic was run locally against a temporary folder and works. The steps have not run against an SMB share.

**Lab requirement:** set `BAS_DLP_SMB_SHARE` and `BAS_DLP_SMB_RO_SHARE` on the agent host to a writable share and a share that should refuse writes. Until they are set, both steps grade Untested.

**Limits:** L1 only, with no sink. A refusal cannot be attributed to a specific control (NTFS, share permission, or endpoint DLP). Lateral movement, mapped drives and per-user exceptions are not built.

### 21. Device control scenario (dlp-exfiltration-device-control) — not run; device policy and exceptions not built — open

**Status:** Open. One removable-media write step that also reads the Deny_Write value for an operator-supplied class GUID (commit 12764913). Signed and catalogued. Not run against removable media.

**Lab requirement:** a removable volume on the agent host, and the correct class GUID for that device, confirmed against Microsoft's documentation. Public sources conflict on the GUID, so the scenario does not hard-code one. Until a GUID is supplied, the policy state is recorded as not supplied.

**Limits:** device exceptions, allow and deny lists by hardware ID, user and group exceptions, and read-only versus blocked distinctions are recorded as Unsupported in this environment. They need a device policy and several accounts.

### 22. Lateral data movement scenario (dlp-exfiltration-lateral-movement) — not run; needs a second internal host — open

**Status:** Open. Two steps: copy to an internal file server share, and copy to a peer workstation share (commit bf6687e6). Signed and catalogued. Not run against a second host.

**Lab requirement:** a second internal host and two operator-configured shares, set in `BAS_DLP_LATERAL_SERVER_SHARE` and `BAS_DLP_LATERAL_PEER_SHARE`. Until they are set, both steps grade Untested.

**Limits:** L1 only, with no sink. A refusal cannot be attributed to a specific control. The authorized versus unauthorized split is a label the operator records in run notes, not something the scenario decides. Remote execution, credential use and non-SMB protocols are not covered.

## Resolved items

- Item 11: the eight unclaimed AI-prompt and DB-export steps are catalogued (commit 226b1f40). Values come from each step's own command; no payload changed. Both drift checks pass.

