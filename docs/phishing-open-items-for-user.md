# Phishing BAS: items waiting on the user

These cannot be completed from the repository. Each needs input or access that only the user has.

1. **1.9.0 build provenance.** Needs the `verification.json` file for the 1.9.0 build.
2. **Staging database state.** Unknown whether the staging database was wiped during the earlier UFW incident. Confirm the current state before any deployment. Do not wipe it.
3. **Staging `setup.test.sh` command name.** Resolved. The test is `bash packaging/compose/setup.test.sh`, run from a Linux checkout as root. It is not in the 1.9.7 bundle. It passes in an Ubuntu container (fix in `fe5b3bc7`).

4. **Tenant-admin consent for `Policy.Read.ConditionalAccess`.** A tenant administrator must grant admin consent in Entra ID for the app registration. Needed by PH-ID-003 to read Conditional Access policies. Until granted, PH-ID-003 returns Unknown rather than Blocked, and it stays unavailable.

5. **SentinelOne disconnect request schema.** The official Management API reference was not reachable from here. Check the `filter`/`ids` body and response shape in the SentinelOne console API docs (Agents, v2.1) before any live use.

Explicitly excluded by the user for now: live validation and QA parts.

## Unavailable scenarios and how each one closes

No scenario below is available, and none is claimed as validated. Each closes only when its gate passes and the code change is reviewed.

| Scenario | Why unavailable | How it closes |
|---|---|---|
| PH-ID-002 (OAuth consent grants) | `graphReviewPending`. Needs `Directory.Read.All` consent, the service-principal allowlist, and a live `nextLink`/`$filter` test. | 1) Tenant admin records consent for `Directory.Read.All`. 2) Set `AUDSPECT_PHISH_OAUTH_SP_OBJECT_IDS`. 3) Run the live `nextLink`/`$filter` test in a test tenant and record it. 4) Remove PH-ID-002 from `graphReviewPending` in a reviewed change. Code tests alone never close this gate. |
| PH-ID-003 (device-code sign-ins) | `graphReviewPending`. Needs `Policy.Read.ConditionalAccess` and `AuditLog.Read.All` consent, and target users allowlisted. Missing evidence reports Inconclusive, not a control outcome. | 1) Tenant admin records consent for both permissions. 2) Set `AUDSPECT_PHISH_IDENTITY_TARGET_USERS`. 3) A test-tenant run shows complete Conditional Access data. 4) Remove PH-ID-003 from `graphReviewPending` in a reviewed change. |
| PH-ID-005 (session revocation) | `graphReviewPending`. The `$select` property conflicts across sources and is unconfirmed. Experimental. | 1) A test-tenant token confirms the exact property set. 2) Record the result in the Graph permission review doc. 3) Remove PH-ID-005 from `graphReviewPending` in a reviewed change. |
| PH-ID-004 (MFA fatigue) | Experimental heuristic. Read errors report the cause. | **Decided: keep experimental.** Results are labelled best-effort heuristic observations, not confirmed control verdicts (`phishing-run-view.js`). Promotion requires test-tenant validation. |
| PH-CHN-004 | Unregistered by decision. Its behavior is not defined. | **Decided: keep unregistered.** No execution until behavior, mailbox allowlist, invitation scope, and cleanup are formally defined and reviewed. No calendar invitations to real mailboxes without explicit authorization. |
| PH-CHN-001, PH-CHN-002, PH-CHN-006, PH-CHN-008, PH-IR-002 (side-effecting) | Not registered. Design exists in `docs/phishing-side-effect-guardrails.md`. It is not approval to run. | Each scenario needs individual approval, then: bounded scope, explicit opt-in, count limits, audit of intent and outcome, a cleanup path, and an authoritative postcondition check. PH-IR-002 also needs the `$select` permission confirmed. |
| PH-IR-003 (SentinelOne leg) | The CrowdStrike request shape is confirmed from the official reference. The SentinelOne disconnect schema is not. | Check the schema in the SentinelOne console API docs (item 5 above). Then record it in `docs/phishing-ir003-vendor-request-shapes.md`. |
| PH-BEC-002 (EmailGW dispatch) | No dispatch mapping. Its Response expectation can only come from EG-008, which covers a different message. | **Decided: exclude from EmailGW dispatch.** Do not reuse EG-008. Reconsider only when a dedicated mapping and lab evidence exist. |
| PH-EVA-002 (EmailGW dispatch) | Two-leg relay grade. Not a single dispatch. | **Decided: same campaign only.** Both runs must belong to the same campaign. Each leg records its role (`direct_path` or `relay_path`). Mismatched campaigns, a leg with no campaign, and incomplete legs are refused. Implemented in `phishingrun_relaypath.go`. |
| PH-AUTH-007, PH-BEC-006, PH-ATT-002, PH-ATT-003, PH-CHN-005 | Now mapped to EmailGW expectations. Dispatchable. | Verify each in a lab EmailGW run. Until then, the mapping is code-only. |
| All other scenarios | Dispatch covers only EmailGW-backed scenarios. | Add an EmailGW expectation only where a clean mapping and testable evidence exist. Do not force a match. |
