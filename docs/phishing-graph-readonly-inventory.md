# Phishing Graph read-only phase: per-scenario inventory

Step 1 of the approved read-only phase. Scope: the Microsoft Graph calls that
registered phishing scenarios reach through `internal/phishidentity`. Nothing
here wires a client or changes the registry. Permission names marked
**unverified** must be checked against the Microsoft Graph permissions
reference before any scenario is enabled.

## Auth model (all phishidentity clients)

All clients request `https://graph.microsoft.com/.default` (client
credentials), so every permission below is an **application** permission. No
delegated access is used.

## Per-scenario inventory

| Scenario | Executor | Graph call (method, path) | Read or write | Permission | Decision |
|---|---|---|---|---|---|
| PH-ID-002 | `executePHID002` | `ListOAuthConsentGrants`: GET `/oauth2PermissionGrants` | Read, **tenant-wide** | Unverified. Single-grant GET page lists `Directory.Read.All` as least-privileged delegated; application equivalent not confirmed | Candidate. Blocked until the permission is verified and a target scope is decided (see below) |
| PH-ID-003 | `executePHID003` | `SignInsByAuthenticationProtocol`: GET `/auditLogs/signIns?$filter=authenticationProtocol eq 'deviceCode'` | Read, **tenant-wide** | `AuditLog.Read.All` (confirmed, application and delegated). Also needs `Policy.Read.ConditionalAccess` if the code relies on `appliedConditionalAccessPolicies` (see notes) | Candidate. Blocked until a target scope is decided |
| PH-ID-004 | `executePHID004` via `MFADenialEventsForUser` | GET `/auditLogs/signIns?$filter=userId eq '<id>' and status/errorCode eq 500121` | Read, per user | `AuditLog.Read.All` (same endpoint as PH-ID-003) | Candidate. Target is one user, so the allowlist is natural |
| PH-ID-005 | `executePHID005` via `RiskySignInsForUser` and `SignInSessionsValidFromDateTime` | GET `/auditLogs/signIns?$filter=userId eq '<id>'`; GET `/users/{id}?$select=signInSessionsValidFromDateTime` | Read, per user | Sign-ins: `AuditLog.Read.All`. The `$select` call: **conflicting sources**. Microsoft's user-get page lists `User.Read.All` as least-privileged. An older Q&A thread says `AuditLog.Read.All` and `Directory.Read.All` are needed. Must be tested with a real token | Candidate, but the `$select` permission is unresolved |
| PH-CHN-004 | `executePHCHN004` | POST `/users/{id}/events` (create), GET `/users/{id}/events/{eventId}` (verify), DELETE `/users/{id}/events/{eventId}` (cleanup) | **Write** (creates and deletes a calendar event in a real mailbox) | `Calendars.ReadWrite` (not read-only) | **Not in the read-only phase.** It is a side-effecting scenario and needs its own approval, permission review, and mailbox allowlist |

## Calls with no registered scenario (out of scope)

These exist in `phishidentity` but no registered scenario reaches them, so
they are not wired by this phase:

- `ConditionalAccessPolicies` (GET `/identity/conditionalAccess/policies`)
- `RevokeSignInSessions` (POST `/users/{id}/revokeSignInSessions`). Side-effecting. Used only by PH-IR-002, which stays unregistered.
- `CreateSharingInvite` (POST `/drives/{id}/items/{id}/invite`), `DeleteSharingInvite`, `VerifySharingInviteExists`. Create and delete are writes. Not registered.

## Findings that block enabling

1. **Target scope for tenant-wide reads (PH-ID-002, PH-ID-003).** Both list
   the whole tenant. The approved rule is that a missing target never means
   "scan the entire tenant". These two need an explicit scenario-level target
   allowlist, or they need to stay unavailable. Decision required.
2. **`appliedConditionalAccessPolicies` (PH-ID-003).** Without
   `Policy.Read.ConditionalAccess`, Graph omits this property from sign-in
   records. If the code uses it, PH-ID-003 can report "no CA policy blocked"
   when it simply could not read the property. That would be an unsupported
   PASS. The code must treat a missing property as incomplete evidence, or the
   permission must be granted. Needs a check in `EvaluateDeviceCodeEnforcement`.
3. **PH-ID-005 `$select` permission.** Conflicting sources (see table). Must be
   settled by a live test with a token, not by documentation alone.
4. **PH-ID-002 list permission.** Not confirmed by the search. Must be checked
   against the list operation's own reference page.
5. **No concrete connector is wired.** The production handler wires no
   identity client, so these scenarios stay unavailable until the wiring step
   is built and tested. This matches the current capability reporting.

## Sources

- Sign-in list permission: https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0
- Sign-in list conditional access note: https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0
- Get user (least-privileged permission): https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0
- Permission reference: https://learn.microsoft.com/en-us/graph/permissions-reference
- oauth2PermissionGrant (single-grant GET page): https://learn.microsoft.com/en-us/graph/api/oauth2permissiongrant-get?view=graph-rest-1.0

## Decisions recorded (approved)

1. **PH-ID-002 stays unavailable.** Tenant-wide `oauth2PermissionGrants` read
   with application `Directory.Read.All` is broad. Enable only after the exact
   query, filter behavior, and permission justification are reviewed, and only
   with a client/application allowlist. An Audspect allowlist does not narrow
   the Graph permission.
2. **PH-ID-003 stays unavailable until a target allowlist can be enforced**
   against the actual sign-in query. The current query is tenant-wide.
3. **PH-ID-003 evidence.** Done in this change: an omitted
   `appliedConditionalAccessPolicies` property is now recorded as absent
   (`SignInEvent.ConditionalAccessEvidence = false`) and yields an Unknown
   verdict (inconclusive), never Allowed. A present-but-empty list is still
   Allowed. A failure still wins. Covered by fixtures for both states, plus an
   end-to-end test that an omitted property is never a pass.
4. **`Policy.Read.ConditionalAccess` is not granted.** It is required only
   if Conditional Access evaluation is essential to PH-ID-003's stated purpose,
   and that is still undecided. Without it, the scenario reports inconclusive
   for every sign-in, which is the honest outcome.

## Not yet done (later steps)

- Capability reporting does not yet account for target restrictions or
  evidence completeness. Today it reflects only wired dependencies. No client
  is wired, so no scenario here can report available. Required before any
  enablement.
- PH-ID-005 `$select` permission (conflicting sources) needs a live test
  with a real token.
- PH-ID-002 list-operation permission is unconfirmed.
