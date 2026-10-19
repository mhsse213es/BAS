# Phishing identity scenarios: Graph permission review (draft for sign-off)

Status: **not approved.** This review gates PH-ID-002 and PH-ID-003. Both stay
unavailable (`graph_permission_review_pending`) until the approver records a
decision below. Nothing here adds a permission, registers a scenario, or enables
live execution.

## Summary of findings

1. **Allowlist identifier mismatch (blocking, new).** Microsoft's Bicep reference
   for `oauth2PermissionGrants` describes `clientId` as the **object ID of the
   client service principal**, not the application (client) ID. The installer's
   `AUDSPECT_PHISH_OAUTH_CLIENT_IDS` holds application IDs. A filter built from
   those values would match nothing, or the wrong thing. The allowlist must hold
   service-principal object IDs, or the executor must resolve application IDs to
   service-principal object IDs before the query. This changes the allowlist design
   and must be decided before PH-ID-002 is enabled.
2. **PH-ID-002 list permission: unverified.** The single-grant page lists
   `Directory.Read.All` as least-privileged for delegated access. The application
   equivalent for the list operation is not confirmed. Microsoft's guidance is to
   request the narrowest permission that works, and `Directory.Read.All` is broad.
3. **PH-ID-002 filter syntax: partly confirmed.** Microsoft's own examples use
   `$filter=clientId eq '...' and consentType eq 'AllPrincipals'`. The
   `$filter` on the list call is documented. The `clientId` value meaning (finding
   1) is what is unresolved.
4. **PH-ID-003 sign-in permission: confirmed.** `AuditLog.Read.All` is the least
   privileged permission for listing sign-ins, for both delegated and application
   access. The per-user `userId` filter used by the code is **not yet verified**
   against the signIns list page.
5. **PH-ID-003 Conditional Access data: confirmed behavior, decision needed.** The
   `appliedConditionalAccessPolicies` property is omitted when the app lacks a
   Conditional Access read permission. Microsoft's guidance names
   `Policy.Read.ConditionalAccess` as the least-privileged option. The code already
   treats an omitted property as incomplete evidence (Unknown), never as "no
   policy blocked". Granting the permission is a separate decision.
6. **PH-ID-005 `$select` permission: unresolved.** A Microsoft Q&A answer (2023,
   community) says reading `signInSessionsValidFromDateTime` needs
   `AuditLog.Read.All` and `Directory.Read.All`. Microsoft's Get-user reference
   lists `User.Read.All` as least-privileged. These conflict. A live token test is
   the only way to settle it. PH-ID-005 is experimental and stays unavailable.

## Permission matrix (as currently known)

| Scenario | Graph call | Least privilege per Microsoft | Status |
|---|---|---|---|
| PH-ID-002 | GET `/oauth2PermissionGrants?$filter=clientId eq '<sp object id>'` | Not confirmed for the list call; `Directory.Read.All` is the documented delegated option on the single-grant page | **Unverified, blocked by finding 1** |
| PH-ID-003 | GET `/auditLogs/signIns?$filter=authenticationProtocol eq 'deviceCode' and userId eq '<id>'` | `AuditLog.Read.All` | Permission confirmed; `userId` filter unverified |
| PH-ID-003 (CA) | `appliedConditionalAccessPolicies` in the same response | `Policy.Read.ConditionalAccess` | **Decision needed** |
| PH-ID-005 | GET `/users/{id}?$select=signInSessionsValidFromDateTime` | Conflicting: `User.Read.All` vs `AuditLog.Read.All` + `Directory.Read.All` | **Unresolved; live test needed** |

No permission has been added. The app registration is unchanged.

## Decisions needed (approver)

1. **Identifier.** Should the OAuth client allowlist hold service-principal object
   IDs (the installer then needs a way to find them), or application IDs resolved
   to object IDs at run time? Recommendation: object IDs in the allowlist, validated
   at install, because it removes a lookup from the query path.
2. **PH-ID-002 permission.** Approve a specific application permission for the
   list call only after its least-privileged option is confirmed on Microsoft's
   list page. Do not grant `Directory.Read.All` by default.
3. **PH-ID-003 Conditional Access.** Grant `Policy.Read.ConditionalAccess` only if
   Conditional Access evaluation is essential to PH-ID-003's stated purpose.
   Without it, every sign-in reports inconclusive, which is the honest outcome.
4. **PH-ID-005.** Keep unavailable until the live token test settles the `$select`
   permission.

## Verification still required before enabling

- Check the current permissions table on the oauth2PermissionGrant list page and
  the signIn list page, and record the exact permission names here.
- Confirm the `userId` filter on the signIns list.
- Run the filtered queries with a test-tenant token, and record the request IDs.
- Live test in a dedicated Microsoft 365 test tenant, not production.

## Sources

- [List oAuth2PermissionGrants (v1.0)](https://learn.microsoft.com/en-us/graph/api/oauth2permissiongrant-list?view=graph-rest-1.0)
- [oauth2PermissionGrants Bicep reference (clientId is the service principal object ID)](https://learn.microsoft.com/en-us/graph/templates/bicep/reference/oauth2permissiongrants?view=graph-bicep-1.0)
- [Get oAuth2PermissionGrant (single grant, Directory.Read.All)](https://learn.microsoft.com/en-us/graph/api/oauth2permissiongrant-get?view=graph-rest-1.0)
- [List signIns (AuditLog.Read.All; conditional access permission note)](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0)
- [Get user (User.Read.All least privileged)](https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0)
- [Microsoft Graph permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference)
- Community, 2023, unverified: [Microsoft Q&A on SignInSessionsValidFromDateTime permissions](https://learn.microsoft.com/en-us/answers/questions/1349928/using-powershell-for-microsoft-graphs-to-view-the)

## Recorded decisions (approver)

These decisions are recorded here. They are not approval to enable live execution.

- **PH-ID-002 allowlist identifier:** service principal object IDs. The setup key is `AUDSPECT_PHISH_OAUTH_SP_OBJECT_IDS`, renamed from the application-ID key. How to find and check an ID is in `setup.conf.template`.
- **PH-ID-002 permission:** not approved. Pending confirmation of the least-privileged permission for the exact list operation, and of whether the query restricts results to the allowlisted service principals. If `Directory.Read.All` is needed, it becomes an explicit permission decision with its residual exposure documented.
- **PH-ID-003 `AuditLog.Read.All`:** accepted as the least-privileged sign-in-list permission, subject to tenant validation. Still gated by `graph_permission_review_pending`.
- **PH-ID-003 Conditional Access:** granted only if the scenario's declared objective requires it. Missing `appliedConditionalAccessPolicies` yields inconclusive, never pass.
- **PH-ID-005:** unavailable until its `$select` permission is validated against a test tenant. Gated in code by `graph_permission_review_pending`.
- **Live registration and execution:** remain blocked until the checks above pass.

## Finding for the approver: PH-ID-003 Conditional Access objective

The catalog defines PH-ID-003's expectation as `Enforcement: Blocked`, and its
limitation reads `appliedConditionalAccessPolicies` on the device-code sign-in.
The scenario therefore claims that a Conditional Access policy blocked the sign-in.
That claim cannot be made without the policy result, so Conditional Access
evaluation is essential to the stated objective. Under the approver's rule,
`Policy.Read.ConditionalAccess` is a candidate for a documented, tenant-admin-consented
grant. It has **not** been added. Approval is the approver's decision.

## Recorded approval: PH-ID-003 Conditional Access permission

- **Approved:** `Policy.Read.ConditionalAccess`, as a documented, tenant-admin-consented
  application permission for PH-ID-003. The reason is the scenario's `Enforcement: Blocked`
  objective, recorded in the finding above.
- **Not yet done:** the grant has not been made in any Entra tenant. It is made by a
  tenant administrator when the dedicated test tenant exists. The code does not grant it.
- **Still gated:** PH-ID-003 stays unavailable (`graph_permission_review_pending`) until the
  test-tenant validation passes, as the approval boundary requires.
- **Not decided:** the PH-ID-002 permission (`Directory.Read.All`) and the PH-ID-002
  identifier conflict. Both remain open.

## Recorded approval (round 2): permissions and accepted exposure

- **PH-ID-003:** `Policy.Read.ConditionalAccess` approved as a documented,
  tenant-admin-consented permission, recorded in the connector audit trail (the
  startup record carries the declared permissions). Missing Conditional Access
  evidence stays inconclusive. It never yields PASS.
- **PH-ID-002:** `Directory.Read.All` approved for the reviewed, read-only
  consent-grant list only. Not approved for any other directory read or write.
  **Accepted exposure:** the permission is tenant-wide read on directory data. The
  installation allowlist limits what Audspect intends to query. It does not narrow
  the permission Microsoft grants the application. Anyone holding the application's
  credentials could read the grants the permission covers.
- **PH-ID-002 still unavailable** until the filtered query, target enforcement, and
  pagination and error behavior are verified, and until live-tenant permission
  behavior is confirmed.
- **Identifier:** service principal object IDs, per Microsoft's documented
  `clientId` semantics. A live check in the test tenant still verifies the actual
  request and response.
- **PH-ID-005:** not registered and not enabled.
- **Side-effecting scenarios:** remain unregistered. Calendar writes, session
  revocation, sharing invitations, and Conditional Access changes are not approved.
- **Availability gate:** crafted triggers create no run, and that gate stays in place.

## Gate progress: pagination and filter enforcement (offline only)

Implemented and covered by httptest tests. These are code-level results, not live
validation.

- Consent-grant and sign-in reads now follow `@odata.nextLink` through one pager
  (`internal/phishidentity/paging.go`). A partial first page is no longer returned
  as the whole answer.
- A next link must keep the first request's origin, path, and `$filter`. A foreign
  or filter-changing link is refused and never followed. This is the "no unfiltered
  fallback" rule for pagination.
- A listing longer than 100 pages is an error, never a truncated success.
- Still open, and needing the test tenant: whether Graph's real `nextLink` keeps the
  `$filter`. If it does not, the pager refuses it. That fails closed, but PH-ID-002
  then cannot read a second page live.
