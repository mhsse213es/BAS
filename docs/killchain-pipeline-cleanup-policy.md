# Pipeline injection, approval and cleanup policy

Status: accepted defaults. Controls are built in stages. Live injection and destructive
cleanup stay disabled until their authorization and isolation tests pass.

## Why this exists

An injection stage writes test events and cases into a customer SIEM or ticketing system.
Cleanup removes them later. Neither may act on records that were not created by the test
run, and neither may happen just because a campaign was launched. Audit records are
evidence, so they are never deleted.

## Deployment classification

A deployment is `lab` or `customer`. It is set explicitly by the operator in
`BAS_DEPLOYMENT_CLASS`. An unset or unknown value is `customer`, the stricter default. A
lab classification relaxes only the single-person approval rule below. It does not
relax any other control.

## Injection approval

| Decision | Rule |
|---|---|
| Who can approve | A user holding `pipeline:injection:approve`, granted explicitly by an administrator. |
| Self-approval | Refused in `customer`. Allowed in `lab` only for a user holding the permission, in a lab-classified deployment. |
| Expiry | 15 minutes after approval. An expired approval cannot be renewed. A new approval is needed. |
| Scope | Bound to the exact campaign, stage, connector ID, target, payload hash, test scope and expected observable change. |
| Reuse | One approval authorizes one execution. It is consumed atomically when used. |
| Changes after approval | Any change to target, payload, scope or expected change invalidates the approval. |
| Enforcement | Permission, expiry, consumption and binding are checked again immediately before execution. |
| Campaign launch | A campaign launch never approves an injection. Missing, expired or invalid approval means the injection is NOT_TESTED, with the reason recorded. |

Every approval event (request, approve, reject, consume, expire, refuse) is written to an
append-only history. The database rejects UPDATE and DELETE on that history.

## Cleanup

| Decision | Rule |
|---|---|
| Default retention | 30 days for test events, cases and associated pipeline evidence. Subject to customer policy and applicable retention requirements. The window is a platform default, not an override of a customer's policy. |
| Approval, lab | A single person may approve, if they hold `pipeline:cleanup:approve` and the deployment is `lab`. |
| Approval, customer | A different authorized person must approve destructive cleanup. |
| Scope | Only records positively identified as belonging to the test run. Identification uses the run identifier and marker, never time windows or wildcards. |
| Uncertain ownership | Not deleted. Reported as RETAINED, with the reason ownership could not be verified. |
| Audit records | Approval, execution and cleanup audit trail is preserved. Audit records are never deleted because related test data is cleaned up. |
| Provider limits | A connector that cannot reliably select only tagged test records reports cleanup as UNSUPPORTED. Records are retained. |
| Trigger | Cleanup is a separate, auditable operation. It is never an automatic result of a campaign finishing. |
| Preview | A dry run lists what would be deleted and why. Deletion is a separate, approved step. |

## Tagging

Each injected event or case carries a server-generated run identifier and a fixed marker,
written at creation. Cleanup selects by identifier and marker only.

## Connectors

Splunk, QRadar, Sentinel, CrowdStrike, Defender and Trellix are unsupported for ingestion
verification until test instances and API permissions are available. A connection check
is never reported as functional verification. Normalisation, correlation, alert, case and
routing stay NOT_TESTED until each has its own observable evidence.

## Build order

1. Approval records, permissions, expiry, single-use consumption and immutable history.
2. Tagging and dry-run cleanup previews. Deletion stays disabled.
3. Injection behind the approval gate.
4. Tests for: missing, expired, reused, modified-scope and self-approved customer requests
   (all rejected); cleanup against unrelated events and cases (only tagged records eligible).

## Implementation status

Built and tested:
- Approval records with 15-minute expiry, scope binding, single use and an append-only history.
- HTTP routes for request, read, approve and refuse. Each route requires
  `pipeline:injection:approve`, and each decision checks the permission for the approval's kind.
- Deployment classification from `BAS_DEPLOYMENT_CLASS`, read at startup. Unset, empty or
  unrecognised values are customer. A config file cannot set it, and no request can.
- A refused request cannot be approved. An approved request cannot be refused.
- Consumed approvals record `executed` or `failed`. An approval consumed with no outcome is
  shown as unknown and is never reused. Recovery is a new request and a new approval.
- Cleanup preview: refuses malformed run identifiers and pattern indexes; checks that the marker
  fields are mapped before searching, so an unmapped index is an error and never an empty result;
  lists a record only if its stored marker matches exactly.
- Injection stage in campaigns: validates, reports NOT_TESTED, consumes no approval, and writes
  nothing. Retrying the campaign does not change that.

Not built, by decision:
- Live injection. The gate exists, but no provider writes, and no campaign path reaches it.
- Deletion. There is no delete function, and no route for one.
- Connectors other than Elastic. They report unsupported.
