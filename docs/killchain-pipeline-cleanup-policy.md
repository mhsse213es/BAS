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
- Deletion, now built behind approval: a cleanup request previews the run's tagged records on the
  server and binds the exact candidate set; execution re-checks that set, refuses without spending
  the approval if it changed, then deletes only those records by identifier, marker and tag.
  Verified against the lab: exact matches deleted, near-miss records (other run, untagged) kept.
- Cleanup second-person rule: enforced for customer deployments at approval time; lab may self-approve.
- Retention, enforced server-side in preview and execution: a record is eligible only if its
  @timestamp (a date field, required in the index mapping) is at least 30 days before server time.
  Exactly 30 days old is eligible. Missing, null, malformed, non-date-mapped and future event times
  are held. The eligible set, with each record's identity and event time, is bound to the approval;
  execution re-previews and refuses if either changed. The delete query repeats the cutoff. Judgement
  call to confirm: "older than the window" is read as eligible, not "kept for the window".
- A partial or failed deletion is recorded as failed and the approval is spent; a retry needs a new
  approval. Execution is not restricted to the approver; any holder of pipeline:cleanup:approve can
  execute an approved request. Decide whether that should be the approver only.
- Connectors other than Elastic. They report unsupported.

## Confirmed decisions (cleanup execution)

- Execution is limited to the approver. Only the authenticated user who approved an exact cleanup
  request may execute it, and every other user is refused with nothing deleted. For a customer
  deployment the approver is never the requester. For a lab deployment, self-approval makes the
  requester the approver, so the requester may execute.
- Retention: a record is eligible only when its `@timestamp` is strictly earlier than the cutoff,
  which is server time minus 30 days. A record exactly at the cutoff is held. Missing, null,
  malformed, non-date-mapped and future timestamps are held and reported with the reason. Preview
  and the delete query use the same rule.
- Audit sequence: a cleanup.started record is committed before any deletion. If it cannot be
  committed, nothing is deleted and the approval is not spent. A cleanup.finished record carries the
  counts and is committed after deletion. If the finish record cannot be committed after a deletion
  ran, the response is unresolved, the start record stands, the approval outcome stays unknown, and
  nothing is retried automatically. Reconciliation of unresolved executions is not yet built.

## Reconciliation of unresolved cleanup executions

- GET `/api/pipeline-approvals/unresolved-cleanups` lists executions that have a started record and
  no finished, not-run or reconciled record.
- POST `/api/pipeline-approvals/unresolved-cleanups/{executionId}/reconcile` records a human
  resolution: `deleted` or `not_deleted`, with a required note saying how it was established. It
  writes one durable audit record. It deletes nothing, retries nothing, and leaves the approval spent.
- Both routes need `pipeline:cleanup:approve`. Each resolution is audited with the reconciler's identity.
- Not yet built: automatic detection of the actual state in Elasticsearch during reconciliation. The
  resolution is currently a human statement, recorded as such.
