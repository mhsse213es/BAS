# Cloud BAS — tenant trial checklist (live testing, before a client environment)

**Date:** 2026-11-10
**Scope:** what to provision in AWS, Azure and GCP to run everything *already built* in `orchestrator/internal/cloudgraph` against a real account — discovery, the authorization evaluators, preflight, the two read-only probes, and audit-log/event correlation.
**Out of scope:** Stratus Red Team (`R-21` in `docs/cloud-open-decisions.md`, tracked as `O-15`). That is a separate, state-changing execution subsystem on its own dedicated sandbox account, parked pending provisioning. Do not reuse that account for this checklist, and do not reuse this checklist's account(s) for Stratus once it resumes — the permission footprints and risk profiles are deliberately different.

Every permission and preflight-check name below was read from the current code (`aws_discovery.go`, `azure_discovery.go`, `azure_preflight.go`, `gcp_discovery.go`, `gcp_preflight.go`, `probe.go`, `probe_aws.go`, `cloud_event_sources.go`, `cloud_scenarios.go`) on 2026-11-10, not reconstructed from memory. None of this has been run against a real account yet — see the open items this closes, listed per provider below.

## Two kinds of identity, in every provider

1. **The BAS server's own credentials.** Least-privilege, read-only. The only thing discovery, the probes, and preflight ever use. Never a credential that can write.
2. **Test subjects.** Identities *inside* the trial account that the server evaluates, with a deliberate spread of real permission levels (fully open, scoped, denied by policy), so the evaluator has genuine allow/block cases to reason about — not something it invents.

## AWS

**Account:** one dedicated test account. For the SCP check below, it should be a **member account inside an AWS Organization**, not the management account. A standalone account covers everything else.

**BAS server role** — exactly `docs/aws/bas-server-readonly-policy.json`, nothing more:
`iam:GetAccountAuthorizationDetails`, `iam:SimulatePrincipalPolicy`, `s3:ListAllMyBuckets`, `s3:ListBucket`, `s3:GetBucketPolicy`, `backup:ListBackupVaults`, `cloudtrail:LookupEvents`, `organizations:ListParents`, `organizations:ListPoliciesForTarget`, `organizations:DescribePolicy`.

**Resources to seed:**

| Resource | Purpose |
|---|---|
| 2+ IAM test identities with different attached policies (one fully permissive, one scoped, one denied by an explicit deny or SCP) | Gives the evaluator real allow/deny cases |
| 1 IAM role with a permission boundary attached | Exercises permission-boundary evaluation (`R-10`) |
| An SCP attached at the OU or account level, denying one specific action | Exercises SCP evaluation (`R-10`) — see caveat below |
| 2+ S3 buckets — at least one with a bucket policy, one without, and ideally one in a different region | Discovery, and the `GetBucketPolicy` cross-region-redirect edge case noted in `O-2` |
| 1 AWS Backup vault with a backup plan and at least one recovery point | So `backup-assurance-aws` has something real to discover and evaluate |
| CloudTrail available (a trail, or just the default 90-day event history) | `cloudtrail:LookupEvents`, `O-4` |

**Caveat (from `docs/aws/README.md`):** `organizations:ListPoliciesForTarget`/`DescribePolicy` only succeed from the Organization's management account or a registered delegated administrator. From any other account the SCP check reports "could not read policies" — handled gracefully, but it validates nothing. Either run the BAS role from the management account, or register the test account as a delegated admin for the Organizations service.

**To exercise the Observe/evidence-correlation path for real** (not just the graph prediction): have a test identity actually perform one benign read (e.g. a real `s3:GetObject` on its own test object) once, then confirm the server's CloudTrail read finds that event. That is a permission on the *test identity*, not the BAS server's role.

**Closes:** `O-2` (live AWS discovery), part of `O-4` (live audit evidence — management events only; S3 object reads are data events CloudTrail doesn't return, so they correctly show as Unknown), part of `O-5` (live scenario HTTP path, AWS side).

## Azure

**Status:** this is the exact tenant gap already logged as blocked, `O-1` — no subscription, no directory role in the tenant, and the prior app registration no longer exists (see `docs/cloud-open-decisions.md` / `project_azure_real_discovery_integration` memory). Everything below needs that resolved first.

**Tenant/subscription:** one subscription. For management-group testing, it should sit under a management group (even one level under root).

**App registration + consent:** Graph application permissions `User.Read.All`, `Application.Read.All`, admin consent granted. Service principal given **Reader** on the subscription, ideally also Reader at the management-group root so `mg-hierarchy-readable` passes.

**Preflight checks this must satisfy** (`azure_preflight.go`, 7 checks): `token-graph`, `token-arm`, `subscription-visible`, `rbac-readable`, `deny-assignments-readable`, `mg-hierarchy-readable`, `graph-users-readable`.

**Resources to seed:**

| Resource | Purpose |
|---|---|
| 2+ role assignments at different scopes (subscription, resource group), different roles | Real RBAC for the evaluator |
| At least one deny assignment | Deny-precedence logic — not present by default on a plain subscription; Azure Blueprints or an Azure Lighthouse delegation creates these automatically, or create one directly |
| A management group hierarchy with the test subscription nested in it | `mg-hierarchy-readable`, scope-inheritance tests |
| 1 storage account with at least one container/blob | `data-access-azure` scenario (list keys + read blob) |
| 1 Recovery Services vault with a protected item and a backup policy | `backup-assurance-azure` scenario |
| Activity Log (on by default for control-plane operations) | `O-4` — blob *reads* are data-plane and will correctly show as Unknown regardless |

**Closes:** `O-1` (tenant readiness), part of `O-4` (control-plane Activity Log evidence), part of `O-5` (Azure side).

## GCP

**Project:** one dedicated test project. A folder under an organization is optional — it only matters for exercising hierarchy inheritance beyond project level, and the evaluator's folder→project resolution already has a documented limitation (`TestGCPEvaluator_FolderScopeInheritsToProjectUnderIt`), so this is a nice-to-have, not something this closes.

**Service account** (read-only): `resourcemanager.projects.getIamPolicy`, `resourcemanager.projects.get`, `iam.roles.get`, `iam.serviceAccounts.list`, `storage.buckets.list`, `storage.buckets.getIamPolicy`, `iam.denypolicies.list`.

**Preflight checks this must satisfy** (`gcp_preflight.go`, 6 checks): `project-ancestry-readable`, `project-iam-readable`, `ancestor-iam-readable`, `deny-policies-readable`, `buckets-readable`, `service-accounts-readable`.

**Resources to seed:**

| Resource | Purpose |
|---|---|
| 2+ IAM bindings at the project level, different roles (custom and predefined) | Real bindings for the evaluator |
| 1+ GCP IAM Deny Policy on the project | `deny-policies-readable`, deny-rule evaluation — creating one needs a role beyond the read-only service account; a one-time setup action |
| 1 storage bucket with a bucket-level IAM policy | `data-access-gcp` scenario |
| Data Access audit logs enabled on that bucket | Off by default per-resource (`O-4`). Without it, `storage.objects.get` correctly shows as Unknown — expected, not a bug — but it needs to be on to test the "it actually works" path |

**Closes:** `O-3` (live GCP discovery), part of `O-4` (Data Access logs, once enabled), part of `O-5` (GCP side).

## Cross-cutting, all three providers

- `CLOUD_ALLOWED_ACCOUNTS` (and the separate, narrower probe allow-list) must name these exact accounts before the server will touch them at all, regardless of credentials.
- Azure credentials load from a file (`CLOUD_AZURE_SECRETS_FILE`), not the environment — the server refuses to start otherwise.
- None of this provisions a meaningful ongoing cloud spend. It's a small fixed footprint seeded once (a couple of buckets, one backup vault, one storage account, one Recovery Services vault) — materially different from Stratus's per-run ephemeral infrastructure cost.

## What this does not cover

- Stratus Red Team (`R-21`/`O-15`) — separate dedicated sandbox account, parked.
- State-changing cloud actions of any kind — none exist in the code this checklist tests.
- GCP folder/org hierarchy inheritance beyond the documented limitation.
- Kubernetes on managed platforms (`O-12`) or multi-node K3s (`O-13`) — unrelated to this checklist, tracked separately.
