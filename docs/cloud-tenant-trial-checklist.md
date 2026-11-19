# Cloud BAS — tenant trial checklist (live testing, before a client environment)

**Date:** 2026-11-10
**Scope:** what to provision in AWS, Azure, GCP and Kubernetes to run everything *already built* in `orchestrator/internal/cloudgraph` against a real account or cluster — discovery, the authorization evaluators, preflight, the two read-only cloud probes, audit-log/event correlation, and the Kubernetes static RBAC/pod/network-policy analysis.
**Out of scope:** Stratus Red Team (`R-21` in `docs/cloud-open-decisions.md`, tracked as `O-15`). That is a separate, state-changing execution subsystem on its own dedicated sandbox account, parked pending provisioning. Do not reuse that account for this checklist, and do not reuse this checklist's account(s) for Stratus once it resumes — the permission footprints and risk profiles are deliberately different.

Every permission and preflight-check name below was read from the current code (`aws_discovery.go`, `azure_discovery.go`, `azure_preflight.go`, `gcp_discovery.go`, `gcp_preflight.go`, `probe.go`, `probe_aws.go`, `cloud_event_sources.go`, `cloud_scenarios.go`, `k8s_discovery.go`, `k8s_rbac_analysis.go`) on 2026-11-10, not reconstructed from memory. None of this has been run against a real account yet — see the open items this closes, listed per provider below.

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

**Credentials:** the standard AWS SDK default chain (environment variables, shared credentials file, or an instance role) — no file-based mechanism like Azure's below. Region comes from that same config; `cloudtrail:LookupEvents` is regional, so run discovery/observe in the same region the test actions happened in, or use a multi-region trail.

**Cross-account grant detection does not need a second AWS account.** `aws_crossaccount.go` reads bucket-policy principals that name another account ID as text in the policy document — it never queries or assumes into that account. One account with a bucket policy naming a foreign account ID is enough to exercise it.

**Optional, for multi-account fan-out (`RunMultiAccount`, Phase 3):** a second AWS account, same provider, to actually exercise the concurrent fan-out code with two real accounts rather than one. Not required for anything else in this checklist.

**Caveat (from `docs/aws/README.md`):** `organizations:ListPoliciesForTarget`/`DescribePolicy` only succeed from the Organization's management account or a registered delegated administrator. From any other account the SCP check reports "could not read policies" — handled gracefully, but it validates nothing. Either run the BAS role from the management account, or register the test account as a delegated admin for the Organizations service.

**To exercise the Observe/evidence-correlation path for real** (not just the graph prediction): have a test identity actually perform one benign read (e.g. a real `s3:GetObject` on its own test object) once, then confirm the server's CloudTrail read finds that event. That is a permission on the *test identity*, not the BAS server's role.

**Closes:** `O-2` (live AWS discovery), part of `O-4` (live audit evidence — management events only; S3 object reads are data events CloudTrail doesn't return, so they correctly show as Unknown), part of `O-5` (live scenario HTTP path, AWS side).

## Azure

**Status:** this is the exact tenant gap already logged as blocked, `O-1` — no subscription, no directory role in the tenant, and the prior app registration no longer exists (see `docs/cloud-open-decisions.md` / `project_azure_real_discovery_integration` memory). Everything below needs that resolved first.

**Tenant/subscription:** one subscription. For management-group testing, it should sit under a management group (even one level under root).

**App registration + consent:** Graph application permissions `User.Read.All`, `Application.Read.All`, admin consent granted. Service principal given **Reader** on the subscription, ideally also Reader at the management-group root so `mg-hierarchy-readable` passes.

**Credentials:** loaded from the file named by `CLOUD_AZURE_SECRETS_FILE` — four keys, `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_SUBSCRIPTION_ID`. The server refuses to start if `AZURE_CLIENT_SECRET` is set in the process environment instead.

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

**APIs that must be enabled on the project first** — disabled by default on a fresh project, a common first-run failure: Cloud Resource Manager API (`cloudresourcemanager.googleapis.com`), IAM API (`iam.googleapis.com`), Cloud Storage API (`storage.googleapis.com`), Cloud Logging API (`logging.googleapis.com`).

**Credentials:** Application Default Credentials — a service-account JSON key file via `GOOGLE_APPLICATION_CREDENTIALS`, or workload identity. No secrets-file mechanism like Azure's.

**Preflight checks this must satisfy** (`gcp_preflight.go`, 6 checks): `project-ancestry-readable`, `project-iam-readable`, `ancestor-iam-readable`, `deny-policies-readable`, `buckets-readable`, `service-accounts-readable`.

**Resources to seed:**

| Resource | Purpose |
|---|---|
| 2+ IAM bindings at the project level, different roles (custom and predefined) | Real bindings for the evaluator |
| 1+ GCP IAM Deny Policy on the project | `deny-policies-readable`, deny-rule evaluation — creating one needs a role beyond the read-only service account; a one-time setup action |
| 1 storage bucket with a bucket-level IAM policy | `data-access-gcp` scenario |
| Data Access audit logs enabled on that bucket | Off by default per-resource (`O-4`). Without it, `storage.objects.get` correctly shows as Unknown — expected, not a bug — but it needs to be on to test the "it actually works" path |

**Closes:** `O-3` (live GCP discovery), part of `O-4` (Data Access logs, once enabled), part of `O-5` (GCP side).

## Kubernetes

**Status:** the Safe-profile discovery and static RBAC/pod/network-policy analysis is already proven live, on one cluster — `kind-bas-lab` (single-node `kind`), scenarios S9 and S10 (`docs/k8s-bas/lab-run-2026-11-04.md`). What this checklist is for is a *second* cluster to broaden that proof, or to set one up from scratch the same way. What's genuinely open is listed at the end of this section.

**Cluster registration:** display name, API server URL, cluster CA fingerprint (read from `/version`), and a **cluster class** — `lab`, `non-production`, or `production` — set by an administrator, never by the requester. For this checklist, register it as `lab`: Safe-profile analysis works on any class, but the Lab-profile network probes below only run on a lab-classified cluster (`docs/k8s-bas/SPEC-first-wave.md` §1–3).

**Discovery identity (read-only, Safe profile).** The lab uses a ServiceAccount `kube-system/bas-discovery` bound to a ClusterRole with `get`/`list` on exactly the resources `k8s_discovery.go` lists: `namespaces`, `pods`, `serviceaccounts`, `roles` and `rolebindings` (`rbac.authorization.k8s.io`, namespaced), `clusterroles` and `clusterrolebindings` (same group, cluster-scoped), `replicasets`/`deployments`/`statefulsets`/`daemonsets` (`apps`), `jobs`/`cronjobs` (`batch`), `networkpolicies` (`networking.k8s.io` — added as a separate ClusterRole in `orchestrator/testdata/k8s-netpol/lab-discovery-rbac.yaml` so it doesn't widen the base role), and optionally `helmcharts.helm.cattle.io` (a CRD; its absence is read as "none," not a gap, if Rancher isn't installed).

**This base ClusterRole is not committed anywhere in the repo.** It exists only as whatever was manually applied to `kind-bas-lab` — `lab-discovery-rbac.yaml` only *adds* the NetworkPolicy rule to it, and assumes it already exists. Before setting up a second cluster, either find and commit the original manifest, or write a new one from the resource list above — otherwise it has to be re-derived by hand every time.

**Resources to seed, so the static analysis has real findings to produce (not an empty cluster):**

| Resource | Purpose |
|---|---|
| A pod whose ServiceAccount is bound to a role granting `list`/`get` on `secrets`, `create` on `pods`, `create` on `pods/exec`, or `escalate` on `roles` | Exercises the privilege-escalation catalogue (`k8s_rbac_analysis.go`'s `k8sPrivilegeCatalog`) |
| A mix of pods with and without `automountServiceAccountToken: false` | Token-exposure analysis |
| Pods with varying security contexts (privileged, hostNetwork, hostPath, `runAsNonRoot` unset) | Dangerous-pod-configuration analysis |
| Two namespaces with a NetworkPolicy restricting traffic between them, plus a listener pod/Service pair in one and a prober identity in the other (the lab uses `np-app`/`np-db`, default-deny ingress on `np-db` with one allow rule) | Network-policy boundary analysis — this is exactly scenario S9 |

**The Lab-profile network probes are their own, separate trust boundary** — the same distinction as Stratus vs. discovery for cloud, just smaller in scope: they create and delete real, short-lived pods to test actual connectivity, not just read RBAC/policy objects. The lab's `bas-probe` ServiceAccount (`orchestrator/testdata/k8s-netpol/lab-probe-rbac.yaml`) is scoped to `create`/`get`/`list`/`delete` on `pods` and `get` on `pods/log` in exactly one namespace, with `automountServiceAccountToken: false`, bound only via a namespaced `Role` — never a `ClusterRole`. Lab cluster only, never customer production, per the execution-profile table in `SPEC-first-wave.md`.

**What's open:**
- `O-12` — managed platforms (EKS, AKS, GKE, OpenShift). Each is its own cloud-account provisioning exercise on top of (not instead of) the AWS/Azure/GCP work above, since a managed cluster lives inside a cloud account.
- `O-13` — a genuine multi-node K3s environment; `kind-bas-lab` is single-node.
- `O-14`'s node-proxy attack-path route is modelled from RBAC grants only and has never been checked against real kubelet behaviour.

**What this is not:** the `Controlled` execution profile — state-changing actions against a customer's cluster under a signed customer authorization (`docs/k8s-bas/customer-authorization.md`). That's the live-engagement path, not something to provision for internal pre-client testing.

## Cross-cutting, all three providers

- **One allow-list covers everything:** `CLOUD_ALLOWED_ACCOUNTS` must name these exact accounts before the server will touch them at all, regardless of credentials. It applies to discovery, every plan run, campaigns, scenario runs, preflight, and the probes. An older, probe-specific `CLOUD_PROBE_ALLOWED_ACCOUNTS` variable existed earlier and is no longer read — don't set it expecting it to do anything.
- Azure credentials load from a file (`CLOUD_AZURE_SECRETS_FILE`), not the environment — the server refuses to start otherwise. AWS and GCP use their SDKs' own standard credential mechanisms (see each section above).
- **Who can run any of this:** the API routes for discovery/plan runs, scenario runs, campaigns, preflight and the probes all require the `CanRunScenario` permission; cloud topology import and path-finding require `CanImportCloudTopology`. Whoever runs the trial needs one of those roles.
- **Running more than one account/provider at once:** discovery allows one pass per account at a time (a second concurrent request gets a 409) and caps total concurrent passes server-wide (`CLOUD_DISCOVERY_MAX_CONCURRENT`, `CLOUD_DISCOVERY_MAX_QUEUED`, `CLOUD_DISCOVERY_QUEUE_WAIT`). The defaults are fine for a handful of trial accounts; just don't expect to fire discovery at all three providers at the exact same instant without some queuing.
- None of this provisions a meaningful ongoing cloud spend. It's a small fixed footprint seeded once (a couple of buckets, one backup vault, one storage account, one Recovery Services vault) — materially different from Stratus's per-run ephemeral infrastructure cost.

## AWS — Stratus Red Team sandbox (separate account, parked)

This is a cloud account requirement too, so it belongs in this doc even though the work on it is parked. Keep it a **different account** from the three discovery-trial accounts above: Stratus needs create/delete rights to provision ephemeral attack infrastructure, a materially bigger blast radius than the read-only role those accounts use, and the owner decision (`R-21`) was explicit that it must stay isolated from everything else, including the discovery sandbox.

**Account:** one dedicated AWS account, owned by Audspect, isolated from customer accounts, operational accounts, and the discovery-trial account above. Not provisioned yet (confirmed 2026-11-09).

**Before any detonation-capable code is written, the account needs:**
- Ownership confirmed.
- A per-run budget guardrail and an account-level budget alert (Audspect owns the spend — warmup, detonate, cleanup, and any leaked-resource recovery).
- Permissions **scoped to the eventual approved technique set only** — this cannot be finalized yet, because the technique registry itself (`R-21` Priority 3: "fixed technique registry — versioned, reviewed, reversible techniques only") hasn't been built. Provisioning the account doesn't require that registry first; scoping its permissions precisely does.
- The pinned `stratus` binary, checksum-verified against the official GitHub release and signed through Audspect's own process (no upstream signature exists to verify against — see `R-21`'s verification findings).

**What it is not:** a read-only account like the three above. It will hold real create/delete permissions (IAM, storage, compute, depending on which techniques are eventually approved) and real, if ephemeral, billable resources.

**Full decision record, approval conditions, and current status:** `docs/cloud-open-decisions.md` (`R-21`), tracked as `O-15` in `docs/cloud-mastery-qa-log.md`.

## What this does not cover

- Building any part of Stratus Red Team itself (registry, approval, executor) — the section above names the account requirement; the build is parked (`R-21`/`O-15`).
- State-changing cloud actions of any kind — none exist in the code this checklist tests.
- GCP folder/org hierarchy inheritance beyond the documented limitation.
- The `Controlled` Kubernetes execution profile (state-changing actions against a customer's cluster under a signed customer authorization) — see the Kubernetes section above for what Safe/Lab-profile testing needs instead.
