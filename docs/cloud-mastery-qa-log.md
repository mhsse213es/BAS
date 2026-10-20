# Cloud BAS Mastery — QA Log

**Scope:** the seven sub-projects in `cloud.txt` (real cloud integration), built 2026-10-20.
**Status:** all buildable scope is built and unit-tested. **Nothing has run against a live cloud account yet.** Live testing, validation and QA are deliberately deferred to one session, after the build.

Read this before making any external claim about cloud coverage. Every item below is grounded in the code at the commits named.

## Sub-project status

| # | cloud.txt item | Status | Where |
|---|---|---|---|
| 1 | Real AWS discovery (SDK-backed inventory + IAM policy retrieval) | Built, fake-API tested | `cloudgraph/aws_discovery.go` (`3aad60f8`, `7ae44b57`) |
| 2 | Close the Azure tenant gaps, run the existing real discovery | Code was already built. Tenant actions remain. Preflight added to name each gap. | `cloudgraph/azure_preflight.go`, `azure_denies.go` (`7ae44b57`, this commit) |
| 3 | Real GCP discovery (SDK-backed) | Built, httptest-tested against the real Google clients | `cloudgraph/gcp_discovery.go` (`85e578bd`) |
| 4 | Wire real discovery into CloudPlan / cloud_runs | Built: `discover:true` on runs and campaigns, scenario runs | `db/cloudrun_executor.go`, `api/cloudrun_discovery.go` (`28304ead`), `db/cloudscenario_executor.go` (`7ae44b57`) |
| 5 | Real CloudTrail / Activity Log / Audit Log ingestion | Built, parser- and fake-service-tested | `cloudgraph/cloud_event_sources.go` (`7ae44b57`) |
| 6 | Backup-assurance + data-access scenario content, through prerequisite/step gates | Built: 6 builtin scenarios, wired through `PrerequisiteResolver` and `StepGate` | `cloudgraph/cloud_scenarios.go` (`7ae44b57`) |
| 7 | Deployment/release hardening (credentials, rate limits, errors at scale) | Built to the extent code can do it. Items remaining are operational. | `cloudgraph/callguard.go` (`3aad60f8`); see Open items O-9 |

## Open items (for the single live-QA session)

Status key: **OPEN** = needs a live account or a decision. **MODEL** = known limit of the current evaluation model; documented, not fixed.

### O-1 — Azure tenant readiness (sub-project 2) — OPEN, tenant action
- **What's needed:** activate an Azure subscription in tenant `ed059a30-13d2-4042-9c81-dc0e4af979ef`; grant admin consent to app `870e1fcd-0338-46b4-89a7-cc19f5517097` for `User.Read.All` and `Application.Read.All`; give the service principal Reader on the subscription.
- **Why not code:** subscription activation and consent need a human with the right role. The earlier diagnosis is in `project_azure_real_discovery_integration`.
- **Resolution path:** set `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_SUBSCRIPTION_ID`, then run `Preflight`. It returns one line per gap: `token-graph`, `token-arm`, `subscription-visible`, `rbac-readable`, `deny-assignments-readable`, `mg-hierarchy-readable`, `graph-users-readable`, `graph-service-principals-readable`. Then run the existing integration test with `-tags=integration`.

### O-2 — Live AWS discovery — OPEN
- **What's needed:** a least-privilege read role in a test account. It needs `iam:GetAccountAuthorizationDetails`, `sts:GetCallerIdentity`, `s3:ListAllMyBuckets`, `backup:ListBackupVaults`, and for enforcement layers `organizations:ListParents`, `organizations:ListPoliciesForTarget`, `organizations:DescribePolicy`. Then compare the discovered edges against IAM Policy Simulator for a sample of identities.
- **Also needs** `s3:GetBucketPolicy` on each bucket. A bucket with no policy is normal. Any other failure fails the pass, naming the permission. Buckets in another region may return a redirect from `GetBucketPolicy`; if that happens, the pass fails rather than skipping the bucket. Verify this on a bucket in a second region.
- **Verify:** the `GetAccountAuthorizationDetails` pagination marker; that policy documents arrive URL-encoded and decode cleanly; that the `backup_vaults` count matches the console; that `scp_levels` and `boundary_attached` in the discovery report match the Organizations console and each identity's permissions boundary. A discovery pass fails if Organizations cannot be read, so a missing permission shows up as a named error, not as silent over-reporting.

### O-3 — Live GCP discovery — OPEN
- **What's needed:** a project with a read-only service account. It needs `resourcemanager.projects.getIamPolicy`, `resourcemanager.projects.get` (for ancestry), `iam.roles.get`, `iam.serviceAccounts.list`, `storage.buckets.list`, `storage.buckets.getIamPolicy`, and `iam.denypolicies.list` at the project. If the project sits under a folder or organization, the same account also needs `resourcemanager.folders.getIamPolicy`, `resourcemanager.organizations.getIamPolicy`, and `iam.denypolicies.list` at each of those levels. A missing permission fails the pass with the call named.
- **Verify:** that the deny attachment point now reads `cloudresourcemanager.googleapis.com/projects/…` (it was wrong before R-12). That real deny principal URIs match the forms `gcpDenyPrincipal` maps (`principal://goog/subject/…`, `principal://iam.googleapis.com/projects/-/serviceAccounts/…`). Any unmapped form is counted in `unmapped_deny_principals`; check that counter first. For a project under a folder, confirm that a folder binding and an org deny each appear with `inherited_from`.

### O-4 — Live audit evidence coverage — OPEN, important
Audit sources read what the provider logs. Some scenario steps are logged only if the provider is configured to log them:
- **AWS:** CloudTrail `LookupEvents` covers management events only, for 90 days. S3 object reads (`s3:GetObject`) are data events and are not returned, so those steps will observe as **Unknown**. This is correct, not a bug.
- **Azure:** the Activity Log covers control-plane operations only. Blob reads (`blobs/read`) are not logged there, so they will observe as **Unknown**.
- **GCP:** Data Access audit logs are off by default for most services. `storage.objects.get` needs them enabled, or it will observe as **Unknown**.
- **Verify:** for each provider, that a known control-plane action (for example, a role assignment) returns a `perfect` match, and that the Unknown results above are the only ones.

### O-5 — Live scenario HTTP path — OPEN
- The unit tests cover validation (`validateCloudScenarioRunBody`) and the DB executor against Postgres. The full path (`POST /api/cloud-scenario-runs` with real credentials, a real discovery pass, and `observe`) has not been exercised end-to-end.
- **Verify:** one run per provider, with `observe` on, through the HTTP API. Check the stored `cloud_runs.result` and the audit-log row.

### O-6 — Azure wildcard roles under-report — RESOLVED (see R-9)
- Previously a subscription Owner's `*` edge never matched a concrete action, so Owner looked like no access. Fixed in R-9.
- **Still to verify live:** on a real subscription, an Owner's scenario steps should read as granted, and the `role_not_actions` carve-outs should match what the portal shows for a custom role.

### O-7 — Enforcement layers: closed; expansion limits remain (MODEL)
SCPs, permission boundaries, S3 bucket policies, management-group inheritance, and folder and organization inheritance are now read and applied (R-10 to R-13). What remains:
- **AWS session policies:** IAM does not store them; each AssumeRole call carries its own. Discovery therefore reports a role's maximal grant, which is an upper bound for any session. An operator can supply the session policy a run will use (`sessionPolicy` on `POST /api/cloud-scenario-runs`, R-14). Without one, a scenario result is an upper bound for that role.
- **Bucket policy Allows that are counted, not expanded:** `NotPrincipal` allows and `NotAction`/`NotResource` allows cannot be turned into a finite set of identities, so they are counted (`not_principal_allows`, `not_action_statements`) and produce no edge (under-report). Service principals (for example `cloudtrail.amazonaws.com` writing to a bucket) are not modelled.
- **Verify:** run one scenario as a role with a session policy that allows only part of the role's grants, and confirm the blocked steps match the session. Then pick one identity with an S3 bucket policy that denies its action, and confirm the verdict.

### O-8 — Conditions (MODEL; conditional grants and denies reported as conditional on AWS and GCP)
- **AWS identity policies:** a statement with a `Condition` is no longer treated as unconditional. An Allow with a `Condition` is reported as `ConditionallyReachable` (unresolved condition `enforcement-condition`). A Deny with a `Condition` yields `ConditionallyReachable` instead of `Blocked`. Conditions are not evaluated.
- **AWS cross-document denies:** each identity edge is now checked against all of its holder's identity policies, so an explicit Deny in one document blocks an Allow in another. This closes an over-report in the earlier per-edge check.
- **Verify on a real account:** the `conditional_allows` count, and that conditional grants are not over- or under-reported against the live console.
- **GCP:** conditional bindings are emitted as edges marked `binding_condition`, and the evaluator reports them as conditionally reachable (unresolved condition `gcp-binding-condition`). The count stays in `conditional_bindings`. Conditions are not evaluated. Deny rules with a condition are reported as conditional; see R-18.

### O-9 — Operational hardening not built — OPEN
- Discovery and event calls are not exported as metrics or traces.
- There is no per-tenant quota. The rate limiter is per client process.
- Azure client secret is read from an environment variable. Confirm this matches the project's secret-handling policy before deployment.
- No RBAC scope on who may point a server at which account. Today, the server's own environment decides which account is reachable.

### O-10 — Console UI — OPEN
- No UI exists for `discover:true` runs or scenario runs. The API is in place: `GET /api/cloud-scenarios` and `POST /api/cloud-scenario-runs`.

### O-11 — Cloud actions are never executed — MODEL, by design
- Scenarios predict outcomes from the discovered graph. Audspect does **not** perform cloud actions. `ObserveCloudScenario` checks predictions against audit evidence that already exists, for an execution that happened elsewhere.
- Running a real cloud attack is a separate initiative that needs safety design. It is out of scope here.

## Resolved items (this build)

### R-1 — `CloudPlan` reported unrelated branches as the path — RESOLVED `3aad60f8`
- **What was wrong:** every hop reached during the search was appended to `CloudPath.Hops`. A viable side branch leaked into the path and could lower `OverallState`.
- **What changed:** the path is now the chain of parent hops from target back to a held identity. Covered by `TestAWSDiscover_MultiHopReachesBucketThroughRole`.

### R-2 — Shared event matcher counted the wrong action as evidence — RESOLVED `7ae44b57`
- **What was wrong:** `SyntheticEventCorrelator` scored any two-field match as partial. A same-principal, same-resource event for a different action counted as evidence for an unobserved step.
- **What changed:** evidence requires principal and action to match, as documented. Covered by `TestObserveCloudScenario_EvidenceDecidesOutcome`.

### R-3 — AWS `NotResource` allow became a wildcard edge — RESOLVED (this commit)
- **What was wrong:** a `NotResource` statement with no `Resource` field defaulted to `*`, so "everything except X" produced an unconditional edge.
- **What changed:** `NotAction` and `NotResource` statements are counted in `not_action_statements` and emit no edge. Covered by `TestAWSDiscover_NotResourceStatementEmitsNoWildcardEdge`.

### R-4 — AWS policy matching was substring-based — RESOLVED (this commit)
- **What was wrong:** `s3:GetObject` was satisfied by a document granting `s3:GetObjectAcl`.
- **What changed:** `AWSEvaluator` matches each statement's own `Action` with glob patterns. It falls back to the old check only for unparseable documents. Covered by `TestAWSEvaluator_ActionNameIsMatchedWholeNotAsSubstring` and `TestAWSEvaluator_ServiceWildcardSatisfiesConcreteAction`.

### R-5 — Wildcard grants were invisible to concrete scenario steps — RESOLVED (this commit)
- **What was wrong:** `backup:*` never matched the step `backup:DeleteRecoveryPoint`, so the step was reported as blocked.
- **What changed:** `findScenarioEdge` derives an edge carrying the step's action from a covering pattern grant. Literal and resource-specific matches still take precedence. Covered by `TestExecuteCloudScenario_WildcardGrantCoversConcreteSteps`.

### R-6 — Azure deny assignments were not read — RESOLVED (this commit)
- **What was wrong:** discovery never listed deny assignments, so a grant blocked by a deny looked usable.
- **What changed:** `DiscoverDenyAssignments` reads them, honours `excludePrincipals`, and attaches the first covering deny to each affected edge. `doNotApplyToChildScopes` denies are counted and not guessed. Covered by `azure_denies_test.go`.

### R-7 — Retry, throttling, and secret handling for cloud calls — RESOLVED `3aad60f8`
- Azure, GCP and the audit sources retry 429 and 5xx with backoff and `Retry-After`, bounded by a cap. They are throttled to 5 requests per second, burst 10. Secrets are redacted from errors. Page counts are capped and a cap aborts the pass.
- AWS uses the SDK's own retry policy.

### R-9 — Azure wildcard roles were invisible to concrete steps — RESOLVED (this commit)
- **What was wrong:** an Owner or Contributor `*` edge never matched a concrete action, and `notActions` were merged across a role's permission blocks.
- **What changed:** each permission block is netted against its own exclusions. Wildcard grants are kept as patterns and carry the block's `role_not_actions`. The evaluator matches with glob rules and honours carve-outs. Scenario steps are evaluated against the step's resource, so a grant on an ancestor subscription still applies, and a deny at a child resource group blocks it. Covered by `azure_wildcard_test.go`.
- Management-group inheritance is now read (R-11).

### R-10 — AWS permission boundaries and SCPs were ignored (over-reporting) — RESOLVED `20a4d59d`
- **What was wrong:** a grant that a boundary or SCP blocked was reported as usable.
- **What changed:** each user's and role's boundary is attached to its edges and must allow the action. SCPs are read for the account, each parent OU, and the root, one level each, and every level must allow the action. An explicit Deny at any level blocks. Statements with `NotAction` now count, so "Deny NotAction [s3:GetObject]" guardrails work. A conditional Allow or Deny gives ConditionallyReachable. An unreadable boundary gives Unknown. Discovery fails if Organizations cannot be read. Covered by `aws_enforcement_test.go`.

### R-11 — Management-group grants and denies did not reach subscriptions (under- and over-reporting) — RESOLVED `a085a42c`
- **What was wrong:** an Owner granted at a management group looked like no access. A deny at the group was invisible.
- **What changed:** the tenant root group is read with `$expand=children&$recurse=true` to find the subscription's ancestors. Assignments and denies are read at each ancestor and kept only when their scope is exactly that group, since a list at a group's scope can return other subscriptions' grants. Grants reach the subscription's scope and are tagged `inherited_from`. A deny with `doNotApplyToChildScopes` at a group applies only there, so it is dropped. If the subscription is not in the visible hierarchy, the pass fails. Covered by `azure_hierarchy_test.go`. The preflight gains `mg-hierarchy-readable`.

### R-12 — GCP folder and organization bindings and denies were not read; project deny endpoint was wrong — RESOLVED `f0486ae0`
- **What was wrong:** grants set on a folder or organization were invisible, and denies above the project were not read (both directions). Separately, the project deny read used the attachment point `crm.googleapis.com`. The documented form is `cloudresourcemanager.googleapis.com` (URL-encoded). The fixture matched the substring `denypolicies`, so it could not catch this.
- **What changed:** ancestry comes from `projects.getAncestry`. Each folder and organization's bindings are read and applied to the project, tagged `inherited_from`. Denies are read at the project and every ancestor, using the corrected attachment point. An ancestor of an unrecognized type fails the pass. The fixture now matches the full encoded attachment point. Covered by `gcp_hierarchy_test.go`.
- **Consequence:** the project deny read before this commit was calling the wrong resource. Any GCP run from before `f0486ae0` should be treated as having missed project-level denies.

### R-13 — S3 bucket policies were not read (over-reporting) — RESOLVED (this commit)
- **What was wrong:** an explicit Deny in a bucket policy was invisible, so a grant on that bucket was reported as usable.
- **What changed:** each bucket's policy is read with `s3:GetBucketPolicy`, and attached to every edge whose target is in that bucket. Denies are applied: the Principal or NotPrincipal must name the source identity (or its account root, or `*`), the Resource or NotResource must cover the target, and the Action or NotAction must cover the action. A conditional Deny gives ConditionallyReachable. An unreadable policy gives Unknown. Allows in bucket policies are not applied, since same-account access comes from the identity's own policies. Covered by `aws_s3policy_test.go`.

### R-14 — Enforcement gates ignored the resource; session policies could not be applied (over-reporting) — RESOLVED (this commit)
- **What was wrong:** a boundary, SCP, or session policy that allowed an action on a different resource still counted as covering the target. Separately, there was no way to evaluate a scenario as a role session that carries a session policy.
- **What changed:** every gate now requires a matching Resource or NotResource as well as Action. A `sessionPolicy` on a scenario run (AWS scenarios, role principals only) is checked, normalized, and applied to each step the way a boundary is. Session policies are limited to 2,048 characters, and an unreadable or empty policy is refused, not partly applied. Covered by `aws_session_test.go` and `cloudscenario_session_test.go`.

### R-15 — Bucket policy Allows were not discovered (under-reporting) — RESOLVED (this commit)
- **What was wrong:** a bucket policy that allowed another account, anyone, or a same-account principal directly, granted access the identity policies never showed. None of those grants appeared in discovery.
- **What changed:** each Allow in a bucket policy now produces an edge with source type `resource-policy`. Same-account principals (and this account's root, which expands to every identity in the account) get a clean grant. A principal in another account, and the account root of another account, is conditional on `cross-account-identity-policy`, since the other account's identity policy is not readable. A `"*"` grant is public and conditional on `public-access`. Denies in the same policy still apply. Covered by `aws_crossaccount_test.go`.
- **Limits:** service principals are not modelled. `NotPrincipal` and `NotAction` allows are counted, not expanded.

### R-16 — AWS and GCP had no preflight; a missing permission failed mid-pass — RESOLVED (this commit)
- **What was wrong:** only Azure named each missing tenant prerequisite. An AWS or GCP run hit the first gap as a mid-pass error, which hid the others.
- **What changed:** `AWSDiscoveryClient.Preflight` and `GCPDiscoveryClient.Preflight` run one read-only call per prerequisite and return a PASS, FAIL or SKIPPED line for each, in the same shape as Azure. AWS checks: `sts-identity`, `iam-authorization-details`, `s3-list-buckets`, `s3-bucket-policy-readable`, `organizations-readable`, `backup-vaults-readable`. GCP checks: `project-ancestry-readable`, `project-iam-readable`, one `ancestor-iam-readable:<canonical>` per folder or organization above the project, `deny-policies-readable`, `buckets-readable`, `service-accounts-readable`. A missing bucket policy is a PASS. An account outside an organization is a PASS. Optional clients that are not configured are SKIPPED. A bucket policy check with no bucket to probe is SKIPPED, not passed, because the permission is unverified. Covered by `aws_preflight_test.go` and `gcp_preflight_test.go`.
- **Limits:** at the time of this entry preflight was a method only. Wiring into runs and the API is R-17. The AWS check reports the SDK's error text, not a classified code. The GCP check classifies 401, 403 and 404 as permission gaps.
- **QA runner:** the `aws` group now includes the identity-condition tests (previously none ran). The `azure` group no longer matches the AWS and GCP preflight tests.

### R-17 — Preflight was not connected to runs or the API — RESOLVED (this commit)
- **What was wrong:** the AWS, GCP and Azure preflights could only be called as methods. A run still began discovery without checking, and the first gap failed mid-pass.
- **What changed:** the three discoverers implement `Preflight`, and so does the account-scoped wrapper. The wrapper adds an `account-match` check first, so a mismatched account is reported as a named failure, with the inner checks still shown. Both run executors (plan and scenario) call preflight before `Discover`. Any FAIL stops the run and records it as failed, with every failed check named in the error. SKIPPED checks do not block. The checks that passed are kept on the stored result, as `preflight`. A discovery source that cannot be preflighted is refused, so discovery never runs unchecked. The new endpoint `POST /api/cloud-preflight` takes `{account}` and returns `{passed, checks}` with no inventory read. It needs `CanRunScenario`, the permission discovery already requires. Covered by `db/cloudpreflight_test.go`, `api/cloudrun_discovery_test.go`, and the RBAC matrix (`TestRBACMatrix_*`).
- **Limits:** a run's preflight adds one set of read calls before discovery. Only the run's own result keeps the checks; a failed run keeps only the error text. The route runs the same reads as a run, so a permission the run needs is checked before any pass starts.

### R-18 — GCP conditional bindings and deny rules were mishandled (under- and over-reporting) — RESOLVED (this commit)
- **What was wrong:** a conditional IAM binding was dropped, so a grant it made was invisible. Deny rules are read, but their conditions are not, so a conditional deny blocks outright.
- **What changed (bindings):** conditional bindings produce edges with `binding_condition`. The evaluator reports them as `ConditionallyReachable` with `gcp-binding-condition`. A same-member unconditional grant stays a clean grant. Covered by `gcp_conditional_test.go`.
- **Deny side:** a deny rule with a `denialCondition` no longer blocks outright. Its denied actions are kept apart (`deny_conditional_actions`), and a grant it covers is `ConditionallyReachable` with `gcp-deny-condition` named. An unconditional deny still blocks first. Both conditions are named when a binding and a deny are conditional together. Counted in `conditional_deny_rules`. Covered by `gcp_conditional_test.go`.
- **Counting:** a rule is counted once, however many principals or permissions it names.

### R-8 — Credentials never come from a request — RESOLVED `28304ead`, `7ae44b57`
- AWS uses the SDK default chain, GCP uses Application Default Credentials, Azure reads service-principal variables. Each discoverer proves the credentials resolve to the account the run names before it reads inventory. Error text names a missing variable, never its value.

## Test and build summary

Commands and what they covered at each commit:

- `go test ./internal/cloudgraph/` — **passes** at the final state of this commit. Covers callguard, AWS, GCP, Azure (including preflight and deny), audit sources, scenarios, glob matching, the existing evaluators and reachability.
- `go test ./internal/db/ -run 'ExecuteCloudPlanRun|ExecuteCloudScenarioRun'` — **passes** against Postgres via Testcontainers (Docker required).
- `go test ./internal/api/ -run 'Cloud|ValidateCloud|AccountChecked'` — **passes**. This includes the existing cloud-run and campaign handler tests, which still pass after the `discover` change.
- Full `go build ./...` in the main tree is **not green at the time of writing**. An untracked, in-progress killchain change in another session references symbols that do not exist at HEAD (`killchain_hostevidence.go`, `killchain_executor.go`). None of the failing files are part of this initiative. Cloud packages build and test cleanly.

Dependencies added: `aws-sdk-go-v2` (config, iam, sts, s3, cloudtrail, backup), `google.golang.org/api` v0.264.0 (cloud resource manager, iam v1 and v2, storage, logging, transport). `go mod tidy` moved the Google API module from v0.200.0 to v0.264.0 as a side effect; the cloud tests pass on it.
