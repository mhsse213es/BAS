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
- **Resolution path:** set `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_SUBSCRIPTION_ID`, then run `Preflight`. It returns one line per gap: `token-graph`, `token-arm`, `subscription-visible`, `rbac-readable`, `deny-assignments-readable`, `graph-users-readable`, `graph-service-principals-readable`. Then run the existing integration test with `-tags=integration`.

### O-2 — Live AWS discovery — OPEN
- **What's needed:** a least-privilege read role in a test account. It needs `iam:GetAccountAuthorizationDetails`, `sts:GetCallerIdentity`, `s3:ListAllMyBuckets`, `backup:ListBackupVaults`. Then compare the discovered edges against IAM Policy Simulator for a sample of identities.
- **Verify:** the `GetAccountAuthorizationDetails` pagination marker; that policy documents arrive URL-encoded and decode cleanly; that the `backup_vaults` count matches the console.

### O-3 — Live GCP discovery — OPEN
- **What's needed:** a project with a read-only service account. It needs `resourcemanager.projects.getIamPolicy`, `iam.roles.get`, `iam.serviceAccounts.list`, `storage.buckets.list`, `storage.buckets.getIamPolicy`, and `iam.denypolicies.list` (the deny read is the one most likely to be missing).
- **Verify:** that real deny principal URIs match the forms `gcpDenyPrincipal` maps (`principal://goog/subject/…`, `principal://iam.googleapis.com/projects/-/serviceAccounts/…`). Any unmapped form is counted in `unmapped_deny_principals`; check that counter first.

### O-4 — Live audit evidence coverage — OPEN, important
Audit sources read what the provider logs. Some scenario steps are logged only if the provider is configured to log them:
- **AWS:** CloudTrail `LookupEvents` covers management events only, for 90 days. S3 object reads (`s3:GetObject`) are data events and are not returned, so those steps will observe as **Unknown**. This is correct, not a bug.
- **Azure:** the Activity Log covers control-plane operations only. Blob reads (`blobs/read`) are not logged there, so they will observe as **Unknown**.
- **GCP:** Data Access audit logs are off by default for most services. `storage.objects.get` needs them enabled, or it will observe as **Unknown**.
- **Verify:** for each provider, that a known control-plane action (for example, a role assignment) returns a `perfect` match, and that the Unknown results above are the only ones.

### O-5 — Live scenario HTTP path — OPEN
- The unit tests cover validation (`validateCloudScenarioRunBody`) and the DB executor against Postgres. The full path (`POST /api/cloud-scenario-runs` with real credentials, a real discovery pass, and `observe`) has not been exercised end-to-end.
- **Verify:** one run per provider, with `observe` on, through the HTTP API. Check the stored `cloud_runs.result` and the audit-log row.

### O-6 — Azure wildcard roles under-report — OPEN, important (MODEL)
- Roles such as Owner and Contributor carry `*` in `actions`. Discovery emits edges with the literal action `*`, and `AzureEvaluator` matches exactly, so a concrete query such as `Microsoft.Storage/storageAccounts/listKeys/action` finds no grant. The result is that **a subscription Owner appears to have no access**. This is a conservative error, but a wrong one.
- **Why not fixed now:** a naive glob match would over-report, because `notActions` carve-outs are currently only subtracted as exact strings (`effectiveRoleActions`). Fixing it properly needs (a) an action catalogue from `providerOperations`, and (b) a `role_not_actions` attribute the evaluator checks. That is a design change to a working evaluator and is not made silently.
- **Verify live:** confirm that an Owner-assigned identity's scenario steps read as unknown or blocked, and confirm the size of the gap.

### O-7 — Enforcement layers not modelled (MODEL, high impact)
These can make discovery over-report access, which is the dangerous direction:
- **AWS:** Organizations SCPs, permission boundaries, session policies, and resource-based policies (for example S3 bucket policies) are not read. A grant blocked by an SCP shows as reachable.
- **Azure:** deny assignments are now read and applied (`azure_denies.go`). Management-group-level role assignments are **not** read, so inherited grants are missing (under-report).
- **GCP:** only project and bucket bindings are read. Folder and organization bindings, and deny policies above the project, are missing. Missing org admin bindings under-report; missing org-level denies over-report.
- **Verify:** pick one identity per provider with an SCP, a permission boundary, or an org-level binding, and confirm the verdict.

### O-8 — Conditions (MODEL)
- **AWS:** Allow statements with a `Condition` are emitted and evaluated as unconditional. Counted in `conditional_allows`. The evaluator does not evaluate conditions.
- **GCP:** conditional bindings are skipped and counted in `conditional_bindings`. Those grants are invisible (under-report).
- **Verify:** the counts on a real account. Decide whether a conditional allow should map to `ConditionallyReachable`. That is a design decision for the user.

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

### R-8 — Credentials never come from a request — RESOLVED `28304ead`, `7ae44b57`
- AWS uses the SDK default chain, GCP uses Application Default Credentials, Azure reads service-principal variables. Each discoverer proves the credentials resolve to the account the run names before it reads inventory. Error text names a missing variable, never its value.

## Test and build summary

Commands and what they covered at each commit:

- `go test ./internal/cloudgraph/` — **passes** at the final state of this commit. Covers callguard, AWS, GCP, Azure (including preflight and deny), audit sources, scenarios, glob matching, the existing evaluators and reachability.
- `go test ./internal/db/ -run 'ExecuteCloudPlanRun|ExecuteCloudScenarioRun'` — **passes** against Postgres via Testcontainers (Docker required).
- `go test ./internal/api/ -run 'Cloud|ValidateCloud|AccountChecked'` — **passes**. This includes the existing cloud-run and campaign handler tests, which still pass after the `discover` change.
- Full `go build ./...` in the main tree is **not green at the time of writing**. An untracked, in-progress killchain change in another session references symbols that do not exist at HEAD (`killchain_hostevidence.go`, `killchain_executor.go`). None of the failing files are part of this initiative. Cloud packages build and test cleanly.

Dependencies added: `aws-sdk-go-v2` (config, iam, sts, s3, cloudtrail, backup), `google.golang.org/api` v0.264.0 (cloud resource manager, iam v1 and v2, storage, logging, transport). `go mod tidy` moved the Google API module from v0.200.0 to v0.264.0 as a side effect; the cloud tests pass on it.
